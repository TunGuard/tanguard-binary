package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// policyTun wraps the real TUN device and enforces policy groups in the data
// plane.
//
// TunGuard runs WireGuard in userspace, which means every decrypted packet
// from a peer is handed to this wrapper on its way into the kernel stack, and
// every packet the kernel routes into the tunnel passes through on its way to
// a peer. That makes this the one place where the destination peer and the
// sending peer are both known, so it is where a denied packet is dropped.
//
// Dropping here rather than rejecting a configuration has the property the
// feature needs: a denied device sees no error and no crash, it simply finds
// that the other device does not exist. Nothing about how a device connects
// or how its .conf file looks changes.
//
// Only the rule switches change what happens here. With no custom groups every
// peer evaluates against the default group, whose rules are all on, so the
// allow path is taken for every packet exactly as before this existed.
type policyTun struct {
	inner tun.Device

	policies *PolicyStore
	peers    *PeerStore

	// tunnel is the configured VPN subnet, used to separate tunnel-internal
	// traffic (the inter-device rule) from internet-bound traffic (the
	// WireGuard-access rule).
	tunnel tunnelNet
	// serverIP is the server's own address inside the tunnel. Traffic to it is
	// infrastructure -- DHCP, DNS, NTP and pings to the gateway -- and is never
	// subject to policy, because a device that cannot reach the gateway looks
	// broken rather than isolated.
	serverIP uint32

	// dropInter and dropAccess count silently discarded packets, by reason.
	// The dashboard reads them so an operator can see a policy taking effect.
	dropInter  atomic.Uint64
	dropAccess atomic.Uint64

	// writeMu guards writeScratch, which is only touched on the slow path
	// where at least one packet is dropped.
	writeMu      sync.Mutex
	writeScratch [][]byte

	// logMu and lastDropLog rate-limit drop logging so a denied device cannot
	// flood the log by keeping a connection busy.
	logMu       sync.Mutex
	lastDropLog time.Time
	dropLog     int
}

// newPolicyTun wraps inner so that packets are filtered against ps. It returns
// inner unchanged when there is nothing to enforce against, so a nil or
// unloaded policy store can never break the tunnel.
func newPolicyTun(inner tun.Device, policies *PolicyStore, peers *PeerStore, cfg *Config) tun.Device {
	if inner == nil || policies == nil || peers == nil {
		return inner
	}
	f := &policyTun{
		inner:    inner,
		policies: policies,
		peers:    peers,
		tunnel:   parseTunnelNet(cfg.Subnet),
	}
	if ip, _, err := net.ParseCIDR(cfg.Address); err == nil {
		if v4 := ip.To4(); v4 != nil {
			f.serverIP = binary.BigEndian.Uint32(v4)
		}
	}
	return f
}

// allowsPacket decides the fate of one bare IP packet.
//
// Anything it does not understand is allowed: the policy layer is defined in
// terms of tunnel IPv4 addresses and must never become a new way to break
// ARP, IPv6, or a protocol version added to the kernel after this was written.
func (f *policyTun) allowsPacket(pkt []byte) bool {
	// Fast path for a deployment that has no custom policy groups. No peer can
	// be in anything but the default group, whose rules are all on, so the
	// answer is always "allow" and no lock or lookup is needed. This is the
	// case for every installation that does not use policy groups, and it makes
	// the feature indistinguishable from not having it.
	if !f.policies.IsActive() {
		return true
	}

	src, dst, ok := parseIPv4Packet(pkt)
	if !ok {
		return true
	}

	srcKey, isPeer := f.peers.PublicKeyForIP(src)
	if !isPeer {
		// Not from a peer: either the server itself or a packet the kernel
		// originated. Policy governs peers, so let it through.
		return true
	}

	if !f.tunnel.contains(dst) {
		// Leaving the tunnel: this is ordinary WireGuard internet access.
		if !f.policies.Allows(srcKey, CapWGAccess) {
			f.noteDrop(CapWGAccess, src, dst, srcKey)
			return false
		}
		return true
	}

	if f.isInfraIP(dst) {
		return true
	}

	dstKey, isPeer := f.peers.PublicKeyForIP(dst)
	if !isPeer {
		// Inside the tunnel but unowned. Nothing to isolate it from.
		return true
	}

	// Both ends must permit it. Enforcing on the sending side alone would let
	// a device in a restricted group still be reached by everyone else, which
	// is not what isolating a group means.
	if !f.policies.Allows(srcKey, CapInterDevice) || !f.policies.Allows(dstKey, CapInterDevice) {
		f.noteDrop(CapInterDevice, src, dst, srcKey)
		return false
	}
	return true
}

// isInfraIP reports whether a tunnel-internal address belongs to the server
// itself or to the subnet's own network and broadcast addresses.
func (f *policyTun) isInfraIP(ip uint32) bool {
	return ip == f.serverIP || ip == f.tunnel.net || ip == f.tunnel.net|^f.tunnel.mask
}

// noteDrop records a dropped packet and logs the first few at most once every
// few seconds.
func (f *policyTun) noteDrop(c Capability, src, dst uint32, srcKey string) {
	if c == CapInterDevice {
		f.dropInter.Add(1)
	} else {
		f.dropAccess.Add(1)
	}

	f.logMu.Lock()
	defer f.logMu.Unlock()
	f.dropLog++
	if f.dropLog > 3 || time.Since(f.lastDropLog) < 30*time.Second {
		return
	}
	f.lastDropLog = time.Now()
	name := f.policies.GroupForPeer(srcKey)
	group := "unknown"
	if name != nil {
		group = name.Name
	}
	reason := "internet access"
	if c == CapInterDevice {
		reason = "inter-device traffic"
	}
	log.Printf("[policy] dropped %s from %s to %s (group %q)", reason, ipv4String(src), ipv4String(dst), group)
}

// Stats reports how many packets have been silently dropped, split by rule, so
// the dashboard can show that a policy is actually doing something.
func (f *policyTun) Stats() (inter, access uint64) {
	if f == nil {
		return 0, 0
	}
	return f.dropInter.Load(), f.dropAccess.Load()
}

// ---- tun.Device ----------------------------------------------------------

// Read filters packets the kernel is routing out through the tunnel. A dropped
// packet is marked with a zero size rather than removed from the slice: the
// WireGuard reader skips entries whose size is below one, so leaving the
// element in place is both correct and allocation free.
func (f *policyTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := f.inner.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		if sizes[i] < 1 {
			continue
		}
		pkt := bufs[i][offset:]
		if len(pkt) > sizes[i] {
			pkt = pkt[:sizes[i]]
		}
		if !f.allowsPacket(pkt) {
			sizes[i] = 0
		}
	}
	return n, err
}

// Write filters packets decrypted from peers on their way into the kernel
// stack. This is where device-to-device and device-to-internet traffic is
// first seen with both endpoints known.
func (f *policyTun) Write(bufs [][]byte, offset int) (int, error) {
	// Deciding and counting happen in a single pass so a denied packet is
	// only ever counted and logged once. A drop is rare enough that building
	// the surviving batch here is fine. The scratch slice is reused; WireGuard
	// does not retain the bufs slice or its elements past the call.
	f.writeMu.Lock()
	f.writeScratch = f.writeScratch[:0]
	kept := 0
	for i := range bufs {
		if f.allowsPacket(bufs[i][offset:]) {
			f.writeScratch = append(f.writeScratch, bufs[i])
			kept++
		}
	}
	scratch := f.writeScratch
	f.writeMu.Unlock()

	switch kept {
	case 0:
		// Every packet in the batch was denied. Report success without
		// touching the device: handing it an empty batch can surface as a
		// spurious write error.
		return len(bufs), nil
	case len(bufs):
		// Nothing was denied. This is the common case, so hand the original
		// batch straight through instead of the scratch copy.
		return f.inner.Write(bufs, offset)
	default:
		return f.inner.Write(scratch, offset)
	}
}

func (f *policyTun) File() *os.File           { return f.inner.File() }
func (f *policyTun) MTU() (int, error)        { return f.inner.MTU() }
func (f *policyTun) Name() (string, error)    { return f.inner.Name() }
func (f *policyTun) Events() <-chan tun.Event { return f.inner.Events() }
func (f *policyTun) Close() error             { return f.inner.Close() }
func (f *policyTun) BatchSize() int           { return f.inner.BatchSize() }

// parseIPv4Packet extracts the source and destination addresses from a bare
// IPv4 packet, ignoring any IPv6, ARP or otherwise unrecognised traffic.
func parseIPv4Packet(pkt []byte) (src, dst uint32, ok bool) {
	// A fixed IPv4 header is 20 bytes; the IHL field may extend it with
	// options, which are skipped by reading the address offsets directly.
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, 0, false
	}
	headerLen := int(pkt[0]&0x0f) * 4
	if headerLen < 20 || len(pkt) < headerLen {
		return 0, 0, false
	}
	// Total Length is authoritative; a packet claiming more than it carries is
	// malformed, and a truncated header would mean reading whatever follows.
	if total := int(binary.BigEndian.Uint16(pkt[2:4])); total > 0 && total < headerLen {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(pkt[12:16]), binary.BigEndian.Uint32(pkt[16:20]), true
}

// ipv4String renders a numeric address for logs.
func ipv4String(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}
