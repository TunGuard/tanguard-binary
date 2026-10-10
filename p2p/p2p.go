package p2p

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// P2PRelay is a UDP hub on RELAY_LISTEN. tun clients in mesh mode are told
// (via cmd 0x04) to UDP-connect back to this socket; their NAT mapping then
// becomes their reachable endpoint, which the relay records for discovery.
//
// Two roles overlap here on purpose:
//   - Rendezvous. Before a node knows a peer's real endpoint it punches toward
//     this socket, which is how the server learns each node's mapped address.
//   - Fallback data path. A node whose punch to its peer never completes keeps
//     its peers in the hub's routing table, so datagrams are forwarded
//     node-to-node instead of being lost.
//
// The client's 4-byte "TUN" keepalive probes are consumed to keep the endpoint
// fresh and are never forwarded. Any non-probe datagram received on a node's
// socket is an echo from its peer, which is what tells the server a direct
// path is open.
type P2PRelay struct {
	mu    sync.Mutex
	hub   *MeshHub
	addr  string
	conn  *net.UDPConn
	links map[string]map[string]bool // src node id -> set of dst node ids
	byEP  map[string]string          // udp endpoint -> node id
	// ready is closed once the UDP socket is bound, so a caller can wait for a
	// relay that binds asynchronously instead of racing it.
	ready chan struct{}
	// stop is closed to shut the relay down and release its socket.
	stopOnce sync.Once
	stopped  chan struct{}
}

// Up reports whether the rendezvous socket is bound and serving. A relay that
// failed to bind cannot carry discovery, so callers must be able to see that
// rather than assume it.
func (r *P2PRelay) Up() bool {
	select {
	case <-r.ready:
	default:
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conn != nil
}

// Stop releases the rendezvous socket. Without this the UDP port is never
// freed, which matters when a hub is restarted on the same address.
func (r *P2PRelay) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopped)
		r.mu.Lock()
		uc := r.conn
		r.conn = nil
		r.mu.Unlock()
		if uc != nil {
			uc.Close()
		}
	})
}

func NewP2PRelay(h *MeshHub, addr string) *P2PRelay {
	return &P2PRelay{
		hub:     h,
		addr:    addr,
		links:   make(map[string]map[string]bool),
		byEP:    make(map[string]string),
		ready:   make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

func (r *P2PRelay) Run() {
	if r.addr == "" {
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", r.addr)
	if err != nil {
		log.Printf("[p2p] relay resolve %s: %v", r.addr, err)
		return
	}
	uc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		// Signal readiness even on failure: a caller waiting to talk to the
		// relay should be released rather than hang on a port that will never
		// bind.
		close(r.ready)
		log.Printf("[p2p] relay listen %s: %v", r.addr, err)
		return
	}
	r.mu.Lock()
	r.conn = uc
	r.mu.Unlock()
	close(r.ready)
	log.Printf("[p2p] relay listening on %s", r.addr)

	buf := make([]byte, 65536)
	for {
		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			r.mu.Lock()
			r.conn = nil
			r.mu.Unlock()
			return
		}
		r.handleDatagram(src, buf[:n])
	}
}

// ---- Hub datagram formats -------------------------------------------------
//
// Every datagram a node sends to the hub starts with a 3-byte magic and the
// sender's 8-char node id, so the hub never has to guess who is talking from a
// source address — several devices behind one NAT all share a public IP.
//
//	'T','U','N' | node_id(8) | counter(1)                     keepalive probe
//	'P','1','H' | node_id(8)                                   rendezvous request
//	'P','1','R' | count(1) | count x { node_id(8) | ip(4) | port(2) }
//
// A probe only refreshes the sender's registered endpoint. A rendezvous
// request is answered with every online peer the sender shares a PSK with,
// which is how a device discovers the others without any dashboard action.

const hubProbeMagic = "TUN"
const hubRendHello = "P1H"
const hubRendReply = "P1R"

func hubSender(data []byte) (string, bool) {
	if len(data) < 11 || string(data[3:11]) == "" {
		return "", false
	}
	id := sanitizeDeviceID(string(data[3:11]))
	if len(id) != 8 {
		return "", false
	}
	return id, true
}

func (r *P2PRelay) handleDatagram(src *net.UDPAddr, data []byte) {
	if len(data) < 3 {
		return
	}
	magic := string(data[:3])

	if magic == hubProbeMagic {
		r.trackEndpoint(src, data)
		return
	}
	if magic == hubRendHello {
		r.answerRendezvous(src, data)
		return
	}
	// Anything else came from a peer: forward it to the sender's linked peers
	// so a link that could not be punched directly still carries traffic.
	r.route(src, data)
}

// trackEndpoint attributes a seen UDP source to a node and stores it both on
// the node's control connection (for discovery/direct punching) and in the
// relay routing table.
func (r *P2PRelay) trackEndpoint(src *net.UDPAddr, data []byte) {
	ep := src.String()
	id, ok := hubSender(data)
	if !ok {
		return
	}
	if r.hub.GetNode(id) == nil {
		return
	}
	r.bindEndpoint(id, ep)
}

func (r *P2PRelay) bindEndpoint(id, ep string) {
	nc := r.hub.GetConn(id)
	if nc == nil {
		return
	}
	nc.mu.Lock()
	// The node may have reconnected or remapped; a stale endpoint would punch
	// at a dead port, so drop any direct paths that depended on the old one.
	if nc.relayEP != "" && nc.relayEP != ep {
		for peerID, peer := range nc.peers {
			if peer.Direct {
				log.Printf("[p2p] node %s remapped, %s must re-punch", id, peerID)
			}
			peer.Direct = false
		}
	}
	nc.relayEP = ep
	nc.relayEPAt = time.Now()
	nc.mu.Unlock()

	r.mu.Lock()
	r.byEP[ep] = id
	r.mu.Unlock()
}

// answerRendezvous replies to a node with the endpoints of every online peer
// in its own PSK group, so it can punch each one directly.
func (r *P2PRelay) answerRendezvous(src *net.UDPAddr, data []byte) {
	sender, ok := hubSender(data)
	if !ok {
		return
	}
	h := r.hub
	if h.GetNode(sender) == nil {
		return
	}
	// Refresh the sender's endpoint from the request itself so a device whose
	// probes were lost is still discoverable.
	r.bindEndpoint(sender, src.String())

	group := h.groupOf(sender)
	if !h.p2pAllowed(sender) {
		// The device's policy group denies P2P mesh. Answer with nobody so it
		// learns no peers, exactly as if the relay had nothing to offer.
		return
	}
	type entry struct {
		id   string
		addr *net.UDPAddr
	}
	var found []entry
	for _, peerID := range h.groupMembers(group) {
		if peerID == sender || len(peerID) != 8 || len(found) >= maxP2PPerNode {
			continue
		}
		if !h.p2pAllowed(peerID) {
			// Do not hand out a peer whose group denies P2P either: punching is
			// mutual, and offering one end would make both try.
			continue
		}
		if !h.interDeviceAllowed(sender, peerID) {
			// Different policy groups, or a group that denies inter-device
			// traffic. Offering the endpoint would build a direct link carrying
			// exactly the traffic the server-side filter drops, so the pair is
			// treated as if it did not exist.
			continue
		}
		nc := h.GetConn(peerID)
		if nc == nil {
			continue
		}
		nc.mu.Lock()
		ep, fresh := nc.relayEP, !nc.relayEPAt.IsZero() && time.Since(nc.relayEPAt) < 120*time.Second
		nc.mu.Unlock()
		if !fresh || ep == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", ep)
		if err != nil || addr.IP.To4() == nil {
			continue
		}
		found = append(found, entry{peerID, addr})
	}

	out := make([]byte, 0, 4+len(found)*14)
	out = append(out, hubRendReply...)
	out = append(out, byte(len(found)))
	for _, e := range found {
		out = append(out, e.id...)
		out = append(out, e.addr.IP.To4()...)
		out = append(out, byte(e.addr.Port>>8), byte(e.addr.Port&0xFF))
	}
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()
	if conn != nil {
		conn.WriteToUDP(out, src)
	}
}

// route forwards a peer datagram to every peer of the sending node, so a link
// that never punched through still carries traffic via the hub.
func (r *P2PRelay) route(src *net.UDPAddr, data []byte) {
	sender, ok := hubSender(data)
	if !ok {
		return
	}
	// A node whose group denies P2P mesh gets its datagrams dropped here, so a
	// peer that punched it before it was moved keeps seeing a dead link rather
	// than a working one.
	if !r.hub.p2pAllowed(sender) {
		return
	}
	r.mu.Lock()
	srcID, known := r.byEP[src.String()]
	if !known {
		srcID = sender
	}
	var dsts []string
	for dstID := range r.links[srcID] {
		dsts = append(dsts, dstID)
	}
	r.mu.Unlock()
	if len(dsts) == 0 {
		return
	}
	for _, dstID := range dsts {
		nc := r.hub.GetConn(dstID)
		if nc == nil {
			continue
		}
		if !r.hub.p2pAllowed(dstID) {
			continue
		}
		nc.mu.Lock()
		ep, fresh := nc.relayEP, !nc.relayEPAt.IsZero() && time.Since(nc.relayEPAt) < 120*time.Second
		nc.mu.Unlock()
		if !fresh || ep == "" {
			continue
		}
		daddr, err := net.ResolveUDPAddr("udp", ep)
		if err != nil {
			continue
		}
		r.mu.Lock()
		conn := r.conn
		r.mu.Unlock()
		if conn != nil {
			conn.WriteToUDP(data, daddr)
		}
	}
}

// LinkRelay adds a directed relay circuit src -> dst.
func (r *P2PRelay) LinkRelay(src, dst string) error {
	if src == dst {
		return errLinkSelf
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.links[src] == nil {
		r.links[src] = make(map[string]bool)
	}
	r.links[src][dst] = true
	return nil
}

func (r *P2PRelay) Unlink(src string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.links, src)
}

func (r *P2PRelay) getLinks() map[string][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]string)
	for k, set := range r.links {
		for v := range set {
			out[k] = append(out[k], v)
		}
		sort.Strings(out[k])
	}
	return out
}

var errLinkSelf = &simpleErr{"cannot link a node to itself"}

// errPolicyIsolated is returned when a link would cross a policy group boundary.
// A direct link never reaches the server, so it has to be refused here rather
// than left to the packet filter.
var errPolicyIsolated = &simpleErr{"policy groups are isolated: these devices are in different groups, or their group does not allow inter-device traffic"}

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }

// ---- Node-side mesh management -------------------------------------------

// JoinRelay points a node at the hub's UDP socket so its NAT mapping is
// discoverable. This is the first step of a punch: the node has to have a
// reachable endpoint before it can be handed to its peers as a target.
func (h *MeshHub) JoinRelay(id string) error {
	nc := h.GetConn(id)
	if nc == nil {
		return errNodeOffline
	}
	nc.mu.Lock()
	localIP, self := nc.localIP, nc.nodeID
	nc.mu.Unlock()
	addr, err := hubAddrFor(h.cfg.RelayListen, localIP)
	if err != nil {
		return err
	}
	var payload [8]byte
	applyTarget(&payload, addr)
	// The node id field carries this node's own id, which it must stamp on
	// every hub datagram.
	return nc.sendCommandTo(cmdP2PHub, payload, self)
}

// LeaveRelay drops only the node's P2P work. A full CMD_RESET would also tear
// down that node's TRP and FRP sessions, which has nothing to do with leaving
// the mesh.
func (h *MeshHub) LeaveRelay(id string) error {
	nc := h.GetConn(id)
	if nc == nil {
		return errNodeOffline
	}
	if err := nc.SendCommand(cmdP2PClear, [8]byte{}); err != nil {
		return err
	}
	return nc.SendCommand(cmdHubStop, [8]byte{})
}

// DirectConnect points node A at node B's observed UDP endpoint and vice
// versa, so both clients hole-punch straight at each other.
func (h *MeshHub) DirectConnect(a, b string) error {
	if a == b {
		return errLinkSelf
	}
	// Checked before the endpoints: a link the policy layer forbids must be
	// refused whatever the nodes happen to be doing, and the operator gets the
	// real reason instead of "both nodes must join the relay first".
	if !h.interDeviceAllowed(a, b) {
		return errPolicyIsolated
	}
	ac, bc := h.GetConn(a), h.GetConn(b)
	if ac == nil || bc == nil {
		return errNodeOffline
	}
	ac.mu.Lock()
	aEP := ac.relayEP
	ac.mu.Unlock()
	bc.mu.Lock()
	bEP := bc.relayEP
	bc.mu.Unlock()
	if aEP == "" || bEP == "" {
		return &simpleErr{"both nodes must join the relay first (endpoints unknown)"}
	}

	aAddr, err1 := net.ResolveUDPAddr("udp", bEP)
	bAddr, err2 := net.ResolveUDPAddr("udp", aEP)
	if err1 != nil || err2 != nil {
		return &simpleErr{"cannot resolve peer endpoint"}
	}
	var aToB, bToA [8]byte
	applyTarget(&aToB, aAddr)
	applyTarget(&bToA, bAddr)
	if err := ac.addPeer(b, bEP, aToB); err != nil {
		return err
	}
	return bc.addPeer(a, aEP, bToA)
}

// ensurePeerPunch makes a punch each a wants toward b live. It is idempotent:
// a pair already pointed at each other with fresh endpoints is left alone, so
// the periodic mesh maintenance can call it without churn.
func (h *MeshHub) ensurePeerPunch(a, b string) error {
	if !h.interDeviceAllowed(a, b) {
		return errPolicyIsolated
	}
	ac, bc := h.GetConn(a), h.GetConn(b)
	if ac == nil || bc == nil {
		return errNodeOffline
	}

	ac.mu.Lock()
	aEP := ac.relayEP
	ac.mu.Unlock()
	bc.mu.Lock()
	bEP := bc.relayEP
	bc.mu.Unlock()
	if aEP == "" || bEP == "" {
		return &simpleErr{"peer endpoints unknown (waiting for rendezvous registration)"}
	}
	aAddr, err1 := net.ResolveUDPAddr("udp", aEP)
	bAddr, err2 := net.ResolveUDPAddr("udp", bEP)
	if err1 != nil || err2 != nil {
		return &simpleErr{"cannot resolve peer endpoint"}
	}

	// Each side is told the *other* side's endpoint: the payload carries the
	// address to punch, the node-id field carries who it belongs to.
	var toB, toA [8]byte
	applyTarget(&toB, bAddr)
	applyTarget(&toA, aAddr)
	if err := ac.addPeer(b, bEP, toB); err != nil {
		return err
	}
	if err := bc.addPeer(a, aEP, toA); err != nil {
		return err
	}
	// Both sides are also told about the hub so a punch that never completes
	// still has somewhere to be relayed through.
	if err := h.relay.LinkRelay(a, b); err != nil {
		return err
	}
	return h.relay.LinkRelay(b, a)
}

// addPeer registers (or refreshes) a punch target on this node and sends the
// client the command that makes it start punching.
func (nc *NodeConn) addPeer(nodeID, endpoint string, payload [8]byte) error {
	nc.mu.Lock()
	peer := nc.peers[nodeID]
	if peer == nil {
		if len(nc.peers) >= maxP2PPerNode {
			nc.mu.Unlock()
			return &simpleErr{"node already holds the maximum number of P2P peers"}
		}
		peer = &P2PPeer{NodeID: nodeID}
		nc.peers[nodeID] = peer
	}
	// Nothing to do when the peer is already at this exact endpoint and is
	// still reporting in: re-sending would restart the client's session and
	// knock an established direct path down.
	if peer.Endpoint == endpoint && time.Since(peer.LastReport) < 60*time.Second {
		nc.mu.Unlock()
		return nil
	}
	changed := peer.Endpoint != endpoint
	peer.Endpoint = endpoint
	if changed {
		peer.Direct = false
	}
	nc.mu.Unlock()
	// The client's peer table is keyed by node id, so re-sending this is what
	// makes it restart the session against a new mapping.
	return nc.sendCommandTo(cmdP2PAdd, payload, nodeID)
}

func (nc *NodeConn) dropPeer(nodeID string) {
	nc.mu.Lock()
	delete(nc.peers, nodeID)
	nc.mu.Unlock()
}

func (nc *NodeConn) peerSnapshot() map[string]*P2PPeer {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	out := make(map[string]*P2PPeer, len(nc.peers))
	for k, v := range nc.peers {
		cp := *v
		out[k] = &cp
	}
	return out
}

// hubAddrFor decides which address to advertise to a node for the rendezvous
// socket. A listen config of ":7001" resolves to the unspecified address, which
// is not something a client can send to, so fall back to the address this node
// was actually reached on.
func hubAddrFor(listen, localIP string) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	if addr.IP == nil || addr.IP.IsUnspecified() {
		if ip := net.ParseIP(localIP); ip != nil {
			addr.IP = ip
		}
	}
	return addr, nil
}

// sendHubTarget tells a node where the rendezvous socket is, and hands it its
// own node id in the same frame — the id it must stamp on hub traffic.
func (h *MeshHub) sendHubTarget(nc *NodeConn) {
	nc.mu.Lock()
	ip, self := nc.localIP, nc.nodeID
	nc.mu.Unlock()
	addr, err := hubAddrFor(h.cfg.RelayListen, ip)
	if err != nil {
		log.Printf("[p2p] hub resolve %s: %v", h.cfg.RelayListen, err)
		return
	}
	var payload [8]byte
	applyTarget(&payload, addr)
	if err := nc.sendCommandTo(cmdP2PHub, payload, self); err != nil {
		log.Printf("[p2p] hub command to %s failed: %v", self, err)
	}
}

// maintainGroupMesh re-links a group as membership changes. It runs for the
// lifetime of one node's control channel, so a peer that comes online after us
// is picked up without the operator doing anything.
func (h *MeshHub) maintainGroupMesh(group, selfID string, stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		h.linkGroup(group, selfID)
		select {
		case <-stop:
			return
		case <-tick.C:
		}
	}
}

// linkGroup punches every online pair inside a PSK group. restrict, when set,
// limits the sweep to the peers of one node (used to avoid a full O(n^2) sweep
// from every member on every tick).
func (h *MeshHub) linkGroup(group, restrict string) {
	members := h.groupMembers(group)
	if len(members) < 2 {
		return
	}
	sort.Strings(members)
	pairs := [][2]string{}
	for i := 0; i < len(members); i++ {
		for j := i + 1; j < len(members); j++ {
			if restrict != "" && members[i] != restrict && members[j] != restrict {
				continue
			}
			// A pair is only punched when both ends' groups allow P2P mesh.
			// Checking here covers every reconnect and every group change without
			// the operator touching the mesh.
			if !h.p2pAllowed(members[i]) || !h.p2pAllowed(members[j]) {
				continue
			}
			pairs = append(pairs, [2]string{members[i], members[j]})
		}
	}
	for _, p := range pairs {
		if err := h.ensurePeerPunch(p[0], p[1]); err != nil {
			// Missing endpoints are the normal case until every node has
			// registered with the relay, so stay quiet about those.
			if _, quiet := err.(*simpleErr); !quiet {
				log.Printf("[p2p] link %s <-> %s: %v", p[0], p[1], err)
			}
		}
	}
}

// groupMembers lists every node id sharing a PSK, online ones first-class.
func (h *MeshHub) groupMembers(group string) []string {
	if group == "" {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []string
	for id := range h.byPSK[group] {
		out = append(out, id)
	}
	return out
}

// MeshGroup is the dashboard entry point: turn auto-mesh on or off for one
// PSK group.
func (h *MeshHub) MeshGroup(group string, enable bool) (int, error) {
	if group == "" {
		return 0, fmt.Errorf("group required")
	}
	if _, ok := h.getNodeByGroup(group); !ok {
		return 0, fmt.Errorf("unknown group")
	}
	members := h.groupMembers(group)
	if enable {
		h.linkGroup(group, "")
		return len(members), nil
	}
	for _, id := range members {
		h.relay.Unlink(id)
		if nc := h.GetConn(id); nc != nil {
			// Drop the punch targets before the command so the client cannot
			// re-report a link the dashboard has just been told to remove.
			nc.mu.Lock()
			nc.peers = make(map[string]*P2PPeer)
			nc.mu.Unlock()
			nc.SendCommand(cmdP2PClear, [8]byte{})
		}
	}
	return len(members), nil
}

func (h *MeshHub) getNodeByGroup(group string) (*NodeRecord, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	groupSet, ok := h.byPSK[group]
	if !ok {
		return nil, false
	}
	for id := range groupSet {
		if rec := h.nodes[id]; rec != nil {
			return rec, true
		}
	}
	return nil, false
}

var errNodeOffline = &simpleErr{"node offline"}

// ---- Payload helpers ------------------------------------------------------

// toV4 normalises a configured/observed address to 4 raw bytes for the wire
// format, falling back to loopback for anything unusable.
func toV4(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return net.IPv4(127, 0, 0, 1).To4()
}

// applyTarget writes an IPv4 endpoint into a control payload: 4 raw bytes of
// address then a big-endian port. The payload is taken by pointer because a
// [8]byte passed by value would leave every write here in a discarded copy.
func applyTarget(payload *[8]byte, addr *net.UDPAddr) {
	copy(payload[0:4], toV4(addr.IP.String()))
	binary.BigEndian.PutUint16(payload[4:6], uint16(addr.Port))
}

// groupLabel is a short, non-secret stand-in for a PSK so the dashboard can
// show which devices are grouped without printing the key everywhere.
func groupLabel(psk string) string {
	if psk == "" {
		return ""
	}
	if len(psk) <= 8 {
		return psk
	}
	return psk[:4] + "…" + psk[len(psk)-4:]
}

// ---- Discovery view -------------------------------------------------------

// PeerLink is one row of the P2P page: what node A can see about the link it
// holds toward node B.
type PeerLink struct {
	From      string `json:"from"`
	FromName  string `json:"from_name"`
	To        string `json:"to"`
	ToName    string `json:"to_name"`
	Online    bool   `json:"online"`
	Endpoint  string `json:"endpoint,omitempty"`
	Direct    bool   `json:"direct"`
	DirectFor string `json:"direct_since,omitempty"`
	// Tested is the client's own round trip to this peer: a packet it sent that
	// the peer echoed back. Direct only says a punch landed at some point, so
	// this is the field that says the two devices can talk right now. rtt_ms is
	// omitted until a test has come back, rather than reported as 0.
	Tested bool   `json:"tested"`
	RTTMS  int    `json:"rtt_ms,omitempty"`
	IP     string `json:"control_ip,omitempty"`
}

// NodeStatus is the discovery view of a node.
type NodeStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Online      bool   `json:"online"`
	ControlIP   string `json:"control_ip,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	RelayEP     string `json:"relay_ep,omitempty"`
	RelaySeen   string `json:"relay_seen,omitempty"`
	Peers       int    `json:"peers"`
	DirectPeers int    `json:"direct_peers"`
	// TestedPeers counts the punch targets this node has a live round trip to,
	// which is what separates a link that merely punched from one that carries
	// traffic in both directions.
	TestedPeers  int    `json:"tested_peers"`
	PSK          string `json:"psk,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	LastSeen     string `json:"last_seen,omitempty"`
	ConnectedFor string `json:"connected_for,omitempty"`
}

// GroupView is one PSK group: a set of devices that discover each other.
type GroupView struct {
	PSK     string       `json:"psk"`
	Label   string       `json:"label"`
	Nodes   int          `json:"nodes"`
	Online  int          `json:"online"`
	Links   int          `json:"links"`
	Direct  int          `json:"direct_links"`
	Members []NodeStatus `json:"members"`
}

func (h *MeshHub) ListNodes(withPSK bool) []NodeStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// An empty slice, not nil: the dashboard renders this directly and null
	// would need special-casing on every page.
	out := []NodeStatus{}
	for _, rec := range h.nodes {
		// Filter out nodes with obviously bogus device IDs (ghosts from
		// misbehaving clients). Persisted nodes may already have them.
		if rec.DeviceID != "" {
			ld := strings.ToLower(rec.DeviceID)
			if len(rec.DeviceID) > 32 || strings.Contains(ld, "version") || strings.Contains(ld, "systemtype") || strings.Contains(ld, "clienttype") || strings.Contains(ld, "user-agent") || strings.Contains(ld, "host:") || strings.Contains(ld, "accept") || strings.Contains(ld, "connection") {
				continue
			}
		}
		st := NodeStatus{
			ID:    rec.ID,
			Name:  rec.Name,
			PSK:   rec.PSK,
			Peers: 0,
		}
		if withPSK {
			st.CreatedAt = rec.CreatedAt.Format(time.RFC3339)
		} else {
			st.PSK = groupLabel(rec.PSK)
		}
		st.DeviceID = rec.DeviceID
		if nc := h.conns[rec.ID]; nc != nil {
			snap := nc.snapshot()
			st.Online = snap.connected
			st.ControlIP = snap.controlIP
			st.LastSeen = snap.lastSeen.Format(time.RFC3339)
			st.ConnectedFor = time.Since(snap.startedAt).Round(time.Second).String()
			st.RelayEP = snap.relayEP
			if !snap.relayEPAt.IsZero() {
				st.RelaySeen = snap.relayEPAt.Format(time.RFC3339)
			}
			st.Peers = len(nc.peers)
			for _, p := range nc.peers {
				if p.Direct {
					st.DirectPeers++
				}
				if p.Tested {
					st.TestedPeers++
				}
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ListGroups is the grouped view the P2P page renders: devices bucketed by the
// PSK they share, with per-node peer status.
func (h *MeshHub) ListGroups(withPSK bool) []GroupView {
	nodes := h.ListNodes(withPSK)
	idx := map[string]int{}
	views := []GroupView{}
	for _, n := range nodes {
		pos, ok := idx[n.PSK]
		if !ok {
			pos = len(views)
			idx[n.PSK] = pos
			views = append(views, GroupView{PSK: n.PSK, Label: groupLabel(n.PSK)})
		}
		v := &views[pos]
		v.Nodes++
		if n.Online {
			v.Online++
			v.Links += n.Peers
			v.Direct += n.DirectPeers
		}
		v.Members = append(v.Members, n)
	}
	return views
}

// ListLinks returns the live punch topology between every node and its peers.
func (h *MeshHub) ListLinks() []PeerLink {
	byID := map[string]NodeStatus{}
	for _, n := range h.ListNodes(false) {
		byID[n.ID] = n
	}
	out := []PeerLink{}
	for _, id := range h.onlineNodes() {
		nc := h.GetConn(id)
		if nc == nil {
			continue
		}
		for peerID, p := range nc.peerSnapshot() {
			l := PeerLink{
				From:     id,
				FromName: byID[id].Name,
				To:       peerID,
				ToName:   peerID,
				Online:   true,
				Endpoint: p.Endpoint,
				Direct:   p.Direct,
				Tested:   p.Tested,
			}
			if p.RTTKnown {
				l.RTTMS = p.RTTMS
			}
			if peer, ok := byID[peerID]; ok {
				l.ToName = peer.Name
				l.Online = peer.Online
				l.IP = peer.ControlIP
			}
			if !p.DirectAt.IsZero() {
				l.DirectFor = p.DirectAt.Format(time.RFC3339)
			}
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

func (h *MeshHub) MeshStatus() map[string]interface{} {
	h.mu.RLock()
	online := 0
	for _, nc := range h.conns {
		if nc.snapshot().connected {
			online++
		}
	}
	nodes := len(h.nodes)
	groups := len(h.byPSK)
	h.mu.RUnlock()
	return map[string]interface{}{
		"enabled":        true,
		"control_listen": h.cfg.ControlListen,
		"relay_listen":   h.cfg.RelayListen,
		"nodes":          nodes,
		"groups":         groups,
		"online":         online,
		"max_peers":      maxP2PPerNode,
	}
}
