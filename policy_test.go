package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

func testPolicyStore(t *testing.T) *PolicyStore {
	t.Helper()
	ps := NewPolicyStore(t.TempDir())
	if err := ps.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	return ps
}

func boolPtr(b bool) *bool { return &b }

// fakeTun is an in-memory tun.Device used to drive the filter through the real
// interface, so the tests exercise Read and Write exactly as WireGuard calls
// them rather than calling the decision helper directly.
type fakeTun struct {
	readPkts [][]byte
	written  [][]byte
	// gotBufs records the outer slice handed to Write, before any copying, so
	// a test can tell a pass-through from a filtered rewrite.
	gotBufs [][]byte
	mtu     int
}

func (f *fakeTun) File() *os.File           { return nil }
func (f *fakeTun) MTU() (int, error)        { return f.mtu, nil }
func (f *fakeTun) Name() (string, error)    { return "fake0", nil }
func (f *fakeTun) Events() <-chan tun.Event { return nil }
func (f *fakeTun) Close() error             { return nil }
func (f *fakeTun) BatchSize() int           { return 1 }

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := len(f.readPkts)
	if n > len(sizes) {
		n = len(sizes)
	}
	for i := 0; i < n; i++ {
		sizes[i] = len(f.readPkts[i])
		copy(bufs[i][offset:], f.readPkts[i])
	}
	return n, nil
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	f.gotBufs = bufs
	for _, b := range bufs {
		p := make([]byte, len(b)-offset)
		copy(p, b[offset:])
		f.written = append(f.written, p)
	}
	return len(bufs), nil
}

// TestPolicyDefaultGroupIsFullyOpen is the guarantee the whole feature rests
// on: a fresh install, or any install that never sends a policy, allows
// everything for every device.
func TestPolicyDefaultGroupIsFullyOpen(t *testing.T) {
	ps := testPolicyStore(t)

	g := ps.GroupForPeer("some-unknown-peer")
	if g == nil {
		t.Fatal("every peer must resolve to a group")
	}
	if g.ID != DefaultPolicyGroupID {
		t.Fatalf("unassigned peer resolved to %q, want %q", g.ID, DefaultPolicyGroupID)
	}
	for _, c := range []Capability{CapInterDevice, CapP2PMesh, CapTRP, CapWGAccess} {
		if !ps.Allows("some-unknown-peer", c) {
			t.Errorf("default group denies capability %v", c)
		}
	}

	// With no custom group the layer must report itself inactive so the packet
	// filter short-circuits without taking any locks.
	if ps.IsActive() {
		t.Error("a store with no custom group must not be active")
	}
}

// TestPolicyInactiveIgnoresEveryRule guards the fast path: while inactive, the
// filter must allow anything even if a group exists that would deny it.
func TestPolicyInactiveIgnoresEveryRule(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !ps.IsActive() {
		t.Fatal("creating a custom group must activate the policy layer")
	}

	// A group that exists but holds nobody denies nothing.
	if got := ps.Group(g.ID); got == nil || got.Name != "Guests" {
		t.Fatalf("group not found by id: %+v", got)
	}
	if !ps.Allows("any-peer", CapInterDevice) {
		t.Error("a device in no group must still be allowed by the default group")
	}
}

func TestPolicyCreateDefaultsToDenyAll(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guest Network", PolicyGroup{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if g.AllowInterDevice || g.AllowP2PMesh || g.AllowTRP || g.AllowWGAccess {
		t.Errorf("a new group must deny everything until opted in: %+v", g)
	}
}

func TestPolicyCreateAndAssign(t *testing.T) {
	ps := testPolicyStore(t)
	guests, err := ps.Create("Guests", PolicyGroup{
		AllowInterDevice: true,
		AllowP2PMesh:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	known := func(k string) bool { return k == "peerA" || k == "peerB" }
	if err := ps.Assign(guests.ID, []string{"peerA", "peerB"}, known); err != nil {
		t.Fatalf("assign: %v", err)
	}

	if !ps.Allows("peerA", CapInterDevice) {
		t.Error("assigned device lost its enabled rule")
	}
	if ps.Allows("peerA", CapTRP) {
		t.Error("assigned device kept a rule that was never enabled")
	}
	if ps.Allows("nobody", CapInterDevice) != true {
		t.Error("an untouched device must keep working normally")
	}

	members := ps.Members(guests.ID)
	if len(members) != 2 || members[0] != "peerA" || members[1] != "peerB" {
		t.Errorf("members = %v, want [peerA peerB]", members)
	}

	// Removing a device returns it to the default group, which means it can
	// reach the internet again without any further action.
	if err := ps.Unassign([]string{"peerA"}); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if !ps.Allows("peerA", CapWGAccess) {
		t.Error("an unassigned device must be back on the default group")
	}
	if !ps.Allows("peerA", CapInterDevice) {
		t.Error("an unassigned device must be fully permitted again")
	}
}

func TestPolicyAssignRejectsUnknownDevice(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	known := func(k string) bool { return k == "real" }
	if err := ps.Assign(g.ID, []string{"real", "typo"}, known); err == nil {
		t.Fatal("assigning an unknown device must be rejected")
	}
	// The failed call must not have partially applied.
	if got := ps.Members(g.ID); len(got) != 0 {
		t.Errorf("a rejected assign must change nothing, members = %v", got)
	}
}

func TestPolicyCannotEditOrDeleteDefault(t *testing.T) {
	ps := testPolicyStore(t)
	if _, err := ps.Update(DefaultPolicyGroupID, PolicyGroup{AllowInterDevice: false}); err == nil {
		t.Error("the default group must not be editable")
	}
	if err := ps.Delete(DefaultPolicyGroupID); err == nil {
		t.Error("the default group must not be deletable")
	}
	if !ps.Allows("peer", CapWGAccess) {
		t.Error("the default group must still allow internet access")
	}
}

func TestPolicyDeleteRefusesNonEmptyGroup(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := ps.Delete(g.ID); err == nil {
		t.Fatal("deleting a populated group must be refused so no device is silently moved")
	}
	if err := ps.Unassign([]string{"peerA"}); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if err := ps.Delete(g.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ps.IsActive() {
		t.Error("removing the last custom group must deactivate the layer again")
	}
}

func TestPolicyDuplicateNameRejected(t *testing.T) {
	ps := testPolicyStore(t)
	if _, err := ps.Create("Guests", PolicyGroup{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := ps.Create("guests", PolicyGroup{}); err == nil {
		t.Error("a group name must be unique regardless of case")
	}
}

func TestPolicyUpdateReplacesAllRules(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{AllowInterDevice: true, AllowWGAccess: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// The store's Update is a full replacement; preserving rules the caller
	// did not mention is the route layer's job, and is covered by the API test.
	next, err := ps.Update(g.ID, PolicyGroup{AllowP2PMesh: true})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !next.AllowP2PMesh || next.AllowInterDevice || next.AllowWGAccess {
		t.Errorf("update must replace the whole rule set, got %+v", next)
	}
	if next.Name != "Guests" {
		t.Errorf("an update with no name must keep the old one, got %q", next.Name)
	}
}

func TestPolicyPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ps := NewPolicyStore(dir)
	if err := ps.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	g, err := ps.Create("Guests", PolicyGroup{AllowP2PMesh: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}

	// Restart: a new store over the same directory.
	reloaded := NewPolicyStore(dir)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.IsActive() {
		t.Error("a persisted custom group must reactivate the layer")
	}
	if !reloaded.Allows("peerA", CapP2PMesh) {
		t.Error("membership and rules must survive a restart")
	}
	if reloaded.Allows("peerA", CapTRP) {
		t.Error("a rule that was off must stay off after a restart")
	}
	if !reloaded.Allows("peerB", CapWGAccess) {
		t.Error("an untouched device must be unaffected by another device's group")
	}
	if len(reloaded.List()) != 2 {
		t.Errorf("want the default group plus one custom group, got %d", len(reloaded.List()))
	}
}

func TestPolicyLoadRepairsDanglingMembership(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_groups.json")
	// A membership pointing at a group the file does not contain must not leave
	// a device assigned to nothing.
	if err := os.WriteFile(path, []byte(`{"assign":{"peerA":"gone"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	ps := NewPolicyStore(dir)
	if err := ps.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ps.Allows("peerA", CapWGAccess) {
		t.Error("a dangling membership must fall back to the default group")
	}
	if !ps.Allows("peerA", CapInterDevice) {
		t.Error("a dangling membership must not restrict the device at all")
	}
}

func TestPolicyLoadCorruptFileIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_groups.json")
	bad := []byte("{not json")
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	ps := NewPolicyStore(dir)
	if err := ps.Load(); err == nil {
		t.Fatal("a corrupt file must be reported")
	}
	if err := ps.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bad) {
		t.Error("a file that failed to load must never be overwritten")
	}
}

func TestPolicyApplyReplacesState(t *testing.T) {
	ps := testPolicyStore(t)
	known := func(k string) bool { return k == "peerA" || k == "peerB" }

	rejected := PolicyFile{
		Groups: []*PolicyGroup{{Name: "Guests", AllowP2PMesh: true}},
		Assign: map[string]string{"peerA": "unknown-group-id"},
	}
	if err := ps.Apply(rejected, known); err == nil {
		t.Error("a membership naming an unknown group must be rejected")
	}
	if ps.IsActive() {
		t.Error("a rejected apply must not change any state")
	}

	guests, err := ps.Create("Guests", PolicyGroup{AllowP2PMesh: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	servers, err := ps.Create("Servers", PolicyGroup{AllowInterDevice: true, AllowTRP: true, AllowWGAccess: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// A single apply replaces the whole state, so it also drops any group the
	// caller left out.
	if err := ps.Apply(PolicyFile{
		Groups: []*PolicyGroup{
			{Name: "Guests", AllowP2PMesh: true, ID: guests.ID},
			{Name: "Servers", AllowInterDevice: true, AllowTRP: true, AllowWGAccess: true, ID: servers.ID},
		},
		Assign: map[string]string{"peerA": guests.ID, "peerB": servers.ID},
	}, known); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if len(ps.List()) != 3 {
		t.Fatalf("want default plus two groups, got %d", len(ps.List()))
	}
	if !ps.Allows("peerA", CapP2PMesh) || ps.Allows("peerA", CapTRP) {
		t.Error("applied group rules are not being enforced")
	}
	if !ps.Allows("peerB", CapTRP) || !ps.Allows("peerB", CapWGAccess) {
		t.Error("the second applied group is not being enforced")
	}
	// A device the payload never mentioned stays on the default group.
	if !ps.Allows("peerC", CapWGAccess) {
		t.Error("apply must not restrict a device it did not mention")
	}
}

func TestPolicyApplyRefusesToShadowDefaultGroup(t *testing.T) {
	ps := testPolicyStore(t)
	err := ps.Apply(PolicyFile{
		Groups: []*PolicyGroup{{Name: "Fake default", ID: DefaultPolicyGroupID}},
	}, nil)
	if err == nil {
		t.Error("a payload must not be able to redefine the default group")
	}
	if !ps.Allows("peerA", CapWGAccess) {
		t.Error("the default group must remain permissive")
	}
}

// ---- packet filter --------------------------------------------------------

// buildIPv4 assembles a minimal IPv4 packet with the given addresses.
func buildIPv4(src, dst string) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 20)
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())
	return pkt
}

// testFilter wires a policy filter over an in-memory peer list.
func testFilter(t *testing.T, ps *PolicyStore) (*policyTun, *PeerStore) {
	t.Helper()
	peers := NewPeerStore(t.TempDir())
	for _, p := range []*PeerRecord{
		{PublicKey: "peerA", AllowedIP: "10.100.0.2/32", DeviceID: "devA"},
		{PublicKey: "peerB", AllowedIP: "10.100.0.3/32", DeviceID: "devB"},
	} {
		peers.Add(p)
	}
	cfg := &Config{Address: "10.100.0.1/24", Subnet: "10.100.0.0/24"}
	inner, ok := newPolicyTun(&fakeTun{mtu: 1420}, ps, peers, cfg).(*policyTun)
	if !ok {
		t.Fatal("expected the policy filter to be installed")
	}
	return inner, peers
}

// TestNewPolicyTunLeavesTunnelAloneWithoutPolicy proves the filter is not even
// installed when there is nothing to enforce against, so the tunnel runs the
// unmodified code path.
func TestNewPolicyTunLeavesTunnelAloneWithoutPolicy(t *testing.T) {
	inner := &fakeTun{}
	peers := NewPeerStore(t.TempDir())
	cfg := &Config{Address: "10.100.0.1/24", Subnet: "10.100.0.0/24"}

	if got := newPolicyTun(inner, nil, peers, cfg); got != tun.Device(inner) {
		t.Error("a nil policy store must leave the device untouched")
	}
	if got := newPolicyTun(inner, testPolicyStore(t), nil, cfg); got != tun.Device(inner) {
		t.Error("a nil peer store must leave the device untouched")
	}
	if got := newPolicyTun(nil, testPolicyStore(t), peers, cfg); got != nil {
		t.Error("a nil device must stay nil")
	}
	// A fully wired filter is installed even with no custom groups, so a group
	// created later takes effect without restarting the tunnel.
	if _, ok := newPolicyTun(inner, testPolicyStore(t), peers, cfg).(*policyTun); !ok {
		t.Error("the filter must be installed so dynamic groups work")
	}
}

func TestFilterAllowsEverythingWithoutPolicy(t *testing.T) {
	ps := testPolicyStore(t)
	f, _ := testFilter(t, ps)

	// Inter-device, internet, and anything unrecognised.
	if !f.allowsPacket(buildIPv4("10.100.0.2", "10.100.0.3")) {
		t.Error("device-to-device traffic must pass when no policy is configured")
	}
	if !f.allowsPacket(buildIPv4("10.100.0.2", "8.8.8.8")) {
		t.Error("internet access must pass when no policy is configured")
	}
	if f.dropInter.Load() != 0 || f.dropAccess.Load() != 0 {
		t.Error("nothing should have been dropped")
	}
}

func TestFilterDropsDeniedInterDeviceTraffic(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{AllowWGAccess: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// A guests group that may reach the internet but not other devices.
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}
	f, _ := testFilter(t, ps)

	if f.allowsPacket(buildIPv4("10.100.0.2", "10.100.0.3")) {
		t.Error("guest to another device must be dropped")
	}
	if !f.allowsPacket(buildIPv4("10.100.0.2", "8.8.8.8")) {
		t.Error("guest must keep the internet access it was granted")
	}
	// The other direction matters too, or the group would not be isolated.
	if f.allowsPacket(buildIPv4("10.100.0.3", "10.100.0.2")) {
		t.Error("reaching into the group from outside must also be dropped")
	}
	inter, access := f.Stats()
	if inter != 2 {
		t.Errorf("inter-device drops = %d, want 2", inter)
	}
	if access != 0 {
		t.Errorf("internet drops = %d, want 0", access)
	}
}

func TestFilterDropsDeniedInternetAccess(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("IoT", PolicyGroup{AllowInterDevice: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}
	f, _ := testFilter(t, ps)

	if f.allowsPacket(buildIPv4("10.100.0.2", "8.8.8.8")) {
		t.Error("internet access must be dropped when the group denies it")
	}
	if !f.allowsPacket(buildIPv4("10.100.0.2", "10.100.0.3")) {
		t.Error("inter-device traffic must still be allowed when granted")
	}
	// Infrastructure stays reachable either way, so a denied device still has
	// a gateway and does not simply look broken.
	for _, dst := range []string{"10.100.0.1", "10.100.0.0", "10.100.0.255"} {
		if !f.allowsPacket(buildIPv4("10.100.0.2", dst)) {
			t.Errorf("traffic to the server's own %s must never be filtered", dst)
		}
	}
	_, access := f.Stats()
	if access != 1 {
		t.Errorf("internet drops = %d, want 1", access)
	}
}

func TestFilterPassesThroughUnrecognisedTraffic(t *testing.T) {
	ps := testPolicyStore(t)
	if _, err := ps.Create("Guests", PolicyGroup{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	f, _ := testFilter(t, ps)

	// IPv6, ARP and runt frames must all pass: the policy layer is defined in
	// terms of tunnel IPv4 addresses and must never break anything else.
	if !f.allowsPacket(make([]byte, 4)) {
		t.Error("a runt frame must not be interpreted as policy")
	}
	ipv6 := make([]byte, 60)
	ipv6[0] = 0x60
	if !f.allowsPacket(ipv6) {
		t.Error("IPv6 must pass: there is no group rule for it")
	}
	if _, _, ok := parseIPv4Packet(ipv6); ok {
		t.Error("parseIPv4Packet must not claim an IPv6 packet")
	}

	// A source address no peer owns is not a peer, so it is never filtered.
	if !f.allowsPacket(buildIPv4("10.100.0.9", "8.8.8.8")) {
		t.Error("traffic from an unknown address must pass")
	}
}

func TestFilterDynamicReassignmentTakesEffect(t *testing.T) {
	ps := testPolicyStore(t)
	// A group that grants internet access but denies inter-device traffic.
	g, err := ps.Create("Guests", PolicyGroup{AllowWGAccess: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f, _ := testFilter(t, ps)

	pkt := buildIPv4("10.100.0.2", "10.100.0.3")
	if !f.allowsPacket(pkt) {
		t.Fatal("setup: traffic should pass before any assignment")
	}
	// Moving the device into a group must change the decision immediately, with
	// no restart and no reconnection.
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if f.allowsPacket(pkt) {
		t.Error("reassignment must take effect without a restart")
	}
}

func TestParseIPv4Packet(t *testing.T) {
	src, dst, ok := parseIPv4Packet(buildIPv4("10.100.0.2", "10.100.0.3"))
	if !ok {
		t.Fatal("a valid IPv4 packet was rejected")
	}
	if src != 0x0a640002 || dst != 0x0a640003 {
		t.Errorf("addresses = %08x %08x, want 0a640002 0a640003", src, dst)
	}
	for _, bad := range [][]byte{nil, make([]byte, 19), {0x60, 0, 0, 0}} {
		if _, _, ok := parseIPv4Packet(bad); ok {
			t.Errorf("malformed packet of %d bytes was accepted", len(bad))
		}
	}
	// An IPv4 header claiming a total length below its own header is malformed.
	trunc := buildIPv4("10.100.0.2", "10.100.0.3")
	binary.BigEndian.PutUint16(trunc[2:4], 4)
	if _, _, ok := parseIPv4Packet(trunc); ok {
		t.Error("a packet with an impossible total length was accepted")
	}
}

func TestParseTunnelNet(t *testing.T) {
	tn := parseTunnelNet("10.100.0.0/24")
	if !tn.contains(0x0a640005) {
		t.Error("10.100.0.5 must be inside 10.100.0.0/24")
	}
	if tn.contains(0x0a650005) {
		t.Error("10.101.0.5 must be outside 10.100.0.0/24")
	}
	if tn.contains(0x08080808) {
		t.Error("8.8.8.8 must be outside the tunnel subnet")
	}
	// An unparseable subnet must make every address look tunnel-internal, so
	// unknown destinations are judged by the inter-device rule rather than
	// silently treated as internet traffic.
	bad := parseTunnelNet("not-a-cidr")
	if !bad.contains(0x08080808) {
		t.Error("an unknown subnet must fall back to treating all addresses as internal")
	}
}

// ---- tun.Device plumbing --------------------------------------------------

// TestFilterWriteDropsDeniedPackets drives the filter through the real
// tun.Device Write path, which is where packets decrypted from a peer enter the
// kernel stack.
func TestFilterWriteDropsDeniedPackets(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{AllowWGAccess: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}
	f, _ := testFilter(t, ps)
	inner := f.inner.(*fakeTun)

	// One denied peer-to-peer packet, one allowed internet packet.
	if _, err := f.Write([][]byte{
		buildIPv4("10.100.0.2", "10.100.0.3"),
		buildIPv4("10.100.0.2", "8.8.8.8"),
	}, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(inner.written) != 1 {
		t.Fatalf("%d packets reached the device, want 1", len(inner.written))
	}
	if got := net.IP(inner.written[0][16:20]).String(); got != "8.8.8.8" {
		t.Errorf("the wrong packet survived: dst = %s", got)
	}
}

// TestFilterWriteAllDeniedIsNotAnError covers the batch where every packet is
// denied. Handing the device an empty batch can surface as a spurious error,
// so the filter must report success without calling through.
func TestFilterWriteAllDeniedIsNotAnError(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}
	f, _ := testFilter(t, ps)
	inner := f.inner.(*fakeTun)

	n, err := f.Write([][]byte{
		buildIPv4("10.100.0.2", "10.100.0.3"),
		buildIPv4("10.100.0.2", "8.8.8.8"),
	}, 0)
	if err != nil {
		t.Errorf("dropping every packet must not report an error, got %v", err)
	}
	if n != 2 {
		t.Errorf("reported %d written, want the batch size 2", n)
	}
	if len(inner.written) != 0 {
		t.Errorf("%d packets reached the device, want 0", len(inner.written))
	}
}

// TestFilterWritePassesEverythingWithoutPolicy is the no-op guarantee at the
// device boundary: with no policy, every packet is forwarded untouched.
func TestFilterWritePassesEverythingWithoutPolicy(t *testing.T) {
	ps := testPolicyStore(t)
	f, _ := testFilter(t, ps)
	inner := f.inner.(*fakeTun)

	batch := [][]byte{
		buildIPv4("10.100.0.2", "10.100.0.3"),
		buildIPv4("10.100.0.2", "8.8.8.8"),
		buildIPv4("10.100.0.2", "192.168.1.1"),
	}
	if _, err := f.Write(batch, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(inner.written) != len(batch) {
		t.Errorf("%d packets reached the device, want %d", len(inner.written), len(batch))
	}
}

// TestFilterReadZeroesDeniedSizes covers the egress path. WireGuard skips
// entries whose size is below one, so a dropped packet is marked with a zero
// size rather than removed from the slice.
func TestFilterReadZeroesDeniedSizes(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{AllowP2PMesh: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}
	f, _ := testFilter(t, ps)
	inner := f.inner.(*fakeTun)
	inner.readPkts = [][]byte{
		buildIPv4("10.100.0.2", "10.100.0.3"),
		buildIPv4("10.100.0.3", "10.100.0.2"),
	}

	bufs := make([][]byte, 2)
	bufs[0] = make([]byte, 1600)
	bufs[1] = make([]byte, 1600)
	sizes := []int{0, 0}

	n, err := f.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 2 {
		t.Fatalf("read returned %d packets, want 2 (dropped ones are zeroed, not removed)", n)
	}
	// Both directions of the pair are denied, so both must be zeroed.
	if sizes[0] != 0 || sizes[1] != 0 {
		t.Errorf("sizes = %v, want both zero", sizes[:n])
	}
}

// TestFilterReadPassesAllowedTraffic checks the allowed packets are left intact
// with their real size, which is what WireGuard needs to route them.
func TestFilterReadPassesAllowedTraffic(t *testing.T) {
	ps := testPolicyStore(t)
	f, _ := testFilter(t, ps)
	inner := f.inner.(*fakeTun)
	pkt := buildIPv4("10.100.0.2", "10.100.0.3")
	inner.readPkts = [][]byte{pkt}

	bufs := [][]byte{make([]byte, 1600)}
	sizes := []int{0}
	if _, err := f.Read(bufs, sizes, 0); err != nil {
		t.Fatalf("read: %v", err)
	}
	if sizes[0] != len(pkt) {
		t.Errorf("size = %d, want %d", sizes[0], len(pkt))
	}
	if net.IP(bufs[0][12:16]).String() != "10.100.0.2" {
		t.Error("an allowed packet was corrupted")
	}
}

// TestFilterWriteCountsEachDropOnce guards the single-pass rewrite of Write.
// Deciding and counting must happen in the same loop: a packet that is denied
// has to move the counter exactly once, or the dashboard reports drops that
// never happened.
func TestFilterWriteCountsEachDropOnce(t *testing.T) {
	ps := testPolicyStore(t)
	g, err := ps.Create("Guests", PolicyGroup{AllowWGAccess: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ps.Assign(g.ID, []string{"peerA"}, func(string) bool { return true }); err != nil {
		t.Fatalf("assign: %v", err)
	}
	f, _ := testFilter(t, ps)
	inner := f.inner.(*fakeTun)

	// Two denied peer-to-peer packets and one allowed internet packet, so the
	// batch is filtered and the pass cannot take the all-allowed shortcut.
	if _, err := f.Write([][]byte{
		buildIPv4("10.100.0.2", "10.100.0.3"),
		buildIPv4("10.100.0.2", "10.100.0.3"),
		buildIPv4("10.100.0.2", "8.8.8.8"),
	}, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, _ := f.Stats(); got != 2 {
		t.Errorf("counted %d inter-device drops, want 2 (one per denied packet)", got)
	}
	if len(inner.written) != 1 {
		t.Fatalf("%d packets reached the device, want 1", len(inner.written))
	}

	// A second identical batch must add the same amount again, which it only
	// can if the first pass was not accumulating state.
	if _, err := f.Write([][]byte{
		buildIPv4("10.100.0.2", "10.100.0.3"),
		buildIPv4("10.100.0.2", "10.100.0.3"),
		buildIPv4("10.100.0.2", "8.8.8.8"),
	}, 0); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got, _ := f.Stats(); got != 4 {
		t.Errorf("counted %d inter-device drops after two batches, want 4", got)
	}
}

// TestFilterWritePassesTheOriginalBatchWhenNothingIsDenied checks the common
// case. With no drop the filter must hand the device the caller's own slice
// rather than the reusable scratch buffer, so a batch that is allowed through
// never depends on filter-owned memory.
func TestFilterWritePassesTheOriginalBatchWhenNothingIsDenied(t *testing.T) {
	ps := testPolicyStore(t)
	f, _ := testFilter(t, ps)
	inner := f.inner.(*fakeTun)

	bufs := [][]byte{
		buildIPv4("10.100.0.2", "8.8.8.8"),
		buildIPv4("10.100.0.3", "1.1.1.1"),
	}
	n, err := f.Write(bufs, 0)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 2 {
		t.Errorf("reported %d written, want the batch size 2", n)
	}
	if len(inner.written) != 2 {
		t.Fatalf("%d packets reached the device, want 2", len(inner.written))
	}
	// The device must have been handed the caller's own outer slice, not the
	// filter's reused scratch buffer.
	if len(inner.gotBufs) != 2 || &inner.gotBufs[0] != &bufs[0] {
		t.Error("an unfiltered batch was rebuilt instead of passed straight through")
	}
}

// TestApplyRejectsADeclaredDefaultGroup pins the error an operator sees. The
// default group is pre-seeded in the apply map, so checking for a duplicate id
// first would report a confusing "duplicate group id" instead of naming the
// actual problem.
func TestApplyRejectsADeclaredDefaultGroup(t *testing.T) {
	ps := testPolicyStore(t)
	err := ps.Apply(PolicyFile{
		Groups: []*PolicyGroup{{ID: DefaultPolicyGroupID, Name: "Mine", AllowWGAccess: false}},
	}, func(string) bool { return true })
	if err == nil {
		t.Fatal("applying a payload that declares the default group must fail")
	}
	if !strings.Contains(err.Error(), "default group") {
		t.Errorf("error should explain the default group is reserved, got %q", err)
	}
}
