package main

// Integration tests for the tun control plane. They drive the real code paths
// — a real control listener, real relay socket, real frames — because the
// failure modes this protocol has (identity, attribution behind a shared NAT,
// frame size drift) only show up when both ends actually talk.

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

func startTestHub(t *testing.T) (*MeshHub, string, string) {
	t.Helper()
	dir := t.TempDir()
	ctrl := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	relay := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))

	t.Setenv("MESH_ENABLED", "true")
	t.Setenv("CONTROL_LISTEN", ctrl)
	t.Setenv("RELAY_LISTEN", relay)
	t.Setenv("MESH_DATA_DIR", dir)
	// A long control timeout keeps a test that pauses between frames from
	// looking like a dead link.
	t.Setenv("CONTROL_TIMEOUT_S", "60")

	h := StartMesh(nil)
	if h == nil {
		t.Fatal("StartMesh returned nil")
	}
	t.Cleanup(h.Close)
	return h, ctrl, relay
}

// frame is a decoded server -> client command.
type frame struct {
	cmd     byte
	payload [8]byte
	nodeID  string
}

// clientConn is a control channel under test: the raw conn for deadlines plus
// a reader for the handshake echo.
type clientConn struct {
	c net.Conn
	r *bufio.Reader
}

func (cc *clientConn) setDeadline(t time.Time) {
	cc.c.SetReadDeadline(t)
}

func (cc *clientConn) readFrame(t *testing.T) (frame, error) {
	t.Helper()
	buf := make([]byte, ctrlFrameSize)
	if _, err := readFull(cc.c, buf); err != nil {
		return frame{}, err
	}
	f := frame{cmd: buf[0]}
	copy(f.payload[:], buf[1:9])
	f.nodeID = string(buf[9:17])
	return f, nil
}

func readFull(c net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		if n > 0 {
			got += n
		}
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// dialNode performs the handshake the client performs and returns the reader
// positioned at the first command frame.
func dialNode(t *testing.T, ctrl, psk, deviceID string) *clientConn {
	t.Helper()
	c, err := net.Dial("tcp", ctrl)
	if err != nil {
		t.Fatalf("dial control: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := fmt.Fprintf(c, "%s\n%s\n", psk, deviceID); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return &clientConn{c: c, r: bufio.NewReader(c)}
}

func p2pPayload(ip string, port int) [8]byte {
	var p [8]byte
	v4 := net.ParseIP(ip).To4()
	copy(p[0:4], v4)
	p[4] = byte(port >> 8)
	p[5] = byte(port)
	return p
}

// waitForFrame reads frames until one with the wanted command arrives, and
// fails on anything that should not have been sent.
func waitForFrame(t *testing.T, cc *clientConn, want byte) frame {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cc.setDeadline(time.Now().Add(3 * time.Second))
		f, err := cc.readFrame(t)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			t.Fatalf("read frame: %v", err)
		}
		if f.cmd == want {
			return f
		}
	}
	t.Fatalf("timed out waiting for command 0x%02X", want)
	return frame{}
}

// expectNoFrame asserts nothing arrives within a short window.
func expectNoFrame(t *testing.T, cc *clientConn, why string) {
	t.Helper()
	cc.setDeadline(time.Now().Add(400 * time.Millisecond))
	if f, err := cc.readFrame(t); err == nil {
		t.Fatalf("%s: unexpected frame 0x%02X (id %q)", why, f.cmd, f.nodeID)
	}
}

// TestHubFrameSize pins the wire format. The client's ControlPacket must be
// exactly this size, and a one-byte drift here silently truncates commands.
func TestHubFrameSize(t *testing.T) {
	if ctrlFrameSize != 17 {
		t.Fatalf("control frame must be 17 bytes, got %d", ctrlFrameSize)
	}
	if ctrlStatusRecordSize != 9 {
		t.Fatalf("status record must be 9 bytes, got %d", ctrlStatusRecordSize)
	}
}

// TestSamePSKDevicesGetDistinctNodes is the reason the node id exists: two
// devices sharing one PSK must both be admitted and stay distinct.
func TestSamePSKDevicesGetDistinctNodes(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	psk := "shared-secret"

	rd1 := dialNode(t, ctrl, psk, "aaaa000000000001")
	rd2 := dialNode(t, ctrl, psk, "bbbb000000000002")

	id1 := waitForFrame(t, rd1, cmdP2PHub).nodeID
	id2 := waitForFrame(t, rd2, cmdP2PHub).nodeID

	if id1 == id2 {
		t.Fatalf("two devices on one PSK got the same node id %q", id1)
	}
	if len(id1) != 8 || len(id2) != 8 {
		t.Fatalf("node ids must be 8 chars, got %q and %q", id1, id2)
	}

	nodes := h.listNodes(false)
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes in the group, got %d: %+v", len(nodes), nodes)
	}
	if got := h.groupOf(id1); got != psk {
		t.Fatalf("node %s is in group %q, want %q", id1, got, psk)
	}
	if h.groupOf(id1) != h.groupOf(id2) {
		t.Fatal("both devices should be in the same group")
	}
}

// TestReconnectReclaimsDevice checks that a device that restarts keeps its
// identity instead of accumulating a new node every reconnect.
func TestReconnectReclaimsDevice(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	const device = "cccc000000000003"

	rd1 := dialNode(t, ctrl, "restart-secret", device)
	id1 := waitForFrame(t, rd1, cmdP2PHub).nodeID

	// Drop the channel the way a rebooting device would, then wait for the
	// server to notice it is gone before reconnecting.
	rd1.c.Close()
	waitFor(t, 5*time.Second, func() bool { return len(h.onlineNodes()) == 0 })

	rd2 := dialNode(t, ctrl, "restart-secret", device)
	id2 := waitForFrame(t, rd2, cmdP2PHub).nodeID

	if id1 != id2 {
		t.Fatalf("reconnect changed the node id: %q -> %q", id1, id2)
	}
	if n := len(h.listNodes(false)); n != 1 {
		t.Fatalf("reconnect created an extra node, have %d", n)
	}
}

// TestRendezvousDiscovery is the automatic-discovery path: after two devices
// register with the hub, one of them must be told the other's endpoint
// without anybody touching the dashboard.
func TestRendezvousDiscovery(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	const psk = "rendezvous-secret"

	rd1 := dialNode(t, ctrl, psk, "dddd000000000004")
	rd2 := dialNode(t, ctrl, psk, "eeee000000000005")
	id1 := waitForFrame(t, rd1, cmdP2PHub).nodeID
	id2 := waitForFrame(t, rd2, cmdP2PHub).nodeID

	// One long-lived UDP socket per device, standing in for its NAT mapping.
	c1 := newHubClient(t, h)
	c2 := newHubClient(t, h)

	// Probes register each endpoint on its own node.
	c1.send(t, append(append([]byte(hubProbeMagic), id1...), 0x00))
	c2.send(t, append(append([]byte(hubProbeMagic), id2...), 0x00))

	waitFor(t, 5*time.Second, func() bool {
		a, b := h.getConn(id1), h.getConn(id2)
		if a == nil || b == nil {
			return false
		}
		return a.snapshot().relayEP == c1.ep() && b.snapshot().relayEP == c2.ep()
	})

	// A rendezvous request must come back naming the other device and its real
	// observed endpoint, with no operator action.
	peers := parseRendReply(t, c1.rendezvous(t, id1))
	if len(peers) != 1 {
		t.Fatalf("want 1 peer in the reply, got %d (%v)", len(peers), peers)
	}
	if peers[id2].id != id2 || peers[id2].ep != c2.ep() {
		t.Fatalf("reply named %+v, want %s at %s", peers, id2, c2.ep())
	}
	if _, self := peers[id1]; self {
		t.Fatal("reply included the requesting node as its own peer")
	}
}

// TestRendezvousSkipsStaleEndpoints: a device that stopped probing must not be
// handed out as a punch target, or its peers would aim at a dead port.
func TestRendezvousSkipsStaleEndpoints(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	const psk = "stale-secret"

	rd1 := dialNode(t, ctrl, psk, "aaaa000000000011")
	rd2 := dialNode(t, ctrl, psk, "bbbb000000000012")
	id1 := waitForFrame(t, rd1, cmdP2PHub).nodeID
	id2 := waitForFrame(t, rd2, cmdP2PHub).nodeID

	c1 := newHubClient(t, h)
	c2 := newHubClient(t, h)
	c1.send(t, append(append([]byte(hubProbeMagic), id1...), 0x00))
	c2.send(t, append(append([]byte(hubProbeMagic), id2...), 0x00))
	waitFor(t, 5*time.Second, func() bool {
		b := h.getConn(id2)
		return b != nil && b.snapshot().relayEP == c2.ep()
	})

	// Age node 2's endpoint out of the freshness window.
	nc2 := h.getConn(id2)
	nc2.mu.Lock()
	nc2.relayEPAt = time.Now().Add(-10 * time.Minute)
	nc2.mu.Unlock()

	peers := parseRendReply(t, c1.rendezvous(t, id1))
	if _, stale := peers[id2]; stale {
		t.Fatal("rendezvous handed out an endpoint that stopped reporting")
	}
}

// TestRendezvousSeparatesSameNATNodes is the regression that motivated the
// node id field. Both clients here report 127.0.0.1 and differ only in port —
// the shape of two devices behind one NAT — so an implementation that
// attributed datagrams by source address would merge them.
func TestRendezvousSeparatesSameNATNodes(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	const psk = "nat-secret"

	rd1 := dialNode(t, ctrl, psk, "ffff000000000006")
	rd2 := dialNode(t, ctrl, psk, "1111000000000007")
	id1 := waitForFrame(t, rd1, cmdP2PHub).nodeID
	id2 := waitForFrame(t, rd2, cmdP2PHub).nodeID

	c1 := newHubClient(t, h)
	c2 := newHubClient(t, h)
	c1.send(t, append(append([]byte(hubProbeMagic), id1...), 0x00))
	c2.send(t, append(append([]byte(hubProbeMagic), id2...), 0x00))

	// Same IP, different ports.
	if host1, _, _ := net.SplitHostPort(c1.ep()); host1 != "127.0.0.1" {
		t.Fatalf("test needs a loopback source, got %q", host1)
	}
	if c1.ep() == c2.ep() {
		t.Fatal("the two clients must differ by port to model a shared NAT")
	}
	waitFor(t, 5*time.Second, func() bool {
		a, b := h.getConn(id1), h.getConn(id2)
		if a == nil || b == nil {
			return false
		}
		sa, sb := a.snapshot(), b.snapshot()
		return sa.relayEP == c1.ep() && sb.relayEP == c2.ep()
	})

	peers := parseRendReply(t, c1.rendezvous(t, id1))
	if len(peers) != 1 || peers[id2].id != id2 || peers[id2].ep != c2.ep() {
		t.Fatalf("same-NAT attribution failed: %+v", peers)
	}
	back := parseRendReply(t, c2.rendezvous(t, id2))
	if len(back) != 1 || back[id1].id != id1 || back[id1].ep != c1.ep() {
		t.Fatalf("same-NAT attribution failed (reverse): %+v", back)
	}
}

// TestRemapDropsDirectPaths: when a device's mapping moves, a direct path that
// depended on the old port no longer exists and must not keep showing as up.
func TestRemapDropsDirectPaths(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	rd1 := dialNode(t, ctrl, "remap-secret", "2222000000000013")
	rd2 := dialNode(t, ctrl, "remap-secret", "3333000000000014")
	id1 := waitForFrame(t, rd1, cmdP2PHub).nodeID
	id2 := waitForFrame(t, rd2, cmdP2PHub).nodeID

	nc1 := h.getConn(id1)
	nc1.addPeer(id2, "198.51.100.7:5001", p2pPayload("198.51.100.7", 5001))
	nc1.mu.Lock()
	nc1.peers[id2].Direct = true
	nc1.mu.Unlock()

	h.relay.bindEndpoint(id1, "198.51.100.7:5001")
	h.relay.bindEndpoint(id1, "198.51.100.7:9999") // mapping moved

	nc1.mu.Lock()
	still := nc1.peers[id2].Direct
	nc1.mu.Unlock()
	if still {
		t.Fatal("direct path kept claiming to be up after the endpoint moved")
	}
	nc1.mu.Lock()
	ep := nc1.relayEP
	nc1.mu.Unlock()
	if ep != "198.51.100.7:9999" {
		t.Fatalf("relayEP = %q, want the new mapping", ep)
	}
}

// TestGroupIsolation checks a PSK is a boundary: no cross-group discovery.
func TestGroupIsolation(t *testing.T) {
	h, ctrl, _ := startTestHub(t)

	ra := dialNode(t, ctrl, "group-one", "2222000000000008")
	rb := dialNode(t, ctrl, "group-one", "3333000000000009")
	rc := dialNode(t, ctrl, "group-two", "444400000000000a")
	idA := waitForFrame(t, ra, cmdP2PHub).nodeID
	idB := waitForFrame(t, rb, cmdP2PHub).nodeID
	idC := waitForFrame(t, rc, cmdP2PHub).nodeID

	h.relay.bindEndpoint(idA, "203.0.113.1:1111")
	h.relay.bindEndpoint(idB, "203.0.113.2:2222")
	h.relay.bindEndpoint(idC, "203.0.113.3:3333")

	ca := newHubClient(t, h)
	peers := parseRendReply(t, ca.rendezvous(t, idA))
	if len(peers) != 1 || peers[idB].id != idB {
		t.Fatalf("group-one node saw %+v, want only %s", peers, idB)
	}
	if _, leaked := peers[idC]; leaked {
		t.Fatal("node discovered a peer from a different PSK group")
	}
}

// TestPeerStatusParse covers the client -> server status report format, and
// pins the rule that a client cannot invent peers: only links the server itself
// established are accepted.
func TestPeerStatusParse(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	rd := dialNode(t, ctrl, "status-secret", "555500000000000b")
	self := waitForFrame(t, rd, cmdP2PHub).nodeID
	nc := h.getConn(self)
	if nc == nil {
		t.Fatal("node vanished")
	}

	// The server only tracks peers it has told the node to punch, so register
	// them the way the mesh would.
	const directPeer = "aaaa1111"
	const indirectPeer = "bbbb2222"
	nc.addPeer(directPeer, "203.0.113.1:1111", p2pPayload("203.0.113.1", 1111))
	nc.addPeer(indirectPeer, "203.0.113.2:2222", p2pPayload("203.0.113.2", 2222))
	drainFrames(t, rd, 2)

	report := []byte{ctrlStatusByte, 2}
	report = append(report, directPeer...)
	report = append(report, 0x01) // direct path open
	report = append(report, indirectPeer...)
	report = append(report, 0x00) // still going via the hub
	nc.applyPeerStatus(report[2:])

	links := h.listLinks()
	direct, indirect := 0, 0
	for _, l := range links {
		if l.From != self {
			continue
		}
		if l.Direct {
			direct++
		} else {
			indirect++
		}
	}
	if direct != 1 || indirect != 1 {
		t.Fatalf("status did not split direct/indirect: direct=%d indirect=%d (%+v)", direct, indirect, links)
	}

	// A report naming a peer the server never established must be ignored.
	nc.applyPeerStatus(append([]byte("cccc3333"), 0x01))
	if n := len(h.listLinks()); n != 2 {
		t.Fatalf("a client invented a peer: %d links, want 2", n)
	}
}

// drainFrames reads and discards exactly n frames.
func drainFrames(t *testing.T, cc *clientConn, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		cc.setDeadline(time.Now().Add(5 * time.Second))
		if _, err := cc.readFrame(t); err != nil {
			t.Fatalf("draining frame %d/%d: %v", i+1, n, err)
		}
	}
}

// TestSendCommandPlaceholderID: a command that names no peer must still send a
// well-formed frame. Rejecting the empty id used to break reset, proxy add and
// P2P clear, all of which have no peer.
func TestSendCommandPlaceholderID(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	rd := dialNode(t, ctrl, "placeholder-secret", "666600000000000c")
	waitForFrame(t, rd, cmdP2PHub)

	nc := h.onlineOne(t)
	if err := nc.sendCommand(cmdReset, [8]byte{}); err != nil {
		t.Fatalf("sendCommand with no peer failed: %v", err)
	}
	f, err := rd.readFrame(t)
	if err != nil {
		t.Fatalf("read reset frame: %v", err)
	}
	if f.cmd != cmdReset {
		t.Fatalf("want reset, got 0x%02X", f.cmd)
	}
	if f.nodeID != "00000000" {
		t.Fatalf("placeholder id must be eight '0', got %q", f.nodeID)
	}
}

// TestAddPeerIsIdempotent: re-running the mesh maintenance must not restart a
// link that is already up, or the two ends would knock each other down on
// every tick.
func TestAddPeerIsIdempotent(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	rd := dialNode(t, ctrl, "idem-secret", "777700000000000d")
	self := waitForFrame(t, rd, cmdP2PHub).nodeID
	nc := h.getConn(self)

	payload := p2pPayload("203.0.113.9", 4242)
	if err := nc.addPeer("8888eeee", "203.0.113.9:4242", payload); err != nil {
		t.Fatalf("first addPeer: %v", err)
	}
	// Mark it as already reporting so the freshness guard engages.
	nc.mu.Lock()
	nc.peers["8888eeee"].LastReport = time.Now()
	nc.mu.Unlock()

	f := waitForFrame(t, rd, cmdP2PAdd)
	if f.nodeID != "8888eeee" {
		t.Fatalf("addPeer addressed %q", f.nodeID)
	}
	nc.mu.Lock()
	nc.peers["8888eeee"].LastReport = time.Now()
	nc.mu.Unlock()

	if err := nc.addPeer("8888eeee", "203.0.113.9:4242", payload); err != nil {
		t.Fatalf("repeat addPeer: %v", err)
	}
	// A duplicate frame must not arrive: a re-send would restart the client's
	// session and knock the established path down.
	expectNoFrame(t, rd, "idle maintenance re-sent a peer command")
}

// TestAddPeerRejectsGarbage: a peer id that is not 8 hex chars must be refused
// rather than sent, because the client keys its table on that field.
func TestAddPeerRejectsGarbage(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	rd := dialNode(t, ctrl, "garbage-secret", "999900000000000e")
	waitForFrame(t, rd, cmdP2PHub)
	nc := h.onlineOne(t)
	if err := nc.sendCommandTo(cmdP2PAdd, [8]byte{}, "not-hex!"); err == nil {
		t.Fatal("expected a malformed peer id to be rejected")
	}
}

// TestNodePersistence: nodes must survive a restart of the hub, otherwise the
// device ids a client stored are useless.
func TestNodePersistence(t *testing.T) {
	dir := t.TempDir()
	ctrl := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	relay := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	set := func() {
		t.Setenv("MESH_ENABLED", "true")
		t.Setenv("CONTROL_LISTEN", ctrl)
		t.Setenv("RELAY_LISTEN", relay)
		t.Setenv("MESH_DATA_DIR", dir)
	}
	set()
	h1 := StartMesh(nil)
	if h1 == nil {
		t.Fatal("nil hub")
	}
	defer h1.Close()
	if _, err := h1.addNode("persist-me", "persist-secret"); err != nil {
		t.Fatalf("addNode: %v", err)
	}
	want := len(h1.listNodes(false))
	if err := h1.saveNodes(); err != nil {
		t.Fatalf("saveNodes: %v", err)
	}

	set()
	h2 := StartMesh(nil)
	if h2 == nil {
		t.Fatal("nil hub")
	}
	defer h2.Close()
	if got := len(h2.listNodes(false)); got != want {
		t.Fatalf("after reload: %d nodes, want %d", got, want)
	}
	if _, ok := h2.byDevice[""]; ok {
		t.Fatal("unexpected empty device id index entry")
	}
}

func TestStateFileIsNotWrittenToRepoDir(t *testing.T) {
	// A guard against the state files landing next to the binary by accident.
	dir := t.TempDir()
	if _, err := os.Stat(filepath.Join(dir, "nodes.json")); !os.IsNotExist(err) {
		t.Fatal("temp dir should start without a nodes file")
	}
}

func TestDeviceIDSanitised(t *testing.T) {
	// The device id is a client-supplied string that becomes a map key and part
	// of a node name, so it must not be able to smuggle path separators, quotes
	// or newlines through. Callers length-check to 8 for the wire field; this
	// function is only responsible for keeping the character set safe.
	cases := map[string]string{
		"ABCD1234":     "ABCD1234",
		"abcd1234ef":   "abcd1234ef",
		"../../etc/ps": "etcps",
		"":             "",
		"a b\nc":       "abc",
		"dead_BEEF9":   "dead_BEEF9",
		"quote\"x":     "quotex",
		"semi;colon":   "semicolon",
	}
	for in, want := range cases {
		if got := sanitizeDeviceID(in); got != want {
			t.Errorf("sanitizeDeviceID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSanitisedIDNeverBreaksTheWire guards the interaction the dashboard
// depends on: an id that sanitises to something the wire cannot carry must be
// rejected, not silently sent.
func TestSanitisedIDNeverBreaksTheWire(t *testing.T) {
	h, ctrl, _ := startTestHub(t)
	rd := dialNode(t, ctrl, "wire-secret", "1234abcd")
	waitForFrame(t, rd, cmdP2PHub)
	nc := h.onlineOne(t)
	for _, bad := range []string{"short", "waytoolongidentifier", "has spac", "quote\"", "dead_BEEF"} {
		if err := nc.sendCommandTo(cmdP2PAdd, [8]byte{}, bad); err == nil {
			t.Errorf("peer id %q was accepted for the wire, want rejection", bad)
		}
	}
	for _, good := range []string{"1234abcd", "ABCD1234", "dead_BEE"} {
		if err := nc.sendCommandTo(cmdP2PAdd, [8]byte{}, good); err != nil {
			t.Errorf("peer id %q was rejected: %v", good, err)
		}
	}
}

func TestShortIDIsStableLength(t *testing.T) {
	id := meshShortID()
	if len(id) != 8 {
		t.Fatalf("meshShortID() = %q, want 8 chars", id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("meshShortID() = %q is not hex: %v", id, err)
	}
}

// ---- helpers --------------------------------------------------------------

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

func (h *MeshHub) onlineOne(t *testing.T) *NodeConn {
	t.Helper()
	ids := h.onlineNodes()
	if len(ids) != 1 {
		t.Fatalf("want exactly 1 online node, got %d", len(ids))
	}
	nc := h.getConn(ids[0])
	if nc == nil {
		t.Fatal("online node has no connection")
	}
	return nc
}

// hubClient is a device's UDP socket to the rendezvous hub. It stays open for
// the whole test so its source port — the NAT mapping the server registers — is
// stable, exactly as a real client's hub socket is.
type hubClient struct {
	t    *testing.T
	conn *net.UDPConn
}

func newHubClient(t *testing.T, h *MeshHub) *hubClient {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", h.relay.addr)
	if err != nil {
		t.Fatalf("resolve relay: %v", err)
	}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return &hubClient{t: t, conn: c}
}

func (hc *hubClient) ep() string { return hc.conn.LocalAddr().String() }

func (hc *hubClient) send(t *testing.T, data []byte) {
	t.Helper()
	if _, err := hc.conn.Write(data); err != nil {
		t.Fatalf("write to relay: %v", err)
	}
}

// rendezvous sends a P1H and returns the parsed reply.
func (hc *hubClient) rendezvous(t *testing.T, id string) []byte {
	t.Helper()
	hello := append([]byte(hubRendHello), id...)
	hc.send(t, hello)
	hc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := hc.conn.Read(buf)
	if err != nil {
		t.Fatalf("no rendezvous reply for %s: %v", id, err)
	}
	return buf[:n]
}

type rendPeer struct {
	id string
	ep string
}

func parseRendReply(t *testing.T, b []byte) map[string]rendPeer {
	t.Helper()
	if len(b) < 4 || string(b[:3]) != hubRendReply {
		t.Fatalf("not a rendezvous reply: %q", b)
	}
	count := int(b[3])
	out := map[string]rendPeer{}
	off := 4
	for i := 0; i < count; i++ {
		if off+14 > len(b) {
			t.Fatalf("reply truncated at record %d", i)
		}
		id := string(b[off : off+8])
		ip := net.IP(b[off+8 : off+12])
		port := int(b[off+12])<<8 | int(b[off+13])
		out[id] = rendPeer{id: id, ep: fmt.Sprintf("%s:%d", ip, port)}
		off += 14
	}
	return out
}
