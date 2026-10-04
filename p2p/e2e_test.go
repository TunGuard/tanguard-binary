package p2p

// End-to-end tests that run the real client binary. Everything else in this
// package tests the server in isolation; these tests are the only ones that
// prove the C and Go halves of the protocol actually agree, which is the part
// that a passing unit test on either side cannot tell you.

import (
	"net"
	"testing"
	"time"

	"tanguard/internal/testenv"
)

// e2eHub boots a hub on the ports the real client hardcodes. The client has no
// way to be told a different control port, so the e2e tests have to use the
// production ports or they would not be testing the real client.
func e2eHub(t *testing.T) *MeshHub {
	t.Helper()
	const ctrl, relay = "127.0.0.1:7000", "127.0.0.1:7001"
	for _, a := range []string{ctrl, relay} {
		var err error
		if a == relay {
			// UDP needs ListenPacket; net.Listen would reject it.
			var pc net.PacketConn
			pc, err = net.ListenPacket("udp", a)
			if err == nil {
				pc.Close()
			}
		} else {
			var l net.Listener
			l, err = net.Listen("tcp", a)
			if err == nil {
				l.Close()
			}
		}
		if err != nil {
			t.Skipf("%s is busy, cannot run the end-to-end test: %v", a, err)
		}
	}
	dir := t.TempDir()
	t.Setenv("MESH_ENABLED", "true")
	t.Setenv("CONTROL_LISTEN", ctrl)
	t.Setenv("RELAY_LISTEN", relay)
	t.Setenv("MESH_DATA_DIR", dir)
	t.Setenv("CONTROL_TIMEOUT_S", "30")
	h := StartMesh(nil)
	if h == nil {
		t.Fatal("StartMesh returned nil")
	}
	t.Cleanup(h.Close)
	// The rendezvous socket binds asynchronously; do not start clients against
	// a hub that has no hub.
	testenv.WaitFor(t, 5*time.Second, func() bool { return h.relay.Up() })
	return h
}

// TestRealClientsSharePSKAndDiscover drives two real client processes through
// the whole path: handshake, node-id assignment, hub rendezvous, punch, and
// status reporting back to the dashboard API.
func TestRealClientsSharePSKAndDiscover(t *testing.T) {
	bin := testenv.ClientBinary(t)
	h := e2eHub(t)
	const psk = "e2e-shared-secret"

	a := testenv.StartClient(t, bin, "127.0.0.1", psk, t.TempDir())
	b := testenv.StartClient(t, bin, "127.0.0.1", psk, t.TempDir())
	t.Cleanup(func() {
		if t.Failed() {
			a.Dump(t)
			b.Dump(t)
		}
	})

	// Both must register, and they must be distinct nodes.
	testenv.WaitFor(t, 20*time.Second, func() bool {
		n := 0
		for _, ns := range h.ListNodes(false) {
			if ns.Online {
				n++
			}
		}
		return n == 2
	})

	// The PSK is masked in the default listing, so ask for the raw value.
	nodes := h.ListNodes(true)
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d: %+v", len(nodes), nodes)
	}
	ids := map[string]bool{}
	for _, n := range nodes {
		ids[n.ID] = true
		if n.PSK != psk {
			t.Errorf("node %s landed in the wrong group %q", n.ID, n.PSK)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("node ids collided: %v", ids)
	}

	// The punch must complete on its own, with no dashboard action. Both nodes
	// should end up with one direct peer.
	testenv.WaitFor(t, 40*time.Second, func() bool {
		if t.Failed() {
			return false
		}
		for _, n := range h.ListNodes(false) {
			if nc := h.GetConn(n.ID); nc != nil {
				sn := nc.snapshot()
				t.Logf("DIAG %s relayEP=%q peers=%d", n.ID, sn.relayEP, len(sn.peers))
				for id, p := range sn.peers {
					t.Logf("DIAG   peer %s ep=%q direct=%v lastReport=%v", id, p.Endpoint, p.Direct, !p.LastReport.IsZero())
				}
			}
		}
		direct := 0
		for _, l := range h.ListLinks() {
			if l.Direct {
				direct++
			}
		}
		return direct == 2
	})

	for _, l := range h.ListLinks() {
		if !l.Direct {
			t.Errorf("link %s -> %s never went direct (endpoint %q)", l.From, l.To, l.Endpoint)
		}
		if l.From == l.To {
			t.Errorf("a node was recorded as its own peer: %+v", l)
		}
	}
	_ = a
	_ = b
}

// TestRealClientsIsolatedByPSK: two clients on different PSKs must never find
// each other, no matter how many punches are attempted.
func TestRealClientsIsolatedByPSK(t *testing.T) {
	bin := testenv.ClientBinary(t)
	h := e2eHub(t)
	testenv.StartClient(t, bin, "127.0.0.1", "psk-alpha", t.TempDir())
	testenv.StartClient(t, bin, "127.0.0.1", "psk-beta", t.TempDir())

	testenv.WaitFor(t, 20*time.Second, func() bool {
		n := 0
		for _, ns := range h.ListNodes(false) {
			if ns.Online {
				n++
			}
		}
		return n == 2
	})

	// Give the mesh maintenance time to try; it must never find a cross-group
	// peer.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if links := h.ListLinks(); len(links) != 0 {
			t.Fatalf("peers crossed a PSK boundary: %+v", links)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestRealClientReconnectKeepsIdentity: restarting a client must reuse its
// node rather than accumulating a new one, which is what the persisted device
// id is for.
func TestRealClientReconnectKeepsIdentity(t *testing.T) {
	bin := testenv.ClientBinary(t)
	h := e2eHub(t)
	stateDir := t.TempDir()

	first := testenv.StartClient(t, bin, "127.0.0.1", "reconnect-secret", stateDir)
	testenv.WaitFor(t, 20*time.Second, func() bool { return len(h.onlineNodes()) == 1 })
	id1 := h.onlineNodes()[0]
	first.Stop(t)
	testenv.WaitFor(t, 20*time.Second, func() bool { return len(h.onlineNodes()) == 0 })

	testenv.StartClient(t, bin, "127.0.0.1", "reconnect-secret", stateDir)
	testenv.WaitFor(t, 20*time.Second, func() bool { return len(h.onlineNodes()) == 1 })
	if id2 := h.onlineNodes()[0]; id2 != id1 {
		t.Fatalf("reconnect changed the node id: %s -> %s", id1, id2)
	}
	if n := len(h.ListNodes(false)); n != 1 {
		t.Fatalf("reconnect created a duplicate node, have %d", n)
	}
}
