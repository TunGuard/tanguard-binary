package main

// End-to-end tests for the real tun client binary against the real control
// plane. The rest of this package speaks the protocol from Go, which cannot
// catch the failure these cover: a client that goes quiet. Here the compiled C
// client is launched and the hub is inspected for what it actually recorded,
// so "the node is online and its liveness is advancing" is an observation
// rather than an assumption.

import (
	"fmt"
	"net"
	"os"

	"path/filepath"

	"testing"
	"time"
)

const clientCtrlPort = 7000 // the client hardcodes this, so the hub must meet it

// startHubOn7000 brings up the real MeshHub exactly where the client looks,
// with every side effect confined to a temp dir.
func startHubOn7000(t *testing.T, dir string) *MeshHub {
	t.Helper()
	if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", clientCtrlPort)); err != nil {
		t.Skipf("port %d busy, skipping: %v", clientCtrlPort, err)
	} else {
		l.Close()
	}

	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay port: %v", err)
	}
	relayAddr := relay.LocalAddr().String()
	relay.Close()

	t.Setenv("MESH_ENABLED", "true")
	t.Setenv("CONTROL_LISTEN", fmt.Sprintf("127.0.0.1:%d", clientCtrlPort))
	t.Setenv("RELAY_LISTEN", relayAddr)
	t.Setenv("MESH_DATA_DIR", dir)
	t.Setenv("CONTROL_TIMEOUT_S", "60")

	// Created before StartMesh: the hub reads its node store on the way up and
	// writes to it as soon as a node registers.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("hub data dir: %v", err)
	}

	h := StartMesh(nil)
	if h == nil {
		t.Fatal("StartMesh returned nil")
	}
	// The rendezvous socket binds asynchronously; the client dials it the moment
	// it is handed a hub target.
	waitFor(t, 5*time.Second, func() bool { return h.relay.Up() })
	return h
}

// alive reports whether the client process is still running. This is the only
// way to catch a client that dies instead of reconnecting.
func (c *clientProc) alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (h *MeshHub) liveConnCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, nc := range h.conns {
		if nc.snapshot().connected {
			n++
		}
	}
	return n
}

func (h *MeshHub) oneLastSeen() (time.Time, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, nc := range h.conns {
		return nc.snapshot().lastSeen, true
	}
	return time.Time{}, false
}

func (h *MeshHub) deviceIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.byDevice))
	for id := range h.byDevice {
		out = append(out, id)
	}
	return out
}

// peerCountAtLeast reports whether any online node holds at least n peers.
func (h *MeshHub) peerCountAtLeast(n int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, nc := range h.conns {
		if len(nc.snapshot().peers) >= n {
			return true
		}
	}
	return false
}

func (h *MeshHub) peerCounts() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]int, 0, len(h.conns))
	for _, nc := range h.conns {
		out = append(out, len(nc.snapshot().peers))
	}
	return out
}

// crashHub kills the control plane the way a dying process does: every live
// node socket is torn down and the listener goes with it.
//
// This is not the same as h.Close(), which only releases the listening socket
// and the relay. That leaves already-accepted node connections open, so a client
// correctly keeps heartbeating into a healthy TCP connection and never
// reconnects -- which is right of it, and useless as a restart test.
//
// TUN_CRASH_STYLE=halfclose makes the server half-close instead of fully
// closing. The kernel answers a write to such a socket with EPIPE rather than
// ECONNRESET, which is the one path that raises SIGPIPE.
func crashHub(t *testing.T, h *MeshHub) {
	t.Helper()
	half := os.Getenv("TUN_CRASH_STYLE") == "halfclose"

	type target struct {
		c   net.Conn
		tcp *net.TCPConn
	}
	var victims []target

	h.mu.Lock()
	for _, nc := range h.conns {
		c := nc.conn
		if c == nil {
			continue
		}
		tgt := target{c: c}
		if tc, ok := c.(*net.TCPConn); ok {
			tgt.tcp = tc
		}
		victims = append(victims, tgt)
	}
	h.mu.Unlock()

	for _, v := range victims {
		if half {
			// Leave the socket open for reading; only the write side goes away.
			_ = v.tcp.CloseWrite()
			continue
		}
		if v.tcp != nil {
			// linger 0 turns Close into an abortive RST, which is what the
			// client sees when the server is killed rather than shut down.
			_ = v.tcp.SetLinger(0)
		}
		_ = v.c.Close()
	}
	h.Close()
}

// TestClientHeartbeatKeepsNodeAlive is the regression test for "the client
// sleeps and stops showing on the server". An empty mesh used to produce no
// traffic at all, so the report now goes out with a peer count of 0 and the hub
// must treat that as proof of life.
func TestClientHeartbeatKeepsNodeAlive(t *testing.T) {
	bin := clientBinary(t)
	dir := t.TempDir()

	h := startHubOn7000(t, dir)
	defer h.Close()

	c := startClient(t, bin, "127.0.0.1", "heartbeat-psk", filepath.Join(dir, "client"))

	waitFor(t, 25*time.Second, func() bool { return h.liveConnCount() == 1 })

	first, ok := h.oneLastSeen()
	if !ok {
		t.Fatal("no node connection recorded")
	}

	// The client reports every 5s; wait out two full intervals.
	time.Sleep(12 * time.Second)

	second, ok := h.oneLastSeen()
	if !ok {
		t.Fatal("node connection vanished")
	}
	if !second.After(first) {
		t.Fatalf("liveness did not advance: %s -> %s — the empty status report "+
			"was not accepted as proof of life",
			first.Format(time.RFC3339Nano), second.Format(time.RFC3339Nano))
	}
	t.Logf("liveness advanced %s -> %s", first.Format(time.RFC3339Nano),
		second.Format(time.RFC3339Nano))

	if !c.alive() {
		t.Fatalf("client died during the session (signal %v)", c.cmd.ProcessState)
	}
}

// TestClientReconnectsAfterHubRestart covers the SIGPIPE crash and the wedged
// reporter: the control plane is pulled out from under the client, which has to
// come back on its own, as the same device, with nobody touching it.
func TestClientReconnectsAfterHubRestart(t *testing.T) {
	bin := clientBinary(t)
	dir := t.TempDir()

	h1 := startHubOn7000(t, dir)
	c := startClient(t, bin, "127.0.0.1", "reconnect-psk", filepath.Join(dir, "client"))

	waitFor(t, 25*time.Second, func() bool { return h1.liveConnCount() == 1 })
	before := h1.deviceIDs()
	if len(before) != 1 {
		t.Fatalf("expected 1 device, got %v", before)
	}
	t.Logf("device before restart: %v", before)

	// Tear the control plane down underneath the client, the way a restart does.
	crashHub(t, h1)
	time.Sleep(3 * time.Second)

	h2 := startHubOn7000(t, filepath.Join(dir, "hub2"))
	defer h2.Close()

	waitFor(t, 30*time.Second, func() bool { return h2.liveConnCount() == 1 })

	after := h2.deviceIDs()
	if len(after) != 1 || after[0] != before[0] {
		t.Fatalf("reconnected as a different device: before=%v after=%v", before, after)
	}
	t.Logf("reconnected unassisted as the same device: %v", after)

	if !c.alive() {
		t.Fatalf("client died instead of reconnecting (signal %v)", c.cmd.ProcessState)
	}
}

// TestMeshedClientSurvivesHubCrash is the SIGPIPE regression.
//
// A client with no peers never writes upward, so it cannot be killed by writing
// to a dead socket -- that is the only reason the previous test passes on the
// old binary. Once two nodes share a PSK the hub hands each a peer, the status
// report acquires records, and the very next write lands on a socket the server
// has already gone away from. With SIGPIPE left at its default, that write
// terminates the daemon: no reconnect, no node on the dashboard, and on the
// Android and Windows boot hooks nothing ever restarts it.
func TestMeshedClientSurvivesHubCrash(t *testing.T) {
	bin := clientBinary(t)
	dir := t.TempDir()

	h1 := startHubOn7000(t, dir)
	a := startClient(t, bin, "127.0.0.1", "mesh-psk", filepath.Join(dir, "clientA"))
	b := startClient(t, bin, "127.0.0.1", "mesh-psk", filepath.Join(dir, "clientB"))

	waitFor(t, 30*time.Second, func() bool { return h1.liveConnCount() == 2 })

	// Both nodes must actually hold a peer, otherwise the reports are still
	// empty and this test would quietly cover nothing.
	waitFor(t, 30*time.Second, func() bool { return h1.peerCountAtLeast(1) })
	t.Logf("both nodes meshed; peer records per node: %v", h1.peerCounts())

	first, _ := h1.oneLastSeen()
	time.Sleep(8 * time.Second)
	second, _ := h1.oneLastSeen()
	if !second.After(first) {
		t.Fatalf("a meshed node stopped reporting: %s -> %s",
			first.Format(time.RFC3339Nano), second.Format(time.RFC3339Nano))
	}

	crashHub(t, h1)

	// The kernel lets the first write after a peer close succeed and only
	// reports EPIPE from the second one on, and the client reports every 5s, so
	// this needs three full intervals to be sure the failing write has happened.
	time.Sleep(18 * time.Second)
	if !a.alive() {
		t.Fatalf("client A died when the server went away "+
			"(signal %v) -- SIGPIPE is not being ignored", a.cmd.ProcessState)
	}
	if !b.alive() {
		t.Fatalf("client B died when the server went away "+
			"(signal %v) -- SIGPIPE is not being ignored", b.cmd.ProcessState)
	}
	t.Log("both clients survived the crash")

	h2 := startHubOn7000(t, filepath.Join(dir, "hub2"))
	defer h2.Close()
	waitFor(t, 30*time.Second, func() bool { return h2.liveConnCount() == 2 })
	t.Log("both clients reconnected unassisted")
}