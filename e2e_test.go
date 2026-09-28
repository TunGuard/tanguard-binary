package main

// End-to-end tests that run the real client binary. Everything else in this
// package tests the server in isolation; these tests are the only ones that
// prove the C and Go halves of the protocol actually agree, which is the part
// that a passing unit test on either side cannot tell you.

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
	waitFor(t, 5*time.Second, func() bool { return h.relay.Up() })
	return h
}

// clientBinary locates the compiled tun client. These tests are skipped when it
// has not been built, so `go test ./...` still works on a machine without a C
// toolchain.
func clientBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the client binary is only built and run on linux in this test")
	}
	var candidates []string
	if p := os.Getenv("TUN_BINARY"); p != "" {
		candidates = append(candidates, p)
	}
	// Relative to this package, walking up to the sibling checkout.
	if wd, err := os.Getwd(); err == nil {
		for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
			candidates = append(candidates, filepath.Join(dir, "tun", "tun"))
			candidates = append(candidates, filepath.Join(dir, "..", "tun", "tun"))
		}
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Skip("tun client binary not found; run `make` in the tun checkout")
	return ""
}

type clientProc struct {
	cmd     *exec.Cmd
	dir     string
	logPath string
	done    chan error
}

// dump prints whatever the client wrote, which is the only way to debug a
// failure that happens inside a forked process.
func (c *clientProc) dump(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile(c.logPath)
	if err != nil {
		return
	}
	t.Logf("client %s log:\n%s", c.cmd.Args[3], b)
}

func (c *clientProc) stop(t *testing.T) {
	t.Helper()
	if c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Error("client did not exit after kill")
	}
}

func startClient(t *testing.T, bin, serverIP, psk, stateDir string) *clientProc {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatalf("state dir: %v", err)
	}
	cmd := exec.Command(bin, serverIP, psk, stateDir)
	cmd.Env = append(os.Environ(), "HOME="+stateDir)
	logPath := filepath.Join(t.TempDir(), "client.log")
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("client log: %v", err)
	}
	cmd.Stdout = logf
	cmd.Stderr = logf
	t.Logf("launching %s with %v", bin, cmd.Args)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	p := &clientProc{cmd: cmd, dir: stateDir, logPath: logPath, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() { p.stop(t) })
	return p
}

// TestRealClientsSharePSKAndDiscover drives two real client processes through
// the whole path: handshake, node-id assignment, hub rendezvous, punch, and
// status reporting back to the dashboard API.
func TestRealClientsSharePSKAndDiscover(t *testing.T) {
	bin := clientBinary(t)
	h := e2eHub(t)
	const psk = "e2e-shared-secret"

	a := startClient(t, bin, "127.0.0.1", psk, t.TempDir())
	b := startClient(t, bin, "127.0.0.1", psk, t.TempDir())
	t.Cleanup(func() {
		if t.Failed() {
			a.dump(t)
			b.dump(t)
		}
	})

	// Both must register, and they must be distinct nodes.
	waitFor(t, 20*time.Second, func() bool {
		n := 0
		for _, ns := range h.listNodes(false) {
			if ns.Online {
				n++
			}
		}
		return n == 2
	})

	// The PSK is masked in the default listing, so ask for the raw value.
	nodes := h.listNodes(true)
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
	waitFor(t, 40*time.Second, func() bool {
		if t.Failed() {
			return false
		}
		for _, n := range h.listNodes(false) {
			if nc := h.getConn(n.ID); nc != nil {
				sn := nc.snapshot()
				t.Logf("DIAG %s relayEP=%q peers=%d", n.ID, sn.relayEP, len(sn.peers))
				for id, p := range sn.peers {
					t.Logf("DIAG   peer %s ep=%q direct=%v lastReport=%v", id, p.Endpoint, p.Direct, !p.LastReport.IsZero())
				}
			}
		}
		direct := 0
		for _, l := range h.listLinks() {
			if l.Direct {
				direct++
			}
		}
		return direct == 2
	})

	for _, l := range h.listLinks() {
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
	bin := clientBinary(t)
	h := e2eHub(t)
	startClient(t, bin, "127.0.0.1", "psk-alpha", t.TempDir())
	startClient(t, bin, "127.0.0.1", "psk-beta", t.TempDir())

	waitFor(t, 20*time.Second, func() bool {
		n := 0
		for _, ns := range h.listNodes(false) {
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
		if links := h.listLinks(); len(links) != 0 {
			t.Fatalf("peers crossed a PSK boundary: %+v", links)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestRealClientReconnectKeepsIdentity: restarting a client must reuse its
// node rather than accumulating a new one, which is what the persisted device
// id is for.
func TestRealClientReconnectKeepsIdentity(t *testing.T) {
	bin := clientBinary(t)
	h := e2eHub(t)
	stateDir := t.TempDir()

	first := startClient(t, bin, "127.0.0.1", "reconnect-secret", stateDir)
	waitFor(t, 20*time.Second, func() bool { return len(h.onlineNodes()) == 1 })
	id1 := h.onlineNodes()[0]
	first.stop(t)
	waitFor(t, 20*time.Second, func() bool { return len(h.onlineNodes()) == 0 })

	startClient(t, bin, "127.0.0.1", "reconnect-secret", stateDir)
	waitFor(t, 20*time.Second, func() bool { return len(h.onlineNodes()) == 1 })
	if id2 := h.onlineNodes()[0]; id2 != id1 {
		t.Fatalf("reconnect changed the node id: %s -> %s", id1, id2)
	}
	if n := len(h.listNodes(false)); n != 1 {
		t.Fatalf("reconnect created a duplicate node, have %d", n)
	}
}

// TestRealClientTRPPortsAreProxied is the other half of the user's request: a
// service listening on a client port must become reachable on a chosen server
// port. This drives a real client, a real echo service and the real TRP path.
func TestRealClientTRPPortsAreProxied(t *testing.T) {
	bin := clientBinary(t)
	h := e2eHub(t)
	startClient(t, bin, "127.0.0.1", "trp-secret", t.TempDir())
	waitFor(t, 20*time.Second, func() bool { return len(h.onlineNodes()) == 1 })
	nodeID := h.onlineNodes()[0]

	// A tiny echo service standing in for whatever runs on the client, here on
	// 8022 as in the user's description.
	svcLn, err := net.Listen("tcp", "127.0.0.1:8022")
	if err != nil {
		t.Skipf("port 8022 unavailable: %v", err)
	}
	defer svcLn.Close()
	go func() {
		for {
			c, err := svcLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	// The service runs on this same host as the server in the test, so the
	// target IP must be this host rather than the client's.
	publicPort := freePort(t)
	rec, err := h.trp.CreateProxy(nodeID, "", publicPort, 8022, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	if rec == nil || rec.ID == "" {
		t.Fatalf("CreateProxy returned no record: %+v", rec)
	}

	// The proxy binds the public port, so the mapping must be live.
	waitFor(t, 20*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(publicPort)), time.Second)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("ping-through-trp\n")); err != nil {
			return false
		}
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		return err == nil && n > 0 && string(buf[:n]) == "ping-through-trp\n"
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestMeshAPIServesP2PAndTRP checks the two pages the user asked for are wired
// to endpoints that actually return data.
func TestMeshAPIServesP2PAndTRP(t *testing.T) {
	// The hub is booted so the handlers have a live instance to read from.
	startTestHub(t)

	// The routes are wrapped in requireAPI, so the requests have to authenticate
	// or every assertion below would just be measuring the 401 guard.
	api := &API{creds: NewCredentialStore(t.TempDir()), cfg: &Config{
		WebUsername: "admin",
		WebPassword: "test-password",
	}}
	mux := http.NewServeMux()
	registerMeshRoutes(mux, api)
	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listener: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(apiLn)
	defer srv.Close()
	base := "http://" + apiLn.Addr().String()

	client := &http.Client{}
	get := func(path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("GET", base+path, nil)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		req.SetBasicAuth("admin", "test-password")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		json.NewDecoder(resp.Body).Decode(new(interface{}))
		resp.Body.Close()
		return resp
	}

	for _, path := range []string{
		"/api/mesh/status",
		"/api/mesh/nodes",
		"/api/mesh/groups",
		"/api/mesh/links",
		"/api/trp/proxies",
	} {
		if code := get(path).StatusCode; code != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200", path, code)
		}
	}

	// A missing group must be an error, not a silent success. This one has to be
	// a POST: the handler rejects other methods before it ever looks at the body.
	req, err := http.NewRequest("POST", base+"/api/mesh/p2p/mesh", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("admin", "test-password")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /api/mesh/p2p/mesh: %v", err)
	}
	var v interface{}
	json.NewDecoder(resp.Body).Decode(&v)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/mesh/p2p/mesh without a group returned %d, want 400", resp.StatusCode)
	}
}
