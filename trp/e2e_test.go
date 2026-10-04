package trp

// End-to-end test for the TRP path against the real client binary: everything
// else in this package drives the proxy manager directly, which cannot show
// that a service on a client really is reachable on a chosen server port.

import (
	"net"
	"strconv"
	"testing"
	"time"

	"tanguard/internal/testenv"
	"tanguard/p2p"
)

// e2eHub boots a hub on the ports the real client hardcodes. The client has no
// way to be told a different control port, so the end-to-end test has to use the
// production ports or it would not be testing the real client.
func e2eHub(t *testing.T) *p2p.MeshHub {
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
	t.Setenv("MESH_ENABLED", "true")
	t.Setenv("CONTROL_LISTEN", ctrl)
	t.Setenv("RELAY_LISTEN", relay)
	t.Setenv("MESH_DATA_DIR", t.TempDir())
	t.Setenv("CONTROL_TIMEOUT_S", "30")

	h := p2p.StartMesh(nil)
	if h == nil {
		t.Fatal("StartMesh returned nil")
	}
	t.Cleanup(h.Close)
	// The rendezvous socket binds asynchronously; do not start a client against
	// a hub that has no hub.
	testenv.WaitFor(t, 5*time.Second, func() bool { return h.Relay().Up() })
	return h
}

// TestRealClientTRPPortsAreProxied is the other half of the user's request: a
// service listening on a client port must become reachable on a chosen server
// port. This drives a real client, a real echo service and the real TRP path.
func TestRealClientTRPPortsAreProxied(t *testing.T) {
	bin := testenv.ClientBinary(t)
	h := e2eHub(t)
	manager := NewTRPManager(h, h.ProxiesPath())
	h.SetProxyReleaser(manager)

	testenv.StartClient(t, bin, "127.0.0.1", "trp-secret", t.TempDir())
	var nodeID string
	testenv.WaitFor(t, 20*time.Second, func() bool {
		for _, n := range h.ListNodes(false) {
			if n.Online {
				nodeID = n.ID
				return true
			}
		}
		return false
	})

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
	publicPort := testenv.FreePort(t)
	rec, err := manager.CreateProxy(nodeID, "", publicPort, 8022, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	if rec == nil || rec.ID == "" {
		t.Fatalf("CreateProxy returned no record: %+v", rec)
	}

	// The proxy binds the public port, so the mapping must be live.
	testenv.WaitFor(t, 20*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(publicPort)), time.Second)
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
