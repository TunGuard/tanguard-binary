package trp

import (
	"net"
	"strconv"
	"testing"
	"time"

	"tanguard/config"
	"tanguard/internal/testenv"
	"tanguard/p2p"
)

// newTRPHub starts a control plane with its TRP manager wired up, which is what
// main does: the manager needs the hub to reach a node, and the hub needs the
// manager to release a node's ports.
func newTRPHub(t *testing.T) (*p2p.MeshHub, *TRPManager) {
	t.Helper()
	t.Setenv("MESH_ENABLED", "true")
	t.Setenv("MESH_DATA_DIR", t.TempDir())
	t.Setenv("CONTROL_LISTEN", "127.0.0.1:0")
	t.Setenv("RELAY_LISTEN", "127.0.0.1:0")
	hub := p2p.StartMesh(&config.Config{})
	if hub == nil {
		t.Fatal("StartMesh returned nil")
	}
	manager := NewTRPManager(hub, hub.ProxiesPath())
	hub.SetProxyReleaser(manager)
	t.Cleanup(hub.Close)
	return hub, manager
}

// portInUse reports whether something is accepting on a loopback port.
func portInUse(t *testing.T, port int) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// TestRemovingANodeReleasesItsTrpPorts covers the reported leak. Deleting a
// device in P2P used to leave every port it had mapped through TRP bound, and
// since the target node was gone the mapping could never work again, so the
// port was stranded with nothing in the UI able to free it.
func TestRemovingANodeReleasesItsTrpPorts(t *testing.T) {
	hub, manager := newTRPHub(t)

	gone, err := hub.AddNode("edge-gone", "")
	if err != nil {
		t.Fatalf("addNode: %v", err)
	}
	kept, err := hub.AddNode("edge-kept", "")
	if err != nil {
		t.Fatalf("addNode: %v", err)
	}

	// Two mappings on the node being deleted, one on a node that stays.
	doomedPorts := []int{testenv.FreePort(t), testenv.FreePort(t)}
	for _, p := range doomedPorts {
		if _, err := manager.CreateProxy(gone.ID, "127.0.0.1", p, 8022, "127.0.0.1"); err != nil {
			t.Fatalf("CreateProxy: %v", err)
		}
	}
	survivorPort := testenv.FreePort(t)
	if _, err := manager.CreateProxy(kept.ID, "127.0.0.1", survivorPort, 22, "127.0.0.1"); err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}

	for _, p := range append(append([]int{}, doomedPorts...), survivorPort) {
		if !portInUse(t, p) {
			t.Fatalf("precondition: port %d should be bound before the delete", p)
		}
	}

	if err := hub.RemoveNode(gone.ID); err != nil {
		t.Fatalf("removeNode: %v", err)
	}
	// Closing a listener is synchronous, but the accept loop wakes on it, so
	// give the runtime a moment before asserting.
	time.Sleep(150 * time.Millisecond)

	for _, p := range doomedPorts {
		if portInUse(t, p) {
			t.Errorf("port %d is still bound after its node was deleted", p)
		}
		// The real symptom: the port must be reusable, not merely idle.
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			t.Errorf("port %d cannot be re-bound after the node was deleted: %v", p, err)
			continue
		}
		l.Close()
	}

	// The surviving node's mapping must be untouched.
	if !portInUse(t, survivorPort) {
		t.Errorf("port %d was released even though its node still exists", survivorPort)
	}
	if got := len(manager.ListProxies()); got != 1 {
		t.Errorf("%d proxies listed after the delete, want 1", got)
	}
}

// TestRemovedNodeProxiesAreNotRestored pins the persistence half: the released
// mappings must not come back when the process reloads proxies.json.
func TestRemovedNodeProxiesAreNotRestored(t *testing.T) {
	hub, manager := newTRPHub(t)

	gone, err := hub.AddNode("edge-gone", "")
	if err != nil {
		t.Fatalf("addNode: %v", err)
	}
	port := testenv.FreePort(t)
	if _, err := manager.CreateProxy(gone.ID, "127.0.0.1", port, 8022, "127.0.0.1"); err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	if err := hub.RemoveNode(gone.ID); err != nil {
		t.Fatalf("removeNode: %v", err)
	}

	// A fresh manager over the same file must not resurrect the mapping.
	fresh := NewTRPManager(hub, hub.ProxiesPath())
	if err := fresh.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := len(fresh.ListProxies()); got != 0 {
		t.Errorf("%d proxies came back from disk after the node was deleted, want 0", got)
	}
	if portInUse(t, port) {
		t.Errorf("port %d was re-bound by Restore for a deleted node", port)
	}
}
