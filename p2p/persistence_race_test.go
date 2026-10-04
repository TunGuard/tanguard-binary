package p2p

// Guards the state-file write against concurrent saves: a fixed temp name
// let two goroutines race and the loser failed its rename.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSaveNodesConcurrent(t *testing.T) {
	dir := t.TempDir()
	ctrl := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	relay := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	t.Setenv("MESH_ENABLED", "true")
	t.Setenv("CONTROL_LISTEN", ctrl)
	t.Setenv("RELAY_LISTEN", relay)
	t.Setenv("MESH_DATA_DIR", dir)
	h := StartMesh(nil)
	if h == nil {
		t.Fatal("nil hub")
	}
	defer h.Close()
	if _, err := h.AddNode("race-me", "race-secret"); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- h.saveNodes() }()
	}
	wg.Wait()
	close(errs)
	bad := 0
	for e := range errs {
		if e != nil {
			bad++
			t.Logf("saveNodes: %v", e)
		}
	}
	if bad != 0 {
		t.Fatalf("%d/64 concurrent saveNodes calls failed", bad)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
	if _, err := os.Stat(filepath.Join(dir, "nodes.json")); err != nil {
		t.Fatalf("nodes.json not written: %v", err)
	}
}
