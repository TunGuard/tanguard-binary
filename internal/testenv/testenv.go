// Package testenv holds the test harness that more than one package needs:
// process control for the real tun client binary, plus the small port and
// polling helpers that go with it. It exists so the p2p, trp and api suites can
// each keep their own tests without copying it, and it deliberately depends on
// nothing inside the server so it can be imported from any of them.
package testenv

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// WaitFor polls cond until it holds or d elapses, then fails the test.
func WaitFor(t *testing.T, d time.Duration, cond func() bool) {
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

// FreePort reserves a loopback TCP port and hands the number back. The listener
// is closed first, so the port is free but no longer reserved: callers use this
// for ports something else is about to bind.
func FreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// FreeUDPPort is FreePort for UDP.
func FreeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

// ClientBinary locates the compiled tun client. Tests that need it are skipped
// when it has not been built, so `go test ./...` still works on a machine
// without a C toolchain.
func ClientBinary(t *testing.T) string {
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

// ClientProc is a running tun client under test.
type ClientProc struct {
	cmd     *exec.Cmd
	dir     string
	logPath string
	done    chan error
	// stopOnce makes Stop idempotent: a test that stops a client explicitly and
	// then lets t.Cleanup stop it again must not wait a second time on a channel
	// whose single value the first call already drained.
	stopOnce sync.Once
}

// StartClient launches the client binary against serverIP with the given PSK.
// The client is stopped when the test ends.
func StartClient(t *testing.T, bin, serverIP, psk, stateDir string) *ClientProc {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatalf("state dir: %v", err)
	}
	cmd := exec.Command(bin, serverIP, psk, stateDir)
	// TUN_FOREGROUND keeps the client from double-forking into a daemon: the
	// harness has to own the real process so Stop can actually end it and a
	// reconnect test sees the control channel drop.
	cmd.Env = append(os.Environ(), "HOME="+stateDir, "TUN_FOREGROUND=1")
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
	p := &ClientProc{cmd: cmd, dir: stateDir, logPath: logPath, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() { p.Stop(t) })
	return p
}

// Alive reports whether the client process is still running. This is the only
// way to catch a client that dies instead of reconnecting.
func (c *ClientProc) Alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// Exit describes how the client process ended, for failure messages.
func (c *ClientProc) Exit() string {
	if c.cmd.ProcessState == nil {
		return ""
	}
	return c.cmd.ProcessState.String()
}

// Dump prints whatever the client wrote, which is the only way to debug a
// failure that happens inside a forked process.
func (c *ClientProc) Dump(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile(c.logPath)
	if err != nil {
		return
	}
	t.Logf("client %s log:\n%s", c.cmd.Args[3], b)
}

// Stop kills the client and waits for it to go away. It is idempotent.
func (c *ClientProc) Stop(t *testing.T) {
	t.Helper()
	c.stopOnce.Do(func() {
		if c.cmd.Process != nil {
			c.cmd.Process.Kill()
		}
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			t.Error("client did not exit after kill")
		}
	})
}
