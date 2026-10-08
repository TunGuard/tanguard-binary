package api

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"tanguard/internal/testenv"
)

// sshTestDial boots a gateway against a test API on a free port and returns
// the address to dial once the listener is up.
func sshTestDial(t *testing.T, a *API) string {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(testenv.FreePort(t)))
	a.cfg.SSHListen = addr
	gw, err := NewSSHGateway(a.cfg, a.creds, a)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	go gw.Start()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("ssh gateway never listened")
	return ""
}

func sshTestClient(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password("test-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// outputPump reads everything from r in the background and lets a test wait
// for a substring without deadlocking on a blocking pipe.
type outputPump struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	done chan struct{}
}

func pumpOutput(r io.Reader) *outputPump {
	p := &outputPump{done: make(chan struct{})}
	go func() {
		defer close(p.done)
		tmp := make([]byte, 4096)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				p.mu.Lock()
				p.buf.Write(tmp[:n])
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return p
}

func (p *outputPump) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

// waitFor blocks until the output contains want or the timeout expires.
func (p *outputPump) waitFor(t *testing.T, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := p.String()
		if strings.Contains(got, want) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %q; output so far:\n%s", want, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSSHShellRunsTheCLI logs in with the dashboard password, requests a pty
// and checks that the interactive TunGuard CLI — welcome, prompt, commands —
// arrives over the wire, including a jump-host line that names this listener
// instead of a literal ":2222".
func TestSSHShellRunsTheCLI(t *testing.T) {
	a := consoleTestAPI(t)
	addr := sshTestDial(t, a)
	client := sshTestClient(t, addr)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm-256color", 24, 120, ssh.TerminalModes{
		ssh.ECHO: 0, // the CLI echoes itself, raw mode like sshd gives us
	}); err != nil {
		t.Fatalf("pty: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	p := pumpOutput(stdout)

	welcome := p.waitFor(t, "Core engine operational", 5*time.Second)
	if !strings.Contains(welcome, "ssh -J admin@"+addr) {
		t.Errorf("welcome should offer a usable jump line for %s:\n%s", addr, welcome)
	}
	if !strings.Contains(welcome, "help") {
		t.Errorf("welcome should point at help:\n%s", welcome)
	}

	// A resize request must be accepted while the session runs.
	sess.WindowChange(40, 120)

	// Type a command: the line is echoed, then the help table streams back.
	if _, err := io.WriteString(stdin, "help\r"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := p.waitFor(t, "Tab completes commands", 5*time.Second)
	if !strings.Contains(got, "ping") || !strings.Contains(got, "policy") {
		t.Errorf("help output incomplete:\n%s", got)
	}

	// exit ends the session cleanly.
	if _, err := io.WriteString(stdin, "exit\r"); err != nil {
		t.Fatalf("write exit: %v", err)
	}
	p.waitFor(t, "logout", 5*time.Second)

	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Errorf("clean exit should report success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close after exit")
	}
}

// TestSSHExecRunsOneLine covers `ssh host status`: one command, streamed
// output, and an exit status a shell script can branch on.
func TestSSHExecRunsOneLine(t *testing.T) {
	a := consoleTestAPI(t)
	addr := sshTestDial(t, a)
	client := sshTestClient(t, addr)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput("status")
	if err != nil {
		t.Errorf("status should exit 0, got %v (output %q)", err, out)
	}
	if !strings.Contains(string(out), "TunGuard") {
		t.Errorf("exec output missing status body: %q", out)
	}
	if strings.Contains(string(out), "Type help for commands") {
		t.Errorf("exec must not print the interactive welcome: %q", out)
	}

	sess2, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess2.Close()
	out2, err2 := sess2.CombinedOutput("frobnicate")
	if err2 == nil {
		t.Errorf("an unknown command should exit non-zero, got success with %q", out2)
	}
	if !strings.Contains(string(out2), "unknown command") {
		t.Errorf("exec error output missing: %q", out2)
	}
}

// TestSSHRejectsBadPassword keeps the gateway on the dashboard login only.
func TestSSHRejectsBadPassword(t *testing.T) {
	a := consoleTestAPI(t)
	addr := sshTestDial(t, a)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		client.Close()
		t.Fatal("a wrong password must not authenticate")
	}
}
