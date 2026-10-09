package api

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestParseSSHArgs covers the option grammar the CLI advertises in `help ssh`:
// flags in any order, then a [user@]host[:port] target and an optional command.
func TestParseSSHArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want sshTarget
	}{
		{"defaults", []string{"example.com"}, sshTarget{user: "root", port: "22", host: "example.com"}},
		{"user and port", []string{"-l", "alice", "-p", "2222", "example.com"}, sshTarget{user: "alice", port: "2222", host: "example.com"}},
		{"inline user", []string{"bob@host"}, sshTarget{user: "bob", port: "22", host: "host"}},
		{"inline host port", []string{"bob@host:2200"}, sshTarget{user: "bob", port: "2200", host: "host"}},
		{"port equals", []string{"--port=2201", "host"}, sshTarget{user: "root", port: "2201", host: "host"}},
		{"password", []string{"--password", "s3cret", "host"}, sshTarget{user: "root", port: "22", host: "host", password: "s3cret"}},
		{"identity", []string{"-i", "/tmp/k", "host"}, sshTarget{user: "root", port: "22", host: "host", keyFile: "/tmp/k"}},
		{"force pty", []string{"-t", "host"}, sshTarget{user: "root", port: "22", host: "host", forcePTY: true}},
		{"no pty", []string{"-T", "host"}, sshTarget{user: "root", port: "22", host: "host", noPTY: true}},
		{"command", []string{"host", "uname", "-a"}, sshTarget{user: "root", port: "22", host: "host", command: "uname -a"}},
		{"ipv6 port", []string{"[::1]:2202"}, sshTarget{user: "root", port: "2202", host: "::1"}},
		{"double dash", []string{"--", "-weird-host"}, sshTarget{user: "root", port: "22", host: "-weird-host"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSSHArgs(tc.args)
			if err != nil {
				t.Fatalf("parseSSHArgs(%v): %v", tc.args, err)
			}
			if *got != tc.want {
				t.Errorf("parseSSHArgs(%v) = %+v, want %+v", tc.args, *got, tc.want)
			}
		})
	}
}

func TestParseSSHArgsErrors(t *testing.T) {
	if _, err := parseSSHArgs([]string{"-p"}); err == nil {
		t.Error("missing value for -p should error")
	}
	if _, err := parseSSHArgs([]string{"--bogus", "host"}); err == nil {
		t.Error("unknown option should error")
	}
}

// TestSSHCommandReachesGateway types the built-in `ssh` command into a live
// console and confirms it can log into TunGuard's own SSH gateway, run a
// remote command and stream the result back before closing cleanly.
func TestSSHCommandReachesGateway(t *testing.T) {
	a := consoleTestAPI(t)
	addr := sshTestDial(t, a)
	client := sshTestClient(t, addr)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 24, 120, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
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
	p.waitFor(t, "Core engine operational", 5*time.Second)

	line := fmt.Sprintf("ssh --password test-password admin@%s status\r", addr)
	if _, err := io.WriteString(stdin, line); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := p.waitFor(t, "[ssh session closed]", 10*time.Second)
	if !strings.Contains(got, "TunGuard") {
		t.Errorf("remote status output missing from ssh session:\n%s", got)
	}

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
