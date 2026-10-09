package api

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshTarget is one parsed `ssh` invocation. The CLI's ssh is a small, focused
// client: it carries the options an operator actually reaches for, not the
// whole of OpenSSH's surface.
type sshTarget struct {
	user     string
	host     string
	port     string
	keyFile  string
	password string
	forcePTY bool
	noPTY    bool
	command  string
	signer   ssh.Signer
}

// parseSSHArgs reads `ssh [-p port] [-l user] [-i key] [--password pass] [-t|-T]
// [user@]host[:port] [command...]`. Option parsing stops at the first
// positional, because in ssh everything after the host is the remote command.
func parseSSHArgs(args []string) (*sshTarget, error) {
	t := &sshTarget{user: "root", port: "22"}
	need := func(i *int, flag string) (string, error) {
		*i++
		if *i >= len(args) {
			return "", fmt.Errorf("%s needs a value", flag)
		}
		return args[*i], nil
	}
	i := 0
	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "-p" || arg == "--port":
			v, err := need(&i, arg)
			if err != nil {
				return nil, err
			}
			t.port = v
		case strings.HasPrefix(arg, "--port="):
			t.port = strings.TrimPrefix(arg, "--port=")
		case arg == "-l" || arg == "--user" || arg == "--login":
			v, err := need(&i, arg)
			if err != nil {
				return nil, err
			}
			t.user = v
		case arg == "-i" || arg == "--identity" || arg == "--key":
			v, err := need(&i, arg)
			if err != nil {
				return nil, err
			}
			t.keyFile = v
		case arg == "--password":
			v, err := need(&i, arg)
			if err != nil {
				return nil, err
			}
			t.password = v
		case arg == "-o": // accept and ignore, the way scripts pass -o options
			if _, err := need(&i, arg); err != nil {
				return nil, err
			}
		case arg == "-t":
			t.forcePTY = true
		case arg == "-T" || arg == "-n":
			t.noPTY = true
		case arg == "-v" || arg == "--verbose":
			// verbose is accepted for muscle memory; there is nothing to print
		case arg == "--":
			i++
			return t.finish(args[i:])
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			return nil, fmt.Errorf("unknown option %q — try `help ssh`", arg)
		default:
			return t.finish(args[i:])
		}
		i++
	}
	return t, nil
}

// finish parses the positional part: the target, then an optional command.
func (t *sshTarget) finish(pos []string) (*sshTarget, error) {
	if len(pos) == 0 {
		return t, nil
	}
	target := pos[0]
	if at := strings.LastIndex(target, "@"); at >= 0 {
		t.user = target[:at]
		target = target[at+1:]
	}
	switch {
	case strings.HasPrefix(target, "["): // [ipv6]:port
		end := strings.Index(target, "]")
		if end < 0 {
			return nil, fmt.Errorf("invalid host %q", target)
		}
		t.host = target[1:end]
		if rest := target[end+1:]; strings.HasPrefix(rest, ":") {
			t.port = rest[1:]
		}
	case strings.Count(target, ":") == 1: // host:port (a bare IPv6 has more)
		idx := strings.LastIndex(target, ":")
		t.host = target[:idx]
		t.port = target[idx+1:]
	default:
		t.host = target
	}
	if len(pos) > 1 {
		t.command = strings.Join(pos[1:], " ")
	}
	return t, nil
}

// loadSigner reads a private key from disk. It accepts what OpenSSH writes
// (PEM or the newer OpenSSH format) but not agent-held keys.
func loadSigner(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// authMethods assembles the authentication attempts, key first. An explicit
// identity is used as given; otherwise the operator's default keys are tried,
// and a password is always appended unless a key-only session was requested.
func (t *sshTarget) authMethods() []ssh.AuthMethod {
	var methods []ssh.AuthMethod
	if t.signer != nil {
		methods = append(methods, ssh.PublicKeys(t.signer))
	} else if t.keyFile == "" {
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			home, err := os.UserHomeDir()
			if err != nil {
				break
			}
			if signer, err := loadSigner(filepath.Join(home, ".ssh", name)); err == nil {
				methods = append(methods, ssh.PublicKeys(signer))
			}
		}
	}
	if t.password != "" || t.keyFile == "" {
		methods = append(methods, ssh.Password(t.password))
	}
	return methods
}

// cmdSSH is the entry point from the command table. Without a key or a
// password it asks for the password first — the same one-shot question the
// `password` command uses — and connects from the answer's callback.
func cmdSSH(s *consoleSession, args []string) {
	t, err := parseSSHArgs(args)
	if err != nil {
		s.errf("%s", err)
		return
	}
	if t.host == "" {
		s.errf("usage: %s", lookupCommand("ssh").usage)
		return
	}

	// A WireGuard peer's name or address is the natural way to name a device.
	if rec, err := s.api.resolvePeer(t.host); err == nil {
		t.host = strings.TrimSuffix(rec.AllowedIP, "/32")
	}

	if t.keyFile != "" {
		signer, err := loadSigner(t.keyFile)
		if err != nil {
			s.errf("identity %s: %s", t.keyFile, err)
			return
		}
		t.signer = signer
	}

	if t.signer == nil && t.password == "" {
		prompt := fmt.Sprintf("Password for %s@%s: ", t.user, t.host)
		s.ask(prompt, true, func(pw string) {
			t.password = pw
			s.dialSSH(t)
		})
		return
	}
	s.dialSSH(t)
}

// sshInput is the live stdin of a remote session. The console's input loop and
// the connection's teardown run on different goroutines, so both the writer
// and the close are guarded.
type sshInput struct {
	mu     sync.Mutex
	w      io.WriteCloser
	closed bool
}

func (h *sshInput) write(p []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.w == nil {
		return
	}
	h.w.Write(p)
}

func (h *sshInput) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	if h.w != nil {
		h.w.Close()
	}
}

// dialSSH connects and installs the session as an interactive foreground job.
// An interactive shell is requested with a PTY; `ssh host command` runs one
// remote command and streams its output, no PTY unless -t was given.
func (s *consoleSession) dialSSH(t *sshTarget) {
	addr := net.JoinHostPort(t.host, t.port)
	s.printf("\x1b[2mconnecting to %s@%s…\x1b[0m\r\n", t.user, addr)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            t.user,
		Auth:            t.authMethods(),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		s.errf("ssh %s: %s", addr, err)
		return
	}

	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		s.errf("ssh session: %s", err)
		return
	}

	interactive := t.command == ""
	if (!t.noPTY && interactive) || t.forcePTY {
		cols, rows := s.size()
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
			sess.Close()
			client.Close()
			s.errf("request pty: %s", err)
			return
		}
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		client.Close()
		s.errf("ssh stdin: %s", err)
		return
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		client.Close()
		s.errf("ssh stdout: %s", err)
		return
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		sess.Close()
		client.Close()
		s.errf("ssh stderr: %s", err)
		return
	}

	if err := sess.Start(t.command); err != nil {
		sess.Close()
		client.Close()
		s.errf("start remote: %s", err)
		return
	}

	in := &sshInput{w: stdin}
	stop := func() {
		in.close()
		sess.Close()
		client.Close()
	}

	out := &crlfWriter{s: s}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(out, stdout) }()
	go func() { defer wg.Done(); io.Copy(out, stderr) }()

	if interactive {
		s.printf("\x1b[2m[connected — Ctrl-] detaches, `exit` on the remote leaves]\x1b[0m\r\n")
	}

	s.startInteractiveJob(stop, in.write, func() {
		waitErr := sess.Wait()
		wg.Wait()
		in.close()
		client.Close()

		if t.command != "" {
			if exitErr, ok := waitErr.(*ssh.ExitError); ok {
				s.exitCode = exitErr.ExitStatus()
				s.printf("\x1b[2mremote exit status %d\x1b[0m\r\n", exitErr.ExitStatus())
			} else if waitErr != nil {
				s.errf("ssh: %s", waitErr)
			}
		}
		s.printf("\x1b[2m[ssh session closed]\x1b[0m\r\n")
	})
}
