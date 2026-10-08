package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"tanguard/auth"
	"tanguard/config"
)

type SSHGateway struct {
	cfg    *config.Config
	creds  *auth.CredentialStore
	api    *API // the CLI sessions run against this server's state
	signer ssh.Signer
}

func NewSSHGateway(cfg *config.Config, creds *auth.CredentialStore, apiSrv *API) (*SSHGateway, error) {
	signer, err := loadOrGenerateHostKey(cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh host key: %w", err)
	}
	return &SSHGateway{cfg: cfg, creds: creds, api: apiSrv, signer: signer}, nil
}

func loadOrGenerateHostKey(cfg *config.Config) (ssh.Signer, error) {
	keyPath := cfg.SSHKeyFile
	if keyPath == "" {
		keyPath = filepath.Join(cfg.DataDir, "ssh_host_key")
	}
	if data, err := os.ReadFile(keyPath); err == nil {
		return ssh.ParsePrivateKey(data)
	}

	log.Printf("[ssh] generating ed25519 host key...")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	privPEM := marshalED25519PrivateKey(priv)
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("save host key: %w", err)
	}
	log.Printf("[ssh] host key saved to %s", keyPath)
	return ssh.NewSignerFromKey(priv)
}

func marshalED25519PrivateKey(priv ed25519.PrivateKey) []byte {
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
}

// validCredentials authenticates against the same login the web dashboard
// uses, so changing the dashboard password immediately applies to SSH access.
func (g *SSHGateway) validCredentials(user, pass string) bool {
	return g.creds.VerifyWeb(user, pass, g.cfg.WebUsername, g.cfg.WebPassword)
}

func (g *SSHGateway) Start() {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if g.validCredentials(c.User(), string(pass)) {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %s", c.User())
		},
	}
	config.AddHostKey(g.signer)

	listener, err := net.Listen("tcp", g.cfg.SSHListen)
	if err != nil {
		log.Printf("[ssh] failed to listen on %s: %v", g.cfg.SSHListen, err)
		return
	}
	log.Printf("[ssh] SSH gateway listening on %s", g.cfg.SSHListen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ssh] accept: %v", err)
			continue
		}
		go g.handleConn(conn, config)
	}
}

func (g *SSHGateway) handleConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("[ssh] handshake failed: %v", err)
		return
	}
	log.Printf("[ssh] connection from %s as %s", sConn.RemoteAddr(), sConn.User())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() == "direct-tcpip" {
			go g.handleDirectTCPIP(newChannel)
		} else if newChannel.ChannelType() == "session" {
			go g.handleSessionChannel(newChannel, sConn.User())
		} else {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

func (g *SSHGateway) handleDirectTCPIP(newChannel ssh.NewChannel) {
	payload := newChannel.ExtraData()
	host, port := parseDirectTCPIPPayload(payload)
	target := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))

	channel, reqs, err := newChannel.Accept()
	if err != nil {
		log.Printf("[ssh] direct-tcpip accept: %v", err)
		return
	}
	go ssh.DiscardRequests(reqs)

	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[ssh] direct-tcpip dial %s: %v", target, err)
		channel.Close()
		return
	}

	log.Printf("[ssh] proxying direct-tcpip %s", target)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(channel, remote); channel.CloseWrite(); wg.Done() }()
	go func() { io.Copy(remote, channel); remote.Close(); wg.Done() }()
	wg.Wait()
	channel.Close()
	remote.Close()
}

// sshPTYRequest is the payload of RFC 4254 "pty-req".
type sshPTYRequest struct {
	Term   string
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
	Modes  string
}

// sshWindowChange is the payload of "window-change" (no term string).
type sshWindowChange struct {
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
}

// sshExecRequest is the payload of "exec": one command line.
type sshExecRequest struct {
	Command string
}

// handleSessionChannel runs the TunGuard CLI over an SSH session channel.
// pty-req and window-change drive the terminal size, shell runs the
// interactive session, exec runs a single line — so `ssh host status` works
// from a script and `ssh host` drops into the same CLI the dashboard's
// Terminal window shows.
func (g *SSHGateway) handleSessionChannel(newChannel ssh.NewChannel, user string) {
	channel, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	// The session exists before any request arrives so pty-req and
	// window-change can size it while Run is going.
	sess := newConsoleSession(g.api, user, channel, channel)
	defer sess.Close()

	type startSpec struct{ exec string }
	start := make(chan startSpec, 1)

	go func() {
		defer close(start)
		for req := range reqs {
			switch req.Type {
			case "pty-req":
				var p sshPTYRequest
				if err := ssh.Unmarshal(req.Payload, &p); err == nil {
					sess.SetCols(int(p.Cols))
				}
				req.Reply(true, nil)
			case "window-change":
				var w sshWindowChange
				if err := ssh.Unmarshal(req.Payload, &w); err == nil {
					sess.SetCols(int(w.Cols))
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "env":
				req.Reply(true, nil) // LANG and friends: accepted, not acted on
			case "shell":
				req.Reply(true, nil)
				select {
				case start <- startSpec{}:
				default:
				}
			case "exec":
				var e sshExecRequest
				ssh.Unmarshal(req.Payload, &e)
				req.Reply(true, nil)
				select {
				case start <- startSpec{exec: strings.TrimSpace(e.Command)}:
				default:
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	spec, ok := <-start
	if !ok {
		return // connection dropped before a command arrived
	}

	status := uint32(0)
	if spec.exec != "" {
		sess.Exec(spec.exec)
	} else if err := sess.Run(); err != nil {
		log.Printf("[ssh] session %s: %v", user, err)
		status = 1
	}
	if sess.exitCode != 0 {
		status = uint32(sess.exitCode)
	}
	channel.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{status}))
}

func parseDirectTCPIPPayload(payload []byte) (host string, port uint32) {
	if len(payload) < 4 {
		return "", 0
	}
	hostLen := binary.BigEndian.Uint32(payload[:4])
	if len(payload) < int(4+hostLen) {
		return "", 0
	}
	host = string(payload[4 : 4+hostLen])
	rest := payload[4+hostLen:]
	if len(rest) < 4 {
		return host, 0
	}
	port = binary.BigEndian.Uint32(rest[:4])
	return host, port
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type wsSSHMsg struct {
	Type     string `json:"type"`
	Target   string `json:"target,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Data     string `json:"data,omitempty"`
	Message  string `json:"message,omitempty"`
	Cols     int    `json:"cols,omitempty"`
	Rows     int    `json:"rows,omitempty"`
}

func (a *API) handleWebSSH(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[webssh] upgrade: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(64 * 1024)

	var writeMu sync.Mutex
	wsWrite := func(msg wsSSHMsg) {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.WriteJSON(msg)
	}

	var target, sshUser, sshPass string
	var session *ssh.Session
	var stdin io.WriteCloser
	var sshClient *ssh.Client

	defer func() {
		if session != nil {
			session.Close()
		}
		if sshClient != nil {
			sshClient.Close()
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var msg wsSSHMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "":
			if msg.Target != "" {
				target = msg.Target
				sshUser = msg.Username
				sshPass = msg.Password

				if sshUser == "" || sshPass == "" {
					wsWrite(wsSSHMsg{Type: "auth"})
					continue
				}

				if err := a.startSSHSession(conn, target, sshUser, sshPass, &session, &stdin, &sshClient, &writeMu); err != nil {
					wsWrite(wsSSHMsg{Type: "error", Message: err.Error()})
					wsWrite(wsSSHMsg{Type: "closed"})
					return
				}
			}

		case "auth":
			if msg.Username != "" {
				sshUser = msg.Username
			}
			if msg.Password != "" {
				sshPass = msg.Password
			}
			if sshUser != "" && sshPass != "" && target != "" {
				if err := a.startSSHSession(conn, target, sshUser, sshPass, &session, &stdin, &sshClient, &writeMu); err != nil {
					wsWrite(wsSSHMsg{Type: "error", Message: err.Error()})
					wsWrite(wsSSHMsg{Type: "closed"})
					return
				}
			}

		case "input":
			if stdin != nil {
				stdin.Write([]byte(msg.Data))
			}

		case "resize":
			if session != nil && msg.Cols > 0 && msg.Rows > 0 {
				session.WindowChange(msg.Rows, msg.Cols)
			}
		}
	}
}

func (a *API) startSSHSession(ws *websocket.Conn, target, user, pass string, session **ssh.Session, stdin *io.WriteCloser, sshClient **ssh.Client, writeMu *sync.Mutex) error {
	wsWrite := func(msg wsSSHMsg) {
		writeMu.Lock()
		defer writeMu.Unlock()
		ws.WriteJSON(msg)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", target, config)
	if err != nil {
		return fmt.Errorf("SSH dial %s: %w", target, err)
	}

	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return fmt.Errorf("SSH session: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty("xterm-256color", 80, 24, modes); err != nil {
		sess.Close()
		client.Close()
		return fmt.Errorf("SSH pty: %w", err)
	}

	wStdin, _ := sess.StdinPipe()
	wStdout, _ := sess.StdoutPipe()
	wStderr, _ := sess.StderrPipe()

	if err := sess.Shell(); err != nil {
		wStdin.Close()
		sess.Close()
		client.Close()
		return fmt.Errorf("SSH shell: %w", err)
	}

	if *session != nil {
		(*session).Close()
		*session = nil
	}
	if *stdin != nil {
		(*stdin).Close()
		*stdin = nil
	}
	if *sshClient != nil {
		(*sshClient).Close()
		*sshClient = nil
	}

	*stdin = wStdin
	*session = sess
	*sshClient = client

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := wStdout.Read(buf)
			if err != nil {
				break
			}
			wsWrite(wsSSHMsg{Type: "output", Data: string(buf[:n])})
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := wStderr.Read(buf)
			if err != nil {
				break
			}
			wsWrite(wsSSHMsg{Type: "output", Data: string(buf[:n])})
		}
	}()

	go func() {
		sess.Wait()
		wsWrite(wsSSHMsg{Type: "closed"})
		client.Close()
	}()

	return nil
}
