package adguard

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	"tanguard/config"
)

type Manager struct {
	mu      sync.Mutex
	cfg     *config.Config
	cmd     *exec.Cmd
	done    chan struct{}
	running bool

	// adminUser/adminHash mirror the TunGuard dashboard login onto the AdGuard
	// web UI so it is never left without authentication.
	adminUser string
	adminHash string
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg}
}

// SetAuth records the login the AdGuard UI must require. The hash is a bcrypt
// hash (as stored for the dashboard); the plaintext is never needed.
func (m *Manager) SetAuth(user, hash string) {
	m.mu.Lock()
	m.adminUser = user
	m.adminHash = hash
	m.mu.Unlock()
}

// loopbackWebAddr forces the AdGuard admin UI onto loopback and keeps only the
// configured port. The UI is reached through TunGuard's authenticated reverse
// proxy, so the port itself must never be exposed to the network.
func (m *Manager) loopbackWebAddr() string {
	_, port, err := parseListen(m.cfg.AdGuardWebListen)
	if err != nil || port == 0 {
		return "127.0.0.1:1116"
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func (m *Manager) binaryPath() string {
	p := m.cfg.AdGuardBinaryPath
	if filepath.IsAbs(p) {
		return p
	}
	// try relative to cwd, data dir, and executable directory
	cands := []string{p, filepath.Join(m.cfg.AdGuardDataDir, p), filepath.Join(".", p)}
	// also try relative to the running binary's dir
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(exe), p))
		cands = append(cands, filepath.Join(filepath.Dir(exe), filepath.Base(p)))
	}
	// also try common names
	cands = append(cands, "adguardhome")
	cands = append(cands, filepath.Join(m.cfg.AdGuardDataDir, "adguardhome"))
	// also try dirs near binary
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands, filepath.Join(dir, "adguardhome"))
		cands = append(cands, filepath.Join(filepath.Dir(dir), "adguardhome"))
	}
	cands = append(cands, "/usr/local/bin/adguardhome", "/usr/bin/adguardhome")
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			// Return an absolute path: exec.Command resolves a bare name
			// through $PATH, so a file found in the working directory would
			// still fail to launch otherwise.
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
			return c
		}
	}
	// Nothing on disk: fall back to the configured name. ensureBinary will
	// download an absolute path into the data dir.
	return p
}

func (m *Manager) configPath() string {
	return filepath.Join(m.cfg.AdGuardDataDir, "AdGuardHome.yaml")
}

func parseListen(addr string) (host string, port int, err error) {
	h, pstr, err := netSplit(addr)
	if err != nil {
		return "", 0, err
	}
	var p int
	_, _ = fmt.Sscanf(pstr, "%d", &p)
	return h, p, nil
}

func netSplit(a string) (string, string, error) {
	if a == "" {
		return "", "", fmt.Errorf("empty")
	}
	// simple split
	if strings.HasPrefix(a, "[") {
		// ipv6
		end := strings.Index(a, "]:")
		if end > 0 {
			return a[1:end], a[end+2:], nil
		}
	}
	i := strings.LastIndex(a, ":")
	if i < 0 {
		return a, "", fmt.Errorf("no port")
	}
	return a[:i], a[i+1:], nil
}

// ensureConfig writes the AdGuardHome.yaml AdGuard needs to run, and re-applies
// the two things this server owns: the admin login (mirrored from the dashboard)
// and the loopback-only web address. Everything else in an existing file is
// preserved, because AdGuard rewrites this file itself as settings change.
func (m *Manager) ensureConfig() error {
	cp := m.configPath()

	var doc map[string]interface{}
	if data, err := os.ReadFile(cp); err == nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			// An unreadable config must not silently become an anonymous one.
			return fmt.Errorf("parse %s: %w", cp, err)
		}
	}
	if doc == nil {
		doc = map[string]interface{}{}
	}

	// AdGuard Home v0.107+ uses the structured config with an 'http' block;
	// 'address' is the current field name (not bind_host/bind_port).
	httpBlock, _ := doc["http"].(map[string]interface{})
	if httpBlock == nil {
		httpBlock = map[string]interface{}{}
	}
	httpBlock["address"] = m.loopbackWebAddr()
	doc["http"] = httpBlock

	// The DNS listener is owned by this server too: it must sit on the tunnel
	// address clients are handed, so re-apply host and port on every start.
	// Everything else in the dns block (upstreams, blocklists, cache) is
	// preserved because AdGuard manages it.
	dnsBlock, _ := doc["dns"].(map[string]interface{})
	if dnsBlock == nil {
		dnsBlock = map[string]interface{}{}
	}
	dnsHost, dnsPort, err := parseListen(m.bindAddr())
	if err != nil {
		return err
	}
	dnsBlock["bind_hosts"] = []interface{}{dnsHost}
	dnsBlock["port"] = dnsPort
	if _, ok := dnsBlock["upstream_dns"]; !ok {
		upstreams := []string{m.cfg.AdGuardUpstream}
		if m.cfg.AdGuardFilterAdult && m.cfg.AdGuardUpstreamFamily != "" {
			upstreams = []string{m.cfg.AdGuardUpstreamFamily}
		}
		dnsBlock["upstream_dns"] = upstreams
	}
	if _, ok := dnsBlock["enable_dnssec"]; !ok {
		dnsBlock["enable_dnssec"] = false
	}
	doc["dns"] = dnsBlock
	if _, ok := doc["filtering"]; !ok {
		doc["filtering"] = map[string]interface{}{"protection_enabled": true}
	}
	if _, ok := doc["schema_version"]; !ok {
		doc["schema_version"] = 27
	}

	// Mirror the dashboard login so the UI can never be reached without it.
	// Any other AdGuard user accounts are kept, with the managed one first.
	if m.adminHash != "" {
		users := []interface{}{map[string]interface{}{
			"name":     m.adminUser,
			"password": m.adminHash,
		}}
		if existing, ok := doc["users"].([]interface{}); ok {
			for _, u := range existing {
				um, ok := u.(map[string]interface{})
				if ok && um["name"] == m.adminUser {
					continue
				}
				users = append(users, u)
			}
		}
		doc["users"] = users
	}

	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cp), 0755); err != nil {
		return err
	}
	return os.WriteFile(cp, data, 0644)
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
	}
	bin, err := m.ensureBinary()
	if err != nil {
		return fmt.Errorf("adguardhome binary not available: %w", err)
	}
	// exec.Command looks a bare name up in $PATH, so always launch an
	// absolute path — otherwise a binary sitting next to this process (or in
	// the data dir) is found but never runs.
	if !filepath.IsAbs(bin) {
		if abs, aerr := filepath.Abs(bin); aerr == nil {
			bin = abs
		}
	}
	if err := m.ensureConfig(); err != nil {
		return err
	}
	cp := m.configPath()
	if abs, aerr := filepath.Abs(cp); aerr == nil {
		cp = abs
	}
	wd := filepath.Dir(cp)
	if wd == "" {
		wd = "."
	}
	cmd := exec.Command(bin, "--no-check-update", "-c", cp, "-w", wd)
	cmd.Dir = wd
	if err := cmd.Start(); err != nil {
		return err
	}
	m.cmd = cmd
	m.running = true
	done := make(chan struct{})
	m.done = done
	// The watcher must only clear state for the process it started: after a
	// restart the previous process exits and would otherwise clobber the new
	// one, reporting a running server as stopped.
	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.running = false
			m.cmd = nil
		}
		m.mu.Unlock()
		close(done)
	}()
	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	done := m.done
	m.cmd = nil
	m.running = false
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Kill()
	// Wait for the process to actually exit so a following Start can rebind
	// the port without racing the dying instance.
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}

// Restart stops and starts AdGuard so it re-reads AdGuardHome.yaml. It is used
// when the dashboard login changes, because AdGuard only reads the admin users
// at startup.
func (m *Manager) Restart() error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start()
}

func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// bindAddr is the address AdGuard's DNS actually binds. The configured listen
// points at the server's tunnel address so clients can reach the filter; when
// that address is not present on this host (for example mesh-only mode, where
// WireGuard is not running) it falls back to loopback so the filter still
// starts instead of exiting on a bind error.
func (m *Manager) bindAddr() string {
	host, port, err := parseListen(m.cfg.AdGuardDNSListen)
	if err != nil || port == 0 {
		return m.cfg.AdGuardDNSListen
	}
	if host == "" || host == "0.0.0.0" || host == "::" || isLocalIP(host) {
		return m.cfg.AdGuardDNSListen
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// isLocalIP reports whether host names an address assigned to this machine.
// A non-literal host is left alone: AdGuard gets to resolve it.
func isLocalIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// DNSForGroup returns the DNS server to put in a client's WireGuard profile
// when its group uses AdGuard. The port is omitted on the standard DNS port,
// because WireGuard clients expect a bare address there.
func (m *Manager) DNSForGroup(groupAllows bool) string {
	if !m.cfg.AdGuardEnabled || !groupAllows {
		return ""
	}
	host, port, err := parseListen(m.cfg.AdGuardDNSListen)
	if err != nil || host == "" {
		return ""
	}
	if port == 0 || port == 53 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// DNSTarget is the address the tunnel DNS redirect should forward port-53
// queries to. It mirrors what AdGuard actually binds so a redirected query
// always reaches the listener; empty when AdGuard is disabled.
func (m *Manager) DNSTarget() string {
	if !m.cfg.AdGuardEnabled {
		return ""
	}
	return m.bindAddr()
}

// WebAddr is the loopback address the AdGuard UI is actually bound to. Remote
// access goes through the authenticated /adguard-ui/ proxy, never this port.
func (m *Manager) WebAddr() string {
	return m.loopbackWebAddr()
}

func (m *Manager) ensureBinary() (string, error) {
	bin := m.binaryPath()
	if st, err := os.Stat(bin); err == nil && !st.IsDir() {
		if err := os.Chmod(bin, 0755); err == nil {
		}
		return bin, nil
	}
	// try to download to data dir if configured
	target := filepath.Join(m.cfg.AdGuardDataDir, "adguardhome")
	if abs, err := filepath.Abs(target); err == nil {
		target = abs
	}
	if st, err := os.Stat(target); err == nil && !st.IsDir() {
		return target, nil
	}
	// try to copy from binary directory if it exists there
	if exe, err := os.Executable(); err == nil {
		srcCand := filepath.Join(filepath.Dir(exe), "adguardhome")
		if st, err2 := os.Stat(srcCand); err2 == nil && !st.IsDir() {
			_ = os.MkdirAll(filepath.Dir(target), 0755)
			if err3 := copyFile(srcCand, target); err3 == nil {
				_ = os.Chmod(target, 0755)
				return target, nil
			}
		}
	}
	// try current working directory
	if st, err := os.Stat("adguardhome"); err == nil && !st.IsDir() {
		_ = os.MkdirAll(filepath.Dir(target), 0755)
		if err3 := copyFile("adguardhome", target); err3 == nil {
			_ = os.Chmod(target, 0755)
			return target, nil
		}
	}
	// download for current arch
	arch := aghArch()
	url := "https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.61/AdGuardHome_linux_" + arch + ".tar.gz"
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return bin, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return bin, fmt.Errorf("download failed: %s", resp.Status)
	}
	defer resp.Body.Close()
	// save tar.gz
	tgz := target + ".tar.gz"
	f, err := os.Create(tgz)
	if err != nil {
		return bin, err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return bin, err
	}
	f.Close()
	// extract
	cmd := exec.Command("tar", "-xzf", tgz, "-C", m.cfg.AdGuardDataDir)
	if err := cmd.Run(); err != nil {
		return "", err
	}
	// move
	src := filepath.Join(m.cfg.AdGuardDataDir, "AdGuardHome", "AdGuardHome")
	if err := os.Rename(src, target); err != nil {
		// try copy
		if err2 := copyFile(src, target); err2 != nil {
			return bin, err
		}
	}
	os.Chmod(target, 0755)
	os.Remove(tgz)
	os.RemoveAll(filepath.Join(m.cfg.AdGuardDataDir, "AdGuardHome"))
	return target, nil
}

func aghArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "arm":
		// GOARM may not be defined in some builds; default to armv7
		return "armv7"
	case "386":
		return "386"
	default:
		return "amd64"
	}
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()
	_, err = io.Copy(d, s)
	return err
}
