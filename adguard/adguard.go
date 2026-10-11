package adguard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"runtime"
	"sync"
	"time"

	"tanguard/config"
)

type Manager struct {
	mu     sync.Mutex
	cfg    *config.Config
	cmd    *exec.Cmd
	running bool
}

type adguardConfig struct {
	BindHost       string   `json:"bind_host"`
	BindPort       int      `json:"bind_port"`
	DNS            dnsConf  `json:"dns"`
	Filtering      filterConf `json:"filtering"`
	SchemaVersion  int      `json:"schema_version"`
}

type dnsConf struct {
	BindHosts []string `json:"bind_hosts"`
	Port      int      `json:"port"`
	UpstreamDNS []string `json:"upstream_dns"`
	EnableDNSSEC bool   `json:"enable_dnssec"`
}

type filterConf struct {
	ProtectionEnabled bool `json:"protection_enabled"`
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg}
}

func (m *Manager) binaryPath() string {
	p := m.cfg.AdGuardBinaryPath
	if filepath.IsAbs(p) {
		return p
	}
	// try relative to cwd or data dir
	cands := []string{p, filepath.Join(m.cfg.AdGuardDataDir, p), filepath.Join(".", p)}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
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

func (m *Manager) ensureConfig() error {
	cp := m.configPath()
	if st, err := os.Stat(cp); err == nil && !st.IsDir() {
		// already exists - could update, but keep simple
		return nil
	}
	host, port, err := parseListen(m.cfg.AdGuardWebListen)
	if err != nil {
		return err
	}
	dnsHost, dnsPort, err := parseListen(m.cfg.AdGuardDNSListen)
	if err != nil {
		return err
	}
	upstreams := []string{m.cfg.AdGuardUpstream}
	if m.cfg.AdGuardFilterAdult && m.cfg.AdGuardUpstreamFamily != "" {
		upstreams = []string{m.cfg.AdGuardUpstreamFamily}
	}
	cfg := adguardConfig{
		BindHost:      host,
		BindPort:      port,
		SchemaVersion: 27,
		DNS: dnsConf{
			BindHosts: []string{dnsHost},
			Port:      dnsPort,
			UpstreamDNS: upstreams,
			EnableDNSSEC: false,
		},
		Filtering: filterConf{ProtectionEnabled: true},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
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
	if err := m.ensureConfig(); err != nil {
		return err
	}
	wd := filepath.Dir(m.configPath())
	if wd == "" {
		wd = "."
	}
	m.cmd = exec.Command(bin, "--no-check-update", "-c", m.configPath(), "-w", wd)
	m.cmd.Dir = wd
	if err := m.cmd.Start(); err != nil {
		return err
	}
	m.running = true
	go func() {
		_ = m.cmd.Wait()
		m.mu.Lock()
		m.running = false
		m.cmd = nil
		m.mu.Unlock()
	}()
	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	m.running = false
	m.cmd = nil
	return nil
}

func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *Manager) DNSForGroup(groupAllows bool) string {
	if !m.cfg.AdGuardEnabled || !groupAllows {
		return ""
	}
	if _, _, err := netSplit(m.cfg.AdGuardDNSListen); err == nil {
		// return just host:port
		return m.cfg.AdGuardDNSListen
	}
	return ""
}

func (m *Manager) WebAddr() string {
	if m.cfg.AdGuardWebListen == "" {
		return "127.0.0.1:1116"
	}
	return m.cfg.AdGuardWebListen
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
	if st, err := os.Stat(target); err == nil && !st.IsDir() {
		return target, nil
	}
	// download for current arch
	arch := aghArch()
	url := "https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.61/AdGuardHome_linux_" + arch + ".tar.gz"
	client := &http.Client{Timeout: 60*time.Second}
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
