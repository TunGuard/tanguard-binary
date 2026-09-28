package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DDNSClient talks to the tunguard-ddns Cloudflare Worker.
// Flow:
//  1. Login with the user's DDNS email/password -> session token.
//  2. Register this binary -> worker detects this server's public IP and
//     maps the user's claimed subdomain to it (A record). Worker returns a
//     long-lived ddns_token + the assigned subdomain + billing info.
//  3. Every DDNSUpdateInterval the binary pushes its current IP so the record
//     stays fresh (also covers the "server got a new IP" case).
//  4. Once per day the binary uploads an encrypted full-config backup.
//  5. On first run after a migration, the binary pulls the latest backup and
//     restores it so state moves to the new server without downtime.
type DDNSClient struct {
	cfg        *Config
	mu         sync.Mutex
	baseURL    string
	token      string
	ddnsToken  string
	binaryID   string
	subdomain  string
	billing    string
	currentIP  string
	lastUpdate time.Time
	lastBackup time.Time
	enabled    bool
	errored    bool
	restored   bool
	status     string
}

type ddnsState struct {
	Email     string `json:"email"`
	BinaryID  string `json:"binary_id"`
	Session   string `json:"session_token,omitempty"`
	DDNSToken string `json:"ddns_token,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	CurrentIP string `json:"current_ip,omitempty"`
	Restored  bool   `json:"restored,omitempty"`
}

type ddnsRegisterResp struct {
	Linked    bool   `json:"linked"`
	BinaryID  string `json:"binary_id"`
	CurrentIP string `json:"current_ip"`
	Remapped  bool   `json:"remapped"`
	DDNSToken string `json:"ddns_token"`
	Subdomain *struct {
		ID       string `json:"id"`
		FullName string `json:"full_name"`
		Status   string `json:"status"`
	} `json:"subdomain"`
}

func NewDDNSClient(cfg *Config) *DDNSClient {
	c := &DDNSClient{
		cfg:      cfg,
		baseURL:  strings.TrimRight(cfg.DDNSBaseURL, "/"),
		binaryID: cfg.DDNSBinaryID,
	}
	if c.binaryID == "" {
		// Stable per-install ID so the worker can tell "same server" from "new server".
		c.binaryID = defaultBinaryID(cfg)
	}
	c.enabled = cfg.DDNSEnabled
	return c
}

func defaultBinaryID(cfg *Config) string {
	host, _ := os.Hostname()
	if host != "" {
		return host
	}
	return "default-server"
}

// stateFile returns the JSON used to persist DDNS session state.
func (c *DDNSClient) statePath() string {
	return filepath.Join(c.cfg.DataDir, "ddns_state.json")
}

func (c *DDNSClient) loadState() {
	data, err := os.ReadFile(c.statePath())
	if err != nil {
		return
	}
	var s ddnsState
	if json.Unmarshal(data, &s) != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = s.Session
	c.ddnsToken = s.DDNSToken
	c.subdomain = s.Subdomain
	c.currentIP = s.CurrentIP
	c.binaryID = s.BinaryID
	c.restored = s.Restored
}

func (c *DDNSClient) saveState() {
	c.mu.Lock()
	s := ddnsState{
		Email:     c.cfg.DDNSEmail,
		BinaryID:  c.binaryID,
		Session:   c.token,
		DDNSToken: c.ddnsToken,
		Subdomain: c.subdomain,
		CurrentIP: c.currentIP,
		Restored:  c.restored,
	}
	c.mu.Unlock()
	data, _ := json.MarshalIndent(s, "", "  ")
	if err := writeFile(c.statePath(), data, 0600); err != nil {
		log.Printf("[ddns] WARNING: could not save state: %v", err)
	}
}

// Start runs the DDNS loop in the background.
func (c *DDNSClient) Start() {
	if !c.enabled {
		log.Printf("[ddns] disabled (set DDNS_ENABLED=true to link this server to a DDNS subdomain)")
		return
	}
	if c.cfg.DDNSEmail == "" || c.cfg.DDNSPassword == "" {
		log.Printf("[ddns] WARNING: enabled but DDNS_EMAIL/DDNS_PASSWORD not set; DDNS inactive")
		c.status = "not-configured"
		return
	}
	c.loadState()
	log.Printf("[ddns] starting with binary_id=%s base=%s", c.binaryID, c.baseURL)

	// Register (or re-register) this binary immediately. On a new server the
	// worker detects the new public IP and re-maps the subdomain -> zero-downtime.
	if err := c.register(); err != nil {
		log.Printf("[ddns] WARNING: register failed: %v", err)
		c.status = "register-failed"
	} else {
		c.status = "active"
	}

	go c.loop()
}

func (c *DDNSClient) loop() {
	ipTicker := time.NewTicker(time.Duration(c.cfg.DDNSUpdateInterval) * time.Second)
	defer ipTicker.Stop()
	backupTicker := time.NewTicker(24 * time.Hour)
	defer backupTicker.Stop()

	// First backup shortly after startup if we haven't today.
	time.AfterFunc(90*time.Second, func() {
		if c.enabled {
			c.uploadBackupOnce()
		}
	})

	for {
		select {
		case <-ipTicker.C:
			if err := c.pushIP(); err != nil {
				log.Printf("[ddns] IP push failed: %v", err)
				c.errored = true
			}
		case <-backupTicker.C:
			c.uploadBackupOnce()
		}
	}
}

// register logs in (if needed) and registers this binary against the worker.
func (c *DDNSClient) register() error {
	c.mu.Lock()
	session := c.token
	c.mu.Unlock()

	if session == "" {
		tok, err := c.login()
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.token = tok
		c.mu.Unlock()
		c.saveState()
	}

	ip, err := publicIP()
	if err != nil {
		log.Printf("[ddns] WARNING: could not detect public IP at register time: %v", err)
	}

	// Register the binary: the worker maps our (new) IP onto the subdomain.
	body, _ := json.Marshal(map[string]string{
		"binary_id":   c.binaryID,
		"name":        c.binaryID,
		"ip":          ip,
	})
	req, err := http.NewRequest("POST", c.baseURL+"/api/binary/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("register returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var reg ddnsRegisterResp
	if err := json.Unmarshal(data, &reg); err != nil {
		return fmt.Errorf("register response: %v", err)
	}

	c.mu.Lock()
	if reg.DDNSToken != "" {
		c.ddnsToken = reg.DDNSToken
	}
	if reg.Subdomain != nil {
		c.subdomain = reg.Subdomain.FullName
	}
	c.binaryID = reg.BinaryID
	if reg.CurrentIP != "" {
		c.currentIP = reg.CurrentIP
	}
	c.lastUpdate = time.Now()
	c.errored = false
	c.mu.Unlock()
	c.saveState()

	log.Printf("[ddns] registered binary %s -> subdomain %s ip=%s remapped=%v",
		reg.BinaryID, reg.SubdomainFull(), reg.CurrentIP, reg.Remapped)

	// After a migration the fresh server restores the user's last backup.
	if !c.restored {
		if err := c.tryRestoreBackup(); err != nil {
			log.Printf("[ddns] WARNING: backup restore skipped: %v", err)
		}
	}
	return nil
}

// helper to get full subdomain (avoid nil panic)
func (r ddnsRegisterResp) SubdomainFull() string {
	if r.Subdomain == nil {
		return "(none)"
	}
	return r.Subdomain.FullName
}

func (c *DDNSClient) login() (string, error) {
	form := url.Values{}
	form.Set("email", c.cfg.DDNSEmail)
	form.Set("password", c.cfg.DDNSPassword)
	resp, err := http.Post(c.baseURL+"/api/auth/login", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, c.cfg.DDNSEmail, c.cfg.DDNSPassword)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("login response: %v", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("login returned no token")
	}
	return out.Token, nil
}

// pushIP reports the current public IP to the worker (keeps the A record fresh).
func (c *DDNSClient) pushIP() error {
	c.mu.Lock()
	token := c.ddnsToken
	c.mu.Unlock()
	if token == "" {
		return fmt.Errorf("no ddns token yet")
	}
	ip, err := publicIP()
	if err != nil {
		return err
	}

	u := fmt.Sprintf("%s/api/ddns/update?token=%s", c.baseURL, url.QueryEscape(token))
	resp, err := httpClient().Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("ddns update returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	c.mu.Lock()
	c.currentIP = ip
	c.lastUpdate = time.Now()
	c.errored = false
	c.status = "active"
	c.mu.Unlock()
	c.saveState()
	log.Printf("[ddns] ip updated -> %s (subdomain %s)", ip, c.subdomain)
	return nil
}

// uploadBackupOnce uploads a full-config backup even if no state exists.
func (c *DDNSClient) uploadBackupOnce() {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	token := c.ddnsToken
	c.mu.Unlock()
	if token == "" {
		log.Printf("[ddns] backup skipped: not registered yet")
		return
	}
	archive, err := c.buildBackupArchive()
	if err != nil {
		log.Printf("[ddns] backup build failed: %v", err)
		return
	}
	u := fmt.Sprintf("%s/api/backup/upload?token=%s", c.baseURL, url.QueryEscape(token))
	resp, err := httpClient().Post(u, "application/octet-stream", bytes.NewReader(archive))
	if err != nil {
		log.Printf("[ddns] backup upload failed: %v", err)
		return
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		log.Printf("[ddns] backup upload returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		return
	}
	c.mu.Lock()
	c.lastBackup = time.Now()
	c.mu.Unlock()
	log.Printf("[ddns] daily backup uploaded (%d bytes)", len(archive))
}

// buildBackupArchive packages the current TunGuard state into a tar.gz in memory.
func (c *DDNSClient) buildBackupArchive() ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	files := []struct {
		name string
		path string
	}{
		{"peers.json", filepath.Join(c.cfg.DataDir, "peers.json")},
		{"server_private.key", filepath.Join(c.cfg.DataDir, "server_private.key")},
		{"web_credentials.json", filepath.Join(c.cfg.DataDir, "web_credentials.json")},
		{"ssh_host_key", filepath.Join(c.cfg.DataDir, "ssh_host_key")},
		{"api_key.json", filepath.Join(c.cfg.DataDir, "api_key.json")},
	}
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("[ddns] WARNING: could not read %s: %v", f.path, err)
			}
			continue
		}
		hdr := &tar.Header{Name: f.name, Mode: 0600, Size: int64(len(data)), ModTime: time.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	gz.Close()
	return buf.Bytes(), nil
}

// tryRestoreBackup pulls the user's latest stored backup and restores it locally.
func (c *DDNSClient) tryRestoreBackup() error {
	c.mu.Lock()
	token := c.ddnsToken
	binaryID := c.binaryID
	c.mu.Unlock()
	if token == "" {
		return fmt.Errorf("no ddns token")
	}
	u := c.baseURL + "/api/backup/download?token=" + url.QueryEscape(token) + "&binary=" + url.QueryEscape(binaryID)
	resp, err := httpClient().Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return fmt.Errorf("no backup available yet")
	}
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("download returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "tanguard-ddns-restore-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	if err := c.applyRestoredBackup(tmp.Name()); err != nil {
		return err
	}
	c.mu.Lock()
	c.restored = true
	c.mu.Unlock()
	c.saveState()
	log.Printf("[ddns] restored backup from DDNS (%d bytes) - state migrated to this server", len(data))
	return nil
}

// applyRestoredBackup restores backup archive contents into DATA_DIR.
func (c *DDNSClient) applyRestoredBackup(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a valid backup: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Base(filepath.Clean(hdr.Name))
		if name == "" || name == "." || hdr.Typeflag != tar.TypeReg {
			continue
		}
		dest := filepath.Join(c.cfg.DataDir, name)
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
	return nil
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// publicIP detects the outbound public IPv4 of this server.
func publicIP() (string, error) {
	probe := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	var lastErr error
	for _, u := range probe {
		if ip, err := fetchIPv4(u); err == nil {
			return ip, nil
		} else {
			lastErr = err
		}
	}
	return "", lastErr
}

func fetchIPv4(u string) (string, error) {
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	ip := strings.TrimSpace(string(data))
	if !netIPOK(ip) {
		return "", fmt.Errorf("probe returned non-IP: %q", ip)
	}
	return ip, nil
}

func netIPOK(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == ':' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// hexKey helpers reused elsewhere (kept here for the register pubkey payload).
func hexToByte(hexKey string) ([]byte, error) {
	return hex.DecodeString(strings.TrimSpace(hexKey))
}

// --- API handlers exposed to the web dashboard ---

func (c *DDNSClient) handleDDNSStatus(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data := map[string]any{
		"enabled":          c.enabled,
		"base_url":         c.baseURL,
		"email":            c.cfg.DDNSEmail,
		"binary_id":        c.binaryID,
		"subdomain":        c.subdomain,
		"current_ip":       c.currentIP,
		"last_update_sec":  int(time.Since(c.lastUpdate).Seconds()),
		"last_backup_sec":  int(time.Since(c.lastBackup).Seconds()),
		"status":           c.status,
		"registered":       c.ddnsToken != "",
		"backup_restored":  c.restored,
		"errored":          c.errored,
		"update_interval":  c.cfg.DDNSUpdateInterval,
	}
	jsonResp(w, 200, data)
}

func (c *DDNSClient) handleDDNSRegister(w http.ResponseWriter, r *http.Request) {
	if c.ddnsToken != "" {
		jsonResp(w, 200, map[string]any{"success": true, "already": true, "subdomain": c.subdomain})
		return
	}
	if err := c.register(); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, 200, map[string]any{"success": true, "subdomain": c.subdomain})
}

func (c *DDNSClient) handleDDNSPush(w http.ResponseWriter, r *http.Request) {
	if err := c.pushIP(); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, 200, map[string]any{"success": true, "ip": c.currentIP})
}