package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type API struct {
	wg     *WgServer
	store  *PeerStore
	cfg    *Config
	creds  *CredentialStore
	apiKey *APIKeyStore
	ipMu   sync.Mutex
}

func NewAPI(wg *WgServer, store *PeerStore, cfg *Config, creds *CredentialStore, apiKeys *APIKeyStore) *API {
	return &API{wg: wg, store: store, cfg: cfg, creds: creds, apiKey: apiKeys}
}

func (a *API) Start() {
	mux := http.NewServeMux()

	if a.cfg.WebEnabled {
		mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		webHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.authenticated(r) {
				requireBasicAuth(w)
				return
			}
			webUIHandler().ServeHTTP(w, r)
		})
		mux.Handle("/", webHandler)
		log.Printf("[api] web dashboard enabled at http://localhost%s (auth: %s)", a.cfg.APIListen, a.effectiveWebUsername())
	}

	mux.HandleFunc("/api/health", a.handleHealth)
	mux.Handle("/api/system", a.requireAPI(a.handleSystem))
	mux.Handle("/api/status", a.requireAPI(a.handleStatus))
	mux.Handle("/api/peers", a.requireAPI(a.handlePeers))
	mux.Handle("/api/peer/add", a.requireAPI(a.handlePeerAdd))
	mux.Handle("/api/peer/remove", a.requireAPI(a.handlePeerRemove))
	mux.Handle("/api/server_key", a.requireAPI(a.handleServerKey))
	mux.Handle("/api/peer/generate-config", a.requireAPI(a.handleGenerateConfig))
	mux.Handle("/api/peer/config", a.requireAPI(a.handlePeerConfig))
	mux.Handle("/api/configure", a.requireAPI(a.handleConfigure))
	mux.Handle("/api/backup/download", a.requireAPI(a.handleBackupDownload))
	mux.Handle("/api/backup/restore", a.requireAPI(a.handleBackupRestore))
	mux.Handle("/api/auth/status", a.requireDashboardAuth(a.handleAuthStatus))
	mux.Handle("/api/web/credentials", a.requireDashboardAuth(a.handleChangeCredentials))
	mux.Handle("/api/key", a.requireDashboardAuth(a.handleAPIKey))
	mux.Handle("/api/key/regenerate", a.requireDashboardAuth(a.handleAPIKeyRegenerate))
	mux.Handle("/api/ws/ssh", a.requireAPI(a.handleWebSSH))
	mux.Handle("/api/version", a.requireAPI(a.handleVersion))
	mux.Handle("/api/update", a.requireAPI(a.handleUpdate))

	handler := corsMiddleware(logMiddleware(mux))

	a.startVersionChecker()

	log.Printf("[api] listening on %s", a.cfg.APIListen)
	if a.apiKey != nil && a.apiKey.Exists() {
		log.Printf("[api] API authentication: dashboard login or API key (X-API-Key header)")
	} else {
		log.Printf("[api] API authentication: dashboard login (no API key set yet; generate one in Settings)")
	}
	if err := http.ListenAndServe(a.cfg.APIListen, handler); err != nil {
		log.Fatalf("[api] server failed: %v", err)
	}
}

func (a *API) effectiveWebUsername() string {
	if u, ok := a.creds.Username(); ok {
		return u
	}
	return a.cfg.WebUsername
}

func (a *API) authenticated(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return a.creds.VerifyWeb(user, pass, a.cfg.WebUsername, a.cfg.WebPassword)
}

// apiAuthorized accepts the dashboard login (HTTP Basic Auth) or a valid API
// key sent as either the X-API-Key header or an Authorization: Bearer header.
func (a *API) apiAuthorized(r *http.Request) bool {
	if a.authenticated(r) {
		return true
	}
	if a.apiKey == nil {
		return false
	}
	if k := r.Header.Get("X-API-Key"); k != "" && a.apiKey.Verify(k) {
		return true
	}
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(authz, "Bearer ") && a.apiKey.Verify(strings.TrimPrefix(authz, "Bearer ")) {
		return true
	}
	return false
}

// requireAPI guards API endpoints with either the dashboard login or the API key.
func (a *API) requireAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.apiAuthorized(r) {
			jsonErr(w, 401, "unauthorized: valid dashboard login or API key required")
			return
		}
		next(w, r)
	}
}

// requireDashboardAuth guards dashboard-management endpoints (credential / API
// key management) with the dashboard login only, never the API key.
func (a *API) requireDashboardAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authenticated(r) {
			requireBasicAuth(w)
			return
		}
		next(w, r)
	}
}

func (a *API) usingDefaultWebCreds() bool {
	if a.creds.Exists() {
		return false
	}
	return a.cfg.WebUsername == "admin" && a.cfg.WebPassword == "tanguard"
}

func requireBasicAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="TunGuard"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (a *API) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, 200, map[string]interface{}{
		"authenticated": true,
		"username":      a.effectiveWebUsername(),
		"must_change":   a.usingDefaultWebCreds(),
	})
}

func (a *API) handleChangeCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}

	var req struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON: "+err.Error())
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		jsonErr(w, 400, "username cannot be empty")
		return
	}
	if len(req.Password) < 8 {
		jsonErr(w, 400, "password must be at least 8 characters")
		return
	}
	if req.Password != req.ConfirmPassword {
		jsonErr(w, 400, "passwords do not match")
		return
	}

	if err := a.creds.Set(req.Username, req.Password); err != nil {
		jsonErr(w, 500, "failed to save credentials: "+err.Error())
		return
	}

	log.Printf("[api] web dashboard credentials updated for user %q", req.Username)
	jsonResp(w, 200, map[string]interface{}{
		"success":     true,
		"username":    req.Username,
		"must_change": false,
	})
}

// handleAPIKey returns the current API key (for display in the dashboard).
// Requires the dashboard login; never the API key itself.
func (a *API) handleAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonErr(w, 405, "GET required")
		return
	}
	key, ok := a.apiKey.Key()
	if !ok {
		jsonResp(w, 200, map[string]interface{}{
			"exists": false,
			"key":    "",
		})
		return
	}
	resp := map[string]interface{}{
		"exists": true,
		"key":    key,
	}
	if ts, ok := a.apiKey.CreatedAt(); ok {
		resp["created_at"] = ts.Format(time.RFC3339)
	}
	jsonResp(w, 200, resp)
}

// handleAPIKeyRegenerate creates a new API key, invalidating the old one.
// Requires the dashboard login; never the API key itself.
func (a *API) handleAPIKeyRegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	key, err := a.apiKey.Generate()
	if err != nil {
		jsonErr(w, 500, "failed to generate API key: "+err.Error())
		return
	}
	log.Printf("[api] API key regenerated by %q", a.effectiveWebUsername())
	jsonResp(w, 200, map[string]interface{}{
		"success":    true,
		"key":        key,
		"created_at": time.Now().Format(time.RFC3339),
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[api] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func jsonResp(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonResp(w, code, map[string]string{"error": msg})
}

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8] + "..."
	}
	return k
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, 200, map[string]string{"status": "ok"})
}

func (a *API) handleSystem(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, 200, collectSystemStats(a.cfg.DataDir))
}

func (a *API) handleServerKey(w http.ResponseWriter, r *http.Request) {
	pub := a.wg.PublicKey()
	if pub == "" {
		jsonErr(w, 500, "server key not initialized")
		return
	}
	jsonResp(w, 200, map[string]string{
		"public_key":  pub,
		"listen_port": fmt.Sprintf("%d", a.cfg.ListenPort),
	})
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	status, err := a.wg.GetStatus()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	storedPeers := a.store.All()
	metaMap := make(map[string]*PeerRecord)
	for _, sp := range storedPeers {
		metaMap[sp.PublicKey] = sp
	}

	type enrichedPeer struct {
		PeerStatus
		DeviceID   string `json:"device_id,omitempty"`
		DeviceName string `json:"device_name,omitempty"`
		AddedAt    string `json:"added_at,omitempty"`
	}

	var peers []enrichedPeer
	for _, p := range status.Peers {
		ep := enrichedPeer{PeerStatus: p}
		if meta, ok := metaMap[p.PublicKey]; ok {
			ep.DeviceID = meta.DeviceID
			ep.DeviceName = meta.DeviceName
			ep.AddedAt = meta.AddedAt.Format(time.RFC3339)
		}
		peers = append(peers, ep)
	}

	jsonResp(w, 200, map[string]interface{}{
		"server_public_key": a.wg.PublicKey(),
		"private_key_set":   status.PrivateKeySet,
		"listen_port":       status.ListenPort,
		"fwmark":            status.FwMark,
		"subnet":            a.cfg.Subnet,
		"peers":             peers,
		"peer_count":        len(peers),
	})
}

func (a *API) handlePeers(w http.ResponseWriter, r *http.Request) {
	status, err := a.wg.GetStatus()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	storedPeers := a.store.All()
	metaMap := make(map[string]*PeerRecord)
	for _, sp := range storedPeers {
		metaMap[sp.PublicKey] = sp
	}

	type peerInfo struct {
		PeerStatus
		DeviceID   string `json:"device_id,omitempty"`
		DeviceName string `json:"device_name,omitempty"`
		AddedAt    string `json:"added_at,omitempty"`
	}

	var peers []peerInfo
	for _, p := range status.Peers {
		pi := peerInfo{PeerStatus: p}
		if meta, ok := metaMap[p.PublicKey]; ok {
			pi.DeviceID = meta.DeviceID
			pi.DeviceName = meta.DeviceName
			pi.AddedAt = meta.AddedAt.Format(time.RFC3339)
		}
		peers = append(peers, pi)
	}

	jsonResp(w, 200, map[string]interface{}{
		"peers":      peers,
		"peer_count": len(peers),
	})
}

type peerAddReq struct {
	PublicKey    string `json:"public_key"`
	AllowedIP    string `json:"allowed_ip"`
	PresharedKey string `json:"preshared_key,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
}

func (a *API) handlePeerAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}

	var req peerAddReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON: "+err.Error())
		return
	}

	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.AllowedIP = strings.TrimSpace(req.AllowedIP)

	if req.PublicKey == "" {
		jsonErr(w, 400, "public_key required")
		return
	}
	if req.AllowedIP == "" {
		jsonErr(w, 400, "allowed_ip required (e.g. 10.100.0.2/32)")
		return
	}

	if _, err := ValidateHexKey(req.PublicKey); err != nil {
		jsonErr(w, 400, "invalid public_key: "+err.Error())
		return
	}
	if _, _, err := net.ParseCIDR(req.AllowedIP); err != nil {
		jsonErr(w, 400, "invalid allowed_ip: "+err.Error())
		return
	}

	a.ipMu.Lock()
	defer a.ipMu.Unlock()

	if a.store.Get(req.PublicKey) != nil {
		jsonErr(w, 409, "a peer with this public_key already exists")
		return
	}
	if a.store.AllowedIPInUse(req.AllowedIP) {
		jsonErr(w, 409, "allowed_ip already assigned to another peer: "+req.AllowedIP)
		return
	}

	rec := &PeerRecord{
		PublicKey:    req.PublicKey,
		AllowedIP:    req.AllowedIP,
		DeviceID:     req.DeviceID,
		DeviceName:   req.DeviceName,
		PreSharedKey: req.PresharedKey,
		AddedAt:      time.Now(),
	}

	if err := a.wg.AddPeer(req.PublicKey, req.AllowedIP, req.PresharedKey); err != nil {
		jsonErr(w, 500, "add peer to device: "+err.Error())
		return
	}
	a.store.Add(rec)
	if err := a.store.Save(); err != nil {
		log.Printf("[api] WARNING: failed to persist peer: %v", err)
	}

	log.Printf("[api] peer added: %s -> %s (device=%s)", shortKey(req.PublicKey), req.AllowedIP, req.DeviceID)

	jsonResp(w, 200, map[string]interface{}{
		"success":    true,
		"public_key": req.PublicKey,
		"allowed_ip": req.AllowedIP,
		"device_id":  req.DeviceID,
	})
}

func (a *API) handlePeerRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}

	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}

	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.PublicKey == "" {
		jsonErr(w, 400, "public_key required")
		return
	}

	a.ipMu.Lock()
	if err := a.wg.RemovePeer(req.PublicKey); err != nil {
		a.ipMu.Unlock()
		jsonErr(w, 500, "remove peer: "+err.Error())
		return
	}
	a.store.Remove(req.PublicKey)
	a.ipMu.Unlock()

	if err := a.store.Save(); err != nil {
		log.Printf("[api] WARNING: failed to persist peer removal: %v", err)
	}

	log.Printf("[api] peer removed: %s", shortKey(req.PublicKey))

	jsonResp(w, 200, map[string]interface{}{
		"success":    true,
		"public_key": req.PublicKey,
	})
}

func (a *API) handleConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}

	var req struct {
		PrivateKey string `json:"private_key"`
		ListenPort int    `json:"listen_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}

	if req.PrivateKey != "" {
		if _, err := ValidateHexKey(req.PrivateKey); err != nil {
			jsonErr(w, 400, "invalid private_key: "+err.Error())
			return
		}
		if err := a.wg.Configure(req.PrivateKey, a.cfg.ListenPort); err != nil {
			jsonErr(w, 500, "configure: "+err.Error())
			return
		}
		keyFile := a.cfg.DataDir + "/server_private.key"
		if err := writeFile(keyFile, []byte(req.PrivateKey), 0600); err != nil {
			log.Printf("[api] WARNING: could not save key: %v", err)
		}
		log.Printf("[api] server private key updated")
	}

	if req.ListenPort > 0 {
		a.cfg.ListenPort = req.ListenPort
		log.Printf("[api] listen port set to %d (restart required to apply)", req.ListenPort)
	}

	jsonResp(w, 200, map[string]interface{}{
		"success":           true,
		"server_public_key": a.wg.PublicKey(),
	})
}

func (a *API) handleGenerateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}

	var req struct {
		AllowedIP  string `json:"allowed_ip"`
		DeviceID   string `json:"device_id,omitempty"`
		DeviceName string `json:"device_name,omitempty"`
		ServerHost string `json:"server_host,omitempty"`
		DNS        string `json:"dns,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}

	if req.ServerHost == "" {
		req.ServerHost = r.Host
		if h, _, err := net.SplitHostPort(req.ServerHost); err == nil {
			req.ServerHost = h
		}
	}

	if req.DNS == "" {
		req.DNS = "1.1.1.1"
	}

	privBytes, pubBytes, err := GenerateKeyPair()
	if err != nil {
		jsonErr(w, 500, "key generation failed")
		return
	}
	clientPriv := hex.EncodeToString(privBytes)
	clientPub := hex.EncodeToString(pubBytes)

	a.ipMu.Lock()
	if req.AllowedIP == "" {
		ip, err := a.nextAvailableIP()
		if err != nil {
			a.ipMu.Unlock()
			jsonErr(w, 500, "no IP available: "+err.Error())
			return
		}
		req.AllowedIP = ip.String() + "/32"
	} else {
		req.AllowedIP = strings.TrimSpace(req.AllowedIP)
		if _, _, err := net.ParseCIDR(req.AllowedIP); err != nil {
			a.ipMu.Unlock()
			jsonErr(w, 400, "invalid allowed_ip: "+err.Error())
			return
		}
	}
	if a.store.AllowedIPInUse(req.AllowedIP) {
		a.ipMu.Unlock()
		jsonErr(w, 409, "allowed_ip already assigned to another peer: "+req.AllowedIP)
		return
	}

	rec := &PeerRecord{
		PublicKey:        clientPub,
		AllowedIP:        req.AllowedIP,
		DeviceID:         req.DeviceID,
		DeviceName:       req.DeviceName,
		ClientPrivateKey: clientPriv,
		AddedAt:          time.Now(),
	}

	if err := a.wg.AddPeer(clientPub, req.AllowedIP, ""); err != nil {
		a.ipMu.Unlock()
		jsonErr(w, 500, "add peer: "+err.Error())
		return
	}
	a.store.Add(rec)
	if err := a.store.Save(); err != nil {
		log.Printf("[api] WARNING: failed to persist peer: %v", err)
	}
	a.ipMu.Unlock()

	interfaceIP := strings.TrimSuffix(req.AllowedIP, "/32")
	pub := a.wg.PublicKey()
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
		HexToBase64(clientPriv), interfaceIP, req.DNS, HexToBase64(pub), req.ServerHost, a.cfg.ListenPort)

	log.Printf("[api] generated config for %s -> %s", req.AllowedIP, req.DeviceName)

	jsonResp(w, 200, map[string]interface{}{
		"success":            true,
		"client_private_key": clientPriv,
		"client_public_key":  clientPub,
		"allowed_ip":         req.AllowedIP,
		"config":             config,
		"server_host":        req.ServerHost,
		"server_port":        a.cfg.ListenPort,
		"device_id":          req.DeviceID,
		"device_name":        req.DeviceName,
	})
}

func (a *API) handlePeerConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}

	var req struct {
		PublicKey  string `json:"public_key"`
		ServerHost string `json:"server_host,omitempty"`
		DNS        string `json:"dns,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return
	}

	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.PublicKey == "" {
		jsonErr(w, 400, "public_key required")
		return
	}

	rec := a.store.Get(req.PublicKey)
	if rec == nil {
		jsonErr(w, 404, "peer not found")
		return
	}
	if rec.ClientPrivateKey == "" {
		jsonErr(w, 409, "no client config stored for this peer; only peers created via Generate Config can be re-downloaded")
		return
	}

	if req.ServerHost == "" {
		req.ServerHost = r.Host
		if h, _, err := net.SplitHostPort(req.ServerHost); err == nil {
			req.ServerHost = h
		}
	}
	if req.DNS == "" {
		req.DNS = "1.1.1.1"
	}

	interfaceIP := strings.TrimSuffix(rec.AllowedIP, "/32")
	pub := a.wg.PublicKey()
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
		HexToBase64(rec.ClientPrivateKey), interfaceIP, req.DNS, HexToBase64(pub), req.ServerHost, a.cfg.ListenPort)

	jsonResp(w, 200, map[string]interface{}{
		"success":     true,
		"config":      config,
		"allowed_ip":  rec.AllowedIP,
		"server_host": req.ServerHost,
		"server_port": a.cfg.ListenPort,
		"device_id":   rec.DeviceID,
		"device_name": rec.DeviceName,
		"public_key":  rec.PublicKey,
	})
}

func (a *API) nextAvailableIP() (net.IP, error) {
	_, ipnet, err := net.ParseCIDR(a.cfg.Subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}

	used := make(map[string]bool)
	for _, p := range a.store.All() {
		ip := strings.Split(p.AllowedIP, "/")[0]
		if ip != "" {
			used[ip] = true
		}
	}

	ip := ipnet.IP.Mask(ipnet.Mask)
	ip = nextIP(ip)
	ip = nextIP(ip)

	for ipnet.Contains(ip) {
		if !used[ip.String()] {
			return ip, nil
		}
		ip = nextIP(ip)
	}
	return nil, fmt.Errorf("subnet full")
}

func nextIP(ip net.IP) net.IP {
	n := make(net.IP, len(ip))
	copy(n, ip)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

const githubRepo = "TunGuard/tanguard-binary"

func goArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "386"
	default:
		return runtime.GOARCH
	}
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Body    string        `json:"body"`
	HTMLURL string        `json:"html_url"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type cachedVersion struct {
	mu              sync.RWMutex
	latestVersion   string
	downloadURL     string
	releaseNotes    string
	releaseURL      string
	updateAvailable bool
	lastCheck       time.Time
	checking        bool
}

var versionCache cachedVersion

func (a *API) startVersionChecker() {
	go func() {
		a.checkGitHubRelease()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			a.checkGitHubRelease()
		}
	}()
}

func (a *API) checkGitHubRelease() {
	versionCache.mu.Lock()
	if versionCache.checking {
		versionCache.mu.Unlock()
		return
	}
	versionCache.checking = true
	versionCache.mu.Unlock()

	defer func() {
		versionCache.mu.Lock()
		versionCache.checking = false
		versionCache.mu.Unlock()
	}()

	current := version
	resp, err := http.Get("https://api.github.com/repos/" + githubRepo + "/releases/latest")
	if err != nil {
		log.Printf("[version] check failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("[version] github returned HTTP %d", resp.StatusCode)
		return
	}

	var release githubRelease
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[version] read body: %v", err)
		return
	}
	if err := json.Unmarshal(body, &release); err != nil {
		log.Printf("[version] parse json: %v", err)
		return
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	if latest == "" || latest == current {
		versionCache.mu.Lock()
		versionCache.latestVersion = latest
		versionCache.updateAvailable = false
		versionCache.lastCheck = time.Now()
		versionCache.mu.Unlock()
		log.Printf("[version] current=%s latest=%s (up to date)", current, latest)
		return
	}

	archName := "tanguard-linux-" + goArch()
	var dlURL string
	for _, asset := range release.Assets {
		if asset.Name == archName {
			dlURL = asset.BrowserDownloadURL
			break
		}
	}

	versionCache.mu.Lock()
	versionCache.latestVersion = latest
	versionCache.downloadURL = dlURL
	versionCache.releaseNotes = release.Body
	versionCache.releaseURL = release.HTMLURL
	versionCache.updateAvailable = dlURL != ""
	versionCache.lastCheck = time.Now()
	versionCache.mu.Unlock()
	log.Printf("[version] current=%s latest=%s update=%v", current, latest, dlURL != "")
}

func (a *API) handleVersion(w http.ResponseWriter, r *http.Request) {
	versionCache.mu.RLock()
	defer versionCache.mu.RUnlock()

	jsonResp(w, 200, map[string]interface{}{
		"current_version":  version,
		"latest_version":   versionCache.latestVersion,
		"update_available":  versionCache.updateAvailable,
		"download_url":     versionCache.downloadURL,
		"release_notes":    versionCache.releaseNotes,
		"release_url":      versionCache.releaseURL,
		"arch":             goArch(),
		"last_checked":     versionCache.lastCheck.Format(time.RFC3339),
	})
}

var updateMu sync.Mutex

func (a *API) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}

	if !updateMu.TryLock() {
		jsonErr(w, 409, "update already in progress")
		return
	}
	defer updateMu.Unlock()

	var req struct {
		DownloadURL string `json:"download_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DownloadURL == "" {
		jsonErr(w, 400, "download_url required")
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		jsonErr(w, 500, "cannot find executable path: "+err.Error())
		return
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		jsonErr(w, 500, "cannot resolve executable: "+err.Error())
		return
	}

	log.Printf("[update] downloading %s", req.DownloadURL)
	resp, err := http.Get(req.DownloadURL)
	if err != nil {
		jsonErr(w, 502, "download failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		jsonErr(w, 502, fmt.Sprintf("download returned HTTP %d", resp.StatusCode))
		return
	}

	tmpPath := exePath + ".tmp"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		jsonErr(w, 500, "cannot create temp file: "+err.Error())
		return
	}
	written, err := io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(tmpPath)
		jsonErr(w, 500, "download write failed: "+err.Error())
		return
	}
	if written < 100000 {
		os.Remove(tmpPath)
		jsonErr(w, 502, "downloaded file too small ("+fmt.Sprintf("%d", written)+" bytes), aborting")
		return
	}

	log.Printf("[update] downloaded %d bytes to %s, replacing %s", written, tmpPath, exePath)
	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Remove(tmpPath)
		jsonErr(w, 500, "replace binary failed: "+err.Error())
		return
	}

	log.Printf("[update] binary replaced, restarting process")

	jsonResp(w, 200, map[string]interface{}{
		"success": true,
		"message": "Update installed. Server is restarting.",
	})

	go func() {
		time.Sleep(500 * time.Millisecond)
		cmd := exec.Command(exePath, os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			log.Printf("[update] restart failed: %v", err)
			return
		}
		os.Exit(0)
	}()
}
