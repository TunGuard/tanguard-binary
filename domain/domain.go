// Package domain maps public domain names onto services reachable from this
// machine (through a TRP port mapping or over the WireGuard tunnel) and puts
// them behind HTTPS with automatically-issued Let's Encrypt certificates.
//
// Depending on what is installed on the host, the mapping is exposed one of
// two ways:
//
//   - built-in mode: no web server is detected, so this process listens on the
//     configured HTTP/HTTPS ports itself and answers ACME challenges directly;
//   - external mode: nginx, Apache, Caddy or Traefik is detected, so a vhost
//     config is written into the server's config directory (with the ACME
//     http-01 challenge proxied back to a loopback listener owned by this
//     process) and the server is reloaded.
//
// Records are persisted as JSON in the data directory, one file per the rest
// of the stores.
package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tanguard/config"
)

// Backend is how a domain reaches the service it fronts.
type Backend string

const (
	// BackendTRP proxies to an existing TRP port mapping's local listener:
	// the domain answers on this server, forwarded through the tun control
	// plane to the node-side service.
	BackendTRP Backend = "trp"
	// BackendWG proxies straight to a service listening on a WireGuard peer's
	// address, reachable via the tunnel that peer brought up.
	BackendWG Backend = "wg"
)

// Record is one persisted domain mapping.
type Record struct {
	ID         string    `json:"id"`
	Domain     string    `json:"domain"`
	Backend    Backend   `json:"backend"`
	ProxyRef   string    `json:"proxy_ref,omitempty"`
	TargetIP   string    `json:"target_ip,omitempty"`
	TargetPort int       `json:"target_port,omitempty"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AddRequest is what a domain create/update accepts.
type AddRequest struct {
	Domain     string
	Backend    Backend
	ProxyRef   string
	TargetIP   string
	TargetPort int
	Enabled    bool
}

// Manager owns the domain registry and the reverse-proxy behaviour behind it.
type Manager struct {
	mu        sync.Mutex
	dir       string
	path      string
	httpPort  int
	httpsPort int
	chPort    int

	records  []*Record
	byID     map[string]*Record
	byDomain map[string]*Record

	// trpLookup resolves a TRP mapping reference to the loopback address its
	// listener is bound on. It is injected by the API, which owns the TRP
	// manager.
	trpLookup func(ref string) (addr, desc string, ok bool)

	// detect is an optional override for Detect (tests / unusual hosts).
	detect func() DetectResult

	// routes carries the live backend table the proxy handlers read.
	routes *routeTable

	iss *Issuer

	// serving records the active topology.
	builtinStarted bool
	srv            serveState

	// certMu serializes ACME issuance runs.
	certMu sync.Mutex
}

func NewManager(cfg *config.Config) *Manager {
	dir := filepath.Join(cfg.DataDir, "domains")
	return &Manager{
		dir:       dir,
		path:      filepath.Join(dir, "domains.json"),
		httpPort:  cfg.DomainHTTPPort,
		httpsPort: cfg.DomainHTTPSPort,
		chPort:    cfg.DomainChallengePort,
		byID:      make(map[string]*Record),
		byDomain:  make(map[string]*Record),
		routes:    newRouteTable(),
	}
}

// SetTRPLookup installs the resolver that turns a TRP mapping reference into
// a local proxy target. TPR-backed domains cannot be created before this and
// a TRP backend still resolves at serving time.
func (m *Manager) SetTRPLookup(fn func(ref string) (addr, desc string, ok bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trpLookup = fn
}

// SetDetect overrides host detection. It exists so tests (and operators on
// unusual hosts) can pin the topology; a nil function restores the /proc scan.
func (m *Manager) SetDetect(fn func() DetectResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detect = fn
}

func (m *Manager) detectHost() DetectResult {
	if m.detect != nil {
		return m.detect()
	}
	return Detect()
}

// Load restores the persisted registry.
func (m *Manager) Load() error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read domains file: %w", err)
	}
	var recs []*Record
	if err := json.Unmarshal(data, &recs); err != nil {
		return fmt.Errorf("parse domains file: %w", err)
	}
	for _, r := range recs {
		m.index(r)
	}
	log.Printf("[domain] restored %d domain mapping(s)", len(recs))
	return nil
}

func (m *Manager) index(r *Record) {
	m.records = append(m.records, r)
	m.byID[r.ID] = r
	m.byDomain[strings.ToLower(r.Domain)] = r
}

// save writes the registry to disk. The caller must hold m.mu.
func (m *Manager) save() error {
	recs := make([]*Record, len(m.records))
	copy(recs, m.records)
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// Start boots the ACME machinery and applies every enabled mapping. It is
// called once at startup, after Load. Start never fails hard: whatever cannot
// be served is reported through List/Status and logged, so a half-broken
// host still answers the API.
func (m *Manager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.dir, 0700); err != nil {
		log.Printf("[domain] data dir: %v", err)
	}
	m.iss = newIssuer(filepath.Join(m.dir, "certs"), m.chPort)
	m.resyncLocked()
}

// Add validates and persists a new mapping, then applies it.
func (m *Manager) Add(in AddRequest) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	domain, err := NormalizeDomain(in.Domain)
	if err != nil {
		return nil, err
	}
	if _, exists := m.byDomain[domain]; exists {
		return nil, fmt.Errorf("domain %s already mapped", domain)
	}
	if err := m.validateBackendLocked(in); err != nil {
		return nil, err
	}
	rec := &Record{
		ID:         config.RandomID(),
		Domain:     domain,
		Backend:    in.Backend,
		ProxyRef:   strings.TrimSpace(in.ProxyRef),
		TargetIP:   strings.TrimSpace(in.TargetIP),
		TargetPort: in.TargetPort,
		Enabled:    in.Enabled,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	m.index(rec)
	if rec.Enabled {
		m.applyLocked(rec)
	}
	if err := m.save(); err != nil {
		return nil, fmt.Errorf("persist: %w", err)
	}
	log.Printf("[domain] added %s -> %s", rec.Domain, m.backendDesc(rec))
	return rec, nil
}

// Update changes a mapping's target and/or enabled flag.
func (m *Manager) Update(id, domain string, enabled *bool, in AddRequest) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec := m.byID[id]
	if rec == nil {
		return nil, fmt.Errorf("no such domain mapping")
	}
	if in.Backend != "" || in.TargetIP != "" || in.TargetPort != 0 || in.ProxyRef != "" {
		if in.Backend == "" {
			in.Backend = rec.Backend
		}
		if in.ProxyRef == "" {
			in.ProxyRef = rec.ProxyRef
		}
		if in.TargetIP == "" {
			in.TargetIP = rec.TargetIP
		}
		if in.TargetPort == 0 {
			in.TargetPort = rec.TargetPort
		}
		if err := m.validateBackendLocked(in); err != nil {
			return nil, err
		}
		rec.Backend = in.Backend
		rec.ProxyRef = strings.TrimSpace(in.ProxyRef)
		rec.TargetIP = strings.TrimSpace(in.TargetIP)
		rec.TargetPort = in.TargetPort
	}

	newDomain := rec.Domain
	if domain != "" && domain != rec.Domain {
		nd, err := NormalizeDomain(domain)
		if err != nil {
			return nil, err
		}
		if other, exists := m.byDomain[nd]; exists && other.ID != rec.ID {
			return nil, fmt.Errorf("domain %s already mapped", nd)
		}
		delete(m.byDomain, strings.ToLower(rec.Domain))
		newDomain = nd
		rec.Domain = nd
	}
	if enabled != nil && *enabled != rec.Enabled {
		if *enabled {
			m.applyLocked(rec)
		} else {
			m.unapplyLocked(rec)
		}
		rec.Enabled = *enabled
	}
	rec.UpdatedAt = time.Now()
	m.byDomain[strings.ToLower(newDomain)] = rec

	if err := m.save(); err != nil {
		return nil, fmt.Errorf("persist: %w", err)
	}
	log.Printf("[domain] updated %s -> %s (enabled=%v)", rec.Domain, m.backendDesc(rec), rec.Enabled)
	return rec, nil
}

// Remove drops a mapping and frees its proxy wiring.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec := m.byID[id]
	if rec == nil {
		return fmt.Errorf("no such domain mapping")
	}
	m.unapplyLocked(rec)
	delete(m.byID, id)
	delete(m.byDomain, strings.ToLower(rec.Domain))
	for i, r := range m.records {
		if r.ID == id {
			m.records = append(m.records[:i], m.records[i+1:]...)
			break
		}
	}
	if err := m.save(); err != nil {
		return fmt.Errorf("persist: %w", err)
	}
	log.Printf("[domain] removed %s", rec.Domain)
	return nil
}

func (m *Manager) validateBackendLocked(in AddRequest) error {
	switch Backend(in.Backend) {
	case BackendTRP:
		if m.trpLookup == nil {
			return errors.New("mesh / TRP control plane is disabled")
		}
		if strings.TrimSpace(in.ProxyRef) == "" {
			return errors.New("a TRP backend needs the mapping reference (`--trp <ref>`)")
		}
		if _, _, ok := m.trpLookup(strings.TrimSpace(in.ProxyRef)); !ok {
			return fmt.Errorf("no TRP mapping matches %q", in.ProxyRef)
		}
	case BackendWG:
		if ip := net.ParseIP(strings.TrimSpace(in.TargetIP)); ip == nil {
			return errors.New("a WireGuard backend needs a reachable IP address (`--wg <ip> <port>`)")
		}
		if in.TargetPort < 1 || in.TargetPort > 65535 {
			return errors.New("target port must be between 1 and 65535")
		}
	case "":
		return errors.New("a backend is required: `--trp <ref>` or `--wg <ip> <port>`")
	default:
		return fmt.Errorf("unknown backend %q", in.Backend)
	}
	return nil
}

// backendAddr resolves a record to the local address the proxy should forward
// to. The caller must not hold m.mu.
func (m *Manager) backendAddr(rec *Record) (addr, desc string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.backendAddrLocked(rec)
}

func (m *Manager) backendAddrLocked(rec *Record) (addr, desc string, err error) {
	switch rec.Backend {
	case BackendTRP:
		if m.trpLookup == nil {
			return "", "", fmt.Errorf("mesh / TRP control plane is disabled")
		}
		a, d, ok := m.trpLookup(rec.ProxyRef)
		if !ok {
			return "", "", fmt.Errorf("TRP mapping %q no longer exists", rec.ProxyRef)
		}
		return a, d, nil
	case BackendWG:
		return net.JoinHostPort(rec.TargetIP, fmt.Sprint(rec.TargetPort)),
			fmt.Sprintf("WireGuard %s:%d", rec.TargetIP, rec.TargetPort), nil
	default:
		return "", "", fmt.Errorf("unknown backend %q", rec.Backend)
	}
}

func (m *Manager) backendDesc(rec *Record) string {
	addr, desc, err := m.backendAddrLocked(rec)
	if err != nil {
		return string(rec.Backend)
	}
	_ = addr
	return desc
}

// Lookup resolves a domain at serving time. Used by the API and tests.
func (m *Manager) Lookup(domain string) (addr string, rec *Record, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec = m.byDomain[strings.ToLower(domain)]
	if rec == nil {
		return "", nil, fmt.Errorf("no mapping for domain %s", domain)
	}
	if !rec.Enabled {
		return "", rec, fmt.Errorf("domain %s is disabled", domain)
	}
	addr, _, err = m.backendAddrLocked(rec)
	return addr, rec, err
}

// List returns the registry with the resolved backend for each record.
func (m *Manager) List() []map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := []map[string]interface{}{}
	for _, rec := range m.records {
		item := map[string]interface{}{
			"id":          rec.ID,
			"domain":      rec.Domain,
			"backend":     string(rec.Backend),
			"proxy_ref":   rec.ProxyRef,
			"target_ip":   rec.TargetIP,
			"target_port": rec.TargetPort,
			"enabled":     rec.Enabled,
			"created_at":  rec.CreatedAt.Format(time.RFC3339),
			"updated_at":  rec.UpdatedAt.Format(time.RFC3339),
		}
		addr, desc, err := m.backendAddrLocked(rec)
		if err != nil {
			item["target"] = ""
			item["target_note"] = err.Error()
		} else {
			item["target"] = addr
			item["target_note"] = desc
		}
		out = append(out, item)
	}
	return out
}

// Records returns the raw persisted records (for internal use / diagnostics).
func (m *Manager) Records() []*Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Record, len(m.records))
	copy(out, m.records)
	return out
}

// NormalizeDomain lowercases a hostname and admits only plain ASCII DNS names,
// rejecting anything that looks like a scheme, path, port or whitespace. IDN
// (punycode) input is passed through as-is if it is already ASCII.
func NormalizeDomain(s string) (string, error) {
	d := strings.TrimSpace(s)
	d = strings.TrimSuffix(d, ".")
	d = strings.ToLower(d)
	if d == "" {
		return "", errors.New("domain name is required")
	}
	if strings.ContainsAny(d, " /?#:") || strings.Contains(d, "://") {
		return "", errors.New("enter the bare domain name, e.g. app.example.com (no scheme, path or port)")
	}
	if len(d) > 253 {
		return "", errors.New("domain name is too long")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", errors.New("domain name must include a dot, e.g. app.example.com")
	}
	for _, label := range labels {
		if label == "" {
			return "", errors.New("invalid domain name: empty label")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("invalid domain name: label %q too long", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid domain name: label %q may not start or end with '-'", label)
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", fmt.Errorf("invalid domain name: %q is not a hostname", d)
		}
	}
	return d, nil
}
