package domain

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// serveState records how the mappings are currently being served.
type serveState struct {
	mode      string // "builtin" | "external" | "blocked"
	webserver string
	lastErr   string
	httpSrv   *http.Server
	httpsSrv  *http.Server
}

// routeTable is the live host -> backend address map read by the proxy.
type routeTable struct {
	mu       sync.RWMutex
	backends map[string]string
}

func newRouteTable() *routeTable {
	return &routeTable{backends: make(map[string]string)}
}

func (t *routeTable) set(domain, addr string) {
	t.mu.Lock()
	t.backends[strings.ToLower(domain)] = addr
	t.mu.Unlock()
}

func (t *routeTable) del(domain string) {
	t.mu.Lock()
	delete(t.backends, strings.ToLower(domain))
	t.mu.Unlock()
}

func (t *routeTable) get(domain string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	addr, ok := t.backends[strings.ToLower(domain)]
	return addr, ok
}

func (t *routeTable) clear() {
	t.mu.Lock()
	t.backends = make(map[string]string)
	t.mu.Unlock()
}

// applyLocked / unapplyLocked bring the live serving state in line with the
// registry. Both simply resync, which is cheap and always correct.
func (m *Manager) applyLocked(_ *Record)   { m.resyncLocked() }
func (m *Manager) unapplyLocked(_ *Record) { m.resyncLocked() }

// resyncLocked recomputes the routing table and pushes it to whichever proxy
// owns the public ports. The caller must hold m.mu.
func (m *Manager) resyncLocked() {
	det := m.detectHost()
	m.srv.webserver = det.Webserver

	m.routes.clear()
	live := 0
	for _, rec := range m.records {
		if !rec.Enabled {
			continue
		}
		addr, _, err := m.backendAddrLocked(rec)
		if err != nil {
			log.Printf("[domain] %s: %v", rec.Domain, err)
			continue
		}
		m.routes.set(rec.Domain, addr)
		live++
	}

	// A supported webserver is always preferred, but only touch it when there
	// is something to serve — or when we were already serving through it, so
	// removing the last mapping still cleans its generated config.
	if det.Webserver != "" && det.ConfDir != "" && (live > 0 || m.srv.mode == "external") {
		m.srv.mode = "external"
		m.writeExternalLocked(det)
		if live > 0 {
			go m.issueCerts(det)
		} else {
			m.srv.mode = "idle"
		}
		return
	}

	if m.builtinStarted {
		m.srv.mode = "builtin"
		return
	}
	if live == 0 {
		// Nothing to serve yet: do not grab the public ports on a host that
		// is not using domains. The first mapping starts the proxy.
		m.srv.mode = "idle"
		m.srv.lastErr = ""
		return
	}
	if err := m.startBuiltinLocked(det); err != nil {
		m.srv.mode = "blocked"
		m.srv.lastErr = err.Error()
		log.Printf("[domain] %v", err)
		return
	}
	m.builtinStarted = true
	m.srv.mode = "builtin"
	m.srv.lastErr = ""
}

// startBuiltinLocked binds the built-in proxy. It refuses to guess when a
// process already owns :80 or :443.
func (m *Manager) startBuiltinLocked(det DetectResult) error {
	if !det.Port80Free || !det.Port443Free {
		return fmt.Errorf("refusing to start built-in proxy: %s", conflictMsg(det))
	}

	ac := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(m.dir, "acme")),
		HostPolicy: func(_ context.Context, host string) error {
			if _, ok := m.routes.get(hostOnly(host)); ok {
				return nil
			}
			return fmt.Errorf("domain %s is not configured on this server", host)
		},
	}

	httpLn, err := net.Listen("tcp", ":"+strconv.Itoa(m.httpPort))
	if err != nil {
		return fmt.Errorf("refusing to start built-in proxy: cannot bind :%d (%v)", m.httpPort, err)
	}
	httpsLn, err := net.Listen("tcp", ":"+strconv.Itoa(m.httpsPort))
	if err != nil {
		httpLn.Close()
		return fmt.Errorf("refusing to start built-in proxy: cannot bind :%d (%v)", m.httpsPort, err)
	}

	httpSrv := &http.Server{Handler: ac.HTTPHandler(http.HandlerFunc(redirectHTTPS))}
	httpsSrv := &http.Server{Handler: m.proxyHandler(), TLSConfig: ac.TLSConfig()}
	m.srv.httpSrv = httpSrv
	m.srv.httpsSrv = httpsSrv

	go func() {
		if err := httpSrv.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			log.Printf("[domain] built-in http server stopped: %v", err)
		}
	}()
	go func() {
		if err := httpsSrv.ServeTLS(httpsLn, "", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[domain] built-in https server stopped: %v", err)
		}
	}()
	log.Printf("[domain] built-in proxy listening on :%d (http) and :%d (https)", m.httpPort, m.httpsPort)
	return nil
}

func conflictMsg(det DetectResult) string {
	var parts []string
	if det.Owner80 != "" {
		parts = append(parts, fmt.Sprintf(":80 held by %s", det.Owner80))
	}
	if det.Owner443 != "" {
		parts = append(parts, fmt.Sprintf(":443 held by %s", det.Owner443))
	}
	if len(parts) == 0 {
		parts = append(parts, "a port is already in use")
	}
	return strings.Join(parts, ", ") + " — stop that process or install a supported webserver"
}

func redirectHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + hostOnly(r.Host) + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// proxyHandler returns the host-routed reverse proxy used by built-in mode.
func (m *Manager) proxyHandler() http.Handler {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostOnly(r.Host)
		addr, ok := m.routes.get(host)
		if !ok {
			http.Error(w, "domain not configured on this server", http.StatusNotFound)
			return
		}
		rp := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(&url.URL{Scheme: "http", Host: addr})
				pr.Out.Host = r.Host
				pr.SetXForwarded()
				pr.Out.Header.Set("X-Forwarded-Proto", "https")
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				log.Printf("[domain] %s -> %s: %v", host, addr, err)
				http.Error(w, "bad gateway", http.StatusBadGateway)
			},
		}
		rp.ServeHTTP(w, r)
	})
}

// issueCerts makes sure every enabled domain has a certificate, then rewrites
// the external vhost configs so they reference the written files. It runs off
// the resync path because issuance does network I/O.
func (m *Manager) issueCerts(det DetectResult) {
	m.certMu.Lock()
	defer m.certMu.Unlock()

	if m.iss != nil {
		m.iss.start()
	}

	for _, rec := range m.Records() {
		if !rec.Enabled || m.iss == nil {
			continue
		}
		if _, _, err := m.iss.Ensure(rec.Domain); err != nil {
			log.Printf("[domain] %s: certificate: %v", rec.Domain, err)
		}
	}
	m.mu.Lock()
	if m.srv.mode == "external" {
		m.writeExternalLocked(det)
	}
	m.mu.Unlock()
}

// Status reports the serving topology for the API and dashboard.
func (m *Manager) Status() map[string]interface{} {
	det := m.detectHost()
	m.mu.Lock()
	mode := m.srv.mode
	web := m.srv.webserver
	errStr := m.srv.lastErr
	count := len(m.records)
	m.mu.Unlock()

	return map[string]interface{}{
		"enabled":        true,
		"mode":           mode,
		"webserver":      web,
		"owner_80":       det.Owner80,
		"owner_443":      det.Owner443,
		"http_port":      m.httpPort,
		"https_port":     m.httpsPort,
		"challenge_port": m.chPort,
		"count":          count,
		"error":          errStr,
	}
}
