package domain

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
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

	"tanguard/webui"
)

// serveState records how the mappings are currently being served.
type serveState struct {
	mode      string // "builtin" | "external" | "blocked"
	webserver string
	lastErr   string
	httpSrv   *http.Server
	httpsSrv  *http.Server
}

// certSource is the subset of autocert.Manager the DoT listener needs. It is
// an interface so tests can supply a static certificate.
type certSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// routeTable is the live host -> backend address map read by the proxy. The
// dns set marks the hosts that are public DNS fronts (DoH + DoT) rather than
// ordinary reverse-proxy targets.
type routeTable struct {
	mu       sync.RWMutex
	backends map[string]string
	dns      map[string]bool
}

func newRouteTable() *routeTable {
	return &routeTable{backends: make(map[string]string), dns: make(map[string]bool)}
}

func (t *routeTable) set(domain, addr string) {
	t.mu.Lock()
	t.backends[strings.ToLower(domain)] = addr
	t.mu.Unlock()
}

func (t *routeTable) setDNS(domain string, dns bool) {
	t.mu.Lock()
	if dns {
		t.dns[strings.ToLower(domain)] = true
	} else {
		delete(t.dns, strings.ToLower(domain))
	}
	t.mu.Unlock()
}

func (t *routeTable) isDNS(domain string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dns[strings.ToLower(domain)]
}

func (t *routeTable) del(domain string) {
	t.mu.Lock()
	delete(t.backends, strings.ToLower(domain))
	delete(t.dns, strings.ToLower(domain))
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
	t.dns = make(map[string]bool)
	t.mu.Unlock()
}

// newProxyTransport builds the shared HTTP transport used by every proxy
// request, so connections to AdGuard and tunnel targets are pooled instead of
// dialed per request.
func newProxyTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// applyLocked / unapplyLocked bring the live serving state in line with the
// registry. Both simply resync, which is cheap and always correct.
func (m *Manager) applyLocked(_ *Record)   { m.resyncLocked() }
func (m *Manager) unapplyLocked(_ *Record) { m.resyncLocked() }

// resyncLocked recomputes the routing table and pushes it to whichever proxy
// owns the public ports. The caller must hold m.mu.
func (m *Manager) resyncLocked() {
	det := m.detectHost()
	// The server that should route traffic changed: stop managing the old
	// one's generated config before writing anywhere else.
	if prev := m.srv.webserver; prev != "" && det.Webserver != prev {
		sweepServerLocked(prev)
	}
	m.srv.webserver = det.Webserver

	m.routes.clear()
	live := 0
	dnsLive := 0
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
		if rec.Backend == BackendDNS {
			m.routes.setDNS(rec.Domain, true)
			dnsLive++
		}
		live++
	}

	// The DoT listener is independent of the HTTP serving topology: it answers
	// on its own port whether the DoH side is built-in or handed to a
	// webserver, so it is synced here for every mode.
	m.syncDoTLocked(dnsLive)

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
	// Keep the manager so the DoT listener can present the same certificates.
	m.acm = ac

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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostOnly(r.Host)
		addr, ok := m.routes.get(host)
		if !ok {
			http.Error(w, "domain not configured on this server", http.StatusNotFound)
			return
		}
		if m.routes.isDNS(host) {
			m.serveDNSHTTP(w, r, addr, host)
			return
		}
		m.reverseProxy(host, addr).ServeHTTP(w, r)
	})
}

// reverseProxy builds the host-routed reverse proxy for one backend address.
func (m *Manager) reverseProxy(host, addr string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: m.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: addr})
			pr.Out.Host = host
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("[domain] %s -> %s: %v", host, addr, err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

// serveDNSHTTP serves a public DNS front over HTTPS. Only the DoH endpoint is
// proxied to AdGuard; every other path is a 404 and the root serves the
// TunGuard landing page, so the mapped domain never exposes AdGuard's admin
// UI or login.
func (m *Manager) serveDNSHTTP(w http.ResponseWriter, r *http.Request, addr, host string) {
	switch r.URL.Path {
	case "/dns-query":
		m.reverseProxy(host, addr).ServeHTTP(w, r)
	case "", "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if err := webui.DNSLanding(w, "https://"+host+"/dns-query", m.dotHost(host)); err != nil {
			log.Printf("[domain] landing page: %v", err)
		}
	default:
		http.NotFound(w, r)
	}
}

// dotHost is the DNS-over-TLS endpoint shown on a DNS front's landing page.
func (m *Manager) dotHost(host string) string {
	m.mu.Lock()
	port := m.dotPort
	m.mu.Unlock()
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// syncDoTLocked starts or stops the DNS-over-TLS listener to match the number
// of live DNS mappings. The caller must hold m.mu.
func (m *Manager) syncDoTLocked(dnsLive int) {
	need := dnsLive > 0 && m.dotPort > 0
	if need && !m.dotStarted {
		if err := m.startDoTLocked(); err != nil {
			log.Printf("[domain] DoT listener: %v", err)
			m.srv.lastErr = "dot: " + err.Error()
		} else {
			m.dotStarted = true
		}
	}
	if !need && m.dotStarted {
		m.stopDoTLocked()
	}
}

// startDoTLocked binds the DoT port. The caller must hold m.mu.
func (m *Manager) startDoTLocked() error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(m.dotPort))
	if err != nil {
		return fmt.Errorf("cannot bind :%d (%v)", m.dotPort, err)
	}
	m.dotLn = ln
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.dotGetCertificate,
	}
	go m.serveDoT(ln, cfg)
	log.Printf("[domain] DoT resolver listening on :%d", m.dotPort)
	return nil
}

// stopDoTLocked closes the DoT listener. The caller must hold m.mu.
func (m *Manager) stopDoTLocked() {
	if m.dotLn != nil {
		_ = m.dotLn.Close()
		m.dotLn = nil
	}
	m.dotStarted = false
}

// serveDoT accepts TLS connections and tunnels each one to AdGuard's plain DNS
// listener. DNS-over-TLS is framed by the client and AdGuard, so the bytes are
// copied verbatim in both directions.
func (m *Manager) serveDoT(ln net.Listener, cfg *tls.Config) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go m.serveDoTConn(conn, cfg)
	}
}

func (m *Manager) serveDoTConn(conn net.Conn, cfg *tls.Config) {
	tlsConn := tls.Server(conn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	m.mu.Lock()
	target := ""
	if m.adguardDNS != nil {
		target = m.adguardDNS()
	}
	m.mu.Unlock()
	if target == "" {
		_ = tlsConn.Close()
		return
	}

	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Printf("[domain] DoT upstream %s: %v", target, err)
		_ = tlsConn.Close()
		return
	}
	go func() {
		_, _ = io.Copy(up, tlsConn)
		_ = up.Close()
	}()
	_, _ = io.Copy(tlsConn, up)
	_ = tlsConn.Close()
}

// dotGetCertificate resolves the certificate for a DoT handshake. Only a host
// that is an enabled DNS mapping is allowed; issuance is handled by autocert
// (built-in mode) or by the cached files the issuer wrote (external mode).
func (m *Manager) dotGetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hostOnly(hello.ServerName)
	m.mu.Lock()
	_, ok := m.routes.get(host)
	isDNS := m.routes.isDNS(host)
	acm := m.acm
	iss := m.iss
	m.mu.Unlock()

	if !ok || !isDNS {
		return nil, fmt.Errorf("no DNS mapping for %q", hello.ServerName)
	}
	if acm != nil {
		return acm.GetCertificate(hello)
	}
	if iss != nil {
		certPEM, keyPEM, _, err := iss.loadPEM(host)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
	return nil, fmt.Errorf("no certificate source for %q", hello.ServerName)
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
	dotPort := m.dotPort
	dot := m.dotStarted
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
		"dot_port":       dotPort,
		"dot":            dot,
		"count":          count,
		"error":          errStr,
	}
}
