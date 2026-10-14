package domain

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tanguard/config"
)

// testManager builds a manager pinned to built-in mode on ephemeral ports so
// tests never touch the host's real HTTP ports or webservers.
func testManager(t *testing.T, dir string) *Manager {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	m := NewManager(&config.Config{
		DataDir:       dir,
		DomainEnabled: true,
	})
	m.SetDetect(func() DetectResult {
		return DetectResult{Port80Free: true, Port443Free: true}
	})
	// Resolve the single known TRP reference "abc" to a local listener.
	m.SetTRPLookup(func(ref string) (addr, desc string, ok bool) {
		if ref == "abc" {
			return "127.0.0.1:9111", "TRP mapping abc", true
		}
		return "", "", false
	})
	if err := m.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

// wireAdGuard points a manager at a fake AdGuard DoH endpoint so a DNS mapping
// resolves in tests.
func wireAdGuard(m *Manager, doh, dns string) {
	m.SetAdGuard(func() string { return doh }, func() string { return dns })
}

func TestDNSBackendRequiresAdGuard(t *testing.T) {
	m := testManager(t, "")
	if _, err := m.Add(AddRequest{Domain: "dns.example.com", Backend: BackendDNS, Enabled: true}); err == nil {
		t.Fatal("a DNS backend must fail without AdGuard wired up")
	}
}

func TestDNSFrontRoutesLandingAndDoH(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte("dns-answer"))
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	m := testManager(t, "")
	wireAdGuard(m, backendAddr, "127.0.0.1:5300")
	if _, err := m.Add(AddRequest{Domain: "dns.example.com", Backend: BackendDNS, Enabled: true}); err != nil {
		t.Fatalf("add dns: %v", err)
	}

	h := m.proxyHandler()

	// The root is the TunGuard landing page, not the AdGuard login.
	root := httptest.NewRecorder()
	h.ServeHTTP(root, httptest.NewRequest("GET", "https://dns.example.com/", nil))
	if root.Code != http.StatusOK {
		t.Fatalf("landing status = %d, want 200", root.Code)
	}
	body := root.Body.String()
	for _, want := range []string{"TunGuard", "Frost-bit-star", "https://tunguard.github.io/docs/", "https://dns.example.com/dns-query"} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing %q", want)
		}
	}

	// Only /dns-query reaches AdGuard; anything else is hidden.
	doh := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "https://dns.example.com/dns-query", strings.NewReader("query"))
	req.Header.Set("Content-Type", "application/dns-message")
	h.ServeHTTP(doh, req)
	if doh.Code != http.StatusOK || doh.Body.String() != "dns-answer" {
		t.Fatalf("doh proxy = %d %q, want 200 dns-answer", doh.Code, doh.Body.String())
	}

	hidden := httptest.NewRecorder()
	h.ServeHTTP(hidden, httptest.NewRequest("GET", "https://dns.example.com/login.html", nil))
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("admin path status = %d, want 404", hidden.Code)
	}
}

func TestDNSFrontStartsAndStopsDoT(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dotPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	m := NewManager(&config.Config{DataDir: t.TempDir(), DomainEnabled: true, DomainDoTPort: dotPort})
	m.SetDetect(func() DetectResult { return DetectResult{Port80Free: true, Port443Free: true} })
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	wireAdGuard(m, "127.0.0.1:1116", "127.0.0.1:5300")

	rec, err := m.Add(AddRequest{Domain: "dns.example.com", Backend: BackendDNS, Enabled: true})
	if err != nil {
		t.Fatalf("add dns: %v", err)
	}
	if !m.dotStarted {
		t.Fatal("DoT listener should start when a DNS mapping is live")
	}

	if err := m.Remove(rec.ID); err != nil {
		t.Fatal(err)
	}
	if m.dotStarted {
		t.Fatal("DoT listener should stop when the last DNS mapping is removed")
	}
}

func TestDoTGetCertificateRejectsUnknownHost(t *testing.T) {
	m := testManager(t, "")
	wireAdGuard(m, "127.0.0.1:1116", "127.0.0.1:5300")
	if _, err := m.Add(AddRequest{Domain: "dns.example.com", Backend: BackendDNS, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.dotGetCertificate(&tls.ClientHelloInfo{ServerName: "evil.example.com"}); err == nil {
		t.Fatal("certificate must be refused for a host with no DNS mapping")
	}
}

func TestNormalizeDomain(t *testing.T) {
	valid := map[string]string{
		"app.example.com": "app.example.com",
		"App.Example.com": "app.example.com",
		"example.com.":    "example.com",
		"a-b.c-d.io":      "a-b.c-d.io",
	}
	for in, want := range valid {
		got, err := NormalizeDomain(in)
		if err != nil {
			t.Errorf("NormalizeDomain(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{"", " ", "http://x.com", "x.com/path", "x:8080", "x y", "a..b", "a.", "-a.com"} {
		if _, err := NormalizeDomain(in); err == nil {
			t.Errorf("NormalizeDomain(%q) should have failed", in)
		}
	}
}

func TestManagerIdleWithoutMappings(t *testing.T) {
	// No mappings means no public ports, no ACME call, no webserver touch:
	// the proxy stays dormant until the first mapping is added.
	m := NewManager(&config.Config{DataDir: t.TempDir(), DomainEnabled: true})
	m.SetDetect(func() DetectResult {
		return DetectResult{Webserver: "nginx", ConfDir: "/etc/nginx/conf.d"}
	})
	if err := m.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	m.Start()
	if got := m.Status()["mode"]; got != "idle" {
		t.Fatalf("mode with no mappings = %v, want idle", got)
	}
	if m.builtinStarted {
		t.Fatalf("built-in proxy should not start without mappings")
	}
	if m.iss != nil && m.iss.started {
		t.Fatalf("ACME issuer should not start without mappings")
	}
}

func TestSelectWebserverPrefersPortOwner(t *testing.T) {
	cases := []struct {
		owner80, owner443 string
		running           []string
		want              string
	}{
		// The process holding a public port wins over any other running
		// server.
		{owner80: "nginx", running: []string{"caddy"}, want: "nginx"},
		{owner80: "apache2", running: []string{"nginx"}, want: "apache"},
		{owner443: "httpd", want: "apache"},
		// Unrecognised port holder: any running supported server is used.
		{owner80: "lighttpd", running: []string{"nginx"}, want: "nginx"},
		// No owner: first supported server in preference order.
		{running: []string{"caddy", "nginx"}, want: "nginx"},
		{running: []string{"apache2"}, want: "apache"},
		{},
	}
	for _, tc := range cases {
		got, _ := selectWebserver(tc.owner80, tc.owner443, tc.running)
		if got != tc.want {
			t.Errorf("selectWebserver(%q,%q,%v) = %q, want %q",
				tc.owner80, tc.owner443, tc.running, got, tc.want)
		}
	}
}

func TestManagerAddListUpdateRemove(t *testing.T) {
	m := testManager(t, "")

	trp, err := m.Add(AddRequest{Domain: "App.Forge.io", Backend: BackendTRP, ProxyRef: "abc", Enabled: true})
	if err != nil {
		t.Fatalf("add trp: %v", err)
	}
	if trp.Domain != "app.forge.io" {
		t.Errorf("domain should be normalized, got %q", trp.Domain)
	}

	wg, err := m.Add(AddRequest{Domain: "api.edge.example", Backend: BackendWG, TargetIP: "10.100.0.2", TargetPort: 8080, Enabled: true})
	if err != nil {
		t.Fatalf("add wg: %v", err)
	}

	items := m.List()
	if len(items) != 2 {
		t.Fatalf("want 2 records, got %d", len(items))
	}

	// TRP backend resolves through the injected lookup.
	for _, it := range items {
		if it["domain"] == "app.forge.io" {
			if it["target"] != "127.0.0.1:9111" {
				t.Errorf("trp target = %v, want 127.0.0.1:9111", it["target"])
			}
			wantNote := "TRP mapping abc"
			if !strings.Contains(it["target_note"].(string), wantNote) {
				t.Errorf("trp note %q should contain %q", it["target_note"], wantNote)
			}
		}
		if it["domain"] == "api.edge.example" {
			if it["target"] != "10.100.0.2:8080" {
				t.Errorf("wg target = %v", it["target"])
			}
		}
	}

	// Duplicate domain and bogus TRP refs are rejected.
	if _, err := m.Add(AddRequest{Domain: "app.forge.io", Backend: BackendTRP, ProxyRef: "abc"}); err == nil {
		t.Errorf("duplicate domain should fail")
	}
	if _, err := m.Add(AddRequest{Domain: "missing.helper.example", Backend: BackendTRP, ProxyRef: "nope"}); err == nil {
		t.Errorf("unknown TRP ref should fail")
	}

	// Disable flips state and removes the route.
	disabled := false
	if _, err := m.Update(wg.ID, "", &disabled, AddRequest{}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, _, err := m.Lookup("api.edge.example"); err == nil {
		t.Errorf("disabled domain should not resolve")
	}

	if err := m.Remove(trp.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	items = m.List()
	if len(items) != 1 {
		t.Fatalf("want 1 record after remove, got %d", len(items))
	}
}

func TestManagerPersists(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	if _, err := m.Add(AddRequest{Domain: "keep.example.com", Backend: BackendWG, TargetIP: "10.100.0.9", TargetPort: 80}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// A fresh manager over the same directory must restore the record.
	disk := NewManager(&config.Config{DataDir: dir, DomainEnabled: true})
	disk.SetTRPLookup(func(string) (string, string, bool) { return "", "", false })
	if err := disk.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	items := disk.List()
	if len(items) != 1 || items[0]["domain"] != "keep.example.com" {
		t.Fatalf("persisted record not restored: %+v", items)
	}
	if items[0]["target"] != "10.100.0.9:80" {
		t.Errorf("restored target = %v", items[0]["target"])
	}
}

func TestWritersRendering(t *testing.T) {
	rec := &Record{ID: "abc123", Domain: "app.example.com"}
	rr := renderRec{
		rec:      rec,
		addr:     "10.100.0.2:8080",
		certPath: "/var/certs/cert.pem",
		keyPath:  "/var/certs/key.pem",
		ssl:      true,
	}

	ng := nginxConf(rr, 8100)
	for _, want := range []string{
		"server_name app.example.com;",
		"listen 80;",
		"listen 443 ssl;",
		"proxy_pass http://127.0.0.1:8100;",
		"proxy_pass http://10.100.0.2:8080;",
		"ssl_certificate /var/certs/cert.pem;",
	} {
		if !strings.Contains(ng, want) {
			t.Errorf("nginx config missing %q:\n%s", want, ng)
		}
	}

	ap := apacheConf(rr, 8100)
	for _, want := range []string{
		"ServerName app.example.com",
		"ProxyPass / http://10.100.0.2:8080/",
		"SSLCertificateFile /var/certs/cert.pem",
	} {
		if !strings.Contains(ap, want) {
			t.Errorf("apache config missing %q:\n%s", want, ap)
		}
	}
}

func TestWritersDNSFront(t *testing.T) {
	rec := &Record{ID: "dns1", Domain: "dns.example.com", Backend: BackendDNS}
	rr := renderRec{
		rec:      rec,
		addr:     "127.0.0.1:1116",
		certPath: "/var/certs/cert.pem",
		keyPath:  "/var/certs/key.pem",
		ssl:      true,
		dns:      true,
	}

	ng := nginxConf(rr, 8100)
	for _, want := range []string{
		"location = /dns-query {",
		"proxy_pass http://127.0.0.1:1116;",
		"proxy_pass http://127.0.0.1:8100;",
	} {
		if !strings.Contains(ng, want) {
			t.Errorf("nginx DNS config missing %q:\n%s", want, ng)
		}
	}

	if ap := apacheConf(rr, 8100); !strings.Contains(ap, "ProxyPass /dns-query http://127.0.0.1:1116/dns-query") {
		t.Errorf("apache DNS config missing DoH proxy:\n%s", ap)
	}

	tjDir := t.TempDir()
	if err := writeTraefik(tjDir, []renderRec{rr}, 8100); err != nil {
		t.Fatalf("writeTraefik: %v", err)
	}
	tj, err := os.ReadFile(filepath.Join(tjDir, "tanguard-dynamic.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tj), "Path(`/dns-query`)") {
		t.Errorf("traefik DNS config missing DoH router:\n%s", tj)
	}
}

// TestTLSBlockGatedOnCert locks the failure that used to make mapping dead:
// emitting an ssl_certificate reference before the certificate exists makes
// nginx -t / apachectl configtest fail, so the whole vhost (challenge proxy
// included) never loads and the cert is never issued.
func TestTLSBlockGatedOnCert(t *testing.T) {
	rec := &Record{ID: "abc123", Domain: "app.example.com"}
	noCert := renderRec{
		rec: rec, addr: "10.100.0.2:8080",
		certPath: "/var/certs/cert.pem", keyPath: "/var/certs/key.pem",
		ssl: false,
	}

	for _, conf := range []string{nginxConf(noCert, 8100), apacheConf(noCert, 8100)} {
		if strings.Contains(conf, "cert.pem") {
			t.Errorf("config must not reference the certificate before it exists:\n%s", conf)
		}
		if !strings.Contains(conf, "acme-challenge") {
			t.Errorf("config must still proxy the ACME challenge:\n%s", conf)
		}
	}
}

// TestNginxIncludeDir makes sure we write where nginx actually loads from.
func TestNginxIncludeDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	defaultDir := filepath.Join(dir, "conf.d")

	confD := write("nginx.conf", "http {\n  include /etc/nginx/conf.d/*.conf;\n}")
	if got := nginxIncludeDir(confD, defaultDir); got != defaultDir {
		t.Errorf("conf.d include: got %q, want %q", got, defaultDir)
	}

	sites := write("nginx-sites.conf", "http {\n  include /etc/nginx/sites-enabled/*.conf;\n}")
	want := filepath.Join(dir, "sites-available")
	if got := nginxIncludeDir(sites, defaultDir); got != want {
		t.Errorf("sites-enabled include: got %q, want %q", got, want)
	}

	// A commented-out include must not count.
	commented := write("nginx-commented.conf", "http {\n  #include /etc/nginx/conf.d/*.conf;\n}")
	if got := nginxIncludeDir(commented, defaultDir); got != defaultDir {
		t.Errorf("commented include: got %q, want %q", got, defaultDir)
	}

	// Missing main config falls back to the default directory.
	if got := nginxIncludeDir(filepath.Join(dir, "nope.conf"), defaultDir); got != defaultDir {
		t.Errorf("missing config: got %q, want %q", got, defaultDir)
	}
}

func TestWriteAndCleanStale(t *testing.T) {
	dir := t.TempDir()
	present := map[string]bool{"aaa": true}
	if err := writeNginx(dir, []renderRec{{
		rec:  &Record{ID: "aaa", Domain: "live.example.com"},
		addr: "127.0.0.1:9",
	}}, 8100, present); err != nil {
		t.Fatalf("writeNginx: %v", err)
	}
	// A leftover file for a mapping that no longer exists gets removed.
	leftOver := filepath.Join(dir, "tanguard-old.conf")
	if err := os.WriteFile(leftOver, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	cleanStale(dir, "tanguard-*.conf", "tanguard-", present)
	if _, err := os.Stat(leftOver); !os.IsNotExist(err) {
		t.Errorf("stale config should be removed")
	}
	if _, err := os.Stat(nginxFile(dir, "aaa")); err != nil {
		t.Errorf("live config should remain: %v", err)
	}
}
