package domain

import (
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
