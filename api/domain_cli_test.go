package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tanguard/domain"
)

// TestCommandDomainLifecycle drives the domain CLI end-to-end against an
// in-memory manager pinned to built-in mode with ephemeral ports, so the
// tests never bind the host's real 80/443 or touch the network.
func TestCommandDomainLifecycle(t *testing.T) {
	a := consoleTestAPI(t)
	dm := domain.NewManager(a.cfg)
	dm.SetDetect(func() domain.DetectResult {
		return domain.DetectResult{Port80Free: true, Port443Free: true}
	})
	dm.SetTRPLookup(func(ref string) (addr, desc string, ok bool) {
		if ref == "m1" {
			return "127.0.0.1:9444", "TRP mapping m1", true
		}
		return "", "", false
	})
	if err := dm.Load(); err != nil {
		t.Fatalf("load domain manager: %v", err)
	}
	a.SetDomain(dm)

	// Disabled state guards the command.
	blocked := a.dom
	a.dom = nil
	out := runConsole(t, a, "domain list\r")
	if !strings.Contains(out, "DOMAIN_ENABLED=true") {
		t.Fatalf("disabled message missing: %q", out)
	}
	a.dom = blocked

	// Bad flags are rejected before any state change.
	out = runConsole(t, a, "domain add broken.example.com --wg 10.100.0.2 99999\r")
	if !strings.Contains(out, "between 1 and 65535") {
		t.Fatalf("port validation missing: %q", out)
	}

	out = runConsole(t, a, "domain add app.example.com --trp m1\r")
	if !strings.Contains(out, "app.example.com") && !strings.Contains(out, "added") {
		t.Fatalf("add trp mapping failed: %q", out)
	}

	out = runConsole(t, a, "domain add api.example.com --wg 10.100.0.2 8080\r")
	if !strings.Contains(out, "api.example.com") && !strings.Contains(out, "added") {
		t.Fatalf("add wg mapping failed: %q", out)
	}

	out = runConsole(t, a, "domain list\r")
	for _, want := range []string{"app.example.com", "api.example.com", "TRP mapping m1", "10.100.0.2:8080"} {
		if !strings.Contains(out, want) {
			t.Errorf("domain list missing %q: %q", want, out)
		}
	}

	// Disable via update, then verify it stops resolving.
	out = runConsole(t, a, "domain update api.example.com --disable\r")
	if !strings.Contains(out, "api.example.com") && !strings.Contains(out, "disabled") {
		t.Fatalf("disable failed: %q", out)
	}
	if _, _, err := dm.Lookup("api.example.com"); err == nil {
		t.Errorf("disabled domain still resolves")
	}

	out = runConsole(t, a, "domain remove app.example.com\r")
	if !strings.Contains(out, "removed") {
		t.Fatalf("remove failed: %q", out)
	}
	if recs := dm.Records(); len(recs) != 1 {
		t.Fatalf("want 1 record after remove, got %d", len(recs))
	}
}

// TestDomainAPIEndpoints exercises the JSON routes without a live listener.
func TestDomainAPIEndpoints(t *testing.T) {
	a := consoleTestAPI(t)
	dm := domain.NewManager(a.cfg)
	dm.SetDetect(func() domain.DetectResult {
		return domain.DetectResult{Port80Free: true, Port443Free: true}
	})
	if err := dm.Load(); err != nil {
		t.Fatalf("load domain manager: %v", err)
	}
	a.dom = dm

	mux := http.NewServeMux()
	registerDomainRoutes(mux, a)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	call := func(method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		req.SetBasicAuth("admin", "test-password")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		out := map[string]interface{}{}
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, out := call("POST", "/api/domain/add", `{
		"domain":"app.example.com","backend":"wg",
		"target_ip":"10.100.0.2","target_port":80
	}`)
	if code != 200 {
		t.Fatalf("add status = %d (%v)", code, out)
	}

	code, out = call("GET", "/api/domains", "")
	if code != 200 {
		t.Fatalf("list status = %d", code)
	}
	domains, ok := out["domains"].([]interface{})
	if !ok || len(domains) != 1 {
		t.Fatalf("unexpected list content: %+v", out)
	}
	first := domains[0].(map[string]interface{})
	if first["domain"] != "app.example.com" {
		t.Fatalf("unexpected record: %+v", first)
	}

	code, _ = call("POST", "/api/domain/remove", `{"id":"nope"}`)
	if code != 404 {
		t.Fatalf("remove unknown status = %d", code)
	}

	// Each route still demands login.
	unauth, err := http.Get(srv.URL + "/api/domains")
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != 401 {
		t.Fatalf("GET /api/domains without credentials: got %d, want 401", unauth.StatusCode)
	}
}
