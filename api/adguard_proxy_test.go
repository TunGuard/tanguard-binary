package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"tanguard/adguard"
)

// The AdGuard UI must never be reachable without the dashboard login, and must
// report clearly when AdGuard is not running rather than proxying into the void.
func TestAdGuardUIProxyGuard(t *testing.T) {
	a := consoleTestAPI(t)

	// No manager attached yet.
	rec := httptest.NewRecorder()
	a.requireDashboardAuth(a.handleAdGuardUI)(rec, httptest.NewRequest("GET", adguardUIPrefix+"/", nil))
	if rec.Code != 401 {
		t.Fatalf("unauthenticated proxy: got %d, want 401", rec.Code)
	}

	req := httptest.NewRequest("GET", adguardUIPrefix+"/", nil)
	req.SetBasicAuth("admin", "test-password")

	// Attached but not running: a clear 503, not a proxy attempt.
	a.SetAdGuard(adguard.NewManager(a.cfg))
	rec = httptest.NewRecorder()
	a.requireDashboardAuth(a.handleAdGuardUI)(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("stopped AdGuard: got %d, want 503", rec.Code)
	}
}

// The manager forces the web UI onto loopback regardless of what was configured,
// so the raw port is never exposed even when ADGUARD_WEB_LISTEN says otherwise.
func TestAdGuardWebAddrForcesLoopback(t *testing.T) {
	a := consoleTestAPI(t)
	a.cfg.AdGuardWebListen = "0.0.0.0:1116"
	m := adguard.NewManager(a.cfg)
	if got := m.WebAddr(); got != "127.0.0.1:1116" {
		t.Fatalf("WebAddr() = %q, want loopback 127.0.0.1:1116", got)
	}
}
