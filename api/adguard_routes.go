package api

import (
	"net/http"
)

func registerAdGuardRoutes(mux *http.ServeMux, a *API) {
	mux.Handle("/api/adguard", a.requireAPI(a.handleAdGuardStatus))
	mux.Handle("/api/adguard/start", a.requireAPI(a.handleAdGuardStart))
	mux.Handle("/api/adguard/stop", a.requireAPI(a.handleAdGuardStop))
	mux.Handle("/api/adguard/config", a.requireAPI(a.handleAdGuardConfig))
	// The admin UI is proxied through the dashboard login so the AdGuard port
	// stays on loopback and is never anonymously reachable.
	mux.Handle(adguardUIPrefix+"/", a.requireDashboardAuth(a.handleAdGuardUI))
}

func (a *API) requireAdGuard(w http.ResponseWriter) bool {
	if a.adg == nil {
		jsonErr(w, 409, "adguard not initialized")
		return false
	}
	return true
}

func (a *API) handleAdGuardStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonErr(w, 405, "GET required")
		return
	}
	if a.adg == nil {
		jsonResp(w, 200, map[string]interface{}{"enabled": false, "running": false})
		return
	}
	running := a.adg.IsRunning()
	jsonResp(w, 200, map[string]interface{}{
		"enabled": true,
		"running": running,
		"web":     a.adg.WebAddr(),
	})
}

func (a *API) handleAdGuardStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	if a.adg == nil {
		jsonErr(w, 409, "adguard not initialized")
		return
	}
	if err := a.adg.Start(); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.SyncAdGuardDNS()
	a.refreshDomains()
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func (a *API) handleAdGuardStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	if a.adg == nil {
		jsonErr(w, 409, "adguard not initialized")
		return
	}
	if err := a.adg.Stop(); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.SyncAdGuardDNS()
	a.refreshDomains()
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func (a *API) handleAdGuardConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "GET" {
		jsonErr(w, 405, "GET or POST required")
		return
	}
	// For now, return current config state
	jsonResp(w, 200, map[string]interface{}{
		"enabled":  a.cfg.AdGuardEnabled,
		"dns":      a.cfg.AdGuardDNSListen,
		"web":      a.cfg.AdGuardWebListen,
		"upstream": a.cfg.AdGuardUpstream,
		"family":   a.cfg.AdGuardUpstreamFamily,
		"adult":    a.cfg.AdGuardFilterAdult,
	})
}
