package api

import (
	"net/http"
	"strings"

	"tanguard/domain"
)

// registerDomainRoutes wires the domain reverse-proxy endpoints. Every route
// is guarded like the rest of the API.
func registerDomainRoutes(mux *http.ServeMux, a *API) {
	mux.Handle("/api/domains", a.requireAPI(a.handleDomains))
	mux.Handle("/api/domains/status", a.requireAPI(a.handleDomainsStatus))
	mux.Handle("/api/domain/add", a.requireAPI(a.handleDomainAdd))
	mux.Handle("/api/domain/update", a.requireAPI(a.handleDomainUpdate))
	mux.Handle("/api/domain/remove", a.requireAPI(a.handleDomainRemove))
}

// requireDomain reports the "disabled" case consistently.
func (a *API) requireDomain(w http.ResponseWriter) bool {
	if a.dom == nil {
		jsonErr(w, 409, "domain reverse proxy is disabled (set DOMAIN_ENABLED=true)")
		return false
	}
	return true
}

func (a *API) handleDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonErr(w, 405, "GET required")
		return
	}
	if !a.requireDomain(w) {
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"domains": a.dom.List(),
		"status":  a.dom.Status(),
	})
}

func (a *API) handleDomainsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonErr(w, 405, "GET required")
		return
	}
	if !a.requireDomain(w) {
		return
	}
	jsonResp(w, 200, a.dom.Status())
}

func (a *API) handleDomainAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	if !a.requireDomain(w) {
		return
	}

	var req struct {
		Domain     string `json:"domain"`
		Backend    string `json:"backend"`
		ProxyRef   string `json:"proxy_ref"`
		TargetIP   string `json:"target_ip"`
		TargetPort int    `json:"target_port"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := limitedDecoder(r, &req); err != nil {
		jsonErr(w, 400, "invalid JSON: "+err.Error())
		return
	}

	in := domain.AddRequest{
		Domain:     req.Domain,
		Backend:    domain.Backend(strings.TrimSpace(req.Backend)),
		ProxyRef:   req.ProxyRef,
		TargetIP:   req.TargetIP,
		TargetPort: req.TargetPort,
		Enabled:    true,
	}
	if req.Enabled != nil {
		in.Enabled = *req.Enabled
	}

	rec, err := a.dom.Add(in)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"success": true,
		"id":      rec.ID,
		"domain":  rec.Domain,
	})
}

func (a *API) handleDomainUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	if !a.requireDomain(w) {
		return
	}

	var req struct {
		ID         string `json:"id"`
		Domain     string `json:"domain"`
		Backend    string `json:"backend"`
		ProxyRef   string `json:"proxy_ref"`
		TargetIP   string `json:"target_ip"`
		TargetPort int    `json:"target_port"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := limitedDecoder(r, &req); err != nil {
		jsonErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		jsonErr(w, 400, "id required")
		return
	}

	rec, err := a.dom.Update(req.ID, req.Domain, req.Enabled, domain.AddRequest{
		Backend:    domain.Backend(strings.TrimSpace(req.Backend)),
		ProxyRef:   req.ProxyRef,
		TargetIP:   req.TargetIP,
		TargetPort: req.TargetPort,
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"success": true,
		"id":      rec.ID,
		"domain":  rec.Domain,
		"enabled": rec.Enabled,
	})
}

func (a *API) handleDomainRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	if !a.requireDomain(w) {
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := limitedDecoder(r, &req); err != nil {
		jsonErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		jsonErr(w, 400, "id required")
		return
	}
	if err := a.dom.Remove(req.ID); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}
