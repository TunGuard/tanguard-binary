package api

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// adguardUIPrefix is where the AdGuard Home admin UI is exposed. It is served
// behind the dashboard login so the AdGuard port itself can stay on loopback.
const adguardUIPrefix = "/adguard-ui"

// handleAdGuardUI reverse-proxies the AdGuard Home admin UI through the
// authenticated dashboard. AdGuard's frontend references everything relatively
// (assets, its "control" API), so mounting it under a trailing-slash subpath
// works without rewriting the bundle; only absolute Location redirects need the
// prefix re-applied.
func (a *API) handleAdGuardUI(w http.ResponseWriter, r *http.Request) {
	if a.adg == nil || !a.adg.IsRunning() {
		http.Error(w, "AdGuard Home is not running", http.StatusServiceUnavailable)
		return
	}
	target, err := url.Parse("http://" + a.adg.WebAddr())
	if err != nil {
		http.Error(w, "AdGuard Home address is invalid", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.URL.Path = strings.TrimPrefix(req.URL.Path, adguardUIPrefix)
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		req.URL.RawPath = ""
		req.Host = target.Host
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		loc := resp.Header.Get("Location")
		if loc != "" && strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, adguardUIPrefix) {
			resp.Header.Set("Location", adguardUIPrefix+loc)
		}
		return nil
	}
	proxy.ServeHTTP(w, r)
}

// syncAdGuardAuth mirrors the current dashboard login onto the AdGuard UI. It is
// called after the dashboard credentials change so the two stay in step.
func (a *API) syncAdGuardAuth() {
	if a == nil || a.adg == nil || a.creds == nil {
		return
	}
	if user, hash, err := a.creds.EffectiveHash(a.cfg.WebUsername, a.cfg.WebPassword); err == nil {
		a.adg.SetAuth(user, hash)
	}
}
