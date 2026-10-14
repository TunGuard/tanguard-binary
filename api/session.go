package api

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"sync"
	"time"
)

// The dashboard signs in through an HTML form instead of the browser's native
// HTTP Basic popup. The form posts credentials once and the server hands back a
// random, opaque session token in an HttpOnly cookie; every later request rides
// that cookie. Basic auth is still accepted so scripts, the SSH gateway and
// curl keep working without a browser.
const (
	sessionCookieName = "tanguard_session"
	sessionTTL        = 12 * time.Hour
)

type sessionStore struct {
	mu     sync.Mutex
	tokens map[string]time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{tokens: make(map[string]time.Time)}
}

// create mints a fresh token and records its expiry. It returns false only when
// the system entropy source fails, which is not something a caller can retry
// around.
func (s *sessionStore) create() (string, bool) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", false
	}
	tok := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.tokens[tok] = time.Now().Add(sessionTTL)
	return tok, true
}

func (s *sessionStore) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.tokens[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.tokens, tok)
		return false
	}
	return true
}

func (s *sessionStore) drop(tok string) {
	if tok == "" {
		return
	}
	s.mu.Lock()
	delete(s.tokens, tok)
	s.mu.Unlock()
}

// clearAll invalidates every session. A credential change calls it so a token
// minted under the old password cannot keep using the dashboard.
func (s *sessionStore) clearAll() {
	s.mu.Lock()
	s.tokens = make(map[string]time.Time)
	s.mu.Unlock()
}

func (s *sessionStore) pruneLocked() {
	now := time.Now()
	for k, exp := range s.tokens {
		if now.After(exp) {
			delete(s.tokens, k)
		}
	}
}

// secureCookies ties the cookie's Secure flag to whether the dashboard itself
// is served over TLS, so an HTTPS deployment never leaks the token over plain
// HTTP and a plain-HTTP one still gets a working login.
func (a *API) secureCookies() bool {
	return a.cfg != nil && a.cfg.TLSCertFile != "" && a.cfg.TLSKeyFile != ""
}

func (a *API) setSessionCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.secureCookies(),
		MaxAge:   int(sessionTTL / time.Second),
	})
}

func (a *API) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.secureCookies(),
		MaxAge:   -1,
	})
}

func (a *API) sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// handleLogin is the public endpoint behind the dashboard sign-in form. On
// success it establishes a session cookie; the response tells the page whether
// the shipped default login is still in place so it can move on to the "set
// your login" step.
func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := limitedDecoder(r, &req); err != nil {
		jsonErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if !a.creds.VerifyWeb(req.Username, req.Password, a.cfg.WebUsername, a.cfg.WebPassword) {
		jsonErr(w, 401, "invalid username or password")
		return
	}
	if a.sess == nil {
		jsonErr(w, 500, "sessions are not available")
		return
	}
	tok, ok := a.sess.create()
	if !ok {
		jsonErr(w, 500, "could not create session")
		return
	}
	a.setSessionCookie(w, tok)
	log.Printf("[api] web login for user %q", req.Username)
	jsonResp(w, 200, map[string]interface{}{
		"success":     true,
		"username":    req.Username,
		"must_change": a.usingDefaultWebCreds(),
	})
}

// handleLogout is public on purpose: an expired or already-forgotten session
// still needs to be able to clear its cookie. The "session" field lets the page
// tell a cookie login (which can truly sign out) from a Basic-auth one (which
// the browser keeps re-sending).
func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}
	had := a.sess != nil && a.sess.valid(a.sessionToken(r))
	if a.sess != nil {
		a.sess.drop(a.sessionToken(r))
	}
	a.clearSessionCookie(w)
	jsonResp(w, 200, map[string]interface{}{
		"success": true,
		"session": had,
	})
}
