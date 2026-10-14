package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tanguard/auth"
	"tanguard/config"
)

// authTestServer boots the real route table with the web dashboard enabled and
// the shipped default login, so the tests exercise the same mux and handlers
// production serves. It returns the base URL and a cookie-aware client.
func authTestServer(t *testing.T) (string, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	api := NewAPI(nil, nil, &config.Config{
		WebEnabled:  true,
		WebUsername: "admin",
		WebPassword: "tanguard",
		DataDir:     dir,
	}, auth.NewCredentialStore(dir), nil, nil)

	srv := httptest.NewServer(api.routes())
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return srv.URL, &http.Client{Jar: jar}
}

func TestWebServesLoginPageInsteadOfBasicPopup(t *testing.T) {
	base, client := authTestServer(t)

	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET / content-type = %q, want text/html", ct)
	}
	if h := resp.Header.Get("WWW-Authenticate"); h != "" {
		t.Errorf("login page must not send a Basic challenge, got %q", h)
	}
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read login page: %v", err)
	}
	for _, marker := range []string{"Sign in to the dashboard", "Set your dashboard login", "Frost-bit-star"} {
		if !strings.Contains(string(page), marker) {
			t.Errorf("login page is missing %q", marker)
		}
	}

	// Any other unauthenticated page resolves to the same sign-in page rather
	// than the dashboard it names.
	resp2, err := client.Get(base + "/index.html")
	if err != nil {
		t.Fatalf("GET /index.html: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("GET /index.html status = %d, want 200", resp2.StatusCode)
	}

	// The login page's own assets stay public so it can render.
	for _, asset := range []string{"/style.css", "/common.js", "/login.js"} {
		r, err := client.Get(base + asset)
		if err != nil {
			t.Fatalf("GET %s: %v", asset, err)
		}
		code := r.StatusCode
		r.Body.Close()
		if code != 200 {
			t.Errorf("GET %s status = %d, want 200", asset, code)
		}
	}

	// API endpoints still answer with JSON, not the login page.
	r, err := client.Get(base + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	defer r.Body.Close()
	if r.StatusCode != 401 {
		t.Errorf("GET /api/status without auth = %d, want 401", r.StatusCode)
	}
}

func TestLoginSessionAuthorizesDashboard(t *testing.T) {
	base, client := authTestServer(t)

	resp := authPost(t, client, base+"/api/login", `{"username":"admin","password":"tanguard"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	var body map[string]interface{}
	decodeJSON(t, resp, &body)
	if body["must_change"] != true {
		t.Errorf("first login must_change = %v, want true", body["must_change"])
	}
	if !hasSessionCookie(client, base) {
		t.Fatal("login did not set a session cookie")
	}

	// The session now authorizes dashboard endpoints and pages.
	r, err := client.Get(base + "/api/auth/status")
	if err != nil {
		t.Fatalf("auth status: %v", err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("auth status with session = %d, want 200", r.StatusCode)
	}

	// Logging out drops the session, and the next call is unauthorized again.
	resp = authPost(t, client, base+"/api/logout", "")
	if resp.StatusCode != 200 {
		t.Fatalf("logout status = %d, want 200", resp.StatusCode)
	}
	decodeJSON(t, resp, &body)
	if body["session"] != true {
		t.Errorf("logout session = %v, want true", body["session"])
	}
	r2, err := client.Get(base + "/api/auth/status")
	if err != nil {
		t.Fatalf("auth status after logout: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != 401 {
		t.Errorf("auth status after logout = %d, want 401", r2.StatusCode)
	}
}

// A signed-in server still on the default login must be able to reach the page
// that lets it change the login; the dashboard's own redirect lands here, so
// bouncing it back to the dashboard would be an endless loop.
func TestLoginPageReachableWhileDefaultCredsInPlace(t *testing.T) {
	base, client := authTestServer(t)
	if resp := authPost(t, client, base+"/api/login", `{"username":"admin","password":"tanguard"}`); resp.StatusCode != 200 {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}

	resp, err := client.Get(base + "/login.html")
	if err != nil {
		t.Fatalf("GET /login.html: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /login.html with defaults in place = %d, want 200", resp.StatusCode)
	}

	// Once a real login is set, the page redirects a signed-in user home.
	resp2 := authPost(t, client, base+"/api/web/credentials",
		`{"username":"operator","password":"longenough1","confirm_password":"longenough1"}`)
	resp2.Body.Close()

	noRedirect := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	r3, err := noRedirect.Get(base + "/login.html")
	if err != nil {
		t.Fatalf("GET /login.html: %v", err)
	}
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusFound {
		t.Errorf("GET /login.html after change = %d, want 302", r3.StatusCode)
	}
}

// First login is a two-step: sign in with the shipped defaults, then set your
// own login. Credentials cannot be set without first authenticating.
func TestFirstLoginForcesCredentialChangeAfterSignIn(t *testing.T) {
	base, client := authTestServer(t)

	// Setting the login before signing in is refused,
	resp := authPost(t, client, base+"/api/web/credentials",
		`{"username":"operator","password":"longenough1","confirm_password":"longenough1"}`)
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated credential change = %d, want 401", resp.StatusCode)
	}

	// and signing in with the defaults reports that a change is owed.
	login := authPost(t, client, base+"/api/login", `{"username":"admin","password":"tanguard"}`)
	var body map[string]interface{}
	decodeJSON(t, login, &body)
	if body["must_change"] != true {
		t.Fatalf("first login must_change = %v, want true", body["must_change"])
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	base, client := authTestServer(t)

	resp := authPost(t, client, base+"/api/login", `{"username":"admin","password":"wrong"}`)
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("bad login status = %d, want 401", resp.StatusCode)
	}
	if h := resp.Header.Get("WWW-Authenticate"); h != "" {
		t.Errorf("failed login must not trigger a Basic popup, got %q", h)
	}
	if hasSessionCookie(client, base) {
		t.Error("failed login must not set a session cookie")
	}
}

func TestChangeCredentialsKeepsSessionAndDropsDefaults(t *testing.T) {
	base, client := authTestServer(t)

	if resp := authPost(t, client, base+"/api/login", `{"username":"admin","password":"tanguard"}`); resp.StatusCode != 200 {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}

	resp := authPost(t, client, base+"/api/web/credentials",
		`{"username":"operator","password":"longenough1","confirm_password":"longenough1"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("change credentials status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// The established session survives the change.
	r, err := client.Get(base + "/api/auth/status")
	if err != nil {
		t.Fatalf("auth status: %v", err)
	}
	if r.StatusCode != 200 {
		t.Fatalf("session should survive a credential change, got %d", r.StatusCode)
	}
	var status map[string]interface{}
	decodeJSON(t, r, &status)
	if status["must_change"] != false {
		t.Errorf("must_change after change = %v, want false", status["must_change"])
	}

	authPost(t, client, base+"/api/logout", "").Body.Close()

	// The shipped defaults are gone; only the new login works.
	if resp := authPost(t, client, base+"/api/login", `{"username":"admin","password":"tanguard"}`); resp.StatusCode != 401 {
		t.Errorf("old default login = %d, want 401", resp.StatusCode)
	}
	resp = authPost(t, client, base+"/api/login", `{"username":"operator","password":"longenough1"}`)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("new login = %d, want 200", resp.StatusCode)
	}
	var body map[string]interface{}
	decodeJSON(t, resp, &body)
	if body["must_change"] != false {
		t.Errorf("must_change after custom creds = %v, want false", body["must_change"])
	}
}

func authPost(t *testing.T, client *http.Client, target, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func hasSessionCookie(client *http.Client, base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == sessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}
