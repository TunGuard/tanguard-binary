package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"tanguard/auth"
	"tanguard/config"
	"tanguard/internal/testenv"
	"tanguard/p2p"
	"tanguard/peers"
	"tanguard/policy"
	"tanguard/trp"
)

// startTestHub boots a control plane on free ports and returns it, wired to a
// TRP manager the way main wires them at startup.
func startTestHub(t *testing.T) *p2p.MeshHub {
	t.Helper()
	t.Setenv("MESH_ENABLED", "true")
	t.Setenv("MESH_DATA_DIR", t.TempDir())
	t.Setenv("CONTROL_LISTEN", fmt.Sprintf("127.0.0.1:%d", testenv.FreePort(t)))
	t.Setenv("RELAY_LISTEN", fmt.Sprintf("127.0.0.1:%d", testenv.FreeUDPPort(t)))
	// A long control timeout keeps a test that pauses between frames from
	// looking like a dead link.
	t.Setenv("CONTROL_TIMEOUT_S", "60")

	h := p2p.StartMesh(nil)
	if h == nil {
		t.Fatal("StartMesh returned nil")
	}
	t.Cleanup(h.Close)
	return h
}

// meshAPIServer boots a hub and serves the mesh/TRP routes on a local port,
// returning the base URL. Requests are made with the dashboard login because
// every route is wrapped in requireAPI.
func meshAPIServer(t *testing.T) string {
	t.Helper()
	h := startTestHub(t)

	api := &API{
		creds:    auth.NewCredentialStore(t.TempDir()),
		store:    peers.NewPeerStore(t.TempDir()),
		policies: policy.NewPolicyStore(t.TempDir()),
		cfg: &config.Config{
			WebUsername: "admin",
			WebPassword: "test-password",
		},
	}
	api.SetMesh(h, trp.NewTRPManager(h, h.ProxiesPath()))
	mux := http.NewServeMux()
	registerMeshRoutes(mux, api)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listener: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}

func meshCall(t *testing.T, base, method, path, body string) (int, map[string]interface{}) {
	t.Helper()
	var rdr *strings.Reader = strings.NewReader(body)
	req, err := http.NewRequest(method, base+path, rdr)
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

// TestMeshAPIRequiresAuth locks the documented rule that P2P/TRP automation
// cannot read or change the mesh without a dashboard login or API key.
func TestMeshAPIRequiresAuth(t *testing.T) {
	base := meshAPIServer(t)

	for _, path := range []string{"/api/mesh/status", "/api/trp/proxies", "/api/mesh/nodes"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("GET %s without credentials: got %d, want 401", path, resp.StatusCode)
		}
	}

	// A bad API key must not be accepted either.
	req, _ := http.NewRequest("GET", base+"/api/mesh/status", nil)
	req.Header.Set("X-API-Key", "not-a-real-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bad api key: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("bad API key: got %d, want 401", resp.StatusCode)
	}
}

// TestMeshAPIMutatingRoutesArePostOnly documents the 405 the README tells
// scripts to expect.
func TestMeshAPIMutatingRoutesArePostOnly(t *testing.T) {
	base := meshAPIServer(t)

	posts := []string{
		"/api/mesh/node/add", "/api/mesh/node/remove", "/api/mesh/node/reset",
		"/api/mesh/relay/join", "/api/mesh/relay/leave",
		"/api/mesh/relay/link", "/api/mesh/relay/unlink",
		"/api/mesh/p2p/connect", "/api/mesh/p2p/mesh",
		"/api/trp/proxy/add", "/api/trp/proxy/remove",
	}
	for _, path := range posts {
		code, body := meshCall(t, base, "GET", path, "")
		if code != 405 {
			t.Errorf("GET %s: got %d, want 405", path, code)
		}
		if err, _ := body["error"].(string); !strings.Contains(err, "POST") {
			t.Errorf("GET %s: error = %q, want it to mention POST", path, err)
		}
	}
}

// TestMeshAPIRejectsBadInput pins the validation errors the README documents.
func TestMeshAPIRejectsBadInput(t *testing.T) {
	base := meshAPIServer(t)

	cases := []struct {
		name, path, body, wantErr string
	}{
		{"node/remove without id", "/api/mesh/node/remove", `{}`, "id required"},
		{"trp/add without node_id", "/api/trp/proxy/add",
			`{"bind_port":"9000","target_port":"80"}`, "node_id required"},
		{"trp/add bind_port zero", "/api/trp/proxy/add",
			`{"node_id":"n1","bind_port":"0","target_port":"80"}`, "bind_port"},
		{"trp/add target_port range", "/api/trp/proxy/add",
			`{"node_id":"n1","bind_port":"9000","target_port":"99999"}`, "target_port"},
		{"p2p/mesh unknown group", "/api/mesh/p2p/mesh", `{"group":"nope"}`, "unknown group"},
		{"malformed json", "/api/mesh/node/add", `{not json`, "invalid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := meshCall(t, base, "POST", tc.path, tc.body)
			if code != 400 {
				t.Errorf("got %d, want 400", code)
			}
			if err, _ := body["error"].(string); !strings.Contains(err, tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestMeshAPI503WhenControlPlaneDown documents the failure automation should
// expect when the mesh was not started.
func TestMeshAPI503WhenControlPlaneDown(t *testing.T) {
	api := &API{creds: auth.NewCredentialStore(t.TempDir()), cfg: &config.Config{
		WebUsername: "admin",
		WebPassword: "test-password",
	}}
	mux := http.NewServeMux()
	registerMeshRoutes(mux, api)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listener: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()
	base := "http://" + ln.Addr().String()

	for _, path := range []string{"/api/mesh/status", "/api/mesh/nodes", "/api/trp/proxies"} {
		code, body := meshCall(t, base, "GET", path, "")
		if code != 503 {
			t.Errorf("GET %s: got %d, want 503", path, code)
		}
		if err, _ := body["error"].(string); !strings.Contains(err, "disabled") {
			t.Errorf("GET %s: error = %q, want it to mention disabled", path, err)
		}
	}
}

// TestTRPProxyLifecycle covers the add/list/remove flow the README example
// scripts, including the auto-assigned bind port.
func TestTRPProxyLifecycle(t *testing.T) {
	base := meshAPIServer(t)

	code, add := meshCall(t, base, "POST", "/api/mesh/node/add", `{"name":"edge-a"}`)
	if code != 200 {
		t.Fatalf("node/add: got %d, want 200", code)
	}
	nodeID, _ := add["id"].(string)
	if nodeID == "" {
		t.Fatalf("node/add returned no id: %v", add)
	}

	// An empty bind_port means "pick one for me".
	code, add = meshCall(t, base, "POST", "/api/trp/proxy/add",
		`{"node_id":"`+nodeID+`","bind_port":"","target_port":"8022"}`)
	if code != 200 {
		t.Fatalf("trp/add: got %d, want 200 (%v)", code, add)
	}
	proxyID, _ := add["id"].(string)
	if proxyID == "" {
		t.Fatalf("trp/add returned no id: %v", add)
	}
	if pub, _ := add["public_url"].(string); pub == "" || strings.HasSuffix(pub, ":0") {
		t.Errorf("public_url = %q, want a concrete port", pub)
	}

	code, list := meshCall(t, base, "GET", "/api/trp/proxies", "")
	if code != 200 {
		t.Fatalf("trp/proxies: got %d, want 200", code)
	}
	proxies, _ := list["proxies"].([]interface{})
	if len(proxies) != 1 {
		t.Fatalf("got %d proxies, want 1", len(proxies))
	}

	if code, _ = meshCall(t, base, "POST", "/api/trp/proxy/remove", `{"id":"`+proxyID+`"}`); code != 200 {
		t.Errorf("trp/remove: got %d, want 200", code)
	}
	// Removing it twice is a 404, so scripts can detect a missing binding.
	if code, _ = meshCall(t, base, "POST", "/api/trp/proxy/remove", `{"id":"`+proxyID+`"}`); code != 404 {
		t.Errorf("second trp/remove: got %d, want 404", code)
	}
}

// TestNodeNamesAreNotUnique guards a subtlety the README calls out: name is a
// label, id is the key, so two nodes may share a name.
func TestNodeNamesAreNotUnique(t *testing.T) {
	base := meshAPIServer(t)

	_, first := meshCall(t, base, "POST", "/api/mesh/node/add", `{"name":"edge-a"}`)
	_, second := meshCall(t, base, "POST", "/api/mesh/node/add", `{"name":"edge-a"}`)
	firstID, _ := first["id"].(string)
	secondID, _ := second["id"].(string)

	if firstID == "" || secondID == "" {
		t.Fatalf("expected both adds to succeed: %v %v", first, second)
	}
	if firstID == secondID {
		t.Errorf("duplicate names must still get distinct ids, both got %q", firstID)
	}

	code, _ := meshCall(t, base, "POST", "/api/mesh/node/remove", `{"id":"`+firstID+`"}`)
	if code != 200 {
		t.Errorf("removing by id: got %d, want 200", code)
	}
	// An unknown id is a 404, distinct from a validation 400.
	if code, _ = meshCall(t, base, "POST", "/api/mesh/node/remove", `{"id":"deadbeef"}`); code != 404 {
		t.Errorf("removing unknown id: got %d, want 404", code)
	}
}

// TestMeshAPIServesP2PAndTRP checks the two pages the user asked for are wired
// to endpoints that actually return data.
func TestMeshAPIServesP2PAndTRP(t *testing.T) {
	base := meshAPIServer(t)

	client := &http.Client{}
	get := func(path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("GET", base+path, nil)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		req.SetBasicAuth("admin", "test-password")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		json.NewDecoder(resp.Body).Decode(new(interface{}))
		resp.Body.Close()
		return resp
	}

	for _, path := range []string{
		"/api/mesh/status",
		"/api/mesh/nodes",
		"/api/mesh/groups",
		"/api/mesh/links",
		"/api/trp/proxies",
	} {
		if code := get(path).StatusCode; code != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200", path, code)
		}
	}

	// A missing group must be an error, not a silent success. This one has to be
	// a POST: the handler rejects other methods before it ever looks at the body.
	req, err := http.NewRequest("POST", base+"/api/mesh/p2p/mesh", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("admin", "test-password")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /api/mesh/p2p/mesh: %v", err)
	}
	var v interface{}
	json.NewDecoder(resp.Body).Decode(&v)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/mesh/p2p/mesh without a group returned %d, want 400", resp.StatusCode)
	}
}
