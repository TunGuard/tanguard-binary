package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tanguard/auth"
	"tanguard/config"
	"tanguard/p2p"
	"tanguard/peers"
	"tanguard/policy"
	"tanguard/trp"
	"tanguard/wg"
)

// testPolicyStore returns a loaded policy store with the default group in place.
func testPolicyStore(t *testing.T) *policy.PolicyStore {
	t.Helper()
	ps := policy.NewPolicyStore(t.TempDir())
	if err := ps.Load(); err != nil {
		t.Fatalf("policy load: %v", err)
	}
	return ps
}

// policyAPIServer serves the policy routes over a local port with a couple of
// peers already registered, mirroring the mesh API test's harness.
func policyAPIServer(t *testing.T) (base string, store *peers.PeerStore, policies *policy.PolicyStore) {
	t.Helper()
	return policyAPIServerWithHub(t, nil)
}

// policyAPIServerWithHub serves the policy routes with a control plane attached,
// which the device-id endpoints need because they resolve a device through the
// hub's node list rather than the WireGuard peer list.
func policyAPIServerWithHub(t *testing.T, hub *p2p.MeshHub) (base string, store *peers.PeerStore, policies *policy.PolicyStore) {
	t.Helper()
	store = peers.NewPeerStore(t.TempDir())
	store.Add(&peers.PeerRecord{PublicKey: "keyA", AllowedIP: "10.100.0.2/32", DeviceID: "devA", DeviceName: "Laptop"})
	store.Add(&peers.PeerRecord{PublicKey: "keyB", AllowedIP: "10.100.0.3/32", DeviceID: "devB", DeviceName: "Phone"})

	policies = policy.NewPolicyStore(t.TempDir())
	if err := policies.Load(); err != nil {
		t.Fatalf("policy load: %v", err)
	}

	api := &API{
		creds:    auth.NewCredentialStore(t.TempDir()),
		cfg:      &config.Config{WebUsername: "admin", WebPassword: "test-password"},
		store:    store,
		policies: policies,
	}
	if hub != nil {
		api.SetMesh(hub, trp.NewTRPManager(hub, hub.ProxiesPath()))
	}
	mux := http.NewServeMux()
	registerPolicyRoutes(mux, api)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listener: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String(), store, policies
}

func policyCall(t *testing.T, base, method, path, body string) (int, map[string]interface{}) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, strings.NewReader(body))
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

func TestPolicyAPIRequiresAuth(t *testing.T) {
	base, _, _ := policyAPIServer(t)

	for _, path := range []string{
		"/api/policy/groups",
		"/api/policy/group/create",
		"/api/policy/group/delete",
		"/api/policy/group/assign",
		"/api/policy/apply",
	} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("GET %s without credentials: got %d, want 401", path, resp.StatusCode)
		}
	}
}

func TestPolicyAPIRejectsNonPostMutations(t *testing.T) {
	base, _, _ := policyAPIServer(t)
	if code, _ := policyCall(t, base, "GET", "/api/policy/group/create", ""); code != 405 {
		t.Errorf("GET create: got %d, want 405", code)
	}
	if code, _ := policyCall(t, base, "GET", "/api/policy/group/assign", ""); code != 405 {
		t.Errorf("GET assign: got %d, want 405", code)
	}
}

// TestPolicyAPIDefaultsAreUsableBeforeAnythingIsConfigured is the API view of
// the "do not affect the default" guarantee: with no policy sent, the groups
// endpoint reports every device on the permissive default group.
func TestPolicyAPIDefaultsAreUsableBeforeAnythingIsConfigured(t *testing.T) {
	base, _, policies := policyAPIServer(t)

	code, out := policyCall(t, base, "GET", "/api/policy/groups", "")
	if code != 200 {
		t.Fatalf("GET groups: got %d, want 200", code)
	}
	groups, _ := out["groups"].([]interface{})
	if len(groups) != 1 {
		t.Fatalf("a fresh server must report only the default group, got %d", len(groups))
	}
	def, _ := groups[0].(map[string]interface{})
	if def["id"] != policy.DefaultPolicyGroupID {
		t.Errorf("group id = %v, want %q", def["id"], policy.DefaultPolicyGroupID)
	}
	for _, rule := range []string{"allow_inter_device", "allow_p2p_mesh", "allow_trp", "allow_wg_access"} {
		if def[rule] != true {
			t.Errorf("default group %s = %v, want true", rule, def[rule])
		}
	}
	// Both devices are listed, both in the default group.
	devices, _ := def["devices"].([]interface{})
	if len(devices) != 2 {
		t.Fatalf("default group should hold both devices, got %d", len(devices))
	}
	if policies.IsActive() {
		t.Error("no policy was sent, so the layer must stay inactive")
	}
}

func TestPolicyAPICreateAssignLifecycle(t *testing.T) {
	base, _, _ := policyAPIServer(t)

	code, out := policyCall(t, base, "POST", "/api/policy/group/create",
		`{"name":"Guest Network","allow_wg_access":true}`)
	if code != 200 {
		t.Fatalf("create: got %d (%v)", code, out)
	}
	group, _ := out["group"].(map[string]interface{})
	id, _ := group["id"].(string)
	if id == "" {
		t.Fatalf("create returned no group id: %v", out)
	}
	// Rules the caller did not mention must stay off.
	if group["allow_p2p_mesh"] != false {
		t.Errorf("an unmentioned rule must default to false, got %v", group["allow_p2p_mesh"])
	}
	if group["allow_wg_access"] != true {
		t.Errorf("the rule that was sent must be applied, got %v", group["allow_wg_access"])
	}

	if code, out := policyCall(t, base, "POST", "/api/policy/group/assign",
		`{"id":"`+id+`","devices":["keyA"]}`); code != 200 {
		t.Fatalf("assign: got %d (%v)", code, out)
	}

	code, out = policyCall(t, base, "GET", "/api/policy/groups", "")
	if code != 200 {
		t.Fatalf("GET groups: got %d", code)
	}
	groups, _ := out["groups"].([]interface{})
	if len(groups) != 2 {
		t.Fatalf("want 2 groups, got %d", len(groups))
	}
	// The default group is listed first; the custom group second.
	def := groups[0].(map[string]interface{})
	if def["id"] != policy.DefaultPolicyGroupID {
		t.Fatalf("the default group must be listed first, got %v", def["id"])
	}
	guests := groups[1].(map[string]interface{})
	if guests["name"] != "Guest Network" {
		t.Fatalf("second group = %v, want the created group", guests["name"])
	}
	devices, _ := guests["devices"].([]interface{})
	if len(devices) != 1 || devices[0].(map[string]interface{})["device_name"] != "Laptop" {
		t.Errorf("guests group devices = %v, want just the Laptop", devices)
	}
	// The device that was not assigned must still be on the default group,
	// because it was never moved.
	defDevices, _ := def["devices"].([]interface{})
	if len(defDevices) != 1 || defDevices[0].(map[string]interface{})["device_name"] != "Phone" {
		t.Errorf("default group devices = %v, want just the Phone", defDevices)
	}

	if code, out := policyCall(t, base, "POST", "/api/policy/group/unassign",
		`{"id":"`+id+`","devices":["keyA"]}`); code != 200 {
		t.Fatalf("unassign: got %d (%v)", code, out)
	}
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/delete",
		`{"id":"`+id+`"}`); code != 200 {
		t.Errorf("delete after emptying: got %d, want 200", code)
	}
}

// TestPolicyAPIUpdateKeepsUnmentionedRules covers the pointer-payload contract:
// an update naming one switch must not clear the other three.
func TestPolicyAPIUpdateKeepsUnmentionedRules(t *testing.T) {
	base, _, _ := policyAPIServer(t)

	_, out := policyCall(t, base, "POST", "/api/policy/group/create",
		`{"name":"Guests","allow_inter_device":true,"allow_wg_access":true}`)
	id := out["group"].(map[string]interface{})["id"].(string)

	// Only one rule is mentioned.
	code, out := policyCall(t, base, "POST", "/api/policy/group/update",
		`{"id":"`+id+`","allow_inter_device":false}`)
	if code != 200 {
		t.Fatalf("update: got %d (%v)", code, out)
	}
	g := out["group"].(map[string]interface{})
	if g["allow_inter_device"] != false {
		t.Error("the rule that was sent must be applied")
	}
	if g["allow_wg_access"] != true {
		t.Error("an unmentioned rule must keep its value across an API update")
	}
	if g["name"] != "Guests" {
		t.Errorf("an update with no name must keep the old one, got %v", g["name"])
	}
}

func TestPolicyAPIRejectsBadInput(t *testing.T) {
	base, _, _ := policyAPIServer(t)

	if code, _ := policyCall(t, base, "POST", "/api/policy/group/create", `{"name":"  "}`); code != 400 {
		t.Errorf("blank name: got %d, want 400", code)
	}
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/create", `{}`); code != 400 {
		t.Errorf("missing name: got %d, want 400", code)
	}
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/update", `{"name":"x"}`); code != 400 {
		t.Errorf("missing id: got %d, want 400", code)
	}
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/assign",
		`{"id":"nope","devices":["keyA"]}`); code != 400 {
		t.Errorf("unknown group: got %d, want 400", code)
	}

	// Assigning a device that does not exist must be refused outright.
	_, out := policyCall(t, base, "POST", "/api/policy/group/create", `{"name":"Guests"}`)
	id := out["group"].(map[string]interface{})["id"].(string)
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/assign",
		`{"id":"`+id+`","devices":["keyZ"]}`); code != 400 {
		t.Errorf("unknown device: got %d, want 400", code)
	}
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/assign",
		`{"id":"`+id+`","devices":[]}`); code != 400 {
		t.Errorf("empty device list: got %d, want 400", code)
	}
	// The default group must not be assignable or editable through the API.
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/assign",
		`{"id":"`+policy.DefaultPolicyGroupID+`","devices":["keyA"]}`); code != 400 {
		t.Errorf("assigning into the default group: got %d, want 400", code)
	}
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/update",
		`{"id":"`+policy.DefaultPolicyGroupID+`","allow_wg_access":false}`); code != 400 {
		t.Errorf("editing the default group: got %d, want 400", code)
	}
	if code, _ := policyCall(t, base, "POST", "/api/policy/group/delete",
		`{"id":"`+policy.DefaultPolicyGroupID+`"}`); code != 400 {
		t.Errorf("deleting the default group: got %d, want 400", code)
	}
}

// TestPolicyAPIApplyBulk covers the single-call path an automation client uses
// to declare the whole policy at once.
func TestPolicyAPIApplyBulk(t *testing.T) {
	base, _, _ := policyAPIServer(t)

	code, out := policyCall(t, base, "POST", "/api/policy/group/create", `{"name":"Temp"}`)
	if code != 200 {
		t.Fatalf("create: %v", out)
	}
	tempID := out["group"].(map[string]interface{})["id"].(string)

	// Applying without naming that group drops it: apply is a full replace.
	code, out = policyCall(t, base, "POST", "/api/policy/apply", `{
		"groups":[{"name":"Guests","allow_wg_access":true,"id":"guests"}],
		"assign":{"keyA":"guests"}
	}`)
	if code != 200 {
		t.Fatalf("apply: got %d (%v)", code, out)
	}
	if out["active"] != true {
		t.Error("applying a custom group must activate enforcement")
	}
	if out["assigned"] != float64(1) {
		t.Errorf("assigned = %v, want 1", out["assigned"])
	}

	code, out = policyCall(t, base, "GET", "/api/policy/groups", "")
	if code != 200 {
		t.Fatalf("GET groups: %v", out)
	}
	groups, _ := out["groups"].([]interface{})
	if len(groups) != 2 {
		t.Fatalf("apply must have replaced the state: got %d groups, want 2", len(groups))
	}

	// A payload naming a device that does not exist changes nothing.
	code, _ = policyCall(t, base, "POST", "/api/policy/apply", `{
		"groups":[{"name":"Guests","id":"guests"}],
		"assign":{"keyZ":"guests"}
	}`)
	if code != 400 {
		t.Errorf("apply with an unknown device: got %d, want 400", code)
	}
	code, out = policyCall(t, base, "GET", "/api/policy/groups", "")
	groups, _ = out["groups"].([]interface{})
	if len(groups) != 2 || groups[1].(map[string]interface{})["name"] != "Guests" {
		t.Errorf("a rejected apply must leave the previous policy in place, got %v", out)
	}

	// Clearing every custom group returns the server to unrestricted behaviour.
	if code, out = policyCall(t, base, "POST", "/api/policy/apply",
		`{"groups":[],"assign":{}}`); code != 200 {
		t.Fatalf("clear: %v", out)
	}
	if out["active"] != false {
		t.Error("clearing every custom group must deactivate enforcement")
	}
	if out["default_open"] != true {
		t.Error("the default group must always remain open")
	}
	_ = tempID
}

// TestPolicyGroupsWithAnUnnamedShortKeyPeer covers a peers.json that was
// hand-edited or truncated. Load does not validate key length, so building the
// response must not slice a key that is shorter than the label width: a panic
// in a handler would take the whole policy page down.
func TestPolicyGroupsWithAnUnnamedShortKeyPeer(t *testing.T) {
	dir := t.TempDir()
	// Written straight to disk: the store loads whatever is in the file. Two
	// peers are needed so the response actually sorts them, which is where the
	// label is built.
	if err := os.WriteFile(filepath.Join(dir, "peers.json"), []byte(`[
		{"public_key":"short","allowed_ip":"10.100.0.9/32"},
		{"public_key":"tiny","allowed_ip":"10.100.0.8/32"}
	]`), 0o600); err != nil {
		t.Fatalf("write peers: %v", err)
	}
	store := peers.NewPeerStore(dir)
	if err := store.Load(); err != nil {
		t.Fatalf("load peers: %v", err)
	}
	policies := policy.NewPolicyStore(dir)

	a := &API{store: store, policies: policies, wg: new(wg.WgServer)}
	rec := httptest.NewRecorder()
	a.handlePolicyGroups(rec, httptest.NewRequest("GET", "/api/policy/groups", nil))

	if rec.Code != 200 {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Peers) != 2 {
		t.Fatalf("got %d peers, want 2: %+v", len(got.Peers), got.Peers)
	}
	// Sorted by label, so "short" comes before "tiny".
	if got.Peers[0].PublicKey != "short" || got.Peers[1].PublicKey != "tiny" {
		t.Fatalf("unexpected peer order: %+v", got.Peers)
	}
}

// TestBackupCoversPolicyGroups guards the backup file list. Policy groups are
// deliberate admin configuration; a backup that silently omits them would
// un-restrict the network on restore without saying so.
func TestBackupCoversPolicyGroups(t *testing.T) {
	a := &API{cfg: &config.Config{DataDir: t.TempDir()}}
	var found bool
	for _, sf := range a.backupStateFiles() {
		if sf.name != "policy_groups.json" {
			continue
		}
		found = true
		if sf.perm != 0600 {
			t.Errorf("policy_groups.json perm is %o, want 600", sf.perm)
		}
		if sf.required {
			t.Error("policy_groups.json must be optional: a server with no policy has no file, and that backup is still valid")
		}
	}
	if !found {
		t.Error("policy_groups.json is missing from backupStateFiles()")
	}
}

// TestBackupPolicyValidationRejectsADefaultGroup covers the check a restore runs
// before it touches live state. An archive must not be able to install a policy
// that shadows the default group, which is the one guarantee that keeps a bad
// restore from locking every device out of the network.
func TestBackupPolicyValidationRejectsADefaultGroup(t *testing.T) {
	bad := []struct {
		name string
		pf   policy.PolicyFile
	}{
		{"declares the default group", policy.PolicyFile{Groups: []*policy.PolicyGroup{
			{ID: policy.DefaultPolicyGroupID, Name: "Mine", AllowWGAccess: false},
		}}},
		{"duplicate id", policy.PolicyFile{Groups: []*policy.PolicyGroup{
			{ID: "dup", Name: "A"}, {ID: "dup", Name: "B"},
		}}},
		{"name collision", policy.PolicyFile{Groups: []*policy.PolicyGroup{
			{ID: "a", Name: "Same"}, {ID: "b", Name: "same"},
		}}},
		{"empty name", policy.PolicyFile{Groups: []*policy.PolicyGroup{{ID: "a", Name: "  "}}}},
		{"membership names an unknown group", policy.PolicyFile{
			Groups: []*policy.PolicyGroup{{ID: "a", Name: "A"}},
			Assign: map[string]string{"keyA": "ghost"},
		}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.pf.ValidateAgainst(nil, nil); err == nil {
				t.Error("a restore must reject this policy before writing anything")
			}
		})
	}

	// A normal archive still validates, and unknown peers are allowed here
	// because the archive carries its own peers.json.
	ok := policy.PolicyFile{
		Groups: []*policy.PolicyGroup{{ID: "a", Name: "Guests", AllowWGAccess: true}},
		Assign: map[string]string{"keyA": "a"},
	}
	groups, err := ok.ValidateAgainst(nil, nil)
	if err != nil {
		t.Fatalf("a valid policy was rejected: %v", err)
	}
	if len(groups) != 2 {
		t.Errorf("got %d groups, want 2 (Guests plus the default group)", len(groups))
	}
}

// TestRestoreIntoMeshOnlyServerDoesNotPanic covers restoring a full-server
// backup into a process started with -mesh-only, which has no WireGuard server
// object at all. The archive carries a server_private.key, and reconfiguring a
// nil server used to panic and take the request down with no response. The
// peers, policy groups and credentials must still restore.
func TestRestoreIntoMeshOnlyServerDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	// Restore validates every archived key, so the archive and the live store
	// have to use a real 32-byte key rather than a test shorthand.
	priv, pubBytes, err := config.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub := hex.EncodeToString(pubBytes)
	store := peers.NewPeerStore(dir)
	store.Add(&peers.PeerRecord{PublicKey: pub, AllowedIP: "10.100.0.2/32", DeviceID: "devA", DeviceName: "Laptop"})
	policies := policy.NewPolicyStore(dir)
	if err := policies.Load(); err != nil {
		t.Fatalf("load policies: %v", err)
	}

	a := &API{
		cfg:      &config.Config{DataDir: dir, ListenPort: 51820},
		store:    store,
		policies: policies,
		creds:    auth.NewCredentialStore(dir),
		apiKey:   auth.NewAPIKeyStore(dir),
		wg:       nil, // exactly what -mesh-only leaves behind
	}

	// Build the archive the way handleBackupDownload does.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	write := func(name, body string) {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0600, Size: int64(len(body)),
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	write("peers.json",
		`[{"public_key":"`+pub+`","allowed_ip":"10.100.0.2/32","device_name":"Laptop"}]`)
	// A group that restricts the device, so the restore has something to prove.
	write("policy_groups.json",
		`{"groups":[{"id":"gA","name":"Guests","allow_wg_access":true}],"assign":{"`+pub+`":"gA"}}`)
	write("server_private.key", hex.EncodeToString(priv))
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("backup", "backup.tar.gz")
	if err != nil {
		t.Fatalf("multipart: %v", err)
	}
	if _, err := part.Write(buf.Bytes()); err != nil {
		t.Fatalf("write part: %v", err)
	}
	mw.Close()

	req := httptest.NewRequest("POST", "/api/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()

	// A panic here fails the test rather than being swallowed by net/http.
	a.handleBackupRestore(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	// Peers and policy groups must both be live after the restore.
	if got := len(a.store.All()); got != 1 {
		t.Errorf("got %d peers after restore, want 1", got)
	}
	g := a.policies.GroupForPeer(pub)
	if g == nil || g.Name != "Guests" {
		t.Fatalf("device is not in the restored group, got %+v", g)
	}
	if !g.AllowWGAccess || g.AllowInterDevice {
		t.Errorf("restored rules are wrong: %+v", g)
	}
	if ondisk, err := os.ReadFile(filepath.Join(dir, "policy_groups.json")); err != nil {
		t.Errorf("policy_groups.json was not written: %v", err)
	} else if !strings.Contains(string(ondisk), "Guests") {
		t.Errorf("policy_groups.json on disk does not hold the restored group: %s", ondisk)
	}
}

// TestRestoreRejectsAPolicyThatShadowsTheDefaultGroup makes sure the restore
// path validates before it writes, using the same checks an apply does.
func TestRestoreRejectsAPolicyThatShadowsTheDefaultGroup(t *testing.T) {
	dir := t.TempDir()
	store := peers.NewPeerStore(dir)
	policies := policy.NewPolicyStore(dir)
	a := &API{
		cfg:      &config.Config{DataDir: dir, ListenPort: 51820},
		store:    store,
		policies: policies,
		creds:    auth.NewCredentialStore(dir),
		apiKey:   auth.NewAPIKeyStore(dir),
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	write := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	priv, pubBytes, _ := config.GenerateKeyPair()
	pub := hex.EncodeToString(pubBytes)
	write("peers.json", `[{"public_key":"`+pub+`","allowed_ip":"10.100.0.2/32"}]`)
	write("policy_groups.json",
		`{"groups":[{"id":"default","name":"Mine","allow_wg_access":false}],"assign":{}}`)
	write("server_private.key", hex.EncodeToString(priv))
	tw.Close()
	zw.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("backup", "backup.tar.gz")
	part.Write(buf.Bytes())
	mw.Close()

	req := httptest.NewRequest("POST", "/api/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	a.handleBackupRestore(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "default group") {
		t.Errorf("error should name the default group, got %s", rec.Body.String())
	}
	// Nothing may have been written.
	if _, err := os.Stat(filepath.Join(dir, "policy_groups.json")); !os.IsNotExist(err) {
		t.Error("a rejected archive must not leave policy_groups.json behind")
	}
}

// The policy page used to list only WireGuard peers, so a tun-client device was
// invisible: it could not be seen and, because enforcement resolved a device id
// through the peer list, not even restricted. Both kinds of device have to show
// up, each labelled by how it is grouped.
func TestPolicyGroupsListsClientDevices(t *testing.T) {
	hub := startTestHub(t)
	node, err := hub.AddNode("edge-phone", "")
	if err != nil {
		t.Fatalf("addNode: %v", err)
	}
	// A client reports its identity on connect; that is what a policy group can
	// name it by.
	hub.SetDeviceID(node.ID, "phone001")

	store := peers.NewPeerStore(t.TempDir())
	if err := store.Load(); err != nil {
		t.Fatalf("peer load: %v", err)
	}
	store.Add(&peers.PeerRecord{PublicKey: "peerkeypeerkeypeerkeypeerkeypeerkeypeerkeypeerkey=", AllowedIP: "10.100.0.2/32", DeviceID: "wgdev01"})

	a := &API{store: store, policies: testPolicyStore(t), wg: new(wg.WgServer)}
	a.SetMesh(hub, trp.NewTRPManager(hub, hub.ProxiesPath()))
	rec := httptest.NewRecorder()
	a.handlePolicyGroups(rec, httptest.NewRequest("GET", "/api/policy/groups", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Peers []struct {
			PublicKey    string `json:"public_key"`
			DeviceID     string `json:"device_id"`
			DeviceName   string `json:"device_name"`
			ClientDevice bool   `json:"client_device"`
			GroupID      string `json:"group_id"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var sawPeer, sawClient bool
	for _, d := range got.Peers {
		if d.ClientDevice {
			sawClient = true
			if d.DeviceID != "phone001" {
				t.Errorf("client device listed with device id %q, want phone001", d.DeviceID)
			}
			if d.DeviceName != "edge-phone" {
				t.Errorf("client device name %q, want edge-phone", d.DeviceName)
			}
			if d.PublicKey != "" {
				t.Errorf("a client device must not claim a public key: %q", d.PublicKey)
			}
		} else if d.PublicKey != "" {
			sawPeer = true
		}
	}
	if !sawClient {
		t.Error("the tun-client device is missing from the devices list")
	}
	if !sawPeer {
		t.Error("the WireGuard peer is missing from the devices list")
	}
}

// A client device moves into a group through the device-id endpoint and is then
// evaluated as a member of it.
func TestPolicyAPIAssignsClientDeviceByDeviceID(t *testing.T) {
	// The endpoint only accepts a device id the hub actually knows, so this needs
	// a real control plane with a connected client behind it.
	hub := startTestHub(t)
	node, err := hub.AddNode("edge-phone", "")
	if err != nil {
		t.Fatalf("addNode: %v", err)
	}
	hub.SetDeviceID(node.ID, "phone001")
	base, _, policies := policyAPIServerWithHub(t, hub)
	code, res := policyCall(t, base, "POST", "/api/policy/group/create", `{"name":"Guests"}`)
	if code != 200 {
		t.Fatalf("create: %d %v", code, res)
	}
	grp, _ := res["group"].(map[string]interface{})
	groupID, _ := grp["id"].(string)
	if groupID == "" {
		t.Fatalf("no group id in %v", res)
	}

	code, res = policyCall(t, base, "POST", "/api/policy/group/assign-device",
		`{"id":"`+groupID+`","devices":["phone001"]}`)
	if code != 200 {
		t.Fatalf("assign-device: %d %v", code, res)
	}
	if got := policies.GroupForDevice("phone001"); got == nil || got.ID != groupID {
		t.Error("the client device was not placed in the group")
	}
	// And it is enforced, which was the whole point.
	if policies.AllowTRPForNode(nil, "phone001") {
		t.Error("a client device in a deny-all group must not be allowed as a TRP target")
	}
}
