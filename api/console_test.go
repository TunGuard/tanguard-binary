package api

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tanguard/auth"
	"tanguard/config"
	"tanguard/peers"
	"tanguard/policy"
)

// syncBuffer collects session output. Foreground jobs write from their own
// goroutine, so it has to be safe against the input loop.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// consoleTestAPI builds the API a CLI session touches: stores on disk, no
// WireGuard device (the tests that need one take the mesh-only path).
func consoleTestAPI(t *testing.T) *API {
	t.Helper()
	dir := t.TempDir()
	policies := policy.NewPolicyStore(dir)
	if err := policies.Load(); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	store := peers.NewPeerStore(dir)
	// Save() refuses to write a store that was never loaded — the same
	// protection NewAPI has at startup.
	if err := store.Load(); err != nil {
		t.Fatalf("load peers: %v", err)
	}
	return &API{
		cfg: &config.Config{
			DataDir:       dir,
			WebUsername:   "admin",
			WebPassword:   "test-password",
			Subnet:        "10.100.0.0/24",
			ListenPort:    51820,
			APIListen:     "127.0.0.1:9000",
			SSHListen:     ":2222",
			SSHEnabled:    true,
			WebEnabled:    true,
			InterfaceName: "wg0",
			Address:       "10.100.0.1/24",
			MTU:           1420,
		},
		store:    store,
		policies: policies,
		creds:    auth.NewCredentialStore(dir),
		apiKey:   auth.NewAPIKeyStore(dir),
	}
}

// runConsole types the script at the prompt, line by line, until the input
// runs out — the same bytes a real SSH or browser terminal would send.
func runConsole(t *testing.T, a *API, script string) string {
	t.Helper()
	var out syncBuffer
	s := newConsoleSession(a, "admin", strings.NewReader(script), &out)
	_ = s.Run() // input exhaustion ends the session; that is the test's stop
	return out.String()
}

// dispatchLine runs one command the way submit() does, for assertions that
// care about state rather than keystrokes.
func dispatchLine(s *consoleSession, line string) {
	s.dispatch(line)
}

func TestConsoleHelpListsEveryCommand(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "help\r")

	if !strings.Contains(out, "TunGuard CLI") {
		t.Fatalf("help banner missing: %q", out)
	}
	for _, c := range allCommands() {
		if !strings.Contains(out, c.name) {
			t.Errorf("help does not mention %q", c.name)
		}
		if c.usage == "" || c.desc == "" {
			t.Errorf("command %q has no usage or description", c.name)
		}
	}
	// The network tools are part of the surface, not an afterthought.
	for _, name := range []string{"ping", "dig", "curl", "ss", "ip", "traceroute"} {
		if lookupCommand(name) == nil {
			t.Errorf("network tool %q is not a command", name)
		}
	}
	if !strings.Contains(out, "exit") {
		t.Error("help should mention exit")
	}
}

func TestConsoleHelpForOneCommand(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "help peer\r")
	if !strings.Contains(out, "peer new <name>") {
		t.Errorf("help peer should print usage: %q", out)
	}
	out = runConsole(t, a, "help nosuchcmd\r")
	if !strings.Contains(out, "no such command") {
		t.Errorf("unknown help target: %q", out)
	}
}

func TestConsoleUnknownCommandAndExit(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "frobnicate\r")
	if !strings.Contains(out, `unknown command "frobnicate"`) {
		t.Errorf("missing unknown-command error: %q", out)
	}

	// exit ends the session without an error, and the goodbye is printed.
	var out2 syncBuffer
	s := newConsoleSession(a, "admin", strings.NewReader("exit\r"), &out2)
	if err := s.Run(); err != nil {
		t.Errorf("exit should end the session cleanly, got %v", err)
	}
	if !strings.Contains(out2.String(), "logout") {
		t.Errorf("exit should print a goodbye: %q", out2.String())
	}
}

func TestConsoleStatusOnAMeshOnlyServer(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "status\r")
	for _, want := range []string{"TunGuard", "wireguard", "not attached", "dashboard", "ssh gateway", "policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestConsolePeerCommandsRequireWireGuard(t *testing.T) {
	a := consoleTestAPI(t)
	for _, script := range []string{"peers\r", "peer new laptop\r"} {
		out := runConsole(t, a, script)
		if !strings.Contains(out, "wireguard is not attached") {
			t.Errorf("%q should fail gracefully without a device, got:\n%s", script, out)
		}
	}

	// remove resolves against the store first and skips the tunnel when
	// there is none — an unknown reference still gets a clean error.
	out := runConsole(t, a, "peer remove laptop\r")
	if !strings.Contains(out, "no peer matches") {
		t.Errorf("unknown peer should be reported, got:\n%s", out)
	}

	// A stored peer removes without a tunnel attached.
	_, pubBytes, err := config.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub := hex.EncodeToString(pubBytes)
	a.store.Add(&peers.PeerRecord{PublicKey: pub, AllowedIP: "10.100.0.9/32", DeviceName: "laptop"})
	if err := a.store.Save(); err != nil {
		t.Fatalf("save store: %v", err)
	}
	out = runConsole(t, a, "peer remove laptop\r")
	if !strings.Contains(out, "removed laptop") {
		t.Errorf("remove without a device should still work, got:\n%s", out)
	}
	if a.store.Get(pub) != nil {
		t.Error("peer is still in the store")
	}
}

// TestConsolePolicyLifecycle walks the group through the same steps the
// dashboard performs: create, assign, update, show, export, delete, apply.
func TestConsolePolicyLifecycle(t *testing.T) {
	a := consoleTestAPI(t)

	// A peer to move between groups — the store is enough; policy membership
	// keys off the public key, not off a live tunnel.
	priv, pubBytes, err := config.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_ = priv
	pub := hex.EncodeToString(pubBytes)
	a.store.Add(&peers.PeerRecord{PublicKey: pub, AllowedIP: "10.100.0.9/32", DeviceName: "tablet"})

	out := runConsole(t, a,
		"policy create Guests --wg on\r"+
			"policy assign Guests tablet\r"+
			"policy update Guests --inter on --wg off\r"+
			"policy show Guests\r"+
			"policy list\r")

	g := a.policies.GroupForPeer(pub)
	if g == nil || g.Name != "Guests" {
		t.Fatalf("peer was not assigned to Guests, got %+v", g)
	}
	if !g.AllowInterDevice || g.AllowWGAccess {
		t.Errorf("update did not apply: %+v", g)
	}
	if !strings.Contains(out, "policy") || !strings.Contains(out, "Guests") {
		t.Errorf("policy output missing group: %q", out)
	}

	// Export then delete then apply: the file must be able to bring the
	// group back exactly.
	file := t.TempDir() + "/policy.json"
	out = runConsole(t, a, "policy export "+file+"\r")
	if !strings.Contains(out, "wrote 1 group") {
		t.Errorf("export summary wrong: %q", out)
	}
	out = runConsole(t, a, "policy delete Guests\r")
	if a.policies.GroupForPeer(pub) == nil || a.policies.GroupForPeer(pub).ID == policy.DefaultPolicyGroupID {
		t.Fatalf("delete did not return the peer to default: %v", out)
	}
	out = runConsole(t, a, "policy apply "+file+"\r")
	g = a.policies.GroupForPeer(pub)
	if g == nil || g.Name != "Guests" {
		t.Fatalf("apply did not restore the group: %q", out)
	}
	if !g.AllowInterDevice || g.AllowWGAccess {
		t.Errorf("restored rules are wrong: %+v", g)
	}
}

func TestConsolePolicyRejectsBadSwitches(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "policy create Broken --wg maybe\r")
	if !strings.Contains(out, "on or off") {
		t.Errorf("bad switch value should be rejected: %q", out)
	}
	if a.policies.GroupForPeer("x") == nil && len(a.policies.List()) != 1 {
		t.Errorf("nothing should have been created: %d groups", len(a.policies.List()))
	}
}

// TestConsoleMeshJoinAndList covers the node commands the dashboard's mesh
// page issues, end to end against a live hub.
func TestConsoleMeshJoinAndList(t *testing.T) {
	a := consoleTestAPI(t)
	h := startTestHub(t)
	a.SetMesh(h, nil)

	out := runConsole(t, a,
		"mesh join phone\r"+
			"mesh nodes\r"+
			"mesh groups\r"+
			"mesh status\r")

	if !strings.Contains(out, "join key") {
		t.Errorf("mesh join should print a join key: %q", out)
	}
	if len(h.ListNodes(false)) != 1 {
		t.Fatalf("node was not registered")
	}
	if !strings.Contains(out, "phone") || !strings.Contains(out, "nodes") {
		t.Errorf("mesh listing output incomplete: %q", out)
	}

	// Remove it again by name.
	out = runConsole(t, a, "mesh remove phone\r")
	if !strings.Contains(out, "removed") {
		t.Errorf("remove output: %q", out)
	}
	if len(h.ListNodes(false)) != 0 {
		t.Errorf("node is still registered")
	}
}

func TestConsoleMeshGuardedWhenDisabled(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "mesh nodes\r")
	if !strings.Contains(out, "MESH_ENABLED") {
		t.Errorf("mesh should explain it is disabled: %q", out)
	}
	out = runConsole(t, a, "trp list\r")
	if !strings.Contains(out, "MESH_ENABLED") {
		t.Errorf("trp should explain it is disabled: %q", out)
	}
}

// TestConsolePasswordPrompt exercises the one-question-at-a-time prompt: the
// password never appears in the output and never enters history.
func TestConsolePasswordPrompt(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "password\radmin\rsecret123\rsecret123\r")

	if ok, _ := a.creds.Verify("admin", "secret123"); !ok {
		t.Fatalf("credentials were not saved:\n%s", out)
	}
	if strings.Contains(out, "secret123") {
		t.Errorf("the new password was echoed:\n%s", out)
	}
	if !strings.Contains(out, "login updated") {
		t.Errorf("missing success message: %q", out)
	}
}

func TestConsolePasswordMismatchKeepsOldLogin(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "password\radmin\rsecret123\rguess1234\r")
	if !strings.Contains(out, "passwords do not match") {
		t.Errorf("mismatch not reported: %q", out)
	}
	if a.creds.Exists() {
		t.Error("a mismatched confirmation must not change the login")
	}

	out = runConsole(t, a, "password\radmin\rshort\r")
	if !strings.Contains(out, "at least 8 characters") {
		t.Errorf("length rule not enforced: %q", out)
	}
}

// TestConsoleKeyRegenerateConfirms checks that a destructive action waits for
// a yes, and runs when it gets one.
func TestConsoleKeyRegenerateConfirms(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "key regenerate\rn\r")
	if a.apiKey.Exists() {
		t.Error("a 'no' confirmation must not generate a key")
	}
	if !strings.Contains(out, "cancelled") {
		t.Errorf("cancellation not acknowledged: %q", out)
	}

	out = runConsole(t, a, "key regenerate\ry\r")
	if !a.apiKey.Exists() {
		t.Fatalf("key was not generated:\n%s", out)
	}
	key, ok := a.apiKey.Key()
	if !ok || !strings.Contains(out, key) {
		t.Errorf("the new key should be shown: %q", out)
	}
}

func TestConsoleSettingsAndVersionAndJump(t *testing.T) {
	a := consoleTestAPI(t)
	out := runConsole(t, a, "settings\r")
	for _, want := range []string{"interface", "subnet", "ssh gateway", "environment variable"} {
		if !strings.Contains(out, want) {
			t.Errorf("settings output missing %q: %q", want, out)
		}
	}

	out = runConsole(t, a, "settings set port 51999\r")
	if a.cfg.ListenPort != 51999 {
		t.Errorf("port not applied: %d", a.cfg.ListenPort)
	}
	if !strings.Contains(out, "restart required") {
		t.Errorf("restart note missing: %q", out)
	}

	out = runConsole(t, a, "version\r")
	if !strings.Contains(out, config.Version) {
		t.Errorf("version missing current version: %q", out)
	}

	out = runConsole(t, a, "jump\r")
	if !strings.Contains(out, "ssh -J") || !strings.Contains(out, "2222") {
		t.Errorf("jump should show a usable -J line: %q", out)
	}
}

// TestConsoleBackupRoundTrip: export from the console, destroy state, import
// back through the y/N confirmation — the same archive either surface makes.
func TestConsoleBackupRoundTrip(t *testing.T) {
	a := consoleTestAPI(t)
	// A full server carries its WireGuard private key in the archive, and the
	// restore path requires it to be present.
	priv, pubBytes, err := config.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := os.WriteFile(filepath.Join(a.cfg.DataDir, "server_private.key"),
		[]byte(hex.EncodeToString(priv)), 0600); err != nil {
		t.Fatalf("write server key: %v", err)
	}
	pub := hex.EncodeToString(pubBytes)
	a.store.Add(&peers.PeerRecord{PublicKey: pub, AllowedIP: "10.100.0.11/32", DeviceName: "laptop"})
	if err := a.store.Save(); err != nil {
		t.Fatalf("save store: %v", err)
	}
	if _, err := a.policies.Create("Guests", policy.PolicyGroup{AllowWGAccess: true}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	file := t.TempDir() + "/backup.tar.gz"
	out := runConsole(t, a, "backup export "+file+"\r")
	if !strings.Contains(out, "backup written") {
		t.Fatalf("export failed: %q", out)
	}

	// Destroy the state the archive carries.
	a.store.Remove(pub)
	if err := a.policies.Delete(a.policies.List()[1].ID); err != nil {
		t.Fatalf("delete group: %v", err)
	}
	if a.store.Get(pub) != nil {
		t.Fatal("precondition: peer should be gone")
	}

	out = runConsole(t, a, "backup import "+file+"\ry\r")
	if !strings.Contains(out, "restored from") {
		t.Fatalf("import failed: %q", out)
	}
	if a.store.Get(pub) == nil {
		t.Errorf("peer was not restored")
	}
	found := false
	for _, g := range a.policies.List() {
		if g.Name == "Guests" {
			found = true
		}
	}
	if !found {
		t.Errorf("policy group was not restored")
	}
}

func TestConsoleBackupImportRefusesWithoutConfirmation(t *testing.T) {
	a := consoleTestAPI(t)
	file := t.TempDir() + "/backup.tar.gz"
	if out := runConsole(t, a, "backup export "+file+"\r"); !strings.Contains(out, "backup written") {
		t.Fatalf("export failed: %q", out)
	}
	out := runConsole(t, a, "backup import "+file+"\rn\r")
	if !strings.Contains(out, "cancelled") {
		t.Errorf("a 'no' must cancel the restore: %q", out)
	}
}

// TestConsoleExecForSSHChannel: `ssh host status` runs one line, produces
// output, and returns — no prompt, no waiting for a foreground job.
func TestConsoleExecForSSHChannel(t *testing.T) {
	a := consoleTestAPI(t)
	var out syncBuffer
	s := newConsoleSession(a, "admin", strings.NewReader(""), &out)
	s.Exec("status")
	if !strings.Contains(out.String(), "TunGuard") {
		t.Errorf("exec produced no output: %q", out.String())
	}
	if strings.Contains(out.String(), "help for commands") {
		t.Errorf("exec must not print the interactive welcome: %q", out.String())
	}
}

// TestConsoleForegroundToolStreams checks the shared plumbing the network
// tools run on: output arrives live, the job is visible as foreground while
// it runs, and the session is idle again when it ends.
func TestConsoleForegroundToolStreams(t *testing.T) {
	a := consoleTestAPI(t)
	var out syncBuffer
	s := newConsoleSession(a, "admin", strings.NewReader(""), &out)
	s.runTool("echo", []string{"hello", "console"})

	deadline := time.Now().Add(5 * time.Second)
	for s.foreground() != nil {
		if time.Now().After(deadline) {
			t.Fatal("foreground job never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "hello console") {
		t.Errorf("tool output missing: %q", out.String())
	}
	if !strings.Contains(out.String(), "hello console\r\n") {
		t.Errorf("tool output must use terminal line endings: %q", out.String())
	}
}

func TestConsoleToolMissingIsReported(t *testing.T) {
	a := consoleTestAPI(t)
	var out syncBuffer
	s := newConsoleSession(a, "admin", strings.NewReader(""), &out)
	s.runTool("tanguard-definitely-not-installed", nil)
	if !strings.Contains(out.String(), "not installed") {
		t.Errorf("missing tool should say so: %q", out.String())
	}
	if s.foreground() != nil {
		t.Error("nothing should be running after a failed lookup")
	}
}

// TestConsoleCompletion walks the tab logic: first word from the command
// table, second word from the sub-verb list, later words from the argument
// completers.
func TestConsoleCompletion(t *testing.T) {
	a := consoleTestAPI(t)
	h := startTestHub(t)
	a.SetMesh(h, nil)
	if _, err := h.AddNode("phone", ""); err != nil {
		t.Fatalf("add node: %v", err)
	}
	if _, err := a.policies.Create("Guests", policy.PolicyGroup{}); err != nil {
		t.Fatalf("create group: %v", err)
	}
	_, pubBytes, err := config.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	a.store.Add(&peers.PeerRecord{PublicKey: hex.EncodeToString(pubBytes), AllowedIP: "10.100.0.9/32", DeviceName: "tablet"})
	if err := a.store.Save(); err != nil {
		t.Fatalf("save store: %v", err)
	}

	var out syncBuffer
	s := newConsoleSession(a, "admin", strings.NewReader(""), &out)

	type tc struct {
		typed string
		want  string
	}
	for _, c := range []tc{
		{"he", "help "},
		{"pol", "policy "},
		{"status", "status "},
	} {
		s.line = []rune(c.typed)
		s.cursor = len(s.line)
		s.complete()
		if got := string(s.line); got != c.want {
			t.Errorf("completing %q gave %q, want %q", c.typed, got, c.want)
		}
		s.line = s.line[:0]
		s.cursor = 0
	}

	// Ambiguous input lists the candidates and leaves the line alone.
	for typed, want := range map[string]string{"policy ": "assign", "mesh ": "join"} {
		s.line = []rune(typed)
		s.cursor = len(s.line)
		s.complete()
		if got := string(s.line); got != typed {
			t.Errorf("line %q should be unchanged after listing, got %q", typed, got)
		}
		if !strings.Contains(out.String(), want) {
			t.Errorf("candidates for %q should include %q:\n%s", typed, want, out.String())
		}
		s.line = s.line[:0]
		s.cursor = 0
	}

	// Argument completions.
	if cands := completeMesh(s, []string{"remove"}); len(cands) == 0 || cands[0] != "phone" {
		t.Errorf("mesh remove should complete node names, got %v", cands)
	}
	if cands := completePolicy(s, []string{"assign"}); len(cands) == 0 {
		t.Errorf("policy assign should complete group names")
	}
	if cands := completePolicy(s, []string{"unassign"}); len(cands) == 0 || cands[0] != "tablet" {
		t.Errorf("policy unassign should complete device names, got %v", cands)
	}
}

// TestConsolePromptStringDuringAsk pins the redraw contract: an edit line
// during a question repaints against that question's text, and hidden input
// repaints nothing.
func TestConsolePromptStringDuringAsk(t *testing.T) {
	var out syncBuffer
	s := newConsoleSession(&API{cfg: &config.Config{DataDir: t.TempDir()}}, "admin", strings.NewReader(""), &out)
	if !strings.Contains(s.promptString(), "admin") {
		t.Errorf("idle prompt should show the user: %q", s.promptString())
	}
	s.ask("Username [admin]: ", false, func(string) {})
	if got := s.promptString(); got != "Username [admin]: " {
		t.Errorf("visible question redraw: %q", got)
	}
	s.askHidden = true
	if got := s.promptString(); got != "" {
		t.Errorf("hidden input must redraw nothing, got %q", got)
	}
}

func TestConsoleAskChainAndCancel(t *testing.T) {
	a := consoleTestAPI(t)
	// Ctrl-C (0x03) at a pending question cancels it and returns to the
	// shell prompt without running the callback.
	var out syncBuffer
	s := newConsoleSession(a, "admin", strings.NewReader("password\r\x03help\r"), &out)
	if err := s.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "New password") {
		t.Errorf("Ctrl-C should have cancelled before the password prompt: %q", got)
	}
	if !strings.Contains(got, "TunGuard CLI") {
		t.Errorf("the session should still accept commands after a cancel: %q", got)
	}
	if a.creds.Exists() {
		t.Error("nothing should have been saved")
	}
}

func TestHumanBytesAndHelpers(t *testing.T) {
	cases := map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := ageText(0); got != "never" {
		t.Errorf("ageText(0) = %q", got)
	}
	if got := ageText(time.Now().Add(-2 * time.Hour).Unix()); got != "2h0m" {
		t.Errorf("ageText(2h) = %q", got)
	}
	if got := yesNo(true); got != "yes" {
		t.Errorf("yesNo = %q", got)
	}
	if got := jumpAddr(&config.Config{SSHListen: ":2222"}); got != "<server-address>:2222" {
		t.Errorf("jumpAddr = %q", got)
	}
}

func TestParseRuleSwitches(t *testing.T) {
	got, err := parseRuleSwitches([]string{"--inter", "on", "--wg", "--trp", "off", "--name", "Staff"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]string{"--inter": "on", "--wg": "on", "--trp": "off", "--name": "Staff"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, err := parseRuleSwitches([]string{"--wg", "maybe"}); err == nil {
		t.Error("a non on/off value must be rejected")
	}
	if _, err := parseRuleSwitches([]string{"--unknown"}); err == nil {
		t.Error("unknown flags must be rejected")
	}
	if _, err := parseRuleSwitches([]string{"stray"}); err == nil {
		t.Error("positional arguments must be rejected")
	}
}

// dispatchLine is used by tests that want one command without a keystroke
// script; keep the reference so the helper stays part of the API surface.
var _ = fmt.Sprintf
