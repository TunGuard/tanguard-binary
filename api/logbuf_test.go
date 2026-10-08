package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// logSeed writes a handful of realistic lines into the process-wide buffer.
func logSeed(t *testing.T, extra ...string) {
	t.Helper()
	ServerLogBuffer().Clear()
	lines := append([]string{
		"2026/10/05 08:00:01.000001 [main] starting up\n",
		"2026/10/05 08:00:02.000002 [api] GET /api/health\n",
		"2026/10/05 08:00:03.000003 [p2p] WARNING: slow relay\n",
		"2026/10/05 08:00:04.000004 [api] ERROR adding peer\n",
	}, extra...)
	for _, l := range lines {
		if _, err := ServerLogBuffer().Write([]byte(l)); err != nil {
			t.Fatalf("seed write: %v", err)
		}
	}
}

// TestLogBufferSplitsLinesAndStripsStamps covers io.Writer semantics (partial
// lines across calls, \r\n tolerance) and the timestamp stripping that lets
// viewers print the time exactly once.
func TestLogBufferSplitsLinesAndStripsStamps(t *testing.T) {
	b := NewLogBuffer(10)
	if _, err := b.Write([]byte("2026/10/05 08:00:00 [a] line one\npar")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := b.Write([]byte("tial\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := b.Write([]byte("2026/10/05 08:00:00.123456 [b] done\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, _, _ := b.Since(0, 0)
	if len(entries) != 3 {
		t.Fatalf("expected 3 lines, got %d: %+v", len(entries), entries)
	}
	if entries[0].Line != "[a] line one" {
		t.Errorf("line 1 stamp not stripped: %q", entries[0].Line)
	}
	if entries[1].Line != "partial" {
		t.Errorf("partial line joined wrong: %q", entries[1].Line)
	}
	if entries[2].TS == 0 || entries[2].Line != "[b] done" {
		t.Errorf("microsecond stamp parse failed: %+v", entries[2])
	}
	if entries[0].ID != 1 || entries[1].ID != 2 || entries[2].ID != 3 {
		t.Errorf("ids not monotonic: %d %d %d", entries[0].ID, entries[1].ID, entries[2].ID)
	}
}

func TestLogBufferSinceAndLimit(t *testing.T) {
	b := NewLogBuffer(2000)
	for i := 1; i <= 5; i++ {
		if _, err := b.Write([]byte("line\n")); err != nil {
			t.Fatal(err)
		}
	}
	entries, latest, _ := b.Since(2, 0)
	if latest != 5 {
		t.Errorf("latest = %d, want 5", latest)
	}
	if len(entries) != 3 || entries[0].ID != 3 || entries[2].ID != 5 {
		t.Fatalf("since(2,none) wrong: %+v", entries)
	}
	limited, _, trunc := b.Since(2, 2)
	if len(limited) != 2 || limited[0].ID != 4 || !trunc {
		t.Fatalf("limited tail wrong: ids %d,%d trunc=%v", limited[0].ID, limited[1].ID, trunc)
	}
}

func TestLogBufferEvictsOldestKeepingIDs(t *testing.T) {
	b := NewLogBuffer(3)
	for i := 1; i <= 6; i++ {
		if _, err := b.Write([]byte("line\n")); err != nil {
			t.Fatal(err)
		}
	}
	entries, _, _ := b.Since(0, 0)
	if len(entries) != 3 {
		t.Fatalf("cap not enforced: %d entries", len(entries))
	}
	// IDs still read 1..6, so a reader behind on id=3 gets lines 4,5,6 only.
	if entries[0].ID != 4 || entries[2].ID != 6 {
		t.Fatalf("eviction wrong: %+v", entries)
	}
}

func TestLogBufferClearKeepsPosition(t *testing.T) {
	b := NewLogBuffer(10)
	b.Write([]byte("a\n"))
	b.Write([]byte("b\n"))
	b.Clear()
	entries, latest, _ := b.Since(0, 0)
	if len(entries) != 0 || latest != 2 {
		t.Fatalf("clear: entries=%d latest=%d", len(entries), latest)
	}
	b.Write([]byte("c\n"))
	after, latest, _ := b.Since(2, 0)
	if len(after) != 1 || after[0].ID != 3 || latest != 3 {
		t.Fatalf("post-clear ids wrong: %+v latest=%d", after, latest)
	}
}

// TestLogsEndpointLocksBehindAuth checks the anonymous rejection and the
// since/clear protocol the System Logs window polls.
func TestLogsEndpointLocksBehindAuth(t *testing.T) {
	a := consoleTestAPI(t)
	logSeed(t)
	mux := http.NewServeMux()
	mux.Handle("/api/logs", a.requireAPI(a.handleLogs))
	mux.Handle("/api/logs/clear", a.requireAPI(a.handleLogsClear))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	base := "http://" + ln.Addr().String()

	resp, err := http.Get(base + "/api/logs")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous must 401, got %d", resp.StatusCode)
	}

	get := func(path string) (int, map[string]interface{}) {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.SetBasicAuth("admin", "test-password")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var m map[string]interface{}
		json.NewDecoder(r.Body).Decode(&m)
		return r.StatusCode, m
	}

	code, m := get("/api/logs")
	if code != http.StatusOK {
		t.Fatalf("logs code %d", code)
	}
	entries := m["entries"].([]interface{})
	if len(entries) != 4 {
		t.Fatalf("expected 4 seeded entries, got %d", len(entries))
	}
	first := entries[0].(map[string]interface{})
	if first["id"].(float64) != 1 || strings.Contains(first["line"].(string), "2026/10/05") {
		t.Fatalf("first entry wrong: %+v", first)
	}
	last := entries[len(entries)-1].(map[string]interface{})
	sinceID := int64(last["id"].(float64))

	// Incremental poll: only what came after the last line we held.
	ServerLogBuffer().Write([]byte("2026/10/05 08:00:05 [api] GET /api/logs\n"))
	code, m = get("/api/logs?since=" + strconv.FormatInt(sinceID, 10))
	if code != http.StatusOK {
		t.Fatalf("since code %d", code)
	}
	entries = m["entries"].([]interface{})
	if len(entries) != 1 || entries[0].(map[string]interface{})["id"].(float64) != float64(sinceID+1) {
		t.Fatalf("since poll wrong: %+v", entries)
	}

	// Clear empties the ring and writes a marker line so readers know.
	req, _ := http.NewRequest("POST", base+"/api/logs/clear", strings.NewReader("{}"))
	req.SetBasicAuth("admin", "test-password")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	code, m = get("/api/logs")
	if code != http.StatusOK {
		t.Fatalf("post-clear code %d", code)
	}
	entries = m["entries"].([]interface{})
	if len(entries) != 1 {
		t.Fatalf("expected only the clear marker: %+v", entries)
	}
	markerLine := entries[0].(map[string]interface{})["line"].(string)
	if !strings.Contains(markerLine, "log buffer cleared") {
		t.Fatalf("marker line wrong: %q", markerLine)
	}
	// A fresh poll after the marker is empty: the ring is drained.
	after, _ := strconv.ParseInt(strconv.FormatFloat(m["latest"].(float64), 'f', 0, 64), 10, 64)
	code, m = get("/api/logs?since=" + strconv.FormatInt(after, 10))
	if code != http.StatusOK || len(m["entries"].([]interface{})) != 0 {
		t.Fatalf("post-marker poll should be empty: %+v", m)
	}
}

func TestConsoleLogsCommand(t *testing.T) {
	a := consoleTestAPI(t)
	logSeed(t)

	out := runConsole(t, a, "logs -n 100\r")
	if !strings.Contains(out, "[api] GET /api/health") {
		t.Errorf("logs missed history: %q", out)
	}
	// The timestamp is printed once, dimmed, on its own field.
	if !strings.Contains(out, "08:00:02") || strings.Contains(out, "08:00:02.000002") {
		t.Errorf("timestamp formatting wrong: %q", out)
	}

	out = runConsole(t, a, "logs WARNING\r")
	if !strings.Contains(out, "slow relay") || strings.Contains(out, "GET /api/") {
		t.Errorf("logs filter wrong: %q", out)
	}

	out = runConsole(t, a, "logs nosuchthing\r")
	if !strings.Contains(out, "no log lines match") {
		t.Errorf("absent filter should say so: %q", out)
	}

	// -n caps the window.
	out = runConsole(t, a, "logs -n 1\r")
	if !strings.Contains(out, "ERROR adding peer") || strings.Contains(out, "starting up") {
		t.Errorf("logs -n 1 wrong: %q", out)
	}
}

// TestConsoleLogsFollowStopsOnEOF makes sure a running `logs -f` foreground
// job does not hang a session that simply disconnects.
func TestConsoleLogsFollowStopsOnEOF(t *testing.T) {
	a := consoleTestAPI(t)
	logSeed(t)

	done := make(chan string, 1)
	go func() {
		out := runConsole(t, a, "logs -f\r")
		done <- out
	}()
	select {
	case out := <-done:
		if !strings.Contains(out, "-- following") {
			t.Errorf("follow banner missing: %q", out)
		}
		if !strings.Contains(out, "starting up") {
			t.Errorf("follow should show recent history: %q", out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("logs -f did not stop when the session ended")
	}
}
