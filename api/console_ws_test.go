package api

import (
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// consoleWSServer serves the console route of a test API on a free port.
func consoleWSServer(t *testing.T, a *API) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/api/ws/console", a.requireAPI(a.handleWebConsole))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func wsBasicHeader() http.Header {
	h := http.Header{}
	h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:test-password")))
	return h
}

// readWS accumulates every frame from conn so a test can wait for text that
// may be split across frames.
func readWS(t *testing.T, conn *websocket.Conn, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got strings.Builder
	conn.SetReadDeadline(deadline)
	for !strings.Contains(got.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %q; got:\n%s", want, got.String())
		}
		_, msg, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read (waiting for %q, have %q): %v", want, got.String(), err)
		}
		got.Write(msg)
	}
	return got.String()
}

// TestWebConsoleWSAuthRejection keeps the browser terminal behind the same
// dashboard login as the rest of the API.
func TestWebConsoleWSAuthRejection(t *testing.T) {
	a := consoleTestAPI(t)
	addr := consoleWSServer(t, a)
	_, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+"/api/ws/console", nil)
	if err == nil {
		t.Fatal("anonymous websocket upgrade must be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", resp)
	}
}

// TestWebConsoleWS drives the browser terminal protocol end to end: basic
// auth on the upgrade, output frames for the welcome, input frames echoed
// back through the line discipline, resize, and the "closed" frame when the
// session exits — everything webui/terminal.js consumes.
func TestWebConsoleWS(t *testing.T) {
	a := consoleTestAPI(t)
	addr := consoleWSServer(t, a)

	conn, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+"/api/ws/console", wsBasicHeader())
	if err != nil {
		t.Fatalf("dial: %v (resp %v)", err, resp)
	}
	defer conn.Close()

	// The session greets us before any input, like opening the window.
	readWS(t, conn, "Core engine operational", 5*time.Second)

	// A resize arrives before typing; it must not disturb the stream.
	if err := conn.WriteJSON(wsConsoleMsg{Type: "resize", Cols: 100, Rows: 30}); err != nil {
		t.Fatalf("resize: %v", err)
	}

	// Typed input runs the command and streams the answer back.
	if err := conn.WriteJSON(wsConsoleMsg{Type: "input", Data: "help\r"}); err != nil {
		t.Fatalf("input: %v", err)
	}
	readWS(t, conn, "Tab completes commands", 5*time.Second)

	// exit ends the session: a "closed" frame, then nothing else to run.
	if err := conn.WriteJSON(wsConsoleMsg{Type: "input", Data: "exit\r"}); err != nil {
		t.Fatalf("exit: %v", err)
	}
	readWS(t, conn, `"type":"closed"`, 5*time.Second)

	// The connection stays open until the browser closes it; a second input
	// must not resurrect the session or error the socket.
	if err := conn.WriteJSON(wsConsoleMsg{Type: "input", Data: "help\r"}); err != nil {
		t.Fatalf("input after close: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break // deadline or close: either way nothing more comes
		}
		t.Fatalf("no output expected after closed")
	}
}
