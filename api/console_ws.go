package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
)

// wsConsoleMsg is the browser↔terminal protocol for the dashboard's Terminal
// window: the client sends input and resize, the server streams output and
// announces when the session is gone.
type wsConsoleMsg struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// handleWebConsole runs one CLI session over a WebSocket. It is the same
// consoleSession the SSH gateway drives — bytes in, bytes out — with io.Pipe
// pairs standing in for the tty: one carries keystrokes to the session, the
// other carries its output to xterm.js.
func (a *API) handleWebConsole(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[console] upgrade: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(64 * 1024)

	var writeMu sync.Mutex
	wsWrite := func(msg wsConsoleMsg) {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.WriteJSON(msg)
	}

	// browser → session, session → browser
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	sess := newConsoleSession(a, a.effectiveWebUsername(), inR, outW)
	defer sess.Close()
	defer outW.Close()
	// If the reader goes away first, unblock anything writing input.
	defer inW.CloseWithError(io.EOF)

	// Output pump: forward console output as messages, then announce the end.
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := outR.Read(buf)
			if n > 0 {
				wsWrite(wsConsoleMsg{Type: "output", Data: string(buf[:n])})
			}
			if err != nil {
				break
			}
		}
		wsWrite(wsConsoleMsg{Type: "closed"})
	}()

	// Session: interactive line mode, exactly like logging in over ssh.
	go func() {
		if err := sess.Run(); err != nil {
			log.Printf("[console] session: %v", err)
		}
		sess.Close()
		// Unblock the input writer and EOF the output so the pump finishes.
		inR.CloseWithError(io.EOF)
		outW.Close()
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return // client closed or connection lost: defers tear down
		}
		var msg wsConsoleMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "input":
			if msg.Data != "" {
				inW.Write([]byte(msg.Data))
			}
		case "resize":
			sess.SetSize(msg.Cols, msg.Rows)
		}
	}
}
