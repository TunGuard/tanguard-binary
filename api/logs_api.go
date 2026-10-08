package api

import (
	"net/http"
	"strconv"
)

// handleLogs streams the server's log ring to the System Logs window.
// `since` is the last ID the caller holds: new lines only are returned, so
// the window polls cheaply and keeps its scroll position.
func (a *API) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, 405, "GET required")
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	entries, latest, truncated := ServerLogBuffer().Since(since, limit)
	if entries == nil {
		entries = []LogEntry{}
	}
	jsonResp(w, 200, map[string]interface{}{
		"entries":   entries,
		"latest":    latest,
		"truncated": truncated,
		"capacity":  ServerLogBuffer().cap,
	})
}

// handleLogsClear empties the ring — the same "Clear" a serial console gives
// you, but the lines are only dropped from memory, never from disk, because
// there is no disk copy: journald or the service manager still owns those.
func (a *API) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST required")
		return
	}
	ServerLogBuffer().Clear()
	ServerLogBuffer().Write([]byte("[api] log buffer cleared\n"))
	jsonResp(w, 200, map[string]interface{}{"success": true, "latest": ServerLogBuffer().sincePoint()})
}

// sincePoint is the ID a fresh reader should start from after a Clear.
func (b *LogBuffer) sincePoint() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.nextID - 1
}
