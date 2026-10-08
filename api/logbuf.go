package api

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"time"
)

// LogBuffer is a bounded, concurrently-safe ring of the server's recent log
// lines. The standard logger writes into it (main wires it with a MultiWriter)
// and two readers pull from it: the dashboard's System Logs window over
// /api/logs, and the CLI's `logs` command over ssh or the browser terminal.
type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
	nextID  int64
	cap     int
	pend    []byte // a Write that ended mid-line is finished by the next one
}

// LogEntry is one line. TS is the write time in unix milliseconds; Line has
// the logger's own timestamp prefix stripped, so viewers show the time once.
type LogEntry struct {
	ID   int64  `json:"id"`
	TS   int64  `json:"ts"`
	Line string `json:"line"`
}

// loggerStamp matches the standard log package's timestamp prefix, with or
// without the microseconds Lmicroseconds adds.
var loggerStamp = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?\s+`)

// NewLogBuffer keeps at most capacity lines; the oldest are dropped first.
func NewLogBuffer(capacity int) *LogBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &LogBuffer{cap: capacity}
}

// serverLogBuf is the process-wide buffer: the standard logger is itself a
// global, so its sink is one too — /api/logs and the CLI read the same lines
// the service wrote.
var serverLogBuf = NewLogBuffer(2000)

// ServerLogBuffer returns the process-wide log buffer.
func ServerLogBuffer() *LogBuffer { return serverLogBuf }

// Write implements io.Writer for log.SetOutput. It accepts whole lines and
// holds a trailing partial until its newline arrives.
func (b *LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pend = append(b.pend, p...)
	for {
		i := bytes.IndexByte(b.pend, '\n')
		if i < 0 {
			break
		}
		b.appendLineLocked(string(b.pend[:i]))
		b.pend = b.pend[i+1:]
	}
	// A writer that never sends a newline must not grow the buffer forever.
	if len(b.pend) > 8192 {
		b.appendLineLocked(string(b.pend))
		b.pend = nil
	}
	return len(p), nil
}

// appendLineLocked records one finished line. The caller holds b.mu.
func (b *LogBuffer) appendLineLocked(line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	ts := time.Now().UnixMilli()
	if m := loggerStamp.FindString(line); m != "" {
		if t, err := time.ParseInLocation("2006/01/02 15:04:05.999999",
			strings.TrimSpace(line[:len(m)]), time.Local); err == nil {
			ts = t.UnixMilli()
		}
		line = line[len(m):]
	}
	b.nextID++
	b.entries = append(b.entries, LogEntry{ID: b.nextID, TS: ts, Line: line})
	if len(b.entries) > b.cap {
		// Drop oldest lines but keep IDs monotonic, so a reader's `since`
		// position still means "everything after that line".
		drop := len(b.entries) - b.cap
		b.entries = append([]LogEntry(nil), b.entries[drop:]...)
	}
}

// Since returns entries with an ID greater than id, oldest first, and the
// latest ID in the buffer. A limit above zero keeps the newest `limit`
// matches — when a reader falls behind, recent lines win — and reports
// truncation so the caller can say so.
func (b *LogBuffer) Since(id int64, limit int) (entries []LogEntry, latest int64, truncated bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// nextID is the ID of the most recently written line, so it doubles as
	// the "latest" marker Until() returns to readers.
	latest = b.nextID
	for _, e := range b.entries {
		if e.ID > id {
			entries = append(entries, e)
		}
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
		truncated = true
	}
	return entries, latest, truncated
}

// Clear empties the buffer but keeps IDs moving forward, so readers with an
// old `since` position see a clean slate instead of a replay.
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = nil
	b.pend = nil
}
