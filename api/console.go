package api

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"tanguard/config"
	"tanguard/peers"
)

// byteEv is one keystroke — or the end of input — travelling from the
// session's single reader goroutine to whichever part of the CLI currently
// owns the terminal: the line discipline or a foreground job.
type byteEv struct {
	b   byte
	err error
}

// fgEOFGrace is how long an external tool gets to flush its own output after
// the input side of the session has gone away, before it is killed. `echo`
// finishes inside this window; `ping` does not, and gets stopped.
const fgEOFGrace = 300 * time.Millisecond

// fgJob is a command or streaming loop that owns the terminal until it ends:
// `ping`, `logs -f` and friends. done closes when the job has fully finished
// and every byte of its output has been written.
type fgJob struct {
	cmd  *exec.Cmd
	stop func()
	done chan struct{}
}

type consoleSession struct {
	api        *API
	user       string
	in         io.Reader
	out        io.Writer
	closed     chan struct{}
	mu         sync.Mutex
	line       []rune
	cursor     int
	history    []string
	histIdx    int
	askFn      func(string)
	askPrompt  string
	askHidden  bool
	hostname   string
	exitCode   int
	shouldExit bool
	fg         *fgJob

	// The input pump reads `in` once, in its own goroutine, and queues
	// keystrokes for whoever is listening. eof latches so a reader that has
	// already seen the end of input never blocks again.
	byteCh   chan byteEv
	eof      bool
	skipLF   bool
	pumpStop chan struct{}
	pumpOnce sync.Once
	stopOnce sync.Once
}

func newConsoleSession(api *API, user string, in io.Reader, out io.Writer) *consoleSession {
	s := &consoleSession{
		api:      api,
		user:     user,
		in:       in,
		out:      out,
		closed:   make(chan struct{}),
		history:  make([]string, 0, 200),
		hostname: os.Getenv("HOSTNAME"),
		byteCh:   make(chan byteEv, 4096),
		pumpStop: make(chan struct{}),
	}
	if s.hostname == "" {
		if hn, _ := os.Hostname(); hn != "" {
			s.hostname = hn
		} else {
			s.hostname = "localhost"
		}
	}
	return s
}

func (s *consoleSession) printf(format string, v ...interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.out, format, v...)
}

// write emits pre-formatted terminal text (escape sequences, redraws).
func (s *consoleSession) write(str string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write([]byte(str))
}

func (s *consoleSession) writeBytes(b []byte) {
	s.write(string(b))
}

func (s *consoleSession) Close() {
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}
}

func (s *consoleSession) SetCols(cols int) {}

func (s *consoleSession) foreground() *fgJob { return s.fg }

func (s *consoleSession) stopForeground() {
	if s.fg != nil && s.fg.stop != nil {
		s.fg.stop()
	}
}

func (s *consoleSession) errf(format string, v ...interface{}) {
	s.exitCode = 1
	s.printf("\x1b[31mERROR: \x1b[0m"+format+"\r\n", v...)
}

// ─── input pump ──────────────────────────────────────────────────────────

// startPump launches the one goroutine that reads the session's input. It
// runs for the session's life so no keystroke is ever lost between the line
// discipline and a foreground job.
func (s *consoleSession) startPump() {
	s.pumpOnce.Do(func() {
		go func() {
			buf := make([]byte, 512)
			for {
				n, err := s.in.Read(buf)
				for i := 0; i < n; i++ {
					select {
					case s.byteCh <- byteEv{b: buf[i]}:
					case <-s.pumpStop:
						return
					case <-s.closed:
						return
					}
				}
				if err != nil {
					select {
					case s.byteCh <- byteEv{err: io.EOF}:
					case <-s.pumpStop:
					case <-s.closed:
					}
					return
				}
			}
		}()
	})
}

// stopPump releases the reader goroutine when a session ends with unread
// input still queued.
func (s *consoleSession) stopPump() {
	s.stopOnce.Do(func() { close(s.pumpStop) })
}

func (s *consoleSession) markEOF() {
	s.mu.Lock()
	s.eof = true
	s.mu.Unlock()
}

// nextByte blocks until the next keystroke, the end of input, or the session
// being closed. ok == false means the input side is gone for good.
func (s *consoleSession) nextByte() (byte, bool) {
	s.startPump()
	s.mu.Lock()
	eof := s.eof
	s.mu.Unlock()
	if eof {
		return 0, false
	}
	select {
	case ev := <-s.byteCh:
		if ev.err != nil {
			s.markEOF()
			return 0, false
		}
		return ev.b, true
	case <-s.closed:
		return 0, false
	}
}

// ─── foreground jobs ─────────────────────────────────────────────────────

// runTool runs a system utility as a foreground job: output streams live
// with terminal line endings, Ctrl-C stops it, and the session waits for it
// to finish before prompting again.
func (s *consoleSession) runTool(bin string, args []string) {
	path, err := exec.LookPath(bin)
	if err != nil {
		s.errf("%s is not installed on this server", bin)
		return
	}
	cmd := exec.Command(path, args...)
	cw := &crlfWriter{s: s}
	cmd.Stdout = cw
	cmd.Stderr = cw
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		s.errf("start %s: %s", bin, err)
		return
	}
	done := make(chan struct{})
	job := &fgJob{
		cmd: cmd,
		stop: func() {
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		},
		done: done,
	}
	s.fg = job
	go func() {
		defer close(done)
		cmd.Wait()
	}()
	s.watchForeground(job)
	<-job.done
	s.fg = nil
}

// startForeground runs a streaming body (like `logs -f`) as a foreground
// job. stop ends the body; watchForeground blocks until it has finished.
func (s *consoleSession) startForeground(stop func(), body func()) {
	done := make(chan struct{})
	job := &fgJob{stop: stop, done: done}
	s.fg = job
	go func() {
		defer close(done)
		body()
	}()
	s.watchForeground(job)
	<-job.done
	s.fg = nil
}

// watchForeground keeps the session alive while a job runs: it consumes
// input so nothing queues up behind the job, Ctrl-C stops the job, and the
// end of input stops it too — external processes first get a brief grace
// period to flush their own output.
func (s *consoleSession) watchForeground(job *fgJob) {
	s.startPump()
	input := s.byteCh
	var grace <-chan time.Time
	for {
		select {
		case <-job.done:
			return
		case <-s.closed:
			job.stop()
			<-job.done
			return
		case <-grace:
			grace = nil
			job.stop()
		case ev := <-input:
			if ev.err != nil {
				input = nil // the input side is gone; stop selecting on it
				s.markEOF()
				if job.cmd != nil {
					grace = time.After(fgEOFGrace)
				} else {
					job.stop()
				}
				continue
			}
			if ev.b == 0x03 { // Ctrl-C
				s.printf("\r\n^C\r\n")
				job.stop()
			}
			// Other keystrokes belong to the tool's own terminal while it
			// runs; the CLI drops them.
		}
	}
}

// crlfWriter converts a tool's \n line endings to the \r\n a terminal
// session needs, without assuming a whole line arrives in one Write.
type crlfWriter struct {
	s         *consoleSession
	lastWasCR bool
}

func (w *crlfWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+8)
	for _, c := range p {
		if c == '\n' && !w.lastWasCR {
			out = append(out, '\r')
		}
		out = append(out, c)
		w.lastWasCR = c == '\r'
	}
	w.s.write(string(out))
	return len(p), nil
}

// ─── session lifecycle ───────────────────────────────────────────────────

func (s *consoleSession) welcome() {
	s.printf(" _                                              _ \r\n")
	s.printf("\r\n")
	s.printf(" | |                                            | |\r\n")
	s.printf(" | |_  _   _  _ __   __ _  _   _   ____  _ __  __| |\r\n")
	s.printf(" | __|| | | || '_ \\ / _` || | | | / _  || '__|/ _` |\r\n")
	s.printf(" | |_ | |_| || | | | (_| || |_| || (_| || |  | (_| |\r\n")
	s.printf("  \\__| \\__,_||_| |_|\\__, | \\__,_| \\__,_||_|   \\__,_|\r\n")
	s.printf("                     __/ |                          \r\n")
	s.printf("                    |___/                           \r\n")
	s.printf(" ---------------------------------------------------\r\n")
	hub, relay := "Offline", "Idle"
	control, relayListen := "-", "-"
	if s.api.hub != nil {
		hub, relay = "Online", "Active"
		if m := s.api.hub.MeshStatus(); m != nil {
			if c, ok := m["control_listen"].(string); ok && c != "" {
				control = c
			}
			if r, ok := m["relay_listen"].(string); ok && r != "" {
				relayListen = r
			}
		}
	}
	s.printf("  TunGuard OS %s      (Built-in Userspace)\r\n", config.Version)
	s.printf("  Control Plane Hub     :       %s [%s]\r\n", hub, control)
	s.printf("  P2P/TRP Mesh Relay    :       %s [%s]\r\n", relay, relayListen)
	s.printf(" ---------------------------------------------------\r\n")
	s.printf("\r\n")
	s.printf(" Welcome %s. Core engine operational.\r\n", s.user)
	s.printf("\r\n")
	s.printf(" * Type 'help' to review edge policy & mesh commands.\r\n")
	s.printf(" * Type 'exit' to terminate control session safely.\r\n")
	s.printf("\r\n")
	s.printf(" [Jump Routing Command]:\r\n")
	s.printf(" $ ssh -J %s@%s user@target\r\n\r\n", s.user, jumpAddr(s.api.cfg))
}

// promptString is the text a line edit repaints against: the shell prompt
// when idle, the current question while one is pending, and nothing at all
// while a hidden question's answer is being typed.
func (s *consoleSession) promptString() string {
	if s.askFn != nil {
		if s.askHidden {
			return ""
		}
		return s.askPrompt
	}
	return fmt.Sprintf("%s@%s:~$ ", s.user, s.hostname)
}

// ask installs a one-shot question. The prompt is printed exactly once,
// right here; the main loop suppresses its own prompt until the answer
// arrives.
func (s *consoleSession) ask(prompt string, hidden bool, fn func(string)) {
	s.askPrompt = prompt
	s.askFn = fn
	s.askHidden = hidden
	s.printf("%s", prompt)
}

// confirm asks a y/N question and hands the verdict to fn.
func (s *consoleSession) confirm(prompt string, fn func(bool)) {
	s.ask(prompt, false, func(line string) {
		v := strings.ToLower(strings.TrimSpace(line))
		fn(v == "y" || v == "yes")
	})
}

// dispatch runs one submitted line: a pending question consumes it first,
// then exit, then the command table.
func (s *consoleSession) dispatch(line string) {
	if s.askFn != nil {
		fn := s.askFn
		s.askFn = nil
		s.askHidden = false
		s.askPrompt = ""
		fn(line)
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	fields := strings.Fields(line)
	switch fields[0] {
	case "exit", "quit":
		s.printf("\r\nlogout\r\n")
		s.shouldExit = true
		return
	}
	for _, c := range allCommands() {
		if c.name == fields[0] {
			args := []string{}
			if len(fields) > 1 {
				args = fields[1:]
			}
			c.run(s, args)
			return
		}
	}
	s.errf("unknown command %q — try 'help'", fields[0])
}

// Run is the interactive loop: welcome, then prompt/read/execute until the
// input runs out or the user types exit.
func (s *consoleSession) Run() error {
	defer s.stopPump()
	s.startPump()
	s.welcome()
	askPrinted := false
	for {
		if !askPrinted {
			s.printf("%s", s.promptString())
		}
		askPrinted = false
		line, ok := s.readLine()
		if !ok {
			return nil // input ended: the session is over
		}
		s.dispatch(line)
		if s.shouldExit {
			return nil
		}
		if s.askFn != nil {
			askPrinted = true // ask() already printed the question
		}
	}
}

// Exec runs a single line with no welcome and no prompt — the `ssh host
// status` path.
func (s *consoleSession) Exec(line string) {
	s.dispatch(strings.TrimSpace(line))
}

// ─── line discipline ─────────────────────────────────────────────────────

// readLine edits one input line against promptString(): echo, cursor,
// history, tab completion, Ctrl-C to cancel a question. It returns ok=false
// at the end of the input.
func (s *consoleSession) readLine() (string, bool) {
	s.line = s.line[:0]
	s.cursor = 0
	s.histIdx = len(s.history)
	var pend []byte
	var pendNeed int
	for {
		b, ok := s.nextByte()
		if !ok {
			return "", false
		}
		// A submit on \r swallows the \n of a client's \r\n pair.
		if s.skipLF {
			s.skipLF = false
			if b == '\n' {
				continue
			}
		}
		hidden := s.askFn != nil && s.askHidden

		// Assemble multi-byte UTF-8 input before treating it as a rune.
		if pendNeed > 0 {
			pend = append(pend, b)
			if len(pend) >= pendNeed {
				r, _ := utf8.DecodeRune(pend)
				pend = pend[:0]
				pendNeed = 0
				if r != utf8.RuneError {
					s.insertRune(r, hidden)
				}
			}
			continue
		}
		if b >= 0x80 {
			n := 0
			switch {
			case b&0xE0 == 0xC0:
				n = 2
			case b&0xF0 == 0xE0:
				n = 3
			case b&0xF8 == 0xF0:
				n = 4
			default:
				continue // stray continuation byte
			}
			pend = append(pend, b)
			pendNeed = n
			continue
		}

		switch b {
		case '\r', '\n':
			s.skipLF = b == '\r'
			s.redrawEnd()
			s.printf("\r\n")
			line := string(s.line)
			if s.askFn == nil && line != "" {
				if n := len(s.history); n == 0 || s.history[n-1] != line {
					s.history = append(s.history, line)
					if len(s.history) > 200 {
						s.history = s.history[len(s.history)-200:]
					}
				}
			}
			s.line = s.line[:0]
			s.cursor = 0
			s.histIdx = len(s.history)
			return line, true

		case 0x03: // Ctrl-C: cancel a question, or discard the line
			s.askFn = nil
			s.askHidden = false
			s.askPrompt = ""
			s.line = s.line[:0]
			s.cursor = 0
			s.printf("^C\r\n")
			return "", true

		case 0x04: // Ctrl-D on an empty line ends the session
			if len(s.line) == 0 {
				s.printf("\r\n")
				return "", false
			}

		case 0x7f, 0x08: // backspace
			if s.cursor > 0 {
				s.line = append(s.line[:s.cursor-1], s.line[s.cursor:]...)
				s.cursor--
				s.repaint(hidden)
			}

		case 0x01: // Ctrl-A: line start
			s.cursor = 0
			s.repaint(hidden)

		case 0x05: // Ctrl-E: line end
			s.cursor = len(s.line)
			s.repaint(hidden)

		case 0x15: // Ctrl-U: clear before the cursor
			s.line = append(s.line[:0], s.line[s.cursor:]...)
			s.cursor = 0
			s.repaint(hidden)

		case 0x17: // Ctrl-W: delete the word before the cursor
			i := s.cursor
			for i > 0 && s.line[i-1] == ' ' {
				i--
			}
			for i > 0 && s.line[i-1] != ' ' {
				i--
			}
			s.line = append(s.line[:i], s.line[s.cursor:]...)
			s.cursor = i
			s.repaint(hidden)

		case 0x0c: // Ctrl-L: clear the screen
			s.write("\x1b[2J\x1b[H")
			s.repaint(hidden)

		case '\t':
			if !hidden && s.askFn == nil {
				s.complete()
			}

		case 0x1b: // escape: arrows, home/end
			b1, ok1 := s.nextByte()
			if !ok1 {
				return "", false
			}
			if b1 == '[' || b1 == 'O' {
				b2, ok2 := s.nextByte()
				if !ok2 {
					return "", false
				}
				switch b2 {
				case 'A':
					s.histStep(-1)
				case 'B':
					s.histStep(+1)
				case 'C':
					if s.cursor < len(s.line) {
						s.cursor++
					}
				case 'D':
					if s.cursor > 0 {
						s.cursor--
					}
				case 'H':
					s.cursor = 0
				case 'F':
					s.cursor = len(s.line)
				}
				s.repaint(hidden)
			}

		default:
			if b < 0x20 {
				continue // unhandled control characters are dropped
			}
			s.insertRune(rune(b), hidden)
		}
	}
}

func (s *consoleSession) insertRune(r rune, hidden bool) {
	atEnd := s.cursor == len(s.line)
	tail := append([]rune{r}, s.line[s.cursor:]...)
	s.line = append(s.line[:s.cursor], tail...)
	s.cursor++
	if hidden {
		return
	}
	if atEnd {
		s.printf("%c", r)
	} else {
		s.redraw()
	}
}

// repaint re-prints the line after an edit that is not a simple append.
func (s *consoleSession) repaint(hidden bool) {
	if hidden {
		return
	}
	s.redraw()
}

// redraw repaints prompt + line and puts the cursor back where the user
// left it. Hidden questions repaint nothing at all.
func (s *consoleSession) redraw() {
	if s.askFn != nil && s.askHidden {
		return
	}
	prompt := s.promptString()
	s.printf("\r%s%s\x1b[0K", prompt, string(s.line))
	s.printf("\x1b[%dG", len([]rune(prompt))+s.cursor+1)
}

// redrawEnd paints the full line one last time at the left margin so the
// submit newline lands after it, not in the middle of it.
func (s *consoleSession) redrawEnd() {
	if s.askFn != nil && s.askHidden {
		return
	}
	prompt := s.promptString()
	s.printf("\r%s%s\x1b[0K", prompt, string(s.line))
}

func (s *consoleSession) histStep(delta int) {
	if len(s.history) == 0 {
		return
	}
	if s.histIdx > len(s.history) {
		s.histIdx = len(s.history)
	}
	next := s.histIdx + delta
	if next < 0 || next > len(s.history) {
		return
	}
	s.histIdx = next
	if next == len(s.history) {
		s.line = s.line[:0]
	} else {
		s.line = []rune(s.history[next])
	}
	s.cursor = len(s.line)
}

// ─── completion ──────────────────────────────────────────────────────────

// complete fills in the word being typed from the command table, a
// command's sub-verbs, or its argument completer. A unique match is
// inserted (with a trailing space); several matches are listed and the line
// is left alone.
func (s *consoleSession) complete() {
	if s.askFn != nil {
		return
	}
	prefix := string(s.line[:s.cursor])
	endsSpace := strings.HasSuffix(prefix, " ")
	fields := strings.Fields(prefix)
	var current string
	var head []string
	if endsSpace {
		head = fields
	} else {
		if len(fields) == 0 {
			return
		}
		current = fields[len(fields)-1]
		head = fields[:len(fields)-1]
	}

	var cands []string
	if len(head) == 0 {
		for _, c := range allCommands() {
			if strings.HasPrefix(c.name, current) {
				cands = append(cands, c.name)
			}
		}
	} else {
		c := lookupCommand(head[0])
		if c == nil {
			return
		}
		rest := append([]string{}, head[1:]...)
		var pool []string
		if len(rest) == 0 {
			pool = append(pool, c.subs...)
		}
		if c.complete != nil {
			pool = append(pool, c.complete(s, rest)...)
		}
		seen := map[string]bool{}
		for _, cand := range pool {
			if strings.HasPrefix(cand, current) && !seen[cand] {
				seen[cand] = true
				cands = append(cands, cand)
			}
		}
	}

	if len(cands) == 0 {
		return
	}
	if len(cands) == 1 {
		before := prefix
		if !endsSpace {
			before = prefix[:len(prefix)-len(current)]
		}
		if before != "" && !strings.HasSuffix(before, " ") {
			before += " "
		}
		s.line = []rune(before + cands[0] + " ")
		s.cursor = len(s.line)
		s.redraw()
		return
	}
	s.printf("\r\n  %s\r\n", strings.Join(cands, "  "))
	s.redraw()
}

// ─── output helpers ──────────────────────────────────────────────────────

func jumpAddr(cfg *config.Config) string {
	if cfg == nil || cfg.SSHListen == "" {
		return "<server-address>:2222"
	}
	a := cfg.SSHListen
	if strings.HasPrefix(a, ":") {
		return "<server-address>" + a
	}
	return a
}

func (s *consoleSession) table(header []string, rows [][]string) {
	for i, h := range header {
		s.printf("%s", h)
		if i < len(header)-1 {
			s.printf("\t")
		}
	}
	s.printf("\r\n")
	for _, r := range rows {
		for i, c := range r {
			s.printf("%s", c)
			if i < len(r)-1 {
				s.printf("\t")
			}
		}
		s.printf("\r\n")
	}
}

func uptimeTextU(u uint64) string {
	if u <= 0 {
		return "0s"
	}
	return (time.Duration(u) * time.Second).String()
}

// ageText renders a timestamp (epoch seconds — a handshake time, a node's
// last-seen moment) as "never", "just now", "45m", "2h0m" or "3d2h".
func ageText(epoch int64) string {
	if epoch <= 0 {
		return "never"
	}
	d := time.Now().Unix() - epoch
	if d < 0 {
		d = 0
	}
	switch {
	case d < 60:
		return "just now"
	case d < 3600:
		return fmt.Sprintf("%dm", d/60)
	case d < 86400:
		return fmt.Sprintf("%dh%dm", d/3600, (d%3600)/60)
	default:
		return fmt.Sprintf("%dd%dh", d/86400, (d%86400)/3600)
	}
}

func deviceLabel(rec *peers.PeerRecord) string {
	if rec == nil {
		return "peer"
	}
	if rec.DeviceName != "" {
		return rec.DeviceName
	}
	if rec.DeviceID != "" {
		return rec.DeviceID
	}
	return peers.ShortKey(rec.PublicKey)
}
