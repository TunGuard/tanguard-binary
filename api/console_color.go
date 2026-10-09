package api

import (
	"fmt"
	"unicode/utf8"
)

// The CLI paints with ANSI SGR sequences. Both consumers of a console session
// understand them: a real ssh client (the gateway) and xterm.js (the dashboard
// Terminal window). Keeping them in one place is what makes the output look
// the same wherever it is read.
const (
	ansiReset      = "\x1b[0m"
	ansiBold       = "\x1b[1m"
	ansiDim        = "\x1b[2m"
	ansiRed        = "\x1b[31m"
	ansiGreen      = "\x1b[32m"
	ansiYellow     = "\x1b[33m"
	ansiBlue       = "\x1b[34m"
	ansiMagenta    = "\x1b[35m"
	ansiCyan       = "\x1b[36m"
	ansiBoldRed    = "\x1b[1;31m"
	ansiBoldGreen  = "\x1b[1;32m"
	ansiBoldYellow = "\x1b[1;33m"
	ansiBoldBlue   = "\x1b[1;34m"
	ansiBoldCyan   = "\x1b[1;36m"
)

// paint wraps text in an SGR sequence and a reset. Empty text passes through
// unpainted so a format string with an empty value does not leak a stray code.
func paint(code, text string) string {
	if text == "" {
		return text
	}
	return code + text + ansiReset
}

// onOff paints a boolean the way the CLI reads best: green for on, dim red for
// off. It is used by the rule-flag columns and the settings/status tables.
func onOff(v bool) string {
	if v {
		return paint(ansiGreen, "on")
	}
	return paint(ansiRed, "off")
}

// state paints a small state word: online/enabled/direct/active are green,
// offline/disabled red, anything in between amber.
func state(word string) string {
	switch word {
	case "online", "enabled", "direct", "active", "yes", "up":
		return paint(ansiGreen, word)
	case "offline", "disabled", "inactive", "down", "no":
		return paint(ansiRed, word)
	case "via hub", "connecting":
		return paint(ansiYellow, word)
	}
	return word
}

// stat prints one aligned "label : value" line with a dim label, the layout the
// status and settings screens share.
func (s *consoleSession) stat(label, value string) {
	s.printf("  %s : %s\r\n", paint(ansiDim, fmt.Sprintf("%-13s", label)), value)
}

// okf prints a success line. The whole line is green so callers can build it
// with a single format string.
func (s *consoleSession) okf(format string, v ...interface{}) {
	s.printf("\x1b[32m"+format+"\x1b[0m\r\n", v...)
}

// notef prints a subtle, de-emphasised hint line.
func (s *consoleSession) notef(format string, v ...interface{}) {
	s.printf("\x1b[2m"+format+"\x1b[0m\r\n", v...)
}

// visibleWidth counts the display columns of a string, ignoring ANSI CSI
// escape sequences. The line editor needs it because the shell prompt is
// coloured but the cursor travels over the visible text only.
func visibleWidth(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && !(s[i] >= 0x40 && s[i] <= 0x7e) {
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}
