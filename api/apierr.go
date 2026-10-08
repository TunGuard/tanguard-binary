package api

// apiError is an error that knows which HTTP status it belongs to, so the
// handlers and the CLI can share one implementation of an operation without
// flattening every failure to the same status code.
type apiError struct {
	Code int
	Msg  string
}

func (e *apiError) Error() string { return e.Msg }

func apiErr(code int, msg string) *apiError { return &apiError{Code: code, Msg: msg} }

// errCode picks the status for an error: its own if it carries one, def
// otherwise.
func errCode(err error, def int) int {
	if e, ok := err.(*apiError); ok {
		return e.Code
	}
	return def
}
