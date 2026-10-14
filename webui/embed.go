package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed *.html *.js *.css
var assets embed.FS

// Handler serves the bundled dashboard.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, ".")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServer(http.FS(sub))
}

// LoginPage writes the sign-in page. The API calls it for any unauthenticated
// browser request in place of the native HTTP Basic challenge, so the first
// thing a visitor sees is a real, styled page.
func LoginPage(w http.ResponseWriter) {
	data, err := assets.ReadFile("login.html")
	if err != nil {
		http.Error(w, "login page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}
