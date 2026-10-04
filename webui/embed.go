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
