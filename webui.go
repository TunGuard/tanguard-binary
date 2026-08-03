package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed webui.html
var webUIFS embed.FS

func webUIHandler() http.Handler {
	sub, err := fs.Sub(webUIFS, ".")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServer(http.FS(sub))
}
