package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed webui
var webUIFS embed.FS

func webUIHandler() http.Handler {
	sub, err := fs.Sub(webUIFS, "webui")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServer(http.FS(sub))
}
