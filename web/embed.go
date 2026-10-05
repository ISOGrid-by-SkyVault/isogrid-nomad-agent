// Package web serves the operator frontend. The Vite build in web/dist is
// embedded into the binary, so the agent ships as a single executable.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler serves the built frontend with a single-page-application fallback.
// When the frontend has not been built, it explains that instead of a 404.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return notBuilt()
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return notBuilt()
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if info, err := fs.Stat(sub, path); err == nil && !info.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		r.URL.Path = "/"
		files.ServeHTTP(w, r)
	})
}

func notBuilt() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("The operator frontend is not built into this binary. Run `npm run build` in web/ and rebuild.\n"))
	})
}
