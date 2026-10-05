package console

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/connections"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/store"
)

func reserved(ref string) bool {
	return strings.HasPrefix(strings.TrimLeft(strings.TrimSpace(ref), "/"), connections.RefPrefix)
}

// -- connections ---------------------------------------------------------------------

func (s *Server) connectionsList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Sources.List(r.Context())
	if err != nil {
		s.internal(w, "connections", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vault": s.Vault != nil, "connections": list})
}

func (s *Server) connectionsSave(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Host     string `json:"host"`
		Username string `json:"username"`
		Secret   string `json:"secret"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	c, err := s.Sources.Save(ctx, connections.Connection{
		Name: in.Name, Kind: in.Kind, Host: in.Host, Username: in.Username, CreatedBy: operator(r).Username,
	}, in.Secret)
	if err != nil {
		fail(w, http.StatusBadRequest, "connection", capitalise(err.Error()))
		return
	}
	// The name is logged, never the credential.
	s.Logf("console: %q saved the %s connection %s (%s)", operator(r).Username, c.Kind, c.Name, c.Host)
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) connectionsDelete(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Sources.Delete(ctx, name); err != nil {
		if errors.Is(err, connections.ErrNotFound) {
			fail(w, http.StatusNotFound, "not_found", "No connection with that name")
			return
		}
		fail(w, http.StatusBadGateway, "connection", capitalise(err.Error()))
		return
	}
	s.Logf("console: %q deleted the connection %s", operator(r).Username, name)
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (s *Server) connectionsTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	message, err := s.Sources.Test(ctx, in.Name)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": capitalise(err.Error())})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": message})
}

// -- builds --------------------------------------------------------------------------

func (s *Server) buildsList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListBuilds(r.Context(), 50)
	if err != nil {
		s.internal(w, "builds", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"builds": list})
}

// maxLogView is how much of a build's output the console loads: its end.
const maxLogView = 512 << 10

func (s *Server) buildLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	build, err := s.Store.GetBuild(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "No such build")
		return
	}
	if err != nil {
		s.internal(w, "build log", err)
		return
	}
	text, truncated := "", false
	if logPath, err := s.Builds.LogPath(id); err == nil {
		if file, err := os.Open(logPath); err == nil {
			defer file.Close()
			if info, err := file.Stat(); err == nil && info.Size() > maxLogView {
				_, _ = file.Seek(-maxLogView, io.SeekEnd)
				truncated = true
			}
			raw, _ := io.ReadAll(io.LimitReader(file, maxLogView))
			text = string(raw)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"build": build, "log": text, "truncated": truncated})
}
