package console

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/auth"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/store"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/vault"
)

// -- overview -----------------------------------------------------------------------

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	body := map[string]any{
		"status":  "ok",
		"version": s.Version,
		"mode":    s.mode(),
		"uptime":  time.Since(s.Started).Round(time.Second).String(),
	}
	if info, err := s.Docker.Info(ctx); err != nil {
		body["engine"] = map[string]any{"ok": false, "error": err.Error()}
	} else {
		body["engine"] = map[string]any{
			"ok": true, "name": info.Name, "version": info.ServerVersion,
			"swarm": info.Swarm.LocalNodeState, "manager": info.Swarm.ControlAvailable, "nodes": info.Swarm.Nodes,
		}
	}
	if s.Vault != nil {
		body["vault"] = s.Vault.Health(ctx)
	}
	if s.Stream != nil && s.Executor != nil {
		executed, refused := s.Executor.Counts()
		body["cluster_id"] = s.Config.ClusterID
		body["organization_id"] = s.Config.OrganizationID
		body["stream"] = s.Stream.Status()
		body["capabilities"] = s.Executor.Capabilities()
		body["intents"] = map[string]uint64{"executed": executed, "refused": refused}
	}
	writeJSON(w, http.StatusOK, body)
}

// -- deployments and logs -----------------------------------------------------------

func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := s.Services.List(ctx)
	if err != nil {
		fail(w, http.StatusBadGateway, "engine", "The Docker engine did not answer: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": list})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	name := r.PathValue("name")
	if err := s.Services.Managed(ctx, name); err != nil {
		if docker.IsNotFound(err) {
			fail(w, http.StatusNotFound, "not_found", "No such service")
			return
		}
		fail(w, http.StatusForbidden, "not_managed", capitalise(err.Error()))
		return
	}
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	if tail <= 0 {
		tail = 200
	}
	var since time.Time
	if minutes, _ := strconv.Atoi(r.URL.Query().Get("minutes")); minutes > 0 {
		since = time.Now().Add(-time.Duration(minutes) * time.Minute)
	}
	lines, err := s.Docker.ServiceLogs(ctx, name, tail, since)
	if err != nil {
		fail(w, http.StatusBadGateway, "engine", "The logs could not be read: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"service": name, "lines": lines})
}

// -- performance --------------------------------------------------------------------

type series struct {
	Name   string         `json:"name"`
	Points []store.Sample `json:"points"`
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	minutes, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if minutes <= 0 {
		minutes = 60
	}
	if minutes > 60*24*31 {
		minutes = 60 * 24 * 31
	}
	span := time.Duration(minutes) * time.Minute
	since := time.Now().Add(-span)
	// About two hundred points whatever the range, never finer than a sample.
	bucket := span / 200
	if bucket < s.Config.SampleInterval {
		bucket = s.Config.SampleInterval
	}
	bucket = bucket.Round(time.Second)
	names, err := s.Store.SampledServices(r.Context(), since)
	if err != nil {
		s.internal(w, "metrics", err)
		return
	}
	if len(names) > 50 {
		names = names[:50]
	}
	out := make([]series, 0, len(names))
	for _, name := range names {
		points, err := s.Store.Series(r.Context(), name, since, bucket)
		if err != nil {
			s.internal(w, "metrics", err)
			return
		}
		out = append(out, series{Name: name, Points: points})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"minutes":           minutes,
		"bucket_seconds":    int(bucket / time.Second),
		"sample_seconds":    int(s.Config.SampleInterval / time.Second),
		"retention_seconds": int(s.Config.SampleRetention / time.Second),
		"services":          out,
	})
}

// -- activity -----------------------------------------------------------------------

func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1"
	rows, err := s.Store.ListIntents(r.Context(), 200, all)
	if err != nil {
		s.internal(w, "activity", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attached": s.Config.Attached(), "intents": rows})
}

// -- secrets ------------------------------------------------------------------------

func (s *Server) vaultInfo() map[string]any {
	addr, mount, prefix, method := s.Vault.Where()
	return map[string]any{"address": addr, "mount": mount, "prefix": prefix, "method": method}
}

func (s *Server) secretsList(w http.ResponseWriter, r *http.Request) {
	if s.Vault == nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false, "refs": []string{}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	health := s.Vault.Health(ctx)
	body := map[string]any{"configured": true, "vault": s.vaultInfo(), "health": health, "refs": []string{}}
	if health.LoggedIn {
		refs, truncated, err := s.Vault.List(ctx)
		if err != nil {
			body["error"] = err.Error()
		} else {
			body["refs"] = refs
			body["truncated"] = truncated
		}
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) secretsWrite(w http.ResponseWriter, r *http.Request) {
	if s.Vault == nil {
		fail(w, http.StatusConflict, "no_vault", "No Vault is configured for this agent")
		return
	}
	var in struct {
		Ref   string `json:"ref"`
		Value string `json:"value"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ref, err := s.Vault.Write(ctx, in.Ref, in.Value)
	if err != nil {
		fail(w, http.StatusBadRequest, "vault", capitalise(err.Error()))
		return
	}
	// The reference is logged, never the value.
	s.Logf("console: %q wrote the secret %s", operator(r).Username, ref)
	writeJSON(w, http.StatusOK, map[string]string{"ref": ref})
}

func (s *Server) secretsDelete(w http.ResponseWriter, r *http.Request) {
	if s.Vault == nil {
		fail(w, http.StatusConflict, "no_vault", "No Vault is configured for this agent")
		return
	}
	ref, err := vault.CleanRef(r.URL.Query().Get("ref"))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_ref", capitalise(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.Vault.Delete(ctx, ref); err != nil {
		fail(w, http.StatusBadGateway, "vault", capitalise(err.Error()))
		return
	}
	s.Logf("console: %q deleted the secret %s", operator(r).Username, ref)
	writeJSON(w, http.StatusOK, map[string]string{"ref": ref})
}

// -- settings and the account --------------------------------------------------------

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	op := operator(r)
	cfg := s.Config
	body := map[string]any{
		"account": map[string]any{"username": op.Username, "totp_enabled": op.TOTPEnabled, "created_at": op.CreatedAt},
		"agent": map[string]any{
			"version":           s.Version,
			"listen":            cfg.Listen,
			"data_dir":          cfg.DataDir,
			"docker_host":       cfg.DockerHost,
			"stream_url":        cfg.StreamURL,
			"cluster_id":        cfg.ClusterID,
			"organization_id":   cfg.OrganizationID,
			"sample_interval":   cfg.SampleInterval.String(),
			"sample_retention":  cfg.SampleRetention.String(),
			"session_lifetime":  auth.SessionLifetime.String(),
			"password_min_size": auth.MinPasswordLength,
		},
	}
	if s.Vault != nil {
		body["vault"] = s.vaultInfo()
	}
	writeJSON(w, http.StatusOK, body)
}

// confirmPassword re-checks the operator's password before a sensitive
// change, through the same limiter as sign-in.
func (s *Server) confirmPassword(w http.ResponseWriter, r *http.Request, password string) bool {
	op := operator(r)
	key := clientIP(r) + "|" + op.Username
	if wait := s.limiter.Blocked(key); wait > 0 {
		tooMany(w, wait)
		return false
	}
	if !auth.VerifyPassword(op.PasswordHash, password) {
		s.limiter.Fail(key)
		fail(w, http.StatusForbidden, "bad_credentials", "That is not your current password")
		return false
	}
	return true
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.confirmPassword(w, r, in.Current) {
		return
	}
	if err := auth.CheckPassword(in.New); err != nil {
		fail(w, http.StatusBadRequest, "bad_password", capitalise(err.Error()))
		return
	}
	hash, err := auth.HashPassword(in.New)
	if err != nil {
		s.internal(w, "password", err)
		return
	}
	op := operator(r)
	if err := s.Store.SetPassword(r.Context(), op.ID, hash); err != nil {
		s.internal(w, "password", err)
		return
	}
	token, _ := r.Context().Value(tokenKey{}).(string)
	_ = s.Store.DeleteOtherSessions(r.Context(), op.ID, token)
	s.Logf("console: %q changed their password", op.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) totpBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	op := operator(r)
	if op.TOTPEnabled {
		fail(w, http.StatusConflict, "already_enabled", "The second factor is already on; turn it off first to enrol a new device")
		return
	}
	if !s.confirmPassword(w, r, in.Password) {
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.internal(w, "totp", err)
		return
	}
	// Stored but not required until a code proves the device has it.
	if err := s.Store.SetTOTP(r.Context(), op.ID, secret, false); err != nil {
		s.internal(w, "totp", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret,
		"uri":    auth.TOTPURI(secret, op.Username, "ISOGrid Nomad"),
	})
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	op := operator(r)
	if op.TOTPEnabled || op.TOTPSecret == "" {
		fail(w, http.StatusConflict, "not_started", "Start the enrolment first")
		return
	}
	if !auth.VerifyTOTP(op.TOTPSecret, in.Code, time.Now()) {
		fail(w, http.StatusBadRequest, "bad_code", "That code is not valid. Check the clock of your device and try the next code")
		return
	}
	if err := s.Store.SetTOTP(r.Context(), op.ID, op.TOTPSecret, true); err != nil {
		s.internal(w, "totp", err)
		return
	}
	s.Logf("console: %q turned the second factor on", op.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"totp_enabled": true})
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	op := operator(r)
	if !op.TOTPEnabled {
		fail(w, http.StatusConflict, "not_enabled", "The second factor is not on")
		return
	}
	if !s.confirmPassword(w, r, in.Password) {
		return
	}
	if !auth.VerifyTOTP(op.TOTPSecret, in.Code, time.Now()) {
		fail(w, http.StatusForbidden, "bad_code", "That code is not valid")
		return
	}
	if err := s.Store.SetTOTP(r.Context(), op.ID, "", false); err != nil {
		s.internal(w, "totp", err)
		return
	}
	s.Logf("console: %q turned the second factor off", op.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"totp_enabled": false})
}
