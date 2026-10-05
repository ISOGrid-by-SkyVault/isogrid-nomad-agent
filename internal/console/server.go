// Package console is the HTTP API behind the operator console. Everything it
// serves is read from this machine: the engine, the local store, the
// customer's Vault. ISOGrid cannot reach it; the only thing that crosses to
// ISOGrid is the stream the agent opens itself.
//
// Access: one public health endpoint for probes, the session endpoints, and
// everything else behind a session cookie. The first account is created with
// a setup token the agent prints in its own log, so reaching the port is not
// enough to claim the console.
package console

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/auth"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/config"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/executor"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/store"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/stream"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/vault"
)

const (
	sessionCookie = "nomad_session"
	// Mutating requests must carry this header: a form on another site
	// cannot set it, which with SameSite=Strict closes cross-site requests.
	consoleHeader = "X-ISOGrid-Console"
	maxBody       = 128 << 10
)

// Server holds what the console reads. Vault, Stream and Executor are nil
// when the agent runs without them.
type Server struct {
	Version  string
	Started  time.Time
	Config   config.Config
	Store    *store.Store
	Docker   *docker.Client
	Services *executor.ServiceExecutor
	Vault    *vault.Client
	Stream   *stream.Client
	Executor *executor.Executor
	Logf     func(format string, args ...any)

	limiter *auth.Limiter
	mu      sync.Mutex
	setup   string // setup token while no operator exists
}

// Init prepares the server and, when the console has no account yet, prints
// the setup token.
func (s *Server) Init(ctx context.Context) error {
	s.limiter = auth.NewLimiter()
	count, err := s.Store.OperatorCount(ctx)
	if err != nil {
		return err
	}
	if count == 0 {
		raw := make([]byte, 15)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		s.setup = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		s.Logf("console: no operator account yet. Open the console and create one with this setup token: %s", s.setup)
	}
	return nil
}

// Routes registers the API on a mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/healthz", s.health)
	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("POST /api/setup", s.mutating(s.setupAccount))
	mux.HandleFunc("POST /api/login", s.mutating(s.login))
	mux.HandleFunc("POST /api/logout", s.mutating(s.logout))

	mux.HandleFunc("GET /api/overview", s.authed(s.overview))
	mux.HandleFunc("GET /api/services", s.authed(s.services))
	mux.HandleFunc("GET /api/services/{name}/logs", s.authed(s.logs))
	mux.HandleFunc("GET /api/metrics", s.authed(s.metrics))
	mux.HandleFunc("GET /api/activity", s.authed(s.activity))
	mux.HandleFunc("GET /api/secrets", s.authed(s.secretsList))
	mux.HandleFunc("PUT /api/secrets", s.mutating(s.authed(s.secretsWrite)))
	mux.HandleFunc("DELETE /api/secrets", s.mutating(s.authed(s.secretsDelete)))
	mux.HandleFunc("GET /api/settings", s.authed(s.settings))
	mux.HandleFunc("POST /api/account/password", s.mutating(s.authed(s.changePassword)))
	mux.HandleFunc("POST /api/account/totp/begin", s.mutating(s.authed(s.totpBegin)))
	mux.HandleFunc("POST /api/account/totp/confirm", s.mutating(s.authed(s.totpConfirm)))
	mux.HandleFunc("POST /api/account/totp/disable", s.mutating(s.authed(s.totpDisable)))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		fail(w, http.StatusNotFound, "not_found", "No such endpoint")
	})
}

// Harden wraps a handler with the response headers every console page gets.
func Harden(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// -- plumbing -----------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "error": message})
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "The request body is not the expected JSON")
		return false
	}
	return true
}

func (s *Server) mutating(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(consoleHeader) != "1" {
			fail(w, http.StatusForbidden, "forbidden", "This request did not come from the console")
			return
		}
		next(w, r)
	}
}

type operatorKey struct{}
type tokenKey struct{}

func (s *Server) current(r *http.Request) (*store.Operator, string) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return nil, ""
	}
	hash := auth.HashToken(cookie.Value)
	op, err := s.Store.SessionOperator(r.Context(), hash)
	if err != nil {
		return nil, ""
	}
	return op, hash
}

func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op, hash := s.current(r)
		if op == nil {
			fail(w, http.StatusUnauthorized, "unauthenticated", "Sign in to the console")
			return
		}
		ctx := context.WithValue(r.Context(), operatorKey{}, op)
		ctx = context.WithValue(ctx, tokenKey{}, hash)
		next(w, r.WithContext(ctx))
	}
}

func operator(r *http.Request) *store.Operator {
	op, _ := r.Context().Value(operatorKey{}).(*store.Operator)
	return op
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, op *store.Operator) error {
	token, hash, err := auth.NewToken()
	if err != nil {
		return err
	}
	expires := time.Now().Add(auth.SessionLifetime)
	if err := s.Store.CreateSession(r.Context(), hash, op.ID, expires); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
}

// -- public -------------------------------------------------------------------------

// health is for probes: enough to tell the agent is up, nothing that
// describes the cluster.
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	body := map[string]any{
		"status":  "ok",
		"version": s.Version,
		"mode":    s.mode(),
		"uptime":  time.Since(s.Started).Round(time.Second).String(),
	}
	if s.Stream != nil {
		body["stream"] = s.Stream.Status().State
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) mode() string {
	if s.Config.Attached() {
		return "attached"
	}
	return "detached"
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	setup := s.setup != ""
	s.mu.Unlock()
	body := map[string]any{"setup_required": setup, "authenticated": false, "version": s.Version}
	if op, _ := s.current(r); op != nil {
		body["authenticated"] = true
		body["username"] = op.Username
		body["totp_enabled"] = op.TOTPEnabled
	}
	writeJSON(w, http.StatusOK, body)
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

func (s *Server) setupAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	key := clientIP(r) + "|setup"
	if wait := s.limiter.Blocked(key); wait > 0 {
		tooMany(w, wait)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setup == "" {
		fail(w, http.StatusConflict, "already_set_up", "The console already has an operator account")
		return
	}
	given := strings.ToUpper(strings.TrimSpace(in.Token))
	if subtle.ConstantTimeCompare([]byte(given), []byte(s.setup)) != 1 {
		s.limiter.Fail(key)
		fail(w, http.StatusForbidden, "bad_token", "That is not the setup token. It is in the agent's log: docker service logs isogrid-nomad-agent")
		return
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if !usernamePattern.MatchString(in.Username) {
		fail(w, http.StatusBadRequest, "bad_username", "The username takes 3 to 32 lowercase letters, digits, dots, dashes or underscores")
		return
	}
	if err := auth.CheckPassword(in.Password); err != nil {
		fail(w, http.StatusBadRequest, "bad_password", capitalise(err.Error()))
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		s.internal(w, "setup", err)
		return
	}
	op, err := s.Store.CreateOperator(r.Context(), in.Username, hash)
	if err != nil {
		s.internal(w, "setup", err)
		return
	}
	s.setup = ""
	s.limiter.Succeed(key)
	s.Logf("console: operator account %q created from %s", op.Username, clientIP(r))
	if err := s.startSession(w, r, op); err != nil {
		s.internal(w, "setup", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"username": op.Username})
}

// A hash of nothing in particular, verified when the username does not
// exist so that an unknown account costs the same time as a wrong password.
var decoyHash, _ = auth.HashPassword("decoy-password-for-timing")

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	key := clientIP(r) + "|" + in.Username
	if wait := s.limiter.Blocked(key); wait > 0 {
		tooMany(w, wait)
		return
	}
	op, err := s.Store.OperatorByName(r.Context(), in.Username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, "login", err)
		return
	}
	ok := false
	if op != nil {
		ok = auth.VerifyPassword(op.PasswordHash, in.Password)
	} else {
		auth.VerifyPassword(decoyHash, in.Password)
	}
	if !ok {
		s.limiter.Fail(key)
		s.Logf("console: failed sign-in for %q from %s", in.Username, clientIP(r))
		fail(w, http.StatusUnauthorized, "bad_credentials", "Wrong username or password")
		return
	}
	if op.TOTPEnabled {
		if strings.TrimSpace(in.Code) == "" {
			fail(w, http.StatusUnauthorized, "totp_required", "Enter the code from your authenticator app")
			return
		}
		if !auth.VerifyTOTP(op.TOTPSecret, in.Code, time.Now()) {
			s.limiter.Fail(key)
			s.Logf("console: wrong second factor for %q from %s", in.Username, clientIP(r))
			fail(w, http.StatusUnauthorized, "bad_code", "That code is not valid")
			return
		}
	}
	s.limiter.Succeed(key)
	if err := s.startSession(w, r, op); err != nil {
		s.internal(w, "login", err)
		return
	}
	s.Logf("console: %q signed in from %s", op.Username, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"username": op.Username, "totp_enabled": op.TOTPEnabled})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if _, hash := s.current(r); hash != "" {
		_ = s.Store.DeleteSession(r.Context(), hash)
	}
	clearCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	seconds := int(wait.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	fail(w, http.StatusTooManyRequests, "too_many_attempts", "Too many attempts. Try again in "+wait.Round(time.Second).String())
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.Logf("console: %s failed: %v", what, err)
	fail(w, http.StatusInternalServerError, "internal", "The agent could not complete the request; its log says why")
}

func capitalise(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}
