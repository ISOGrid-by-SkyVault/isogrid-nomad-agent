package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/auth"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/builds"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/config"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/connections"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/executor"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/store"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/vault"
)

// fakeEngine answers what the console asks the Docker engine.
func fakeEngine(t *testing.T) *docker.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/"+docker.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case path == "/info":
			_, _ = w.Write([]byte(`{"Name":"mgr","ServerVersion":"29.0","Swarm":{"LocalNodeState":"active","ControlAvailable":true,"Nodes":1}}`))
		case path == "/services" && strings.Contains(r.URL.RawQuery, "isogrid.managed"):
			_, _ = w.Write([]byte(`[{"ID":"s1","Spec":{"Name":"acme-web","Labels":{"isogrid.managed":"true"},"TaskTemplate":{"ContainerSpec":{"Image":"nginx:1"}},"Mode":{"Replicated":{"Replicas":1}}},"Endpoint":{"Ports":[{"Protocol":"tcp","TargetPort":80,"PublishedPort":30000,"PublishMode":"ingress"}]}}]`))
		case path == "/services/s1" || path == "/services/acme-web":
			_, _ = w.Write([]byte(`{"ID":"s1","Spec":{"Name":"acme-web","Labels":{"isogrid.managed":"true"},"TaskTemplate":{"ContainerSpec":{"Image":"nginx:1"}},"Mode":{"Replicated":{"Replicas":1}}},"Endpoint":{"Ports":[{"Protocol":"tcp","TargetPort":80,"PublishedPort":30000,"PublishMode":"ingress"}]}}`))
		case path == "/services/vault_vault":
			_, _ = w.Write([]byte(`{"ID":"s9","Spec":{"Name":"vault_vault","Labels":{},"TaskTemplate":{"ContainerSpec":{"Image":"vault"}},"Mode":{"Replicated":{"Replicas":1}}}}`))
		case path == "/tasks":
			_, _ = w.Write([]byte(`[{"ID":"t1","NodeID":"n1","Slot":1,"DesiredState":"running","Status":{"State":"running"},"Spec":{"ContainerSpec":{"Image":"nginx:1"}}}]`))
		case path == "/services/acme-web/logs":
			w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
			frame := func(stream byte, text string) {
				_, _ = w.Write([]byte{stream, 0, 0, 0, 0, 0, 0, byte(len(text))})
				_, _ = w.Write([]byte(text))
			}
			frame(2, "2026-10-05T18:00:02.000000000Z second, on stderr\n")
			frame(1, "2026-10-05T18:00:01.000000000Z first\n")
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	t.Cleanup(srv.Close)
	client, err := docker.New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// fakeVault is a KV v2 mount with AppRole login, enough for the client.
func fakeVault(t *testing.T) *vault.Client {
	t.Helper()
	var mu sync.Mutex
	data := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch {
		case path == "sys/health":
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"version":"1.18.5"}`))
		case path == "auth/approle/login":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["role_id"] != "role" || in["secret_id"] != "s3cret-id" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["invalid role or secret ID"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok","lease_duration":3600}}`))
		case r.Header.Get("X-Vault-Token") != "tok":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		case strings.HasPrefix(path, "secret/data/isogrid/"):
			ref := strings.TrimPrefix(path, "secret/data/isogrid/")
			if r.Method == http.MethodPost {
				var in struct {
					Data map[string]string `json:"data"`
				}
				_ = json.NewDecoder(r.Body).Decode(&in)
				data[ref] = in.Data["value"]
				_, _ = w.Write([]byte(`{"data":{"version":1}}`))
				return
			}
			value, ok := data[ref]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]string{"value": value}}})
		case strings.HasPrefix(path, "secret/metadata/isogrid"):
			dir := strings.Trim(strings.TrimPrefix(path, "secret/metadata/isogrid"), "/")
			if r.Method == http.MethodDelete {
				delete(data, dir)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			seen := map[string]bool{}
			keys := []string{}
			for ref := range data {
				rest := ref
				if dir != "" {
					if !strings.HasPrefix(ref, dir+"/") {
						continue
					}
					rest = strings.TrimPrefix(ref, dir+"/")
				}
				head, _, nested := strings.Cut(rest, "/")
				if nested {
					head += "/"
				}
				if !seen[head] {
					seen[head] = true
					keys = append(keys, head)
				}
			}
			if len(keys) == 0 {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	secretFile := filepath.Join(t.TempDir(), "secret-id")
	if err := os.WriteFile(secretFile, []byte("s3cret-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := vault.New(vault.Options{Addr: srv.URL, RoleID: "role", SecretIDFile: secretFile, Mount: "secret", Prefix: "isogrid"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type harness struct {
	t      *testing.T
	url    string
	client *http.Client
	logs   *bytes.Buffer
	store  *store.Store
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	engine := fakeEngine(t)
	secrets := fakeVault(t)
	sources := connections.New(connections.SQLStore{DB: db.DB()}, secrets)
	logs := &bytes.Buffer{}
	var logMu sync.Mutex
	api := &Server{
		Version: "test", Started: time.Now(), Config: config.Config{SampleInterval: 15 * time.Second, SampleRetention: time.Hour},
		Store: db, Docker: engine, Services: executor.NewServiceExecutor(engine, "o1", nil), Vault: secrets, Sources: sources,
		Builds: &builds.Runner{Sources: sources, Docker: engine, Store: db, Dir: t.TempDir(), Logf: t.Logf},
		Logf: func(format string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			logs.WriteString(fmt.Sprintf(format, args...) + "\n")
		},
	}
	if err := api.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api.Routes(mux)
	srv := httptest.NewServer(Harden(mux))
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &harness{t: t, url: srv.URL, client: &http.Client{Jar: jar}, logs: logs, store: db}
}

func (h *harness) call(method, path string, body any, header bool) (int, map[string]any) {
	h.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, h.url+path, reader)
	if header {
		req.Header.Set(consoleHeader, "1")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *harness) setupToken() string {
	h.t.Helper()
	m := regexp.MustCompile(`setup token: ([A-Z2-7]+)`).FindStringSubmatch(h.logs.String())
	if m == nil {
		h.t.Fatalf("no setup token in the log: %q", h.logs.String())
	}
	return m[1]
}

func TestConsoleFlow(t *testing.T) {
	h := newHarness(t)
	const password = "a long enough password"

	// Nothing but health and session answers without a session.
	if code, body := h.call("GET", "/api/healthz", nil, false); code != 200 || body["status"] != "ok" || body["cluster_id"] != nil {
		t.Fatalf("health: %d %v", code, body)
	}
	if code, body := h.call("GET", "/api/session", nil, false); code != 200 || body["setup_required"] != true || body["authenticated"] != false {
		t.Fatalf("session before setup: %d %v", code, body)
	}
	for _, path := range []string{"/api/overview", "/api/services", "/api/secrets", "/api/activity", "/api/metrics", "/api/settings", "/api/services/acme-web/logs"} {
		if code, _ := h.call("GET", path, nil, false); code != http.StatusUnauthorized {
			t.Fatalf("%s without a session: %d", path, code)
		}
	}

	// Setup needs the console header, the token from the log and a real password.
	in := map[string]string{"token": h.setupToken(), "username": "ops", "password": password}
	if code, _ := h.call("POST", "/api/setup", in, false); code != http.StatusForbidden {
		t.Fatalf("setup without the console header: %d", code)
	}
	if code, body := h.call("POST", "/api/setup", map[string]string{"token": "WRONG", "username": "ops", "password": password}, true); code != http.StatusForbidden || body["code"] != "bad_token" {
		t.Fatalf("setup with a wrong token: %d %v", code, body)
	}
	if code, body := h.call("POST", "/api/setup", map[string]string{"token": h.setupToken(), "username": "ops", "password": "short"}, true); code != http.StatusBadRequest || body["code"] != "bad_password" {
		t.Fatalf("setup with a short password: %d %v", code, body)
	}
	if code, body := h.call("POST", "/api/setup", in, true); code != http.StatusCreated {
		t.Fatalf("setup: %d %v", code, body)
	}
	if code, body := h.call("POST", "/api/setup", in, true); code != http.StatusConflict {
		t.Fatalf("second setup: %d %v", code, body)
	}
	if strings.Contains(h.logs.String(), password) {
		t.Fatal("the password is in the log")
	}

	// The session from setup opens everything.
	if code, body := h.call("GET", "/api/session", nil, false); code != 200 || body["authenticated"] != true || body["username"] != "ops" || body["setup_required"] != false {
		t.Fatalf("session after setup: %v", body)
	}
	code, body := h.call("GET", "/api/overview", nil, false)
	if code != 200 || body["engine"].(map[string]any)["ok"] != true || body["vault"].(map[string]any)["logged_in"] != true {
		t.Fatalf("overview: %d %v", code, body)
	}
	code, body = h.call("GET", "/api/services", nil, false)
	services := body["services"].([]any)
	if code != 200 || len(services) != 1 || services[0].(map[string]any)["name"] != "acme-web" || services[0].(map[string]any)["state"] != "running" {
		t.Fatalf("services: %d %v", code, body)
	}

	// Logs: ordered by time, stream kept, and only for managed services.
	code, body = h.call("GET", "/api/services/acme-web/logs?tail=50", nil, false)
	lines := body["lines"].([]any)
	if code != 200 || len(lines) != 2 || lines[0].(map[string]any)["text"] != "first" || lines[1].(map[string]any)["stream"] != "stderr" {
		t.Fatalf("logs: %d %v", code, body)
	}
	if code, body := h.call("GET", "/api/services/vault_vault/logs", nil, false); code != http.StatusForbidden || body["code"] != "not_managed" {
		t.Fatalf("logs of an unmanaged service: %d %v", code, body)
	}
	if code, _ := h.call("GET", "/api/services/nope/logs", nil, false); code != http.StatusNotFound {
		t.Fatalf("logs of a missing service: %d", code)
	}

	// Secrets: written by reference, listed by reference, never read back.
	const secret = "postgres://user:hunter2@db/app"
	if code, body := h.call("PUT", "/api/secrets", map[string]string{"ref": "apps/billing/DATABASE_URL", "value": secret}, true); code != 200 || body["ref"] != "apps/billing/DATABASE_URL" {
		t.Fatalf("secret write: %d %v", code, body)
	}
	if code, _ := h.call("PUT", "/api/secrets", map[string]string{"ref": "../outside", "value": "x"}, true); code != http.StatusBadRequest {
		t.Fatalf("a reference outside the prefix was accepted: %d", code)
	}
	if code, _ := h.call("PUT", "/api/secrets", map[string]string{"ref": "top", "value": "v"}, false); code != http.StatusForbidden {
		t.Fatalf("a write without the console header: %d", code)
	}
	_, _ = h.call("PUT", "/api/secrets", map[string]string{"ref": "top", "value": "v"}, true)
	code, body = h.call("GET", "/api/secrets", nil, false)
	raw, _ := json.Marshal(body)
	refs := body["refs"].([]any)
	if code != 200 || len(refs) != 2 || refs[0] != "apps/billing/DATABASE_URL" || refs[1] != "top" {
		t.Fatalf("secret list: %d %v", code, body)
	}
	if strings.Contains(string(raw), "hunter2") || strings.Contains(h.logs.String(), "hunter2") {
		t.Fatal("a secret value came back or was logged")
	}
	if code, _ := h.call("DELETE", "/api/secrets?ref=top", nil, true); code != 200 {
		t.Fatalf("secret delete: %d", code)
	}
	_, body = h.call("GET", "/api/secrets", nil, false)
	if len(body["refs"].([]any)) != 1 {
		t.Fatalf("after delete: %v", body["refs"])
	}

	// Connections: the credential goes to Vault under a reserved subtree
	// that the Secrets section neither lists nor touches.
	if code, body := h.call("PUT", "/api/connections", map[string]string{"name": "main-registry", "kind": "registry", "host": "https://Registry.Example.com/", "username": "robot", "secret": "r0bot-pass"}, true); code != 200 || body["host"] != "registry.example.com" {
		t.Fatalf("connection save: %d %v", code, body)
	}
	if code, body := h.call("PUT", "/api/connections", map[string]string{"name": "gh", "kind": "github"}, true); code != http.StatusBadRequest {
		t.Fatalf("a short name or a missing token was accepted: %d %v", code, body)
	}
	code, body = h.call("GET", "/api/connections", nil, false)
	raw, _ = json.Marshal(body)
	if code != 200 || len(body["connections"].([]any)) != 1 || strings.Contains(string(raw), "r0bot-pass") {
		t.Fatalf("connection list: %d %s", code, raw)
	}
	_, body = h.call("GET", "/api/secrets", nil, false)
	for _, ref := range body["refs"].([]any) {
		if strings.HasPrefix(ref.(string), "connections/") {
			t.Fatalf("the Secrets section lists a connection credential: %v", body["refs"])
		}
	}
	if code, _ := h.call("PUT", "/api/secrets", map[string]string{"ref": "connections/main-registry", "value": "x"}, true); code != http.StatusBadRequest {
		t.Fatalf("the Secrets section overwrote a connection credential: %d", code)
	}
	if code, _ := h.call("DELETE", "/api/secrets?ref=connections/main-registry", nil, true); code != http.StatusBadRequest {
		t.Fatalf("the Secrets section deleted a connection credential: %d", code)
	}
	if code, body := h.call("GET", "/api/builds", nil, false); code != 200 || len(body["builds"].([]any)) != 0 {
		t.Fatalf("builds: %d %v", code, body)
	}
	if code, _ := h.call("DELETE", "/api/connections?name=main-registry", nil, true); code != 200 {
		t.Fatalf("connection delete: %d", code)
	}
	if code, _ := h.call("DELETE", "/api/connections?name=main-registry", nil, true); code != http.StatusNotFound {
		t.Fatalf("second connection delete: %d", code)
	}

	// Activity and metrics read the store.
	_ = h.store.RecordIntent(context.Background(), store.IntentRecord{ID: "i1", Kind: "service.deploy", Status: "ok", Subject: "acme-web", ReceivedAt: time.Now()})
	_ = h.store.RecordIntent(context.Background(), store.IntentRecord{ID: "i2", Kind: "service.status", Status: "ok", Subject: "acme-web", ReceivedAt: time.Now()})
	_, body = h.call("GET", "/api/activity", nil, false)
	if len(body["intents"].([]any)) != 1 {
		t.Fatalf("activity hides routine reads by default: %v", body)
	}
	_, body = h.call("GET", "/api/activity?all=1", nil, false)
	if len(body["intents"].([]any)) != 2 {
		t.Fatalf("activity with reads: %v", body)
	}
	now := time.Now().Unix()
	_ = h.store.AddSamples(context.Background(), []store.Sample{
		{Service: "acme-web", TS: now - 30, CPUMilli: 100, MemBytes: 50 << 20, MemLimit: 256 << 20, Containers: 1},
		{Service: "acme-web", TS: now - 15, CPUMilli: 300, MemBytes: 60 << 20, MemLimit: 256 << 20, Containers: 1},
	})
	_, body = h.call("GET", "/api/metrics?minutes=60", nil, false)
	series := body["services"].([]any)
	if len(series) != 1 || len(series[0].(map[string]any)["points"].([]any)) < 1 {
		t.Fatalf("metrics: %v", body)
	}

	// Second factor: begin, confirm, then sign-in needs the code.
	code, body = h.call("POST", "/api/account/totp/begin", map[string]string{"password": password}, true)
	if code != 200 {
		t.Fatalf("totp begin: %d %v", code, body)
	}
	totp := body["secret"].(string)
	if code, _ := h.call("POST", "/api/account/totp/confirm", map[string]string{"code": "000000"}, true); code != http.StatusBadRequest {
		t.Fatalf("a wrong code confirmed the second factor: %d", code)
	}
	good, _ := auth.TOTPCode(totp, time.Now())
	if code, body := h.call("POST", "/api/account/totp/confirm", map[string]string{"code": good}, true); code != 200 {
		t.Fatalf("totp confirm: %d %v", code, body)
	}
	if code, _ := h.call("POST", "/api/logout", nil, true); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := h.call("GET", "/api/overview", nil, false); code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", code)
	}
	if code, body := h.call("POST", "/api/login", map[string]string{"username": "ops", "password": "not the password"}, true); code != http.StatusUnauthorized || body["code"] != "bad_credentials" {
		t.Fatalf("wrong password: %d %v", code, body)
	}
	if code, body := h.call("POST", "/api/login", map[string]string{"username": "nobody", "password": password}, true); code != http.StatusUnauthorized || body["code"] != "bad_credentials" {
		t.Fatalf("unknown user: %d %v", code, body)
	}
	if code, body := h.call("POST", "/api/login", map[string]string{"username": "ops", "password": password}, true); code != http.StatusUnauthorized || body["code"] != "totp_required" {
		t.Fatalf("sign-in without the code: %d %v", code, body)
	}
	good, _ = auth.TOTPCode(totp, time.Now())
	if code, body := h.call("POST", "/api/login", map[string]string{"username": "ops", "password": password, "code": good}, true); code != 200 {
		t.Fatalf("sign-in with the code: %d %v", code, body)
	}

	// Password change keeps this session and the old password stops working.
	const next = "another long password"
	if code, _ := h.call("POST", "/api/account/password", map[string]string{"current": "wrong", "new": next}, true); code != http.StatusForbidden {
		t.Fatalf("password change with a wrong current password: %d", code)
	}
	if code, body := h.call("POST", "/api/account/password", map[string]string{"current": password, "new": next}, true); code != 200 {
		t.Fatalf("password change: %d %v", code, body)
	}
	if code, _ := h.call("GET", "/api/settings", nil, false); code != 200 {
		t.Fatalf("the session did not survive the password change: %d", code)
	}
}

func TestLoginLocksAfterRepeatedFailures(t *testing.T) {
	h := newHarness(t)
	in := map[string]string{"token": h.setupToken(), "username": "ops", "password": "a long enough password"}
	if code, _ := h.call("POST", "/api/setup", in, true); code != http.StatusCreated {
		t.Fatal("setup failed")
	}
	_, _ = h.call("POST", "/api/logout", nil, true)
	last := 0
	for i := 0; i < 6; i++ {
		last, _ = h.call("POST", "/api/login", map[string]string{"username": "ops", "password": "guess number " + string(rune('a'+i))}, true)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("the sixth guess answered %d, not 429", last)
	}
	if code, _ := h.call("POST", "/api/login", map[string]string{"username": "ops", "password": "a long enough password"}, true); code != http.StatusTooManyRequests {
		t.Fatalf("the right password during the lock answered %d", code)
	}
}
