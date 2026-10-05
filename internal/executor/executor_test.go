package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
)

func signed(t *testing.T, private ed25519.PrivateKey, kind string, payload any) json.RawMessage {
	t.Helper()
	doc := map[string]any{
		"version":         1,
		"id":              "11111111-2222-3333-4444-" + kind,
		"kind":            kind,
		"organization_id": "o1",
		"cluster_id":      "c1",
		"issued_at":       time.Now().UTC().Format(time.RFC3339),
		"expires_at":      time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		"nonce":           "0123456789abcdef0123",
		"payload":         payload,
	}
	unsigned, _ := json.Marshal(doc)
	canonical, err := intent.Canonical(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	doc["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	raw, _ := json.Marshal(doc)
	return raw
}

func TestHandle(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	e := New(intent.NewVerifier(public, "o1", "c1"), "1.2.3", "c1")
	e.Register("boom", func(context.Context, *intent.Envelope) (any, error) { return nil, errors.New("docker is down") })

	r := e.Handle(context.Background(), signed(t, private, "ping", map[string]any{"echo": "hey"})).(Reply)
	if r.Status != "ok" || r.ID != "11111111-2222-3333-4444-ping" || r.ClusterID != "c1" || r.Agent != "1.2.3" {
		t.Fatalf("ping: %+v", r)
	}
	if r.Result.(map[string]any)["echo"] != "hey" {
		t.Fatalf("ping result: %+v", r.Result)
	}

	r = e.Handle(context.Background(), signed(t, private, "capabilities.describe", map[string]any{})).(Reply)
	caps := r.Result.(map[string]any)["capabilities"].([]string)
	if r.Status != "ok" || len(caps) != 3 || caps[0] != "boom" || caps[1] != "capabilities.describe" || caps[2] != "ping" {
		t.Fatalf("describe: %+v", r)
	}

	r = e.Handle(context.Background(), signed(t, private, "service.deploy", map[string]any{})).(Reply)
	if r.Status != "unsupported" || r.Kind != "service.deploy" {
		t.Fatalf("unsupported: %+v", r)
	}

	r = e.Handle(context.Background(), signed(t, private, "boom", map[string]any{})).(Reply)
	if r.Status != "error" || r.Error != "docker is down" {
		t.Fatalf("handler error: %+v", r)
	}

	// A replayed ping is refused with its id echoed, and nothing runs.
	r = e.Handle(context.Background(), signed(t, private, "ping", map[string]any{})).(Reply)
	if r.Status != "rejected" || r.Code != intent.CodeReplay || r.ID != "11111111-2222-3333-4444-ping" {
		t.Fatalf("replay: %+v", r)
	}

	r = e.Handle(context.Background(), json.RawMessage(`{"id":"x","kind":"ping","garbage":true}`)).(Reply)
	if r.Status != "rejected" || r.Code != intent.CodeMalformed || r.ID != "x" || r.Kind != "ping" {
		t.Fatalf("malformed: %+v", r)
	}
	r = e.Handle(context.Background(), json.RawMessage(`not json`)).(Reply)
	if r.Status != "rejected" || r.ID != "" {
		t.Fatalf("not json: %+v", r)
	}

	executed, refused := e.Counts()
	if executed != 3 || refused != 4 {
		t.Fatalf("counts: executed %d refused %d", executed, refused)
	}
}
