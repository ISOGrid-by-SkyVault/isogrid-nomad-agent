package intent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestCanonicalMatchesPythonDumps(t *testing.T) {
	// json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
	// of the same document: the platform signs what it serialised, and the
	// agent re-derives it from the wire bytes, numbers untouched.
	raw := []byte(`{"z": 1.5, "a": {"y": [true, null, "é\n\"\\\u0001"], "x": 12345678901234567890}, "signature": "drop me", "m": -3}`)
	want := `{"a":{"x":12345678901234567890,"y":[true,null,"é\n\"\\\u0001"]},"m":-3,"z":1.5}`
	got, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical mismatch\n got %s\nwant %s", got, want)
	}
}

func TestCanonicalRejectsNonObject(t *testing.T) {
	if _, err := Canonical([]byte(`[1,2]`)); err == nil {
		t.Fatal("expected an error for a non-object envelope")
	}
}

type fixture struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	v       *Verifier
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	v := NewVerifier(public, "org-1", "cluster-1")
	v.now = func() time.Time { return now }
	return &fixture{public: public, private: private, v: v, now: now}
}

func (f *fixture) envelope(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	doc := map[string]any{
		"version":         1,
		"id":              "11111111-2222-3333-4444-555555555555",
		"kind":            "ping",
		"organization_id": "org-1",
		"cluster_id":      "cluster-1",
		"issued_at":       f.now.Add(-time.Minute).Format(time.RFC3339),
		"expires_at":      f.now.Add(time.Hour).Format(time.RFC3339),
		"nonce":           "0123456789abcdef0123",
		"payload":         map[string]any{"echo": "hi"},
	}
	if mutate != nil {
		mutate(doc)
	}
	unsigned, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	doc["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, canonical))
	raw, err := json.MarshalIndent(doc, "", "  ") // any spacing must do
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyAcceptsAGoodEnvelopeOnce(t *testing.T) {
	f := newFixture(t)
	raw := f.envelope(t, nil)
	env, err := f.v.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.Kind != "ping" || !strings.Contains(string(env.Payload), `"echo"`) {
		t.Fatalf("unexpected envelope %+v", env)
	}
	_, err = f.v.Verify(raw)
	if code(err) != CodeReplay {
		t.Fatalf("second delivery: want replay, got %v", err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		tamper func([]byte) []byte
		want   string
	}{
		{"other cluster", func(d map[string]any) { d["cluster_id"] = "cluster-2" }, nil, CodeScope},
		{"other organization", func(d map[string]any) { d["organization_id"] = "org-2" }, nil, CodeScope},
		{"expired", func(d map[string]any) {
			d["expires_at"] = time.Date(2026, 10, 5, 11, 0, 0, 0, time.UTC).Format(time.RFC3339)
		}, nil, CodeExpired},
		{"from the future", func(d map[string]any) {
			d["issued_at"] = time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC).Format(time.RFC3339)
		}, nil, CodeNotYetValid},
		{"wrong version", func(d map[string]any) { d["version"] = 2 }, nil, CodeVersion},
		{"short nonce", func(d map[string]any) { d["nonce"] = "short" }, nil, CodeMalformed},
		{"tampered payload", nil, func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"hi"`, `"ho"`, 1))
		}, CodeSignature},
		{"unknown field", nil, func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"kind"`, `"extra": 1, "kind"`, 1))
		}, CodeMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			raw := f.envelope(t, tc.mutate)
			if tc.tamper != nil {
				raw = tc.tamper(raw)
			}
			_, err := f.v.Verify(raw)
			if code(err) != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}

func TestVerifyRejectsAnotherKey(t *testing.T) {
	f := newFixture(t)
	raw := f.envelope(t, nil)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifier(other, "org-1", "cluster-1")
	v.now = f.v.now
	if _, err := v.Verify(raw); code(err) != CodeSignature {
		t.Fatalf("want signature refusal, got %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	got, err := ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(public) {
		t.Fatal("parsed key differs")
	}
	if _, err := ParsePublicKey([]byte("nope")); err == nil {
		t.Fatal("expected an error")
	}
}

func code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}
