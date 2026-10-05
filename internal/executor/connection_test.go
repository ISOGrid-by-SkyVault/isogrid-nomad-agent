package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/connections"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
)

// ISOGrid may forward a credential the person chose to keep on the agent,
// and renew it; it may never overwrite or remove what the operator made in
// the console.

type memoryStore struct {
	rows map[string]connections.Connection
}

func (m *memoryStore) ListConnections(context.Context) ([]connections.Connection, error) {
	out := []connections.Connection{}
	for _, c := range m.rows {
		out = append(out, c)
	}
	return out, nil
}

func (m *memoryStore) GetConnection(_ context.Context, name string) (*connections.Connection, error) {
	c, ok := m.rows[name]
	if !ok {
		return nil, connections.ErrNotFound
	}
	return &c, nil
}

func (m *memoryStore) SaveConnection(_ context.Context, c connections.Connection) error {
	m.rows[c.Name] = c
	return nil
}

func (m *memoryStore) DeleteConnection(_ context.Context, name string) error {
	delete(m.rows, name)
	return nil
}

type memoryVault struct{ values map[string]string }

func (v *memoryVault) Read(_ context.Context, ref string) (string, error) {
	value, ok := v.values[ref]
	if !ok {
		return "", errors.New("missing")
	}
	return value, nil
}

func (v *memoryVault) Write(_ context.Context, ref, value string) (string, error) {
	v.values[ref] = value
	return ref, nil
}

func (v *memoryVault) Delete(_ context.Context, ref string) error {
	delete(v.values, ref)
	return nil
}

func TestConnectionPutStoresTheCredentialInVaultAndNeverEchoesIt(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	e := New(intent.NewVerifier(public, "o1", "c1"), "1.2.3", "c1")
	store := &memoryStore{rows: map[string]connections.Connection{}}
	vault := &memoryVault{values: map[string]string{}}
	h := &sourceHandlers{sources: connections.New(store, vault)}
	e.Register("connection.put", h.connectionPut)
	e.Register("connection.remove", h.connectionRemove)

	r := e.Handle(context.Background(), signed(t, private, "connection.put", map[string]any{
		"name": "github-acme", "kind": "github", "username": "x-access-token", "secret": "ghs_token1",
	})).(Reply)
	if r.Status != "ok" {
		t.Fatalf("put: %+v", r)
	}
	result := r.Result.(map[string]any)
	if result["created_by"] != CreatedByISOGrid || result["host"] != "github.com" {
		t.Fatalf("put result: %+v", result)
	}
	for _, v := range result {
		if v == "ghs_token1" {
			t.Fatal("the credential must not be echoed in the reply")
		}
	}
	if vault.values["connections/github-acme"] != "ghs_token1" {
		t.Fatalf("vault: %+v", vault.values)
	}

	// A renewal (ISOGrid's hourly GitHub token) replaces the credential.
	r = e.Handle(context.Background(), signed(t, private, "connection.put", map[string]any{
		"name": "github-acme", "kind": "github", "username": "x-access-token", "secret": "ghs_token2",
	})).(Reply)
	if r.Status != "ok" || vault.values["connections/github-acme"] != "ghs_token2" {
		t.Fatalf("renewal: %+v %+v", r, vault.values)
	}

	// The inventory says who made it.
	summaries, _ := h.sources.Summaries(context.Background())
	if len(summaries) != 1 || summaries[0].CreatedBy != CreatedByISOGrid {
		t.Fatalf("summaries: %+v", summaries)
	}

	// An operator's own connection under the same name is untouchable.
	store.rows["mine"] = connections.Connection{Name: "mine", Kind: "gitlab", Host: "gitlab.com", CreatedBy: "samir"}
	vault.values["connections/mine"] = "glpat-mine"
	r = e.Handle(context.Background(), signed(t, private, "connection.put", map[string]any{
		"name": "mine", "kind": "gitlab", "secret": "glpat-other",
	})).(Reply)
	if r.Status != "error" || vault.values["connections/mine"] != "glpat-mine" {
		t.Fatalf("overwrite of an operator connection must be refused: %+v", r)
	}
	r = e.Handle(context.Background(), signed(t, private, "connection.remove", map[string]any{"name": "mine"})).(Reply)
	if r.Status != "error" || store.rows["mine"].Name != "mine" {
		t.Fatalf("removal of an operator connection must be refused: %+v", r)
	}

	// ISOGrid's own can be removed, and removing it twice is still fine.
	r = e.Handle(context.Background(), signed(t, private, "connection.remove", map[string]any{"name": "github-acme"})).(Reply)
	if r.Status != "ok" || r.Result.(map[string]any)["removed"] != true {
		t.Fatalf("remove: %+v", r)
	}
	if _, ok := vault.values["connections/github-acme"]; ok {
		t.Fatal("the credential must leave the vault with the connection")
	}
	r = e.Handle(context.Background(), signed(t, private, "connection.remove", map[string]any{"name": "github-acme"})).(Reply)
	if r.Status != "ok" || r.Result.(map[string]any)["removed"] != false {
		t.Fatalf("second remove: %+v", r)
	}

	// No credential, no connection.
	r = e.Handle(context.Background(), signed(t, private, "connection.put", map[string]any{"name": "empty", "kind": "github"})).(Reply)
	if r.Status != "error" {
		t.Fatalf("put without a secret: %+v", r)
	}
}
