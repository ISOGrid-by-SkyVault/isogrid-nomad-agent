package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type memStore map[string]Connection

func (m memStore) ListConnections(context.Context) ([]Connection, error) {
	out := []Connection{}
	for _, c := range m {
		out = append(out, c)
	}
	return out, nil
}
func (m memStore) GetConnection(_ context.Context, name string) (*Connection, error) {
	c, ok := m[name]
	if !ok {
		return nil, ErrNotFound
	}
	return &c, nil
}
func (m memStore) SaveConnection(_ context.Context, c Connection) error { m[c.Name] = c; return nil }
func (m memStore) DeleteConnection(_ context.Context, name string) error {
	delete(m, name)
	return nil
}

type memVault map[string]string

func (v memVault) Read(_ context.Context, ref string) (string, error) { return v[ref], nil }
func (v memVault) Write(_ context.Context, ref, value string) (string, error) {
	v[ref] = value
	return ref, nil
}
func (v memVault) Delete(_ context.Context, ref string) error { delete(v, ref); return nil }

func TestImageHost(t *testing.T) {
	cases := map[string]string{
		"nginx:1.27": "docker.io", "library/nginx": "docker.io", "acme/api:1": "docker.io",
		"ghcr.io/acme/api:1": "ghcr.io", "registry.example.com:5000/a/b": "registry.example.com:5000", "localhost/x": "localhost",
	}
	for image, want := range cases {
		if got := ImageHost(image); got != want {
			t.Fatalf("%s: got %s, want %s", image, got, want)
		}
	}
}

func TestSaveAndRegistryAuth(t *testing.T) {
	ctx := context.Background()
	vault := memVault{}
	m := New(memStore{}, vault)
	if _, err := m.Save(ctx, Connection{Name: "reg", Kind: KindRegistry, Host: "ghcr.io", Username: "bot"}, ""); err == nil {
		t.Fatal("a new connection without a credential was accepted")
	}
	c, err := m.Save(ctx, Connection{Name: "reg", Kind: KindRegistry, Host: "HTTPS://GHCR.io/", Username: "bot"}, "tok3n")
	if err != nil || c.Host != "ghcr.io" || vault["connections/reg"] != "tok3n" {
		t.Fatalf("save: %+v %v %v", c, err, vault)
	}
	// Re-saving without a credential keeps the stored one.
	if _, err := m.Save(ctx, Connection{Name: "reg", Kind: KindRegistry, Host: "ghcr.io", Username: "bot2"}, ""); err != nil || vault["connections/reg"] != "tok3n" {
		t.Fatalf("re-save: %v %v", err, vault)
	}
	auth, err := m.RegistryAuth(ctx, "reg", "ghcr.io/acme/api:1")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.URLEncoding.DecodeString(auth)
	var doc map[string]string
	_ = json.Unmarshal(raw, &doc)
	if doc["username"] != "bot2" || doc["password"] != "tok3n" || doc["serveraddress"] != "ghcr.io" {
		t.Fatalf("auth: %v", doc)
	}
	// The credential is never handed to another registry.
	if _, err := m.RegistryAuth(ctx, "reg", "evil.example.com/acme/api:1"); err == nil || !strings.Contains(err.Error(), "evil.example.com") {
		t.Fatalf("credential offered to another host: %v", err)
	}
	if _, err := m.RegistryAuth(ctx, "reg", "nginx:1"); err == nil {
		t.Fatal("credential offered to Docker Hub")
	}
	for _, bad := range []Connection{{Name: "x", Kind: KindGitHub}, {Name: "good-name", Kind: "svn"}, {Name: "good-name", Kind: KindRegistry}, {Name: "good-name", Kind: KindGitLab, Host: "bad host/../x"}} {
		if _, err := m.Save(ctx, bad, "t"); err == nil {
			t.Fatalf("%+v was accepted", bad)
		}
	}
	if _, err := m.Repositories(ctx, "reg", "", 1); err == nil || !strings.Contains(err.Error(), "registry connection") {
		t.Fatalf("a registry connection listed repositories: %v", err)
	}
	if err := m.Delete(ctx, "reg"); err != nil || len(vault) != 0 {
		t.Fatalf("delete: %v %v", err, vault)
	}
	if _, err := CleanRepository("acme/../secret"); err == nil {
		t.Fatal("a repository path with .. was accepted")
	}
	if _, err := CleanRef("main; rm -rf /"); err == nil {
		t.Fatal("a ref with shell characters was accepted")
	}
}

// Against the real Docker Hub, anonymously: the token challenge end to end.
// Run with NOMAD_LIVE=1.
func TestLiveDockerHubTags(t *testing.T) {
	if os.Getenv("NOMAD_LIVE") == "" {
		t.Skip("set NOMAD_LIVE=1 to reach Docker Hub")
	}
	ctx := context.Background()
	m := New(memStore{}, memVault{})
	if _, err := m.Save(ctx, Connection{Name: "hub", Kind: KindRegistry, Host: "docker.io"}, "unused"); err != nil {
		t.Fatal(err)
	}
	images, err := m.Images(ctx, "hub", "nginx")
	if err != nil || images.Repository != "library/nginx" || len(images.Tags) == 0 {
		t.Fatalf("tags: %+v %v", images, err)
	}
	if msg, err := m.Test(ctx, "hub"); err != nil {
		t.Fatalf("test: %s %v", msg, err)
	}
}
