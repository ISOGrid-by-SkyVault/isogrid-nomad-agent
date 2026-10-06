package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/vault"
)

// mapStore is a Vault in a map.
type mapStore struct {
	values map[string]string
	writes int
}

func (m *mapStore) Resolve(_ context.Context, ref string) (string, error) {
	v, ok := m.values[ref]
	if !ok {
		return "", vault.ErrNotFound
	}
	return v, nil
}

func (m *mapStore) Write(_ context.Context, ref, value string) (string, error) {
	m.values[ref] = value
	m.writes++
	return ref, nil
}

func (m *mapStore) Delete(_ context.Context, ref string) error {
	delete(m.values, ref)
	return nil
}

func (m *mapStore) List(_ context.Context) ([]string, bool, error) {
	out := make([]string, 0, len(m.values))
	for k := range m.values {
		out = append(out, k)
	}
	return out, false, nil
}

// platformSwarm answers the extra endpoints the platform handlers call, on
// top of the service ones the shared fake knows.
type platformSwarm struct {
	*fakeSwarm
	volumes map[string]map[string]string // name -> labels
	objects map[string]map[string]any    // id -> {Name, Labels, kind}
	nextObj int
}

func newPlatformSwarm() *platformSwarm {
	return &platformSwarm{fakeSwarm: newFakeSwarm(), volumes: map[string]map[string]string{}, objects: map[string]map[string]any{}}
}

func (p *platformSwarm) handler(t *testing.T) http.HandlerFunc {
	inner := p.fakeSwarm.handler(t)
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/"+docker.APIVersion)
		writeJSON := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		p.mu.Lock()
		switch {
		case path == "/nodes":
			p.mu.Unlock()
			writeJSON(200, []map[string]any{
				{"ID": "node1", "Spec": map[string]any{"Role": "manager", "Availability": "active"}, "Description": map[string]any{"Hostname": "m1"}, "Status": map[string]any{"State": "ready"}},
				{"ID": "node2", "Spec": map[string]any{"Role": "worker", "Availability": "active"}, "Description": map[string]any{"Hostname": "w1"}, "Status": map[string]any{"State": "ready"}},
			})
			return
		case path == "/networks/create":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			p.calls = append(p.calls, "CREATE NETWORK "+body["Name"].(string))
			p.mu.Unlock()
			writeJSON(201, map[string]string{"Id": "netnew"})
			return
		case path == "/networks/sag-db-x-net":
			p.mu.Unlock()
			writeJSON(404, map[string]string{"message": "network not found"})
			return
		case path == "/networks/vault_default" && r.Method == http.MethodDelete:
			p.mu.Unlock()
			writeJSON(500, map[string]string{"message": "must not be reached"})
			return
		case (path == "/configs/create" || path == "/secrets/create") && r.Method == http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			p.nextObj++
			id := "obj" + string(rune('0'+p.nextObj))
			body["kind"] = strings.TrimPrefix(strings.TrimSuffix(path, "/create"), "/")
			p.objects[id] = body
			p.mu.Unlock()
			writeJSON(201, map[string]string{"ID": id})
			return
		case path == "/configs" || path == "/secrets":
			kind := strings.TrimPrefix(path, "/")
			out := []map[string]any{}
			for id, o := range p.objects {
				if o["kind"] == kind {
					out = append(out, map[string]any{"ID": id, "Spec": map[string]any{"Name": o["Name"], "Labels": o["Labels"]}})
				}
			}
			p.mu.Unlock()
			writeJSON(200, out)
			return
		case (strings.HasPrefix(path, "/configs/") || strings.HasPrefix(path, "/secrets/")) && r.Method == http.MethodDelete:
			id := path[strings.LastIndex(path, "/")+1:]
			delete(p.objects, id)
			p.mu.Unlock()
			writeJSON(204, nil)
			return
		case strings.HasPrefix(path, "/volumes/"):
			name := strings.TrimPrefix(path, "/volumes/")
			labels, ok := p.volumes[name]
			if !ok {
				p.mu.Unlock()
				writeJSON(404, map[string]string{"message": "no such volume"})
				return
			}
			if r.Method == http.MethodDelete {
				delete(p.volumes, name)
				p.mu.Unlock()
				writeJSON(204, nil)
				return
			}
			p.mu.Unlock()
			writeJSON(200, map[string]any{"Name": name, "Labels": labels})
			return
		}
		p.mu.Unlock()
		inner(w, r)
	}
}

func setupPlatform(t *testing.T, store SecretStore) (*Executor, *platformSwarm, ed25519.PrivateKey) {
	t.Helper()
	fake := newPlatformSwarm()
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)
	client, err := docker.New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	e := New(intent.NewVerifier(public, "o1", "c1"), "t", "c1")
	var resolver SecretResolver
	if store != nil {
		resolver = store
	}
	services := RegisterServices(e, client, "o1", resolver)
	RegisterPlatform(e, services, store)
	return e, fake, private
}

func reply(t *testing.T, e *Executor, private ed25519.PrivateKey, kind string, payload any) Reply {
	t.Helper()
	r, ok := e.Handle(context.Background(), signed(t, private, kind, payload)).(Reply)
	if !ok {
		t.Fatalf("not a reply")
	}
	return r
}

func TestSubstituteReplacesPlaceholdersFromTheVault(t *testing.T) {
	store := &mapStore{values: map[string]string{"databases/sag-db-x/superuser": "s3cret"}}
	out, err := substitute(context.Background(), store, `"postgres" "{{secret:databases/sag-db-x/superuser}}"`)
	if err != nil || out != `"postgres" "s3cret"` {
		t.Fatalf("got %q, %v", out, err)
	}
	if _, err := substitute(context.Background(), store, "{{secret:databases/sag-db-x/missing}}"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a missing reference must be an error, got %v", err)
	}
	if _, err := substitute(context.Background(), nil, "{{secret:a/b/c}}"); err == nil {
		t.Fatal("no Vault must refuse a placeholder")
	}
	plain, err := substitute(context.Background(), nil, "no secret here")
	if err != nil || plain != "no secret here" {
		t.Fatalf("plain text needs no Vault: %q %v", plain, err)
	}
}

func TestSecretEnsureMintsOnceAndRemoveForgetsAnInstance(t *testing.T) {
	store := &mapStore{values: map[string]string{}}
	e, _, private := setupPlatform(t, store)
	r := reply(t, e, private, "secret.ensure", map[string]any{"refs": []string{"databases/sag-db-x/superuser", "databases/sag-db-x/replication"}})
	if r.Status != "ok" {
		t.Fatalf("ensure: %s %s", r.Status, r.Error)
	}
	result := r.Result.(map[string]any)
	if len(result["created"].([]string)) != 2 || store.writes != 2 {
		t.Fatalf("two secrets minted: %+v writes=%d", result, store.writes)
	}
	if len(store.values["databases/sag-db-x/superuser"]) != secretLength {
		t.Fatal("minted value has the agreed length")
	}
	again := reply(t, e, private, "secret.ensure", map[string]any{"refs": []string{"databases/sag-db-x/superuser"}})
	if store.writes != 2 || len(again.Result.(map[string]any)["existing"].([]string)) != 1 {
		t.Fatal("an existing secret is not minted again")
	}
	if r := reply(t, e, private, "secret.ensure", map[string]any{"refs": []string{"connections/github"}}); r.Status != "error" {
		t.Fatal("the agent's own connections are off limits")
	}
	if r := reply(t, e, private, "secret.ensure", map[string]any{"refs": []string{"apps/key"}}); r.Status != "error" {
		t.Fatal("a minted reference needs three segments")
	}
	store.values["apps/billing/DATABASE_URL"] = "keep"
	rm := reply(t, e, private, "secret.remove", map[string]any{"prefix": "databases/sag-db-x/"})
	if rm.Status != "ok" || len(rm.Result.(map[string]any)["removed"].([]string)) != 2 {
		t.Fatalf("remove: %s %s %+v", rm.Status, rm.Error, rm.Result)
	}
	if _, kept := store.values["apps/billing/DATABASE_URL"]; !kept || len(store.values) != 1 {
		t.Fatal("only the instance's references go")
	}
	if r := reply(t, e, private, "secret.remove", map[string]any{"prefix": "databases"}); r.Status != "error" {
		t.Fatal("a whole kind cannot be removed at once")
	}
}

func TestNodesListAndNetworkEnsure(t *testing.T) {
	e, fake, private := setupPlatform(t, nil)
	r := reply(t, e, private, "nodes.list", map[string]any{})
	nodes := r.Result.(map[string]any)["nodes"].([]nodeInfo)
	if len(nodes) != 2 || nodes[0].Hostname != "m1" || nodes[1].Role != "worker" {
		t.Fatalf("nodes: %+v", nodes)
	}
	created := reply(t, e, private, "network.ensure", map[string]any{"name": "sag-db-x-net"})
	if created.Status != "ok" || created.Result.(map[string]any)["created"] != true {
		t.Fatalf("ensure creates a missing overlay: %s %s", created.Status, created.Error)
	}
	existing := reply(t, e, private, "network.ensure", map[string]any{"name": "isogrid-nomad"})
	if existing.Status != "ok" || existing.Result.(map[string]any)["created"] != false {
		t.Fatalf("an existing overlay is reused: %s %s", existing.Status, existing.Error)
	}
	if r := reply(t, e, private, "network.ensure", map[string]any{"name": "bridge-like"}); r.Status != "error" {
		t.Fatal("a local network under that name is refused")
	}
	if r := reply(t, e, private, "network.remove", map[string]any{"name": "isogrid-nomad"}); r.Status != "error" || !strings.Contains(r.Error, "leaves it alone") {
		t.Fatalf("an unlabelled network is never removed: %s %s", r.Status, r.Error)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "DELETE") {
			t.Fatalf("nothing deleted: %s", call)
		}
	}
}

func TestVolumeRemoveOnlyTouchesManagedVolumes(t *testing.T) {
	e, fake, private := setupPlatform(t, nil)
	fake.volumes["sag-db-x-pg1-data"] = map[string]string{ManagedLabel: "true"}
	fake.volumes["vault_data"] = map[string]string{}
	r := reply(t, e, private, "volume.remove", map[string]any{"names": []string{"sag-db-x-pg1-data", "vault_data", "already-gone"}})
	if r.Status != "ok" {
		t.Fatalf("%s %s", r.Status, r.Error)
	}
	result := r.Result.(map[string]any)
	removed, left := result["removed"].([]string), result["left"].([]string)
	if len(removed) != 2 || removed[0] != "sag-db-x-pg1-data" || removed[1] != "already-gone" {
		t.Fatalf("removed: %v", removed)
	}
	if len(left) != 1 || left[0] != "vault_data" {
		t.Fatalf("the operator's volume is left: %v", left)
	}
	if _, still := fake.volumes["vault_data"]; !still {
		t.Fatal("vault_data must still exist")
	}
}

func TestDeployWithConfigsMakesSwarmObjectsAndUpdateSwapsThem(t *testing.T) {
	store := &mapStore{values: map[string]string{"databases/sag-db-x/admin": "pw1"}}
	e, fake, private := setupPlatform(t, store)
	uid := 70
	deploy := map[string]any{
		"name": "sag-db-x-pgbouncer", "image": "edoburu/pgbouncer:v1.23.1-p2", "no_wait": true,
		"env": map[string]string{"PGPASSWORD": "{{secret:databases/sag-db-x/admin}}"},
		"configs": []ConfigMount{
			{Name: "pgbouncer.ini", Target: "/etc/pgbouncer/pgbouncer.ini", Content: "[databases]\n", Mode: 0o644},
			{Name: "userlist.txt", Target: "/etc/pgbouncer/userlist.txt", Content: `"admin" "{{secret:databases/sag-db-x/admin}}"`, Mode: 0o600, UID: &uid, Secret: true},
		},
	}
	r := reply(t, e, private, "service.deploy", deploy)
	if r.Status != "ok" {
		t.Fatalf("deploy: %s %s", r.Status, r.Error)
	}
	spec := fake.services["sag-db-x-pgbouncer"]["Spec"].(map[string]any)
	container := spec["TaskTemplate"].(map[string]any)["ContainerSpec"].(map[string]any)
	env := container["Env"].([]any)
	if len(env) != 1 || env[0] != "PGPASSWORD=pw1" {
		t.Fatalf("the placeholder in env is substituted: %v", env)
	}
	if len(container["Configs"].([]any)) != 1 || len(container["Secrets"].([]any)) != 1 {
		t.Fatalf("one config and one secret: %v / %v", container["Configs"], container["Secrets"])
	}
	secretRef := container["Secrets"].([]any)[0].(map[string]any)
	if secretRef["File"].(map[string]any)["UID"] != "70" {
		t.Fatalf("the userlist is owned by the pooler's uid: %v", secretRef)
	}
	var userlist string
	for _, o := range fake.objects {
		if o["kind"] == "secrets" {
			userlist = o["Data"].(string)
		}
	}
	if !strings.Contains(decodeB64(t, userlist), `"admin" "pw1"`) {
		t.Fatalf("the secret object holds the substituted content: %q", decodeB64(t, userlist))
	}
	if len(fake.objects) != 2 {
		t.Fatalf("two objects: %d", len(fake.objects))
	}

	// A new userlist: the secret object is replaced, the config reused.
	store.values["databases/sag-db-x/admin"] = "pw2"
	deploy["configs"].([]ConfigMount)[1].Content = `"admin" "{{secret:databases/sag-db-x/admin}}"` + "\n" + `"bob" "x"`
	up := reply(t, e, private, "service.update", map[string]any{"name": "sag-db-x-pgbouncer", "configs": deploy["configs"]})
	if up.Status != "ok" {
		t.Fatalf("update: %s %s", up.Status, up.Error)
	}
	if len(fake.objects) != 2 {
		t.Fatalf("the old secret object is pruned, the config kept: %d objects", len(fake.objects))
	}
	spec = fake.services["sag-db-x-pgbouncer"]["Spec"].(map[string]any)
	if spec["TaskTemplate"].(map[string]any)["ForceUpdate"].(float64) != 1 {
		t.Fatal("a config swap forces the task to restart")
	}

	rm := reply(t, e, private, "service.remove", map[string]any{"name": "sag-db-x-pgbouncer"})
	if rm.Status != "ok" || len(fake.objects) != 0 {
		t.Fatalf("removing the service prunes its objects: %s %d", rm.Status, len(fake.objects))
	}
}

func TestJobRefusesSecretsOnTheCommandLine(t *testing.T) {
	e, _, private := setupPlatform(t, &mapStore{values: map[string]string{}})
	r := reply(t, e, private, "job.run", map[string]any{"image": "postgres:16-alpine", "command": []string{"psql", "{{secret:a/b/c}}"}})
	if r.Status != "error" || !strings.Contains(r.Error, "command line") {
		t.Fatalf("%s %s", r.Status, r.Error)
	}
}

func decodeB64(t *testing.T, s string) string {
	t.Helper()
	out, err := base64Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func base64Decode(s string) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	var buf uint32
	var bits uint
	for _, c := range s {
		if c == '=' {
			break
		}
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return "", errors.New("bad base64")
		}
		buf = buf<<6 | uint32(idx)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
			buf &= 1<<bits - 1
		}
	}
	return string(out), nil
}
