package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
)

// fakeSwarm answers the handful of Engine API calls the executor makes.
type fakeSwarm struct {
	mu       sync.Mutex
	services map[string]map[string]any // name -> service object
	nextID   int
	calls    []string
}

func newFakeSwarm() *fakeSwarm {
	return &fakeSwarm{services: map[string]map[string]any{}}
}

func (f *fakeSwarm) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		path := strings.TrimPrefix(r.URL.Path, "/"+docker.APIVersion)
		writeJSON := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch {
		case path == "/networks":
			writeJSON(200, []map[string]any{
				{"Id": "ing", "Name": "ingress", "Scope": "swarm", "Driver": "overlay", "Attachable": false},
				{"Id": "net1", "Name": "isogrid-nomad", "Scope": "swarm", "Driver": "overlay", "Attachable": true},
				{"Id": "net3", "Name": "vault_default", "Scope": "swarm", "Driver": "overlay", "Attachable": false},
			})
		case path == "/networks/isogrid-nomad":
			writeJSON(200, map[string]any{"Id": "net1", "Name": "isogrid-nomad", "Scope": "swarm", "Driver": "overlay"})
		case path == "/networks/bridge-like":
			writeJSON(200, map[string]any{"Id": "net2", "Name": "bridge-like", "Scope": "local", "Driver": "bridge"})
		case strings.HasPrefix(path, "/networks/"):
			writeJSON(404, map[string]string{"message": "network not found"})
		case path == "/services/create" && r.Method == http.MethodPost:
			var spec map[string]any
			_ = json.NewDecoder(r.Body).Decode(&spec)
			f.nextID++
			id := "svc" + string(rune('0'+f.nextID))
			name := spec["Name"].(string)
			var ports any = []any{}
			if ep, ok := spec["EndpointSpec"].(map[string]any); ok {
				ports = ep["Ports"]
			}
			f.services[name] = map[string]any{
				"ID": id, "Version": map[string]any{"Index": 1}, "Spec": spec,
				"Endpoint": map[string]any{"Ports": ports},
			}
			if r.Header.Get("X-Registry-Auth") != "" {
				f.services[name]["auth"] = r.Header.Get("X-Registry-Auth")
			}
			writeJSON(201, map[string]string{"ID": id})
		case strings.HasPrefix(path, "/services/") && strings.HasSuffix(path, "/update"):
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/services/"), "/update")
			for _, svc := range f.services {
				if svc["ID"] == id {
					var spec map[string]any
					_ = json.NewDecoder(r.Body).Decode(&spec)
					svc["Spec"] = spec
					svc["Version"] = map[string]any{"Index": 2}
					writeJSON(200, map[string]any{})
					return
				}
			}
			writeJSON(404, map[string]string{"message": "no such service"})
		case strings.HasPrefix(path, "/services/") && r.Method == http.MethodDelete:
			id := strings.TrimPrefix(path, "/services/")
			for name, svc := range f.services {
				if svc["ID"] == id {
					delete(f.services, name)
					writeJSON(200, map[string]any{})
					return
				}
			}
			writeJSON(404, map[string]string{"message": "no such service"})
		case strings.HasPrefix(path, "/services/"):
			key := strings.TrimPrefix(path, "/services/")
			if svc, ok := f.services[key]; ok {
				writeJSON(200, svc)
				return
			}
			for _, svc := range f.services {
				if svc["ID"] == key {
					writeJSON(200, svc)
					return
				}
			}
			writeJSON(404, map[string]string{"message": "service " + key + " not found"})
		case path == "/tasks":
			var filter struct {
				Service []string `json:"service"`
			}
			_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filter)
			for _, svc := range f.services {
				if len(filter.Service) == 1 && svc["ID"] == filter.Service[0] {
					image := svc["Spec"].(map[string]any)["TaskTemplate"].(map[string]any)["ContainerSpec"].(map[string]any)["Image"]
					replicas := svc["Spec"].(map[string]any)["Mode"].(map[string]any)["Replicated"].(map[string]any)["Replicas"].(float64)
					tasks := []map[string]any{}
					for i := 0; i < int(replicas); i++ {
						tasks = append(tasks, map[string]any{
							"ID": "task", "NodeID": "node1", "Slot": i + 1, "DesiredState": "running",
							"Status": map[string]any{"State": "running"},
							"Spec":   map[string]any{"ContainerSpec": map[string]any{"Image": image}},
						})
					}
					writeJSON(200, tasks)
					return
				}
			}
			writeJSON(200, []any{})
		default:
			t.Logf("unexpected call %s %s", r.Method, r.URL.Path)
			writeJSON(500, map[string]string{"message": "unexpected"})
		}
	}
}

func setup(t *testing.T) (*Executor, *fakeSwarm, ed25519.PrivateKey) {
	t.Helper()
	fake := newFakeSwarm()
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)
	client, err := docker.New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	e := New(intent.NewVerifier(public, "o1", "c1"), "t", "c1")
	RegisterServices(e, client, "o1", nil)
	return e, fake, private
}

func TestDeployCreatesThenUpdatesAManagedService(t *testing.T) {
	e, fake, private := setup(t)
	payload := map[string]any{
		"name": "acme-web", "image": "nginx:1.27", "replicas": 2,
		"env":       map[string]string{"B": "2", "A": "1"},
		"ports":     []map[string]any{{"published": 8080, "target": 80}},
		"labels":    map[string]string{"isogrid.application": "app-1", "isogrid.managed": "false", "team": "web"},
		"volumes":   []map[string]any{{"name": "acme-data", "target": "/data"}},
		"resources": map[string]any{"cpu": 0.5, "memory_mb": 256},
	}
	r := e.Handle(context.Background(), signed(t, private, "service.deploy", payload)).(Reply)
	if r.Status != "ok" {
		t.Fatalf("deploy: %+v", r)
	}
	st := r.Result.(*ServiceStatus)
	if st.State != "running" || st.Running != 2 || st.Desired != 2 || st.Image != "nginx:1.27" || len(st.Ports) != 1 {
		t.Fatalf("status after deploy: %+v", st)
	}
	spec := fake.services["acme-web"]["Spec"].(map[string]any)
	labels := spec["Labels"].(map[string]any)
	if labels["isogrid.managed"] != "true" || labels["isogrid.application"] != "app-1" || labels["team"] != "web" || labels["isogrid.organization"] != "o1" {
		t.Fatalf("labels: %v", labels)
	}
	env := spec["TaskTemplate"].(map[string]any)["ContainerSpec"].(map[string]any)["Env"].([]any)
	if len(env) != 2 || env[0] != "A=1" || env[1] != "B=2" {
		t.Fatalf("env not sorted: %v", env)
	}
	mounts := spec["TaskTemplate"].(map[string]any)["ContainerSpec"].(map[string]any)["Mounts"].([]any)
	if mounts[0].(map[string]any)["Type"] != "volume" {
		t.Fatalf("mount: %v", mounts)
	}
	limits := spec["TaskTemplate"].(map[string]any)["Resources"].(map[string]any)["Limits"].(map[string]any)
	if limits["NanoCPUs"].(float64) != 5e8 || limits["MemoryBytes"].(float64) != 256<<20 {
		t.Fatalf("limits: %v", limits)
	}

	// Same name again: an update, not a second service.
	payload["image"] = "nginx:1.28"
	r = e.Handle(context.Background(), signed(t, private, "service.deploy", payload)).(Reply)
	if r.Status != "ok" || r.Result.(*ServiceStatus).Image != "nginx:1.28" || len(fake.services) != 1 {
		t.Fatalf("redeploy: %+v", r)
	}
	if !strings.Contains(strings.Join(fake.calls, "\n"), "/services/svc1/update") {
		t.Fatalf("no update call: %v", fake.calls)
	}
}

func TestGuardRails(t *testing.T) {
	e, fake, private := setup(t)
	cases := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"host network", map[string]any{"name": "a", "image": "x", "networks": []string{"host"}}, "not allowed"},
		{"missing network", map[string]any{"name": "a", "image": "x", "networks": []string{"nope"}}, "does not exist"},
		{"local network", map[string]any{"name": "a", "image": "x", "networks": []string{"bridge-like"}}, "not a Swarm overlay"},
		{"bad name", map[string]any{"name": "Bad Name", "image": "x"}, "service name"},
		{"too many replicas", map[string]any{"name": "a", "image": "x", "replicas": 500}, "at most"},
		{"bad env key", map[string]any{"name": "a", "image": "x", "env": map[string]string{"1x": "v"}}, "environment variable"},
		{"relative volume", map[string]any{"name": "a", "image": "x", "volumes": []map[string]any{{"name": "v", "target": "data"}}}, "absolute target"},
		{"constraint", map[string]any{"name": "a", "image": "x", "constraints": []string{"engine.labels.x==1"}}, "node.*"},
		{"secrets without vault", map[string]any{"name": "a", "image": "x", "secrets": []map[string]any{{"key": "K", "ref": "r"}}}, "no Vault"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.Handle(context.Background(), signed(t, private, "service.deploy", tc.payload)).(Reply)
			if r.Status != "error" || !strings.Contains(r.Error, tc.want) {
				t.Fatalf("want error containing %q, got %+v", tc.want, r)
			}
		})
	}
	if len(fake.services) != 0 {
		t.Fatalf("a refused deploy created a service: %v", fake.services)
	}
}

func TestOnlyManagedServicesAreTouched(t *testing.T) {
	e, fake, private := setup(t)
	fake.services["vault_vault"] = map[string]any{
		"ID": "svc9", "Version": map[string]any{"Index": 1},
		"Spec":     map[string]any{"Name": "vault_vault", "Labels": map[string]any{}, "TaskTemplate": map[string]any{"ContainerSpec": map[string]any{"Image": "vault"}}, "Mode": map[string]any{"Replicated": map[string]any{"Replicas": 1}}},
		"Endpoint": map[string]any{"Ports": []any{}},
	}
	for _, kind := range []string{"service.scale", "service.remove", "service.status", "service.rollback"} {
		r := e.Handle(context.Background(), signed(t, private, kind, map[string]any{"name": "vault_vault", "replicas": 0})).(Reply)
		if r.Status != "error" || !strings.Contains(r.Error, "not created by ISOGrid") {
			t.Fatalf("%s touched an unmanaged service: %+v", kind, r)
		}
	}
	r := e.Handle(context.Background(), signed(t, private, "service.deploy", map[string]any{"name": "vault_vault", "image": "x"})).(Reply)
	if r.Status != "error" || !strings.Contains(r.Error, "not created by ISOGrid") {
		t.Fatalf("deploy over an unmanaged service: %+v", r)
	}
	if _, still := fake.services["vault_vault"]; !still {
		t.Fatal("the unmanaged service is gone")
	}

	// A managed one can be scaled, inspected and removed.
	e.Handle(context.Background(), signed(t, private, "service.deploy", map[string]any{"name": "acme-api", "image": "x"}))
	r = e.Handle(context.Background(), signed(t, private, "service.scale", map[string]any{"name": "acme-api", "replicas": 3})).(Reply)
	if r.Status != "ok" || r.Result.(*ServiceStatus).Desired != 3 {
		t.Fatalf("scale: %+v", r)
	}
	r = e.Handle(context.Background(), signed(t, private, "service.status", map[string]any{"name": "acme-api"})).(Reply)
	if r.Status != "ok" || r.Result.(*ServiceStatus).Running != 3 {
		t.Fatalf("status: %+v", r)
	}
	r = e.Handle(context.Background(), signed(t, private, "service.remove", map[string]any{"name": "acme-api"})).(Reply)
	if r.Status != "ok" || r.Result.(map[string]any)["removed"] != true {
		t.Fatalf("remove: %+v", r)
	}
	r = e.Handle(context.Background(), signed(t, private, "service.remove", map[string]any{"name": "acme-api"})).(Reply)
	if r.Status != "ok" || r.Result.(map[string]any)["removed"] != false {
		t.Fatalf("second remove: %+v", r)
	}
}

func TestInventoryListsOverlayNetworksWithoutIngress(t *testing.T) {
	e, _, private := setup(t)
	r := e.Handle(context.Background(), signed(t, private, "networks.list", map[string]any{})).(Reply)
	if r.Status != "ok" {
		t.Fatalf("networks.list: %+v", r)
	}
	inv := r.Result.(Inventory)
	if len(inv.Networks) != 2 || inv.Networks[0].Name != "isogrid-nomad" || !inv.Networks[0].Attachable || inv.Networks[1].Name != "vault_default" {
		t.Fatalf("inventory: %+v", inv)
	}
}
