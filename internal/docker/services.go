package docker

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// The subset of the Swarm service spec the agent writes. Field names follow
// the Engine API so the JSON needs no translation.

type ServiceSpec struct {
	Name           string            `json:"Name"`
	Labels         map[string]string `json:"Labels,omitempty"`
	TaskTemplate   TaskSpec          `json:"TaskTemplate"`
	Mode           ServiceMode       `json:"Mode"`
	UpdateConfig   *UpdateConfig     `json:"UpdateConfig,omitempty"`
	RollbackConfig *UpdateConfig     `json:"RollbackConfig,omitempty"`
	EndpointSpec   *EndpointSpec     `json:"EndpointSpec,omitempty"`
}

type TaskSpec struct {
	ContainerSpec ContainerSpec       `json:"ContainerSpec"`
	Resources     *Resources          `json:"Resources,omitempty"`
	RestartPolicy *RestartPolicy      `json:"RestartPolicy,omitempty"`
	Placement     *Placement          `json:"Placement,omitempty"`
	Networks      []NetworkAttachment `json:"Networks,omitempty"`
	ForceUpdate   uint64              `json:"ForceUpdate,omitempty"`
}

type ContainerSpec struct {
	Image           string            `json:"Image"`
	Labels          map[string]string `json:"Labels,omitempty"`
	Command         []string          `json:"Command,omitempty"`
	Args            []string          `json:"Args,omitempty"`
	Env             []string          `json:"Env,omitempty"`
	Dir             string            `json:"Dir,omitempty"`
	User            string            `json:"User,omitempty"`
	Mounts          []Mount           `json:"Mounts,omitempty"`
	StopGracePeriod *int64            `json:"StopGracePeriod,omitempty"`
	Healthcheck     *Healthcheck      `json:"HealthCheck,omitempty"`
	Secrets         []SecretReference `json:"Secrets,omitempty"`
}

type Mount struct {
	Type     string `json:"Type"` // volume only; bind is refused upstream
	Source   string `json:"Source,omitempty"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly,omitempty"`
}

type Healthcheck struct {
	Test        []string `json:"Test,omitempty"`
	Interval    int64    `json:"Interval,omitempty"`
	Timeout     int64    `json:"Timeout,omitempty"`
	Retries     int      `json:"Retries,omitempty"`
	StartPeriod int64    `json:"StartPeriod,omitempty"`
}

type SecretReference struct {
	File       SecretFile `json:"File"`
	SecretID   string     `json:"SecretID"`
	SecretName string     `json:"SecretName"`
}

type SecretFile struct {
	Name string `json:"Name"`
	UID  string `json:"UID"`
	GID  string `json:"GID"`
	Mode uint32 `json:"Mode"`
}

type Resources struct {
	Limits       *ResourceSet `json:"Limits,omitempty"`
	Reservations *ResourceSet `json:"Reservations,omitempty"`
}

type ResourceSet struct {
	NanoCPUs    int64 `json:"NanoCPUs,omitempty"`
	MemoryBytes int64 `json:"MemoryBytes,omitempty"`
}

type RestartPolicy struct {
	Condition   string `json:"Condition,omitempty"`
	Delay       int64  `json:"Delay,omitempty"`
	MaxAttempts uint64 `json:"MaxAttempts,omitempty"`
	Window      int64  `json:"Window,omitempty"`
}

type Placement struct {
	Constraints []string `json:"Constraints,omitempty"`
}

type NetworkAttachment struct {
	Target  string   `json:"Target"`
	Aliases []string `json:"Aliases,omitempty"`
}

type ServiceMode struct {
	Replicated *Replicated `json:"Replicated,omitempty"`
}

type Replicated struct {
	Replicas uint64 `json:"Replicas"`
}

type UpdateConfig struct {
	Parallelism   uint64 `json:"Parallelism"`
	Delay         int64  `json:"Delay,omitempty"`
	FailureAction string `json:"FailureAction,omitempty"`
	Monitor       int64  `json:"Monitor,omitempty"`
	Order         string `json:"Order,omitempty"`
}

type EndpointSpec struct {
	Mode  string       `json:"Mode,omitempty"`
	Ports []PortConfig `json:"Ports,omitempty"`
}

type PortConfig struct {
	Protocol      string `json:"Protocol"`
	TargetPort    uint32 `json:"TargetPort"`
	PublishedPort uint32 `json:"PublishedPort,omitempty"`
	PublishMode   string `json:"PublishMode,omitempty"`
}

// Service is what GET /services/{id} returns, the parts the agent reads.
type Service struct {
	ID      string `json:"ID"`
	Version struct {
		Index uint64 `json:"Index"`
	} `json:"Version"`
	CreatedAt    time.Time    `json:"CreatedAt"`
	UpdatedAt    time.Time    `json:"UpdatedAt"`
	Spec         ServiceSpec  `json:"Spec"`
	PreviousSpec *ServiceSpec `json:"PreviousSpec,omitempty"`
	Endpoint     struct {
		Ports []PortConfig `json:"Ports"`
	} `json:"Endpoint"`
	UpdateStatus *struct {
		State       string    `json:"State"`
		StartedAt   time.Time `json:"StartedAt"`
		CompletedAt time.Time `json:"CompletedAt"`
		Message     string    `json:"Message"`
	} `json:"UpdateStatus,omitempty"`
}

// Task is one container of a service as the scheduler sees it.
type Task struct {
	ID           string    `json:"ID"`
	NodeID       string    `json:"NodeID"`
	Slot         int       `json:"Slot"`
	CreatedAt    time.Time `json:"CreatedAt"`
	UpdatedAt    time.Time `json:"UpdatedAt"`
	DesiredState string    `json:"DesiredState"`
	Status       struct {
		State           string    `json:"State"`
		Message         string    `json:"Message"`
		Err             string    `json:"Err"`
		Timestamp       time.Time `json:"Timestamp"`
		ContainerStatus *struct {
			ContainerID string `json:"ContainerID"`
			ExitCode    int    `json:"ExitCode"`
		} `json:"ContainerStatus,omitempty"`
	} `json:"Status"`
	Spec struct {
		ContainerSpec struct {
			Image string `json:"Image"`
		} `json:"ContainerSpec"`
	} `json:"Spec"`
}

// Network is the part of GET /networks/{name} the agent checks.
type Network struct {
	ID         string `json:"Id"`
	Name       string `json:"Name"`
	Driver     string `json:"Driver"`
	Scope      string `json:"Scope"`
	Attachable bool   `json:"Attachable"`
}

// CreateService creates a service and returns its id.
func (c *Client) CreateService(ctx context.Context, spec ServiceSpec, registryAuth string) (string, error) {
	var out struct {
		ID string `json:"ID"`
	}
	if err := c.doWithAuth(ctx, http.MethodPost, "/services/create", nil, spec, &out, registryAuth); err != nil {
		return "", err
	}
	return out.ID, nil
}

// UpdateService replaces a service's spec at the given version.
func (c *Client) UpdateService(ctx context.Context, id string, version uint64, spec ServiceSpec, registryAuth string) error {
	q := url.Values{"version": {strconv.FormatUint(version, 10)}}
	return c.doWithAuth(ctx, http.MethodPost, "/services/"+id+"/update", q, spec, nil, registryAuth)
}

// RollbackService asks the scheduler to go back to the previous spec.
func (c *Client) RollbackService(ctx context.Context, id string, version uint64, spec ServiceSpec) error {
	q := url.Values{"version": {strconv.FormatUint(version, 10)}, "rollback": {"previous"}}
	return c.do(ctx, http.MethodPost, "/services/"+id+"/update", q, spec, nil)
}

// InspectService fetches one service by id or name.
func (c *Client) InspectService(ctx context.Context, idOrName string) (*Service, error) {
	var s Service
	if err := c.do(ctx, http.MethodGet, "/services/"+idOrName, nil, nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ListServices lists services carrying a label.
func (c *Client) ListServices(ctx context.Context, label string) ([]Service, error) {
	var out []Service
	if err := c.do(ctx, http.MethodGet, "/services", filters(map[string][]string{"label": {label}}), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveService deletes a service.
func (c *Client) RemoveService(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/services/"+id, nil, nil, nil)
}

// ServiceTasks lists the tasks of a service, newest first is not guaranteed.
func (c *Client) ServiceTasks(ctx context.Context, idOrName string) ([]Task, error) {
	var out []Task
	if err := c.do(ctx, http.MethodGet, "/tasks", filters(map[string][]string{"service": {idOrName}}), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// OverlayNetworks lists the Swarm-scoped overlay networks, the ingress
// network excluded: what a service may attach to.
func (c *Client) OverlayNetworks(ctx context.Context) ([]Network, error) {
	var out []Network
	q := filters(map[string][]string{"driver": {"overlay"}, "scope": {"swarm"}})
	if err := c.do(ctx, http.MethodGet, "/networks", q, nil, &out); err != nil {
		return nil, err
	}
	kept := out[:0]
	for _, n := range out {
		if n.Name == "ingress" {
			continue
		}
		kept = append(kept, n)
	}
	return kept, nil
}

// InspectNetwork fetches one network by id or name.
func (c *Client) InspectNetwork(ctx context.Context, idOrName string) (*Network, error) {
	var n Network
	if err := c.do(ctx, http.MethodGet, "/networks/"+idOrName, nil, nil, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func (c *Client) doWithAuth(ctx context.Context, method, path string, query url.Values, body, out any, registryAuth string) error {
	var headers http.Header
	if registryAuth != "" {
		headers = http.Header{"X-Registry-Auth": {registryAuth}}
	}
	return c.doH(ctx, method, path, query, body, out, headers)
}
