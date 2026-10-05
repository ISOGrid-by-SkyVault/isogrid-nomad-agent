package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
)

// ManagedLabel marks the services the agent created. Status, scale, remove
// and rollback refuse a service without it: an intent can never touch what
// the operator runs beside the agent on the same Swarm (the Vault, for one).
const ManagedLabel = "isogrid.managed"

// Labels the agent sets so the operator can tell what came from ISOGrid.
const (
	LabelApplication  = "isogrid.application"
	LabelOrganization = "isogrid.organization"
	LabelIntent       = "isogrid.intent"
)

// Limits that keep one intent from asking for the whole cluster.
const (
	maxReplicas    = 50
	maxPorts       = 16
	maxEnv         = 128
	maxVolumes     = 16
	convergeWait   = 90 * time.Second
	convergePoll   = 2 * time.Second
	defaultNetwork = "isogrid-nomad"
)

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9_.-]{0,61}[a-z0-9])?$`)
	imagePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)
	envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// DeployPayload is `service.deploy`: everything about a service except the
// secret values, which the agent reads from Vault by reference.
type DeployPayload struct {
	Name             string            `json:"name"`
	Image            string            `json:"image"`
	Replicas         *uint64           `json:"replicas"`
	Env              map[string]string `json:"env"`
	Secrets          []SecretRef       `json:"secrets"`
	Ports            []Port            `json:"ports"`
	Networks         []string          `json:"networks"`
	Aliases          []string          `json:"aliases"`
	Labels           map[string]string `json:"labels"`
	Command          []string          `json:"command"`
	Args             []string          `json:"args"`
	WorkingDir       string            `json:"working_dir"`
	User             string            `json:"user"`
	Resources        *ResourceLimits   `json:"resources"`
	Volumes          []Volume          `json:"volumes"`
	Constraints      []string          `json:"constraints"`
	Restart          *RestartSpec      `json:"restart"`
	Update           *UpdateSpec       `json:"update"`
	Healthcheck      *HealthSpec       `json:"healthcheck"`
	StopGraceSeconds *int64            `json:"stop_grace_seconds"`
	//: Base64 of the registry credential JSON the daemon expects, when the
	//: image is private. Resolved by the agent from a connection, later.
	RegistryAuth string `json:"registry_auth"`
	//: When set, the service is created or updated but the intent returns
	//: before the tasks converge.
	NoWait bool `json:"no_wait"`
}

type SecretRef struct {
	Key string `json:"key"`
	Ref string `json:"ref"`
	As  string `json:"as"`
}

type Port struct {
	Published uint32 `json:"published"`
	Target    uint32 `json:"target"`
	Protocol  string `json:"protocol"`
	Mode      string `json:"mode"`
}

type ResourceLimits struct {
	CPU             float64 `json:"cpu"`
	MemoryMB        int64   `json:"memory_mb"`
	ReserveCPU      float64 `json:"reserve_cpu"`
	ReserveMemoryMB int64   `json:"reserve_memory_mb"`
}

type Volume struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

type RestartSpec struct {
	Condition    string `json:"condition"`
	MaxAttempts  uint64 `json:"max_attempts"`
	DelaySeconds int64  `json:"delay_seconds"`
}

type UpdateSpec struct {
	Order          string `json:"order"`
	FailureAction  string `json:"failure_action"`
	Parallelism    uint64 `json:"parallelism"`
	MonitorSeconds int64  `json:"monitor_seconds"`
}

type HealthSpec struct {
	Test            []string `json:"test"`
	IntervalSeconds int64    `json:"interval_seconds"`
	TimeoutSeconds  int64    `json:"timeout_seconds"`
	Retries         int      `json:"retries"`
	StartSeconds    int64    `json:"start_seconds"`
}

// ServiceStatus is what status, deploy and scale report.
type ServiceStatus struct {
	ServiceID   string       `json:"service_id"`
	Name        string       `json:"name"`
	Image       string       `json:"image"`
	Desired     uint64       `json:"desired"`
	Running     int          `json:"running"`
	State       string       `json:"state"` // running | starting | degraded | failed | stopped
	Message     string       `json:"message,omitempty"`
	UpdateState string       `json:"update_state,omitempty"`
	Ports       []Port       `json:"ports"`
	Tasks       []TaskStatus `json:"tasks"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type TaskStatus struct {
	ID      string    `json:"id"`
	Slot    int       `json:"slot"`
	Node    string    `json:"node"`
	Desired string    `json:"desired"`
	State   string    `json:"state"`
	Error   string    `json:"error,omitempty"`
	Image   string    `json:"image"`
	At      time.Time `json:"at"`
}

// ServiceExecutor executes the service.* intents against one Swarm.
type ServiceExecutor struct {
	docker  *docker.Client
	orgID   string
	secrets SecretResolver
}

// SecretResolver turns references into values at deploy time. Nil until the
// Vault client exists: a deploy that lists secrets is then refused.
type SecretResolver interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// RegisterServices adds the service.* handlers to an executor.
func RegisterServices(e *Executor, client *docker.Client, organizationID string, secrets SecretResolver) *ServiceExecutor {
	s := &ServiceExecutor{docker: client, orgID: organizationID, secrets: secrets}
	e.Register("service.deploy", s.deploy)
	e.Register("service.status", s.status)
	e.Register("service.scale", s.scale)
	e.Register("service.remove", s.remove)
	e.Register("service.rollback", s.rollback)
	return s
}

func (s *ServiceExecutor) deploy(ctx context.Context, env *intent.Envelope) (any, error) {
	var p DeployPayload
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	spec, err := s.buildSpec(ctx, &p, env)
	if err != nil {
		return nil, err
	}
	existing, err := s.docker.InspectService(ctx, p.Name)
	switch {
	case err == nil:
		if !s.managed(existing) {
			return nil, fmt.Errorf("a service named %q exists and was not created by ISOGrid", p.Name)
		}
		if err := s.docker.UpdateService(ctx, existing.ID, existing.Version.Index, spec, p.RegistryAuth); err != nil {
			return nil, err
		}
	case docker.IsNotFound(err):
		if _, err := s.docker.CreateService(ctx, spec, p.RegistryAuth); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	if p.NoWait {
		return s.report(ctx, p.Name)
	}
	return s.converge(ctx, p.Name)
}

func (s *ServiceExecutor) status(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	if _, err := s.managedByName(ctx, p.Name); err != nil {
		return nil, err
	}
	return s.report(ctx, p.Name)
}

func (s *ServiceExecutor) scale(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Name     string `json:"name"`
		Replicas uint64 `json:"replicas"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	if p.Replicas > maxReplicas {
		return nil, fmt.Errorf("at most %d replicas", maxReplicas)
	}
	svc, err := s.managedByName(ctx, p.Name)
	if err != nil {
		return nil, err
	}
	spec := svc.Spec
	spec.Mode = docker.ServiceMode{Replicated: &docker.Replicated{Replicas: p.Replicas}}
	if err := s.docker.UpdateService(ctx, svc.ID, svc.Version.Index, spec, ""); err != nil {
		return nil, err
	}
	return s.converge(ctx, p.Name)
}

func (s *ServiceExecutor) remove(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	svc, err := s.managedByName(ctx, p.Name)
	if docker.IsNotFound(err) {
		return map[string]any{"name": p.Name, "removed": false, "message": "no such service"}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.docker.RemoveService(ctx, svc.ID); err != nil && !docker.IsNotFound(err) {
		return nil, err
	}
	return map[string]any{"name": p.Name, "removed": true}, nil
}

func (s *ServiceExecutor) rollback(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	svc, err := s.managedByName(ctx, p.Name)
	if err != nil {
		return nil, err
	}
	if svc.PreviousSpec == nil {
		return nil, errors.New("the service has no previous version to go back to")
	}
	if err := s.docker.RollbackService(ctx, svc.ID, svc.Version.Index, svc.Spec); err != nil {
		return nil, err
	}
	return s.converge(ctx, p.Name)
}

// buildSpec turns the payload into a Swarm spec, refusing what the guard
// rails exclude: bind mounts, host networking, privileged options (none of
// which the payload can even express) and anything out of bounds.
func (s *ServiceExecutor) buildSpec(ctx context.Context, p *DeployPayload, env *intent.Envelope) (docker.ServiceSpec, error) {
	var spec docker.ServiceSpec
	if !namePattern.MatchString(p.Name) {
		return spec, fmt.Errorf("service name %q: lowercase letters, digits, dots, dashes, underscores", p.Name)
	}
	if !imagePattern.MatchString(p.Image) || strings.Contains(p.Image, "..") {
		return spec, fmt.Errorf("image reference %q is not valid", p.Image)
	}
	replicas := uint64(1)
	if p.Replicas != nil {
		replicas = *p.Replicas
	}
	if replicas > maxReplicas {
		return spec, fmt.Errorf("at most %d replicas", maxReplicas)
	}
	if len(p.Env) > maxEnv {
		return spec, fmt.Errorf("at most %d environment variables", maxEnv)
	}
	if len(p.Ports) > maxPorts {
		return spec, fmt.Errorf("at most %d ports", maxPorts)
	}
	if len(p.Volumes) > maxVolumes {
		return spec, fmt.Errorf("at most %d volumes", maxVolumes)
	}

	envList := make([]string, 0, len(p.Env)+len(p.Secrets))
	keys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		if !envKeyPattern.MatchString(k) {
			return spec, fmt.Errorf("environment variable %q: not a valid name", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		envList = append(envList, k+"="+p.Env[k])
	}
	if len(p.Secrets) > 0 {
		if s.secrets == nil {
			return spec, errors.New("this agent has no Vault configured; secrets by reference cannot be resolved")
		}
		for _, ref := range p.Secrets {
			if !envKeyPattern.MatchString(ref.Key) {
				return spec, fmt.Errorf("secret key %q: not a valid name", ref.Key)
			}
			if ref.As != "" && ref.As != "env" {
				return spec, fmt.Errorf("secret %q: only env references are supported yet", ref.Key)
			}
			value, err := s.secrets.Resolve(ctx, ref.Ref)
			if err != nil {
				return spec, fmt.Errorf("secret %q: %w", ref.Key, err)
			}
			envList = append(envList, ref.Key+"="+value)
		}
	}

	labels := map[string]string{ManagedLabel: "true", LabelOrganization: s.orgID, LabelIntent: env.ID}
	for k, v := range p.Labels {
		if strings.HasPrefix(k, "isogrid.") && k != LabelApplication {
			continue
		}
		labels[k] = v
	}

	networks := p.Networks
	if len(networks) == 0 {
		networks = []string{defaultNetwork}
	}
	attachments := make([]docker.NetworkAttachment, 0, len(networks))
	for _, name := range networks {
		if name == "host" || name == "bridge" || name == "none" {
			return spec, fmt.Errorf("network %q is not allowed; services join overlay networks only", name)
		}
		n, err := s.docker.InspectNetwork(ctx, name)
		if err != nil {
			if docker.IsNotFound(err) {
				return spec, fmt.Errorf("network %q does not exist on this Swarm", name)
			}
			return spec, err
		}
		if n.Scope != "swarm" {
			return spec, fmt.Errorf("network %q is not a Swarm overlay network", name)
		}
		attachments = append(attachments, docker.NetworkAttachment{Target: n.ID, Aliases: p.Aliases})
	}

	mounts := make([]docker.Mount, 0, len(p.Volumes))
	for _, v := range p.Volumes {
		if !namePattern.MatchString(v.Name) || !strings.HasPrefix(v.Target, "/") {
			return spec, fmt.Errorf("volume %q: a named volume and an absolute target path", v.Name)
		}
		mounts = append(mounts, docker.Mount{Type: "volume", Source: v.Name, Target: v.Target, ReadOnly: v.ReadOnly})
	}

	ports := make([]docker.PortConfig, 0, len(p.Ports))
	for _, port := range p.Ports {
		proto := strings.ToLower(port.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" {
			return spec, fmt.Errorf("port %d: protocol must be tcp or udp", port.Target)
		}
		if port.Target == 0 || port.Target > 65535 || port.Published > 65535 {
			return spec, fmt.Errorf("port %d: out of range", port.Target)
		}
		mode := port.Mode
		if mode == "" {
			mode = "ingress"
		}
		if mode != "ingress" && mode != "host" {
			return spec, fmt.Errorf("port %d: mode must be ingress or host", port.Target)
		}
		ports = append(ports, docker.PortConfig{Protocol: proto, TargetPort: port.Target, PublishedPort: port.Published, PublishMode: mode})
	}

	container := docker.ContainerSpec{
		Image:   p.Image,
		Labels:  labels,
		Command: p.Command,
		Args:    p.Args,
		Env:     envList,
		Dir:     p.WorkingDir,
		User:    p.User,
		Mounts:  mounts,
	}
	if p.StopGraceSeconds != nil {
		grace := *p.StopGraceSeconds * int64(time.Second)
		container.StopGracePeriod = &grace
	}
	if p.Healthcheck != nil && len(p.Healthcheck.Test) > 0 {
		container.Healthcheck = &docker.Healthcheck{
			Test:        p.Healthcheck.Test,
			Interval:    p.Healthcheck.IntervalSeconds * int64(time.Second),
			Timeout:     p.Healthcheck.TimeoutSeconds * int64(time.Second),
			Retries:     p.Healthcheck.Retries,
			StartPeriod: p.Healthcheck.StartSeconds * int64(time.Second),
		}
	}

	task := docker.TaskSpec{ContainerSpec: container, Networks: attachments}
	if p.Resources != nil {
		res := &docker.Resources{}
		if p.Resources.CPU > 0 || p.Resources.MemoryMB > 0 {
			res.Limits = &docker.ResourceSet{NanoCPUs: int64(p.Resources.CPU * 1e9), MemoryBytes: p.Resources.MemoryMB << 20}
		}
		if p.Resources.ReserveCPU > 0 || p.Resources.ReserveMemoryMB > 0 {
			res.Reservations = &docker.ResourceSet{NanoCPUs: int64(p.Resources.ReserveCPU * 1e9), MemoryBytes: p.Resources.ReserveMemoryMB << 20}
		}
		task.Resources = res
	}
	restart := &docker.RestartPolicy{Condition: "any", Delay: int64(5 * time.Second)}
	if p.Restart != nil {
		if p.Restart.Condition != "" {
			restart.Condition = p.Restart.Condition
		}
		restart.MaxAttempts = p.Restart.MaxAttempts
		if p.Restart.DelaySeconds > 0 {
			restart.Delay = p.Restart.DelaySeconds * int64(time.Second)
		}
	}
	task.RestartPolicy = restart
	if len(p.Constraints) > 0 {
		for _, c := range p.Constraints {
			if !strings.HasPrefix(c, "node.") {
				return spec, fmt.Errorf("constraint %q: only node.* constraints are accepted", c)
			}
		}
		task.Placement = &docker.Placement{Constraints: p.Constraints}
	}

	update := &docker.UpdateConfig{Parallelism: 1, Order: "start-first", FailureAction: "rollback", Monitor: int64(15 * time.Second)}
	if p.Update != nil {
		if p.Update.Order != "" {
			update.Order = p.Update.Order
		}
		if p.Update.FailureAction != "" {
			update.FailureAction = p.Update.FailureAction
		}
		if p.Update.Parallelism > 0 {
			update.Parallelism = p.Update.Parallelism
		}
		if p.Update.MonitorSeconds > 0 {
			update.Monitor = p.Update.MonitorSeconds * int64(time.Second)
		}
	}

	spec = docker.ServiceSpec{
		Name:           p.Name,
		Labels:         labels,
		TaskTemplate:   task,
		Mode:           docker.ServiceMode{Replicated: &docker.Replicated{Replicas: replicas}},
		UpdateConfig:   update,
		RollbackConfig: &docker.UpdateConfig{Parallelism: 1, Order: "start-first", FailureAction: "pause"},
	}
	if len(ports) > 0 {
		spec.EndpointSpec = &docker.EndpointSpec{Mode: "vip", Ports: ports}
	}
	return spec, nil
}

func (s *ServiceExecutor) managed(svc *docker.Service) bool {
	return svc.Spec.Labels[ManagedLabel] == "true"
}

func (s *ServiceExecutor) managedByName(ctx context.Context, name string) (*docker.Service, error) {
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("service name %q is not valid", name)
	}
	svc, err := s.docker.InspectService(ctx, name)
	if err != nil {
		return nil, err
	}
	if !s.managed(svc) {
		return nil, fmt.Errorf("service %q was not created by ISOGrid; the agent leaves it alone", name)
	}
	return svc, nil
}

// converge waits until the service's tasks settle, then reports.
func (s *ServiceExecutor) converge(ctx context.Context, name string) (any, error) {
	deadline := time.Now().Add(convergeWait)
	var last *ServiceStatus
	for {
		st, err := s.report(ctx, name)
		if err != nil {
			return nil, err
		}
		last = st
		if st.State == "running" || st.State == "stopped" || st.State == "failed" {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return last, nil
		case <-time.After(convergePoll):
		}
	}
}

// report reads the service and its tasks and summarises them.
func (s *ServiceExecutor) report(ctx context.Context, name string) (*ServiceStatus, error) {
	svc, err := s.docker.InspectService(ctx, name)
	if err != nil {
		return nil, err
	}
	tasks, err := s.docker.ServiceTasks(ctx, svc.ID)
	if err != nil {
		return nil, err
	}
	st := &ServiceStatus{
		ServiceID: svc.ID,
		Name:      svc.Spec.Name,
		Image:     svc.Spec.TaskTemplate.ContainerSpec.Image,
		UpdatedAt: svc.UpdatedAt,
		Ports:     []Port{},
		Tasks:     []TaskStatus{},
	}
	if svc.Spec.Mode.Replicated != nil {
		st.Desired = svc.Spec.Mode.Replicated.Replicas
	}
	for _, p := range svc.Endpoint.Ports {
		st.Ports = append(st.Ports, Port{Published: p.PublishedPort, Target: p.TargetPort, Protocol: p.Protocol, Mode: p.PublishMode})
	}
	if svc.UpdateStatus != nil {
		st.UpdateState = svc.UpdateStatus.State
		st.Message = svc.UpdateStatus.Message
	}
	var running, failed, pending int
	var lastErr string
	for _, t := range tasks {
		ts := TaskStatus{ID: t.ID, Slot: t.Slot, Node: t.NodeID, Desired: t.DesiredState, State: t.Status.State, Error: t.Status.Err, Image: t.Spec.ContainerSpec.Image, At: t.Status.Timestamp}
		st.Tasks = append(st.Tasks, ts)
		if t.DesiredState != "running" {
			continue
		}
		switch t.Status.State {
		case "running":
			running++
		case "failed", "rejected", "orphaned":
			failed++
			if t.Status.Err != "" {
				lastErr = t.Status.Err
			}
		default:
			pending++
		}
	}
	sort.Slice(st.Tasks, func(i, j int) bool { return st.Tasks[i].At.After(st.Tasks[j].At) })
	if len(st.Tasks) > 20 {
		st.Tasks = st.Tasks[:20]
	}
	st.Running = running
	switch {
	case st.Desired == 0:
		st.State = "stopped"
	case uint64(running) >= st.Desired && (st.UpdateState == "" || st.UpdateState == "completed"):
		st.State = "running"
	case running > 0:
		st.State = "degraded"
	case pending > 0:
		st.State = "starting"
	default:
		st.State = "failed"
	}
	if st.UpdateState == "paused" || st.UpdateState == "rollback_completed" {
		st.State = "degraded"
		if st.UpdateState == "rollback_completed" && uint64(running) >= st.Desired {
			st.State = "running"
		}
	}
	if lastErr != "" && st.Message == "" {
		st.Message = lastErr
	}
	return st, nil
}

func decode(raw json.RawMessage, into any) error {
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	return nil
}
