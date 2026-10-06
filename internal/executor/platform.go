package executor

// The intents a managed database (and later any managed service) needs
// beyond deploying a service: a look at a service, a change to one, the
// Swarm's nodes, an overlay of its own, a one-off job, a volume gone, a
// secret minted. Each is generic - nothing here knows what Patroni or
// PgBouncer are - and each keeps the guard rails of the rest of the agent:
// only what carries the managed label is touched, overlays only, no bind
// mounts, no exec into a running container, and every `{{secret:ref}}` the
// platform wrote is substituted from the customer's Vault here, so the
// value never crossed the stream.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/vault"
)

// LabelService marks the Swarm configs and secrets made for one service,
// so they can be swapped and pruned with it.
const LabelService = "isogrid.service"

// SecretStore is the Vault as the platform intents need it: read to
// substitute, write to mint, list and delete to forget an instance.
type SecretStore interface {
	SecretResolver
	Write(ctx context.Context, ref, value string) (string, error)
	Delete(ctx context.Context, ref string) error
	List(ctx context.Context) ([]string, bool, error)
}

// placeholderPattern is `{{secret:<ref>}}` with the Vault client's own
// reference grammar.
var placeholderPattern = regexp.MustCompile(`\{\{secret:([A-Za-z0-9][A-Za-z0-9_.-]{0,62}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,62}){0,7})\}\}`)

// Bounds a job and an object may not exceed.
const (
	maxJobTimeout   = 30 * time.Minute
	maxStdin        = 1 << 20
	maxConfigBytes  = 500 << 10
	maxConfigs      = 8
	maxSecretRefs   = 32
	secretLength    = 32
	volumeWait      = 30 * time.Second
	volumePoll      = 2 * time.Second
	reservedPrefix  = "connections/"
	minPrefixDepth  = 2
	secretAlphabet  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	mintedPrefixMax = 120
)

// ConfigMount is a file the platform wants mounted in a service: its content
// (placeholders included), where, and with which mode and owner. Becomes a
// Swarm config, or a Swarm secret when the content is sensitive.
type ConfigMount struct {
	Name    string `json:"name"`
	Target  string `json:"target"`
	Content string `json:"content"`
	Mode    uint32 `json:"mode"`
	UID     *int   `json:"uid"`
	Secret  bool   `json:"secret"`
}

// substitute replaces every placeholder in a text with the value at its
// reference. A text with no placeholder needs no Vault at all.
func substitute(ctx context.Context, store SecretResolver, text string) (string, error) {
	if !strings.Contains(text, "{{secret:") {
		return text, nil
	}
	if store == nil {
		return "", errors.New("this agent has no Vault configured; secrets by reference cannot be resolved")
	}
	var failure error
	out := placeholderPattern.ReplaceAllStringFunc(text, func(match string) string {
		if failure != nil {
			return match
		}
		ref := placeholderPattern.FindStringSubmatch(match)[1]
		value, err := store.Resolve(ctx, ref)
		if err != nil {
			if errors.Is(err, vault.ErrNotFound) {
				failure = fmt.Errorf("secret %q does not exist in the Vault; ISOGrid should have asked for it first (secret.ensure)", ref)
			} else {
				failure = fmt.Errorf("secret %q: %w", ref, err)
			}
			return match
		}
		return value
	})
	if failure != nil {
		return "", failure
	}
	if strings.Contains(out, "{{secret:") {
		return "", errors.New("a secret placeholder could not be parsed")
	}
	return out, nil
}

// PlatformExecutor holds the handlers that complete the service executor.
type PlatformExecutor struct {
	services *ServiceExecutor
	store    SecretStore
}

// RegisterPlatform adds the handlers. `store` may be nil: the handlers that
// need the Vault then refuse with a clear message.
func RegisterPlatform(e *Executor, services *ServiceExecutor, store SecretStore) *PlatformExecutor {
	p := &PlatformExecutor{services: services, store: store}
	e.Register("service.inspect", p.inspect)
	e.Register("service.update", p.update)
	e.Register("nodes.list", p.nodes)
	e.Register("network.ensure", p.networkEnsure)
	e.Register("network.remove", p.networkRemove)
	e.Register("volume.remove", p.volumeRemove)
	e.Register("secret.ensure", p.secretEnsure)
	e.Register("secret.remove", p.secretRemove)
	e.Register("job.run", p.jobRun)
	return p
}

// -- services ---------------------------------------------------------------------

// Inspection is what the platform's provisioner reads back about a service.
type Inspection struct {
	ServiceID   string   `json:"service_id"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Networks    []string `json:"networks"`
	Constraints []string `json:"constraints"`
	// Hostname of the node running the service's task, when one is.
	Node     string `json:"node,omitempty"`
	Replicas uint64 `json:"replicas"`
	State    string `json:"state"`
}

func (p *PlatformExecutor) inspect(ctx context.Context, env *intent.Envelope) (any, error) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decode(env.Payload, &body); err != nil {
		return nil, err
	}
	svc, err := p.services.managedByName(ctx, body.Name)
	if err != nil {
		return nil, err
	}
	return p.describe(ctx, svc)
}

func (p *PlatformExecutor) describe(ctx context.Context, svc *docker.Service) (*Inspection, error) {
	d := p.services.docker
	out := &Inspection{
		ServiceID:   svc.ID,
		Name:        svc.Spec.Name,
		Image:       svc.Spec.TaskTemplate.ContainerSpec.Image,
		Networks:    []string{},
		Constraints: []string{},
	}
	if svc.Spec.Mode.Replicated != nil {
		out.Replicas = svc.Spec.Mode.Replicated.Replicas
	}
	if svc.Spec.TaskTemplate.Placement != nil {
		out.Constraints = append(out.Constraints, svc.Spec.TaskTemplate.Placement.Constraints...)
	}
	for _, attachment := range svc.Spec.TaskTemplate.Networks {
		n, err := d.InspectNetwork(ctx, attachment.Target)
		if err != nil {
			if docker.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		out.Networks = append(out.Networks, n.Name)
	}
	status, err := p.services.report(ctx, svc.Spec.Name)
	if err != nil {
		return nil, err
	}
	out.State = status.State
	for _, task := range status.Tasks {
		if task.Desired == "running" && task.State == "running" {
			out.Node = p.hostname(ctx, task.Node)
			break
		}
	}
	return out, nil
}

func (p *PlatformExecutor) hostname(ctx context.Context, nodeID string) string {
	nodes, err := p.services.docker.ListNodes(ctx)
	if err != nil {
		return ""
	}
	for _, n := range nodes {
		if n.ID == nodeID {
			return n.Description.Hostname
		}
	}
	return ""
}

// UpdatePayload is `service.update`: the few things the provisioner changes
// on a running service. Each is optional; what is absent is left alone.
type UpdatePayload struct {
	Name           string          `json:"name"`
	Image          string          `json:"image"`
	Resources      *ResourceLimits `json:"resources"`
	Args           []string        `json:"args"`
	AddNetworks    []string        `json:"add_networks"`
	RemoveNetworks []string        `json:"remove_networks"`
	AddConstraints []string        `json:"add_constraints"`
	Configs        []ConfigMount   `json:"configs"`
	Aliases        *AliasChange    `json:"aliases"`
}

// AliasChange gives a service exactly these extra DNS names on one of the
// networks it is attached to. An empty list removes them all.
type AliasChange struct {
	Network string   `json:"network"`
	Names   []string `json:"names"`
}

const maxAliases = 16

// A DNS label: what another service on the network can look up.
var aliasPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (p *PlatformExecutor) update(ctx context.Context, env *intent.Envelope) (any, error) {
	var body UpdatePayload
	if err := decode(env.Payload, &body); err != nil {
		return nil, err
	}
	svc, err := p.services.managedByName(ctx, body.Name)
	if err != nil {
		return nil, err
	}
	d := p.services.docker
	spec := svc.Spec
	container := &spec.TaskTemplate.ContainerSpec
	if body.Image != "" {
		if !imagePattern.MatchString(body.Image) || strings.Contains(body.Image, "..") {
			return nil, fmt.Errorf("image reference %q is not valid", body.Image)
		}
		container.Image = body.Image
	}
	if body.Args != nil {
		container.Args = body.Args
	}
	if body.Resources != nil {
		res := &docker.Resources{}
		if spec.TaskTemplate.Resources != nil {
			res.Reservations = spec.TaskTemplate.Resources.Reservations
		}
		if body.Resources.CPU > 0 || body.Resources.MemoryMB > 0 {
			res.Limits = &docker.ResourceSet{NanoCPUs: int64(body.Resources.CPU * 1e9), MemoryBytes: body.Resources.MemoryMB << 20}
		}
		spec.TaskTemplate.Resources = res
	}
	if len(body.RemoveNetworks) > 0 || len(body.AddNetworks) > 0 {
		kept := make([]docker.NetworkAttachment, 0, len(spec.TaskTemplate.Networks))
		for _, attachment := range spec.TaskTemplate.Networks {
			n, err := d.InspectNetwork(ctx, attachment.Target)
			if err != nil && !docker.IsNotFound(err) {
				return nil, err
			}
			if n != nil && contains(body.RemoveNetworks, n.Name) {
				continue
			}
			kept = append(kept, attachment)
		}
		for _, name := range body.AddNetworks {
			n, err := p.swarmNetwork(ctx, name)
			if err != nil {
				return nil, err
			}
			already := false
			for _, attachment := range kept {
				if attachment.Target == n.ID {
					already = true
				}
			}
			if !already {
				kept = append(kept, docker.NetworkAttachment{Target: n.ID})
			}
		}
		spec.TaskTemplate.Networks = kept
	}
	if body.Aliases != nil {
		if len(body.Aliases.Names) > maxAliases {
			return nil, fmt.Errorf("at most %d aliases", maxAliases)
		}
		for _, alias := range body.Aliases.Names {
			if !aliasPattern.MatchString(alias) {
				return nil, fmt.Errorf("alias %q: lowercase letters, digits and dashes", alias)
			}
		}
		n, err := p.swarmNetwork(ctx, body.Aliases.Network)
		if err != nil {
			return nil, err
		}
		found := false
		for i, attachment := range spec.TaskTemplate.Networks {
			if attachment.Target == n.ID || attachment.Target == n.Name {
				spec.TaskTemplate.Networks[i].Aliases = append([]string{}, body.Aliases.Names...)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("the service is not attached to network %q", body.Aliases.Network)
		}
	}
	if len(body.AddConstraints) > 0 {
		for _, c := range body.AddConstraints {
			if !strings.HasPrefix(c, "node.") {
				return nil, fmt.Errorf("constraint %q: only node.* constraints are accepted", c)
			}
		}
		if spec.TaskTemplate.Placement == nil {
			spec.TaskTemplate.Placement = &docker.Placement{}
		}
		spec.TaskTemplate.Placement.Constraints = append(spec.TaskTemplate.Placement.Constraints, body.AddConstraints...)
	}
	var fresh []string
	if body.Configs != nil {
		configs, secrets, ids, err := p.configObjects(ctx, body.Name, body.Configs)
		if err != nil {
			return nil, err
		}
		container.Configs, container.Secrets, fresh = configs, secrets, ids
	}
	spec.TaskTemplate.ForceUpdate = svc.Spec.TaskTemplate.ForceUpdate
	if body.Configs != nil && body.Image == "" && body.Resources == nil && body.Args == nil {
		// New files, same everything else: Swarm only restarts the task when
		// something in the spec changed, and new object ids are a change -
		// but a reload of identical content must restart too, or the
		// userlist PgBouncer holds stays stale. ForceUpdate makes sure.
		spec.TaskTemplate.ForceUpdate++
	}
	if err := d.UpdateService(ctx, svc.ID, svc.Version.Index, spec, ""); err != nil {
		return nil, err
	}
	if body.Configs != nil {
		p.pruneObjects(ctx, body.Name, fresh)
	}
	status, err := p.services.report(ctx, body.Name)
	if err != nil {
		return nil, err
	}
	status.AliasesSet = body.Aliases != nil
	return status, nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func (p *PlatformExecutor) swarmNetwork(ctx context.Context, name string) (*docker.Network, error) {
	if name == "host" || name == "bridge" || name == "none" {
		return nil, fmt.Errorf("network %q is not allowed; services join overlay networks only", name)
	}
	n, err := p.services.docker.InspectNetwork(ctx, name)
	if err != nil {
		if docker.IsNotFound(err) {
			return nil, fmt.Errorf("network %q does not exist on this Swarm", name)
		}
		return nil, err
	}
	if n.Scope != "swarm" {
		return nil, fmt.Errorf("network %q is not a Swarm overlay network", name)
	}
	return n, nil
}

// configObjects turns the files into Swarm configs and secrets, named by
// their content so an unchanged file reuses its object, and returns the
// references a container spec mounts plus the ids now in use.
func (p *PlatformExecutor) configObjects(ctx context.Context, service string, files []ConfigMount) ([]docker.ConfigReference, []docker.SecretReference, []string, error) {
	if len(files) > maxConfigs {
		return nil, nil, nil, fmt.Errorf("at most %d config files per service", maxConfigs)
	}
	d := p.services.docker
	labels := map[string]string{ManagedLabel: "true", LabelOrganization: p.services.orgID, LabelService: service}
	existingConfigs, err := d.ListConfigs(ctx, LabelService+"="+service)
	if err != nil {
		return nil, nil, nil, err
	}
	existingSecrets, err := d.ListSecrets(ctx, LabelService+"="+service)
	if err != nil {
		return nil, nil, nil, err
	}
	var configs []docker.ConfigReference
	var secrets []docker.SecretReference
	var ids []string
	for _, file := range files {
		if !strings.HasPrefix(file.Target, "/") || strings.Contains(file.Target, "..") {
			return nil, nil, nil, fmt.Errorf("config %q: the target must be an absolute path", file.Name)
		}
		content, err := substitute(ctx, p.services.secrets, file.Content)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("config %q: %w", file.Name, err)
		}
		if len(content) > maxConfigBytes {
			return nil, nil, nil, fmt.Errorf("config %q is larger than %d bytes", file.Name, maxConfigBytes)
		}
		sum := sha256.Sum256([]byte(content))
		name := objectName(service, file.Name, hex.EncodeToString(sum[:4]))
		ref := docker.SecretFile{Name: file.Target, UID: "0", GID: "0", Mode: file.Mode}
		if ref.Mode == 0 {
			ref.Mode = 0o444
		}
		if file.UID != nil {
			ref.UID = fmt.Sprint(*file.UID)
			ref.GID = fmt.Sprint(*file.UID)
		}
		if file.Secret {
			id := findObject(existingSecrets, name)
			if id == "" {
				if id, err = d.CreateSecret(ctx, name, []byte(content), labels); err != nil {
					return nil, nil, nil, err
				}
			}
			secrets = append(secrets, docker.SecretReference{File: ref, SecretID: id, SecretName: name})
			ids = append(ids, id)
			continue
		}
		id := findObject(existingConfigs, name)
		if id == "" {
			if id, err = d.CreateConfig(ctx, name, []byte(content), labels); err != nil {
				return nil, nil, nil, err
			}
		}
		configs = append(configs, docker.ConfigReference{File: ref, ConfigID: id, ConfigName: name})
		ids = append(ids, id)
	}
	return configs, secrets, ids, nil
}

func findObject(objects []docker.SwarmObject, name string) string {
	for _, o := range objects {
		if o.Spec.Name == name {
			return o.ID
		}
	}
	return ""
}

var objectNameClean = regexp.MustCompile(`[^a-z0-9_.-]+`)

// objectName is `<service>-<file>-<hash>`, within Swarm's 64 characters.
func objectName(service, file, hash string) string {
	file = objectNameClean.ReplaceAllString(strings.ToLower(file), "-")
	suffix := "-" + file + "-" + hash
	if len(service)+len(suffix) > 64 {
		service = service[:64-len(suffix)]
	}
	return service + suffix
}

// pruneObjects removes a service's config objects that are no longer
// referenced. Best effort: one still held by a task mid-update is refused
// by the engine and picked up by the next prune.
func (p *PlatformExecutor) pruneObjects(ctx context.Context, service string, keep []string) {
	d := p.services.docker
	kept := map[string]bool{}
	for _, id := range keep {
		kept[id] = true
	}
	if configs, err := d.ListConfigs(ctx, LabelService+"="+service); err == nil {
		for _, o := range configs {
			if !kept[o.ID] {
				_ = d.RemoveConfig(ctx, o.ID)
			}
		}
	}
	if secrets, err := d.ListSecrets(ctx, LabelService+"="+service); err == nil {
		for _, o := range secrets {
			if !kept[o.ID] {
				_ = d.RemoveSecret(ctx, o.ID)
			}
		}
	}
}

// -- nodes and networks --------------------------------------------------------------

type nodeInfo struct {
	ID           string `json:"id"`
	Hostname     string `json:"hostname"`
	Role         string `json:"role"`
	Availability string `json:"availability"`
	Status       string `json:"status"`
}

func (p *PlatformExecutor) nodes(ctx context.Context, _ *intent.Envelope) (any, error) {
	nodes, err := p.services.docker.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]nodeInfo, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, nodeInfo{ID: n.ID, Hostname: n.Description.Hostname, Role: n.Spec.Role, Availability: n.Spec.Availability, Status: n.Status.State})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return map[string]any{"nodes": out}, nil
}

func (p *PlatformExecutor) networkEnsure(ctx context.Context, env *intent.Envelope) (any, error) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decode(env.Payload, &body); err != nil {
		return nil, err
	}
	if !namePattern.MatchString(body.Name) || body.Name == "ingress" {
		return nil, fmt.Errorf("network name %q is not valid", body.Name)
	}
	d := p.services.docker
	n, err := d.InspectNetwork(ctx, body.Name)
	switch {
	case err == nil:
		if n.Scope != "swarm" {
			return nil, fmt.Errorf("a network named %q exists and is not a Swarm overlay", body.Name)
		}
		return map[string]any{"name": n.Name, "id": n.ID, "created": false}, nil
	case docker.IsNotFound(err):
		id, err := d.CreateOverlay(ctx, body.Name, map[string]string{ManagedLabel: "true", LabelOrganization: p.services.orgID, LabelIntent: env.ID})
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": body.Name, "id": id, "created": true}, nil
	default:
		return nil, err
	}
}

func (p *PlatformExecutor) networkRemove(ctx context.Context, env *intent.Envelope) (any, error) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decode(env.Payload, &body); err != nil {
		return nil, err
	}
	d := p.services.docker
	n, err := d.InspectNetwork(ctx, body.Name)
	if docker.IsNotFound(err) {
		return map[string]any{"name": body.Name, "removed": false, "message": "no such network"}, nil
	}
	if err != nil {
		return nil, err
	}
	if n.Labels[ManagedLabel] != "true" {
		return nil, fmt.Errorf("network %q was not created by ISOGrid; the agent leaves it alone", body.Name)
	}
	// The services on it were removed a moment ago and their tasks are
	// still letting go of their endpoints; the engine refuses until they
	// have. The same wait a volume gets.
	deadline := time.Now().Add(volumeWait)
	for {
		err := d.RemoveNetwork(ctx, n.ID)
		if err == nil || docker.IsNotFound(err) {
			return map[string]any{"name": body.Name, "removed": true}, nil
		}
		if time.Now().After(deadline) || !strings.Contains(strings.ToLower(errorText(err)), "active endpoints") {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(volumePoll):
		}
	}
}

// -- volumes ---------------------------------------------------------------------------

func (p *PlatformExecutor) volumeRemove(ctx context.Context, env *intent.Envelope) (any, error) {
	var body struct {
		Names []string `json:"names"`
	}
	if err := decode(env.Payload, &body); err != nil {
		return nil, err
	}
	if len(body.Names) > maxVolumes*4 {
		return nil, fmt.Errorf("at most %d volumes at a time", maxVolumes*4)
	}
	d := p.services.docker
	removed, left := []string{}, []string{}
	refused := map[string]string{}
	deadline := time.Now().Add(volumeWait)
	for _, name := range body.Names {
		if !namePattern.MatchString(name) {
			return nil, fmt.Errorf("volume name %q is not valid", name)
		}
		for {
			v, err := d.InspectVolume(ctx, name)
			if docker.IsNotFound(err) {
				removed = append(removed, name)
				break
			}
			if err != nil {
				left = append(left, name)
				refused[name] = err.Error()
				break
			}
			if v.Labels[ManagedLabel] != "true" {
				left = append(left, name)
				refused[name] = "not created by ISOGrid; the agent leaves it alone"
				break
			}
			if err := d.RemoveVolume(ctx, name); err == nil || docker.IsNotFound(err) {
				removed = append(removed, name)
				break
			} else if time.Now().After(deadline) {
				// A task keeps its volume busy for a few seconds after its
				// service is removed; past the wait it is genuinely held.
				left = append(left, name)
				refused[name] = errorText(err)
				break
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(volumePoll):
			}
		}
	}
	return map[string]any{"removed": removed, "left": left, "refused": refused}, nil
}

func errorText(err error) string {
	var de *docker.Error
	if errors.As(err, &de) {
		return de.Message
	}
	return err.Error()
}

// -- secrets ---------------------------------------------------------------------------

func (p *PlatformExecutor) requireStore() error {
	if p.store == nil {
		return errors.New("this agent has no Vault configured; secrets cannot be kept")
	}
	return nil
}

func checkMintedRef(ref string) (string, error) {
	clean, err := vault.CleanRef(ref)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(clean, reservedPrefix) {
		return "", fmt.Errorf("%q: the connections/ references belong to this agent", ref)
	}
	if strings.Count(clean, "/") < minPrefixDepth {
		return "", fmt.Errorf("%q: a minted secret needs at least three segments (<kind>/<instance>/<name>)", ref)
	}
	return clean, nil
}

func mintSecret() (string, error) {
	out := make([]byte, secretLength)
	max := big.NewInt(int64(len(secretAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = secretAlphabet[n.Int64()]
	}
	return string(out), nil
}

// secretEnsure mints a password in the Vault for every reference that has
// no value yet. The value is never returned: the platform asked for it to
// exist, not to know it.
func (p *PlatformExecutor) secretEnsure(ctx context.Context, env *intent.Envelope) (any, error) {
	var body struct {
		Refs []string `json:"refs"`
	}
	if err := decode(env.Payload, &body); err != nil {
		return nil, err
	}
	if err := p.requireStore(); err != nil {
		return nil, err
	}
	if len(body.Refs) == 0 || len(body.Refs) > maxSecretRefs {
		return nil, fmt.Errorf("between 1 and %d references", maxSecretRefs)
	}
	created, existing := []string{}, []string{}
	for _, ref := range body.Refs {
		clean, err := checkMintedRef(ref)
		if err != nil {
			return nil, err
		}
		_, err = p.store.Resolve(ctx, clean)
		switch {
		case err == nil:
			existing = append(existing, clean)
		case errors.Is(err, vault.ErrNotFound):
			value, err := mintSecret()
			if err != nil {
				return nil, err
			}
			if _, err := p.store.Write(ctx, clean, value); err != nil {
				return nil, fmt.Errorf("%s: %w", clean, err)
			}
			created = append(created, clean)
		default:
			return nil, fmt.Errorf("%s: %w", clean, err)
		}
	}
	return map[string]any{"created": created, "existing": existing}, nil
}

// secretRemove forgets every minted reference under a prefix: an instance's
// credentials once the instance is gone.
func (p *PlatformExecutor) secretRemove(ctx context.Context, env *intent.Envelope) (any, error) {
	var body struct {
		Prefix string `json:"prefix"`
	}
	if err := decode(env.Payload, &body); err != nil {
		return nil, err
	}
	if err := p.requireStore(); err != nil {
		return nil, err
	}
	prefix := strings.TrimSuffix(body.Prefix, "/")
	if prefix == "" || len(prefix) > mintedPrefixMax {
		return nil, errors.New("name the prefix to remove")
	}
	if _, err := vault.CleanRef(prefix); err != nil {
		return nil, err
	}
	if strings.HasPrefix(prefix, reservedPrefix) || strings.Count(prefix, "/") < minPrefixDepth-1 {
		return nil, fmt.Errorf("%q: only an instance's own references (<kind>/<instance>/) can be removed together", body.Prefix)
	}
	refs, _, err := p.store.List(ctx)
	if err != nil {
		return nil, err
	}
	removed := []string{}
	for _, ref := range refs {
		if !strings.HasPrefix(ref, prefix+"/") {
			continue
		}
		if err := p.store.Delete(ctx, ref); err != nil {
			return nil, fmt.Errorf("%s: %w", ref, err)
		}
		removed = append(removed, ref)
	}
	return map[string]any{"removed": removed}, nil
}

// -- jobs -----------------------------------------------------------------------------

// JobPayload is `job.run`: one container to completion, on an overlay of
// the Swarm, its stdin and environment with placeholders substituted.
type JobPayload struct {
	Image          string            `json:"image"`
	Network        string            `json:"network"`
	Env            map[string]string `json:"env"`
	Command        []string          `json:"command"`
	Stdin          string            `json:"stdin"`
	TimeoutSeconds int64             `json:"timeout_seconds"`
}

func (p *PlatformExecutor) jobRun(ctx context.Context, env *intent.Envelope) (any, error) {
	var body JobPayload
	if err := decode(env.Payload, &body); err != nil {
		return nil, err
	}
	if !imagePattern.MatchString(body.Image) || strings.Contains(body.Image, "..") {
		return nil, fmt.Errorf("image reference %q is not valid", body.Image)
	}
	if len(body.Env) > maxEnv {
		return nil, fmt.Errorf("at most %d environment variables", maxEnv)
	}
	if len(body.Stdin) > maxStdin {
		return nil, fmt.Errorf("stdin is larger than %d bytes", maxStdin)
	}
	for _, arg := range body.Command {
		if strings.Contains(arg, "{{secret:") {
			return nil, errors.New("a secret may not appear on a command line; pass it through the environment or stdin")
		}
	}
	if body.Network != "" {
		if _, err := p.swarmNetwork(ctx, body.Network); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(body.Env))
	for k := range body.Env {
		if !envKeyPattern.MatchString(k) {
			return nil, fmt.Errorf("environment variable %q: not a valid name", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	envList := make([]string, 0, len(keys))
	for _, k := range keys {
		value, err := substitute(ctx, p.services.secrets, body.Env[k])
		if err != nil {
			return nil, fmt.Errorf("environment variable %q: %w", k, err)
		}
		envList = append(envList, k+"="+value)
	}
	stdin, err := substitute(ctx, p.services.secrets, body.Stdin)
	if err != nil {
		return nil, fmt.Errorf("stdin: %w", err)
	}
	timeout := time.Duration(body.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > maxJobTimeout {
		timeout = maxJobTimeout
	}
	result, err := p.services.docker.RunJob(ctx, docker.JobSpec{
		Image:   body.Image,
		Command: body.Command,
		Env:     envList,
		Network: body.Network,
		Stdin:   stdin,
		Labels:  map[string]string{ManagedLabel: "true", LabelOrganization: p.services.orgID, LabelIntent: env.ID},
		Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"exit_code": result.ExitCode,
		"stdout":    result.Stdout,
		"stderr":    result.Stderr,
		"timed_out": result.TimedOut,
	}, nil
}
