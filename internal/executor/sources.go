package executor

import (
	"context"
	"errors"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/builds"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/connections"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/store"
)

// The intents that read the customer's code hosts and registries, and the
// ones that build. Every one names a connection the operator defined in the
// console; none carries a host, a URL or a credential.

// RegisterSources adds the repository, registry and build handlers, and lets
// deploys pull through a registry connection.
func RegisterSources(e *Executor, services *ServiceExecutor, sources *connections.Manager, runner *builds.Runner) {
	services.sources = sources
	h := &sourceHandlers{sources: sources, runner: runner}
	e.Register("repositories.list", h.repositories)
	e.Register("repository.refs", h.refs)
	e.Register("repository.commits", h.commits)
	e.Register("registry.images", h.images)
	e.Register("build.run", h.buildRun)
	e.Register("build.status", h.buildStatus)
	e.Register("connection.put", h.connectionPut)
	e.Register("connection.remove", h.connectionRemove)
}

type sourceHandlers struct {
	sources *connections.Manager
	runner  *builds.Runner
}

// CreatedByISOGrid marks a connection whose credential ISOGrid forwarded,
// rather than one the operator typed in the console. The console shows the
// difference; the credential sits in the customer's Vault either way.
const CreatedByISOGrid = "isogrid"

// connectionPut is the one intent that carries a credential: the person
// chose, on ISOGrid, to keep a GitHub, GitLab or registry credential on this
// agent instead of on the platform. The value goes to the customer's Vault
// and nowhere else; the reply names the connection and never echoes it.
// ISOGrid also uses it to renew the short-lived GitHub App tokens it forwards.
func (h *sourceHandlers) connectionPut(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Host     string `json:"host"`
		Username string `json:"username"`
		Secret   string `json:"secret"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	if p.Secret == "" {
		return nil, errors.New("the connection's credential is missing")
	}
	existing, err := h.sources.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range existing {
		if c.Name == p.Name && c.CreatedBy != CreatedByISOGrid {
			// A connection the operator made here is theirs: ISOGrid may not
			// overwrite its credential under the same name.
			return nil, errors.New("a connection with that name was created in the agent console; choose another name")
		}
	}
	c, err := h.sources.Save(ctx, connections.Connection{
		Name: p.Name, Kind: p.Kind, Host: p.Host, Username: p.Username, CreatedBy: CreatedByISOGrid,
	}, p.Secret)
	if err != nil {
		return nil, err
	}
	return map[string]any{"name": c.Name, "kind": c.Kind, "host": c.Host, "created_by": c.CreatedBy}, nil
}

func (h *sourceHandlers) connectionRemove(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	existing, err := h.sources.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range existing {
		if c.Name == p.Name {
			if c.CreatedBy != CreatedByISOGrid {
				return nil, errors.New("that connection was created in the agent console; remove it there")
			}
			if err := h.sources.Delete(ctx, p.Name); err != nil {
				return nil, err
			}
			return map[string]any{"name": p.Name, "removed": true}, nil
		}
	}
	// Already gone: the outcome ISOGrid wanted.
	return map[string]any{"name": p.Name, "removed": false}, nil
}

func (h *sourceHandlers) repositories(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Connection string `json:"connection"`
		Query      string `json:"query"`
		Page       int    `json:"page"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	list, err := h.sources.Repositories(ctx, p.Connection, p.Query, p.Page)
	if err != nil {
		return nil, err
	}
	return map[string]any{"connection": p.Connection, "page": max(p.Page, 1), "repositories": list}, nil
}

func (h *sourceHandlers) refs(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Connection string `json:"connection"`
		Repository string `json:"repository"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	return h.sources.Refs(ctx, p.Connection, p.Repository)
}

func (h *sourceHandlers) commits(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Connection string `json:"connection"`
		Repository string `json:"repository"`
		Ref        string `json:"ref"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	list, err := h.sources.Commits(ctx, p.Connection, p.Repository, p.Ref)
	if err != nil {
		return nil, err
	}
	return map[string]any{"commits": list}, nil
}

func (h *sourceHandlers) images(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		Connection string `json:"connection"`
		Repository string `json:"repository"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	return h.sources.Images(ctx, p.Connection, p.Repository)
}

// buildView is what ISOGrid learns about a build: never its output.
func buildView(b *store.Build) map[string]any {
	view := map[string]any{
		"build_id": b.ID, "status": b.Status, "repository": b.Repository, "ref": b.Ref,
		"commit": b.Commit, "image": b.Image, "digest": b.Digest, "started_at": b.StartedAt.UTC(),
	}
	if !b.FinishedAt.IsZero() {
		view["finished_at"] = b.FinishedAt.UTC()
	}
	if b.Error != "" {
		view["error"] = b.Error
	}
	return view
}

// buildRun starts a build and answers at once; the build id is the intent
// id, and `build.status` says how it ended.
func (h *sourceHandlers) buildRun(ctx context.Context, env *intent.Envelope) (any, error) {
	var req builds.Request
	if err := decode(env.Payload, &req); err != nil {
		return nil, err
	}
	b, err := h.runner.Start(ctx, env.ID, req)
	if err != nil {
		return nil, err
	}
	return buildView(b), nil
}

func (h *sourceHandlers) buildStatus(ctx context.Context, env *intent.Envelope) (any, error) {
	var p struct {
		BuildID string `json:"build_id"`
	}
	if err := decode(env.Payload, &p); err != nil {
		return nil, err
	}
	b, err := h.runner.Status(ctx, p.BuildID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errors.New("this agent has no build with that id")
	}
	if err != nil {
		return nil, err
	}
	return buildView(b), nil
}
