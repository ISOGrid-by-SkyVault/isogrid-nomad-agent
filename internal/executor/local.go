package executor

import (
	"context"
	"sort"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
)

// What the console reads locally, without an intent: the same reports the
// platform gets, straight from the engine.

// NewServiceExecutor builds the service executor on its own, for an agent
// that runs detached and still shows its console.
func NewServiceExecutor(client *docker.Client, organizationID string, secrets SecretResolver) *ServiceExecutor {
	return &ServiceExecutor{docker: client, orgID: organizationID, secrets: secrets}
}

// List reports every service the agent manages, by name.
func (s *ServiceExecutor) List(ctx context.Context) ([]*ServiceStatus, error) {
	services, err := s.docker.ListServices(ctx, ManagedLabel+"=true")
	if err != nil {
		return nil, err
	}
	out := make([]*ServiceStatus, 0, len(services))
	for _, svc := range services {
		st, err := s.report(ctx, svc.ID)
		if err != nil {
			if docker.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Managed returns nil when a service exists and was created by the agent,
// and otherwise the reason; the console reads logs of managed services only.
func (s *ServiceExecutor) Managed(ctx context.Context, name string) error {
	_, err := s.managedByName(ctx, name)
	return err
}
