// Package metrics takes the performance samples the console charts: CPU and
// memory of every service the agent manages, read from the engine on this
// node at a fixed interval and kept in the local store for a retention the
// operator chooses. Nothing is sent anywhere.
//
// On a Swarm of several nodes this reads the containers of the manager the
// agent runs on; a collector per node is a later addition.
package metrics

import (
	"context"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/store"
)

// Sampler reads and stores samples until its context ends.
type Sampler struct {
	Docker    *docker.Client
	Store     *store.Store
	Label     string // containers carrying this label are sampled
	Interval  time.Duration
	Retention time.Duration
	Logf      func(format string, args ...any)

	previous map[string]docker.Stats // by container id
}

// Run samples every Interval and prunes hourly.
func (s *Sampler) Run(ctx context.Context) {
	if s.Interval < 5*time.Second {
		s.Interval = 5 * time.Second
	}
	s.previous = make(map[string]docker.Stats)
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-prune.C:
			if err := s.Store.Prune(ctx, s.Retention); err != nil {
				s.Logf("metrics: prune failed: %v", err)
			}
		case <-ticker.C:
			err := s.sample(ctx)
			// Say it once when it starts failing and once when it recovers,
			// not every fifteen seconds.
			if err != nil && !failing {
				s.Logf("metrics: sampling failed: %v", err)
			} else if err == nil && failing {
				s.Logf("metrics: sampling works again")
			}
			failing = err != nil
		}
	}
}

func (s *Sampler) sample(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.Interval)
	defer cancel()
	containers, err := s.Docker.RunningContainers(ctx, s.Label)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	byService := map[string]*store.Sample{}
	seen := make(map[string]bool, len(containers))
	for _, c := range containers {
		service := c.Labels[docker.ServiceNameLabel]
		if service == "" {
			continue
		}
		stats, err := s.Docker.ContainerStats(ctx, c.ID)
		if err != nil {
			// The container may have stopped between the list and the read.
			continue
		}
		seen[c.ID] = true
		sample := byService[service]
		if sample == nil {
			sample = &store.Sample{Service: service, TS: now}
			byService[service] = sample
		}
		sample.Containers++
		sample.MemBytes += int64(stats.Memory)
		sample.MemLimit += int64(stats.MemoryLimit)
		if prev, ok := s.previous[c.ID]; ok {
			elapsed := stats.Read.Sub(prev.Read)
			if elapsed > 0 && stats.CPUTotal >= prev.CPUTotal {
				// Thousandths of a core: CPU nanoseconds per wall nanosecond.
				sample.CPUMilli += int64(float64(stats.CPUTotal-prev.CPUTotal) / float64(elapsed) * 1000)
			}
		}
		s.previous[c.ID] = *stats
	}
	for id := range s.previous {
		if !seen[id] {
			delete(s.previous, id)
		}
	}
	samples := make([]store.Sample, 0, len(byService))
	for _, sample := range byService {
		samples = append(samples, *sample)
	}
	return s.Store.AddSamples(ctx, samples)
}
