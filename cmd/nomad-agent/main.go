// Command nomad-agent is the ISOGrid Nomad agent: the only ISOGrid component
// that runs inside a customer's infrastructure. See the README for what it
// does and, more importantly, what it never does.
//
// Usage:
//
//	nomad-agent run       start the agent and its operator frontend (default)
//	nomad-agent check     validate the configuration and what it points at
//	nomad-agent version   print the version
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/config"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/console"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/executor"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/metrics"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/store"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/stream"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/vault"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/web"
)

// version is set by the release build with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "run":
		err = run()
	case "check":
		err = check()
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("nomad-agent %s: %v", cmd, err)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, "ISOGrid Nomad agent %s\n\nUsage: nomad-agent <command>\n\n  run       start the agent and its operator frontend (default)\n  check     validate the configuration and what it points at\n  version   print the version\n", version)
}

// check validates the configuration, the identity files and the engine, and
// reports what the agent would use. Vault joins it with its client.
func check() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	mode := "detached (no stream configured)"
	if cfg.Attached() {
		mode = "attached to " + cfg.StreamURL
	}
	fmt.Printf("frontend   %s\ndata dir   %s\nmode       %s\ndocker     %s\nvault      %s (mount %s, prefix %s)\n",
		cfg.Listen, cfg.DataDir, mode, cfg.DockerHost, orNone(cfg.VaultAddr), cfg.VaultMount, cfg.VaultPrefix)
	if engine, err := docker.New(cfg.DockerHost); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if info, err := engine.Info(ctx); err != nil {
			fmt.Printf("engine     unreachable: %v\n", err)
		} else {
			fmt.Printf("engine     %s %s, swarm %s, manager=%v, %d nodes\n",
				info.Name, info.ServerVersion, info.Swarm.LocalNodeState, info.Swarm.ControlAvailable, info.Swarm.Nodes)
		}
	}
	if !cfg.Attached() {
		return nil
	}
	key, err := stream.LoadKey(cfg.ClientKeyFile)
	if err != nil {
		return fmt.Errorf("client key: %w", err)
	}
	_, cert, err := stream.LoadCertificate(cfg.ClientCertFile)
	if err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return errors.New("the client key does not match the client certificate")
	}
	if _, err := intent.LoadPublicKey(cfg.IntentPublicKeyFile); err != nil {
		return fmt.Errorf("intent public key: %w", err)
	}
	fmt.Printf("identity   %s, valid until %s\ncluster    %s\norg        %s\n",
		cert.Subject.CommonName, cert.NotAfter.UTC().Format(time.RFC3339), cfg.ClusterID, cfg.OrganizationID)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// journal adapts the store to the executor's journal.
type journal struct {
	store *store.Store
}

func (j journal) Seen(ctx context.Context, id string) (bool, error) {
	return j.store.IntentSeen(ctx, id)
}

func (j journal) Record(ctx context.Context, e executor.JournalEntry) {
	// The request may be gone by the time the line is written.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := j.store.RecordIntent(ctx, store.IntentRecord{
		ID: e.ID, Kind: e.Kind, Status: e.Status, Subject: e.Subject, Error: e.Error,
		ReceivedAt: e.ReceivedAt, DurationMS: e.Duration.Milliseconds(),
	})
	if err != nil {
		log.Printf("journal: %v", err)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	started := time.Now()
	mode := "detached"
	if cfg.Attached() {
		mode = "attached"
	}
	log.Printf("nomad-agent %s starting (%s), frontend on %s, data in %s", version, mode, cfg.Listen, filepath.Clean(cfg.DataDir))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("local store in %s: %w", cfg.DataDir, err)
	}
	defer db.Close()
	if err := db.Prune(ctx, cfg.SampleRetention); err != nil {
		log.Printf("store: prune failed: %v", err)
	}

	engine, err := docker.New(cfg.DockerHost)
	if err != nil {
		return err
	}

	// The customer's Vault, when one is configured. A Vault that is sealed
	// or down does not keep the agent from starting; it shows in the console.
	var secrets *vault.Client
	var resolver executor.SecretResolver
	if cfg.VaultAddr != "" {
		secrets, err = vault.New(vault.Options{
			Addr: cfg.VaultAddr, CACertFile: cfg.VaultCACertFile, TokenFile: cfg.VaultTokenFile,
			RoleID: cfg.VaultRoleID, SecretIDFile: cfg.VaultSecretIDFile,
			Mount: cfg.VaultMount, Prefix: cfg.VaultPrefix,
		})
		if err != nil {
			return err
		}
		resolver = secrets
	}

	var (
		client   *stream.Client
		exec     *executor.Executor
		services *executor.ServiceExecutor
	)
	if cfg.Attached() {
		public, err := intent.LoadPublicKey(cfg.IntentPublicKeyFile)
		if err != nil {
			return fmt.Errorf("intent public key: %w", err)
		}
		exec = executor.New(intent.NewVerifier(public, cfg.OrganizationID, cfg.ClusterID), version, cfg.ClusterID)
		exec.SetJournal(journal{db})
		services = executor.RegisterServices(exec, engine, cfg.OrganizationID, resolver)
		client, err = stream.New(stream.Options{
			Inventory:      services.Inventory,
			URL:            cfg.StreamURL,
			CertFile:       cfg.ClientCertFile,
			KeyFile:        cfg.ClientKeyFile,
			CAFile:         cfg.StreamCAFile,
			ClusterID:      cfg.ClusterID,
			OrganizationID: cfg.OrganizationID,
			Version:        version,
			Capabilities:   exec.Capabilities(),
			Handle:         exec.Handle,
			Logf:           log.Printf,
		})
		if err != nil {
			return err
		}
		go client.Run(ctx)
	} else {
		services = executor.NewServiceExecutor(engine, cfg.OrganizationID, resolver)
	}

	sampler := &metrics.Sampler{
		Docker: engine, Store: db, Label: executor.ManagedLabel + "=true",
		Interval: cfg.SampleInterval, Retention: cfg.SampleRetention, Logf: log.Printf,
	}
	go sampler.Run(ctx)

	api := &console.Server{
		Version: version, Started: started, Config: cfg, Store: db, Docker: engine,
		Services: services, Vault: secrets, Stream: client, Executor: exec, Logf: log.Printf,
	}
	if err := api.Init(ctx); err != nil {
		return fmt.Errorf("console: %w", err)
	}
	mux := http.NewServeMux()
	api.Routes(mux)
	mux.Handle("/", web.Handler())

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           console.Harden(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("nomad-agent: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
