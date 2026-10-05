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
	"encoding/json"
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
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/executor"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/stream"
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

// check validates the configuration and the identity files, and reports what
// the agent would use. Reachability checks for Docker and Vault join it with
// the components that implement them.
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

	var (
		client *stream.Client
		exec   *executor.Executor
	)
	if cfg.Attached() {
		public, err := intent.LoadPublicKey(cfg.IntentPublicKeyFile)
		if err != nil {
			return fmt.Errorf("intent public key: %w", err)
		}
		exec = executor.New(intent.NewVerifier(public, cfg.OrganizationID, cfg.ClusterID), version, cfg.ClusterID)
		client, err = stream.New(stream.Options{
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
	}

	health := func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"status":  "ok",
			"version": version,
			"mode":    mode,
			"uptime":  time.Since(started).Round(time.Second).String(),
		}
		if client != nil {
			executed, refused := exec.Counts()
			body["cluster_id"] = cfg.ClusterID
			body["organization_id"] = cfg.OrganizationID
			body["stream"] = client.Status()
			body["capabilities"] = exec.Capabilities()
			body["intents"] = map[string]uint64{"executed": executed, "refused": refused}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("GET /api/healthz", health)
	mux.Handle("/", web.Handler())

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
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
