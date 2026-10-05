// Package config reads the agent's settings from the environment.
//
// Every value has a safe default so that the binary starts on a laptop with no
// configuration at all and serves its frontend on localhost. Nothing here is a
// secret: the agent's identity is a client certificate on disk, and every
// other secret lives in the customer's Vault or OpenBao, reached through
// VaultAddr.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved agent configuration.
type Config struct {
	// Listen is the address of the agent's own frontend and API. It should bind
	// a private interface: the frontend is for the customer's operators only
	// and must never be reachable by the ISOGrid control plane.
	Listen string

	// DataDir holds the SQLite database, the performance samples and the
	// local log store. Everything the agent remembers lives under it.
	DataDir string

	// StreamURL is where the agent connects: the ISOGrid API over WebSocket
	// (wss://.../api/v1/nomad/stream), through the same edge and certificate
	// as the console. Empty means the agent runs detached: console only.
	StreamURL string
	// ClientCertFile and ClientKeyFile hold the certificate ISOGrid issued for
	// this cluster. It is the agent's identity: at connection the agent
	// signs the nonce the API sends with this key.
	ClientCertFile string
	ClientKeyFile  string
	// StreamCAFile pins a private certificate authority for the API's TLS
	// (a lab behind a self-signed edge). Empty trusts the system roots.
	StreamCAFile string

	// ClusterID and OrganizationID are the identifiers ISOGrid assigned when
	// the customer added the integration; they name the queue the agent reads.
	ClusterID      string
	OrganizationID string

	// IntentPublicKeyFile pins the control plane's intent-signing public key.
	// Intents whose signature does not verify are dropped before parsing.
	IntentPublicKeyFile string

	// VaultAddr points at the customer's Vault or OpenBao. VaultCACertFile pins
	// its certificate authority when it is private. The agent authenticates
	// either with a token file it re-reads on rotation (VaultTokenFile) or by
	// logging in with an AppRole (VaultRoleID plus the secret id read from
	// VaultSecretIDFile). VaultMount and VaultPrefix bound the paths the agent
	// may read and write.
	VaultAddr         string
	VaultCACertFile   string
	VaultTokenFile    string
	VaultRoleID       string
	VaultSecretIDFile string
	VaultMount        string
	VaultPrefix       string

	// DockerHost is the Docker Engine endpoint, a unix socket on a manager node.
	DockerHost string

	// SampleInterval is how often performance samples are taken and stored.
	SampleInterval time.Duration
	// SampleRetention is how long samples are kept before they are pruned.
	SampleRetention time.Duration
	// LogRetention is how long container logs are kept in the local store.
	LogRetention time.Duration
}

// FromEnv builds a Config from ISOGRID_NOMAD_* environment variables.
func FromEnv() (Config, error) {
	c := Config{
		Listen:              env("LISTEN", "127.0.0.1:8460"),
		DataDir:             env("DATA_DIR", "/var/lib/nomad-agent"),
		StreamURL:           env("STREAM_URL", ""),
		ClientCertFile:      env("CLIENT_CERT_FILE", ""),
		ClientKeyFile:       env("CLIENT_KEY_FILE", ""),
		StreamCAFile:        env("STREAM_CA_FILE", ""),
		ClusterID:           env("CLUSTER_ID", ""),
		OrganizationID:      env("ORGANIZATION_ID", ""),
		IntentPublicKeyFile: env("INTENT_PUBLIC_KEY_FILE", ""),
		VaultAddr:           env("VAULT_ADDR", ""),
		VaultCACertFile:     env("VAULT_CACERT_FILE", ""),
		VaultTokenFile:      env("VAULT_TOKEN_FILE", ""),
		VaultRoleID:         env("VAULT_ROLE_ID", ""),
		VaultSecretIDFile:   env("VAULT_SECRET_ID_FILE", ""),
		VaultMount:          env("VAULT_MOUNT", "secret"),
		VaultPrefix:         env("VAULT_PREFIX", "isogrid"),
		DockerHost:          env("DOCKER_HOST", "unix:///var/run/docker.sock"),
	}
	var err error
	if c.SampleInterval, err = duration("SAMPLE_INTERVAL", 15*time.Second); err != nil {
		return c, err
	}
	if c.SampleRetention, err = duration("SAMPLE_RETENTION", 30*24*time.Hour); err != nil {
		return c, err
	}
	if c.LogRetention, err = duration("LOG_RETENTION", 7*24*time.Hour); err != nil {
		return c, err
	}
	if c.VaultAddr != "" && c.VaultTokenFile == "" && (c.VaultRoleID == "" || c.VaultSecretIDFile == "") {
		return c, fmt.Errorf("ISOGRID_NOMAD_VAULT_ADDR needs either VAULT_TOKEN_FILE or VAULT_ROLE_ID with VAULT_SECRET_ID_FILE")
	}
	if c.StreamURL != "" {
		required := []struct{ name, value string }{
			{"CLIENT_CERT_FILE", c.ClientCertFile},
			{"CLIENT_KEY_FILE", c.ClientKeyFile},
			{"INTENT_PUBLIC_KEY_FILE", c.IntentPublicKeyFile},
			{"CLUSTER_ID", c.ClusterID},
			{"ORGANIZATION_ID", c.OrganizationID},
		}
		for _, r := range required {
			if strings.TrimSpace(r.value) == "" {
				return c, fmt.Errorf("ISOGRID_NOMAD_%s is required when a stream is configured", r.name)
			}
		}
	}
	return c, nil
}

// Attached reports whether a control channel to ISOGrid is configured.
func (c Config) Attached() bool { return c.StreamURL != "" }

func env(name, fallback string) string {
	if v, ok := os.LookupEnv("ISOGRID_NOMAD_" + name); ok {
		return v
	}
	return fallback
}

func duration(name string, fallback time.Duration) (time.Duration, error) {
	raw := env(name, "")
	if raw == "" {
		return fallback, nil
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		return time.Duration(secs) * time.Second, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("ISOGRID_NOMAD_%s: %w", name, err)
	}
	return d, nil
}
