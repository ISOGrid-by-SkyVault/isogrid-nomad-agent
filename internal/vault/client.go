// Package vault is the agent's client for the customer's HashiCorp Vault or
// OpenBao: a KV version 2 mount, below one prefix, reached with an AppRole or
// a token file. Standard library only.
//
// The model is deliberately small. A secret reference such as
// `apps/billing/DATABASE_URL` is one KV entry below the prefix holding one
// field, `value`. The console writes values and lists references; the
// executor reads a value at deploy time. Nothing in this package logs or
// returns a value except Read, to its caller.
package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when a reference has no value.
var ErrNotFound = errors.New("no secret at that reference")

// Options configure a Client.
type Options struct {
	Addr         string
	CACertFile   string
	TokenFile    string
	RoleID       string
	SecretIDFile string
	Mount        string
	Prefix       string
}

// Client talks to one Vault.
type Client struct {
	opt  Options
	http *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New builds a client. It does not connect; a Vault that is sealed or down
// when the agent starts must not keep the agent from starting.
func New(opt Options) (*Client, error) {
	if opt.Addr == "" {
		return nil, errors.New("vault: no address")
	}
	opt.Addr = strings.TrimRight(opt.Addr, "/")
	opt.Mount = strings.Trim(opt.Mount, "/")
	opt.Prefix = strings.Trim(opt.Prefix, "/")
	if opt.Mount == "" || opt.Prefix == "" {
		return nil, errors.New("vault: a mount and a prefix are required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opt.CACertFile != "" {
		raw, err := os.ReadFile(opt.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("vault CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("vault CA: no certificate found in the file")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &Client{opt: opt, http: &http.Client{Transport: transport, Timeout: 15 * time.Second}}, nil
}

// Where describes the client for the console: never a credential.
func (c *Client) Where() (addr, mount, prefix, method string) {
	method = "approle"
	if c.opt.TokenFile != "" {
		method = "token file"
	}
	return c.opt.Addr, c.opt.Mount, c.opt.Prefix, method
}

// Health is the part of /sys/health the console shows.
type Health struct {
	Reachable   bool   `json:"reachable"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Version     string `json:"version,omitempty"`
	LoggedIn    bool   `json:"logged_in"`
	Error       string `json:"error,omitempty"`
}

// Health asks the Vault how it is and whether the agent can log in.
func (c *Client) Health(ctx context.Context) Health {
	var h Health
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.opt.Addr+"/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200", nil)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	resp, err := c.http.Do(req)
	if err != nil {
		h.Error = "unreachable: " + err.Error()
		return h
	}
	defer resp.Body.Close()
	var body struct {
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
		Version     string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		h.Error = "unexpected answer from /sys/health"
		return h
	}
	h.Reachable, h.Initialized, h.Sealed, h.Version = true, body.Initialized, body.Sealed, body.Version
	if h.Sealed {
		h.Error = "the Vault is sealed; unseal it to read or write secrets"
		return h
	}
	if _, err := c.authToken(ctx, false); err != nil {
		h.Error = err.Error()
		return h
	}
	h.LoggedIn = true
	return h
}

// authToken returns a usable token, logging in when there is none, when it
// is about to expire, or when `fresh` asks for a new one.
func (c *Client) authToken(ctx context.Context, fresh bool) (string, error) {
	if c.opt.TokenFile != "" {
		// Re-read each time: whatever rotates the file is picked up at once.
		raw, err := os.ReadFile(c.opt.TokenFile)
		if err != nil {
			return "", fmt.Errorf("vault token file: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", errors.New("the vault token file is empty")
		}
		return token, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.token != "" && time.Until(c.expires) > time.Minute {
		return c.token, nil
	}
	raw, err := os.ReadFile(c.opt.SecretIDFile)
	if err != nil {
		return "", fmt.Errorf("vault secret id file: %w", err)
	}
	payload, _ := json.Marshal(map[string]string{"role_id": c.opt.RoleID, "secret_id": strings.TrimSpace(string(raw))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opt.Addr+"/v1/auth/approle/login", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault login refused (HTTP %d): %s", resp.StatusCode, errorText(resp.Body))
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil || out.Auth.ClientToken == "" {
		return "", errors.New("vault login: no token in the answer")
	}
	c.token = out.Auth.ClientToken
	lease := time.Duration(out.Auth.LeaseDuration) * time.Second
	if lease <= 0 {
		lease = time.Hour
	}
	c.expires = time.Now().Add(lease)
	return c.token, nil
}

func errorText(body io.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(body, 4096))
	var parsed struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &parsed) == nil && len(parsed.Errors) > 0 {
		return strings.Join(parsed.Errors, "; ")
	}
	return strings.TrimSpace(string(raw))
}

// call performs one authenticated request. A 403 with an AppRole token is
// retried once after a fresh login: the token may have been revoked.
func (c *Client) call(ctx context.Context, method, path string, body any, out any) (int, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	for attempt := 0; ; attempt++ {
		token, err := c.authToken(ctx, attempt > 0)
		if err != nil {
			return 0, err
		}
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.opt.Addr+"/v1/"+path, reader)
		if err != nil {
			return 0, err
		}
		req.Header.Set("X-Vault-Token", token)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return 0, fmt.Errorf("vault: %w", err)
		}
		status := resp.StatusCode
		if status == http.StatusForbidden && attempt == 0 && c.opt.TokenFile == "" {
			resp.Body.Close()
			continue
		}
		defer resp.Body.Close()
		if status == http.StatusNotFound {
			return status, ErrNotFound
		}
		if status < 200 || status > 299 {
			return status, fmt.Errorf("vault answered HTTP %d: %s", status, errorText(resp.Body))
		}
		if out != nil && status != http.StatusNoContent {
			if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
				return status, fmt.Errorf("vault: unexpected answer: %w", err)
			}
		}
		return status, nil
	}
}

var segment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// CleanRef validates a reference: up to eight segments of letters, digits,
// dots, dashes and underscores. It is what keeps a reference below the prefix.
func CleanRef(ref string) (string, error) {
	ref = strings.Trim(strings.TrimSpace(ref), "/")
	if ref == "" {
		return "", errors.New("the reference is empty")
	}
	parts := strings.Split(ref, "/")
	if len(parts) > 8 {
		return "", errors.New("the reference has more than eight segments")
	}
	for _, p := range parts {
		if !segment.MatchString(p) || strings.Contains(p, "..") {
			return "", fmt.Errorf("segment %q: letters, digits, dots, dashes and underscores, starting with a letter or digit", p)
		}
	}
	return strings.Join(parts, "/"), nil
}

func (c *Client) dataPath(ref string) string {
	return c.opt.Mount + "/data/" + c.opt.Prefix + "/" + ref
}

func (c *Client) metadataPath(ref string) string {
	if ref == "" {
		return c.opt.Mount + "/metadata/" + c.opt.Prefix
	}
	return c.opt.Mount + "/metadata/" + c.opt.Prefix + "/" + ref
}

// Read returns the value at a reference.
func (c *Client) Read(ctx context.Context, ref string) (string, error) {
	clean, err := CleanRef(ref)
	if err != nil {
		return "", err
	}
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if _, err := c.call(ctx, http.MethodGet, c.dataPath(clean), nil, &out); err != nil {
		return "", err
	}
	value, ok := out.Data.Data["value"].(string)
	if !ok {
		return "", ErrNotFound
	}
	return value, nil
}

// Resolve is Read under the name the executor expects.
func (c *Client) Resolve(ctx context.Context, ref string) (string, error) {
	return c.Read(ctx, ref)
}

// MaxValueBytes bounds one secret value.
const MaxValueBytes = 64 << 10

// Write stores a value at a reference, as a new version.
func (c *Client) Write(ctx context.Context, ref, value string) (string, error) {
	clean, err := CleanRef(ref)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("the value is empty")
	}
	if len(value) > MaxValueBytes {
		return "", fmt.Errorf("the value is larger than %d bytes", MaxValueBytes)
	}
	body := map[string]any{"data": map[string]string{"value": value}}
	if _, err := c.call(ctx, http.MethodPost, c.dataPath(clean), body, nil); err != nil {
		return "", err
	}
	return clean, nil
}

// Delete removes a reference and all its versions.
func (c *Client) Delete(ctx context.Context, ref string) error {
	clean, err := CleanRef(ref)
	if err != nil {
		return err
	}
	_, err = c.call(ctx, http.MethodDelete, c.metadataPath(clean), nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// MaxListed bounds what List walks, so a huge tree cannot stall the console.
const MaxListed = 500

// List returns every reference below the prefix, sorted, and whether the walk
// stopped at MaxListed.
func (c *Client) List(ctx context.Context) ([]string, bool, error) {
	refs := []string{}
	truncated := false
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if depth > 8 || truncated {
			return nil
		}
		var out struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		_, err := c.call(ctx, http.MethodGet, c.metadataPath(dir)+"?list=true", nil, &out)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, key := range out.Data.Keys {
			if len(refs) >= MaxListed {
				truncated = true
				return nil
			}
			full := strings.TrimSuffix(key, "/")
			if dir != "" {
				full = dir + "/" + full
			}
			if strings.HasSuffix(key, "/") {
				if err := walk(full, depth+1); err != nil {
					return err
				}
				continue
			}
			refs = append(refs, full)
		}
		return nil
	}
	if err := walk("", 0); err != nil {
		return nil, false, err
	}
	sort.Strings(refs)
	return refs, truncated, nil
}
