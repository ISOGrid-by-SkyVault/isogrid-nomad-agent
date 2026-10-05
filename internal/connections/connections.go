// Package connections is how the agent reaches the customer's code hosts and
// registries: GitHub, GitLab and container registries, with credentials the
// operator typed in the console and that live in the customer's Vault.
//
// ISOGrid never holds these credentials and never names a host. An intent
// refers to a connection by name ("github-main"); where that name points and
// with which token is decided here, by the operator. What goes back to
// ISOGrid is names: repositories, branches, commit ids, image tags.
package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Kinds of connection.
const (
	KindGitHub   = "github"
	KindGitLab   = "gitlab"
	KindRegistry = "registry"
)

// Connection is what the agent remembers about one: never the credential.
type Connection struct {
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Host      string    `json:"host"`
	Username  string    `json:"username,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// Store keeps the connections' descriptions.
type Store interface {
	ListConnections(ctx context.Context) ([]Connection, error)
	GetConnection(ctx context.Context, name string) (*Connection, error)
	SaveConnection(ctx context.Context, c Connection) error
	DeleteConnection(ctx context.Context, name string) error
}

// Vault keeps their credentials.
type Vault interface {
	Read(ctx context.Context, ref string) (string, error)
	Write(ctx context.Context, ref, value string) (string, error)
	Delete(ctx context.Context, ref string) error
}

// ErrNotFound is returned for a connection name nobody defined.
var ErrNotFound = errors.New("no connection with that name")

// RefPrefix is where credentials live below the agent's Vault prefix. The
// console's Secrets section leaves this subtree alone.
const RefPrefix = "connections/"

// Manager owns the connections.
type Manager struct {
	store Store
	vault Vault // nil when the agent has no Vault
	http  *http.Client
}

// New builds a manager. Without a Vault, connections can be listed but not
// created or used.
func New(store Store, vault Vault) *Manager {
	return &Manager{store: store, vault: vault, http: &http.Client{Timeout: 30 * time.Second}}
}

var (
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$`)
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?$`)
	repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){0,6}$`)
	refPattern  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$`)
)

// CleanRepository validates a repository path as an intent may send it.
func CleanRepository(repo string) (string, error) {
	repo = strings.Trim(strings.TrimSpace(repo), "/")
	if !repoPattern.MatchString(repo) || strings.Contains(repo, "..") {
		return "", fmt.Errorf("repository %q is not a valid path", repo)
	}
	return repo, nil
}

// CleanRef validates a branch, tag or commit id.
func CleanRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if !refPattern.MatchString(ref) || strings.Contains(ref, "..") {
		return "", fmt.Errorf("ref %q is not a valid branch, tag or commit", ref)
	}
	return ref, nil
}

// List returns the connections by name.
func (m *Manager) List(ctx context.Context) ([]Connection, error) {
	return m.store.ListConnections(ctx)
}

// Save creates or replaces a connection. An empty secret keeps the stored one.
func (m *Manager) Save(ctx context.Context, c Connection, secret string) (*Connection, error) {
	if m.vault == nil {
		return nil, errors.New("this agent has no Vault configured; connections keep their credentials there")
	}
	c.Name = strings.TrimSpace(c.Name)
	if !namePattern.MatchString(c.Name) {
		return nil, errors.New("the name takes 3 to 40 lowercase letters, digits and dashes")
	}
	c.Host = strings.ToLower(strings.TrimSpace(c.Host))
	c.Host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(c.Host, "https://"), "http://"), "/")
	switch c.Kind {
	case KindGitHub:
		if c.Host == "" {
			c.Host = "github.com"
		}
	case KindGitLab:
		if c.Host == "" {
			c.Host = "gitlab.com"
		}
	case KindRegistry:
		if c.Host == "" {
			return nil, errors.New("a registry needs its host, for example ghcr.io or registry.example.com")
		}
		if c.Host == "hub.docker.com" || c.Host == "index.docker.io" || c.Host == "registry-1.docker.io" {
			c.Host = "docker.io"
		}
	default:
		return nil, errors.New("the kind is github, gitlab or registry")
	}
	if !hostPattern.MatchString(c.Host) {
		return nil, fmt.Errorf("%q is not a host name", c.Host)
	}
	c.Username = strings.TrimSpace(c.Username)
	if len(c.Username) > 128 {
		return nil, errors.New("the username is too long")
	}
	existing, err := m.store.GetConnection(ctx, c.Name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if secret == "" && existing == nil {
		return nil, errors.New("a new connection needs its token or password")
	}
	if secret != "" {
		if _, err := m.vault.Write(ctx, RefPrefix+c.Name, secret); err != nil {
			return nil, fmt.Errorf("the credential could not be stored in Vault: %w", err)
		}
	}
	if existing != nil {
		c.CreatedAt, c.CreatedBy = existing.CreatedAt, existing.CreatedBy
	} else {
		c.CreatedAt = time.Now()
	}
	if err := m.store.SaveConnection(ctx, c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Delete forgets a connection and its credential.
func (m *Manager) Delete(ctx context.Context, name string) error {
	if _, err := m.store.GetConnection(ctx, name); err != nil {
		return err
	}
	if m.vault != nil {
		if err := m.vault.Delete(ctx, RefPrefix+name); err != nil {
			return fmt.Errorf("the credential could not be removed from Vault: %w", err)
		}
	}
	return m.store.DeleteConnection(ctx, name)
}

// load returns a connection of one of the wanted kinds with its credential.
func (m *Manager) load(ctx context.Context, name string, kinds ...string) (*Connection, string, error) {
	if !namePattern.MatchString(name) {
		return nil, "", ErrNotFound
	}
	c, err := m.store.GetConnection(ctx, name)
	if err != nil {
		return nil, "", err
	}
	ok := len(kinds) == 0
	for _, k := range kinds {
		ok = ok || c.Kind == k
	}
	if !ok {
		return nil, "", fmt.Errorf("connection %q is a %s connection, not %s", name, c.Kind, strings.Join(kinds, " or "))
	}
	if m.vault == nil {
		return nil, "", errors.New("this agent has no Vault configured")
	}
	secret, err := m.vault.Read(ctx, RefPrefix+name)
	if err != nil {
		return nil, "", fmt.Errorf("the credential of %q could not be read from Vault: %w", name, err)
	}
	return c, secret, nil
}

// Test checks that a connection's credential is accepted by its host.
func (m *Manager) Test(ctx context.Context, name string) (string, error) {
	c, secret, err := m.load(ctx, name)
	if err != nil {
		return "", err
	}
	switch c.Kind {
	case KindGitHub:
		var who struct {
			Login string `json:"login"`
		}
		if err := m.github(ctx, c, secret, "/user", &who); err != nil {
			// Fine-grained and installation tokens may not read /user.
			var list []json.RawMessage
			if err2 := m.github(ctx, c, secret, "/user/repos?per_page=1", &list); err2 != nil {
				return "", err
			}
			return "The token is accepted.", nil
		}
		return "Signed in as " + who.Login + ".", nil
	case KindGitLab:
		var list []json.RawMessage
		if err := m.gitlab(ctx, c, secret, "/projects?membership=true&simple=true&per_page=1", &list); err != nil {
			return "", err
		}
		return "The token is accepted.", nil
	default:
		if err := m.registryPing(ctx, c, secret); err != nil {
			return "", err
		}
		return "The registry accepts these credentials.", nil
	}
}

// Summary is what the agent tells ISOGrid about its connections: names,
// kinds and hosts, so the console can offer them. Nothing else.
type Summary struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Host string `json:"host"`
}

// Summaries lists the connections for the inventory.
func (m *Manager) Summaries(ctx context.Context) ([]Summary, error) {
	list, err := m.store.ListConnections(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Summary, 0, len(list))
	for _, c := range list {
		out = append(out, Summary{Name: c.Name, Kind: c.Kind, Host: c.Host})
	}
	return out, nil
}

// -- registry credentials for the engine -------------------------------------------

// ImageHost returns the registry an image reference points at.
func ImageHost(image string) string {
	first, _, found := strings.Cut(image, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return strings.ToLower(first)
	}
	return "docker.io"
}

// RegistryAuth returns the credential header the engine wants to pull or
// push `image`, from a registry connection. The image must live on that
// connection's host: the engine sends the credential to whatever registry
// the image names, so anything else would hand it to a stranger.
func (m *Manager) RegistryAuth(ctx context.Context, name, image string) (string, error) {
	c, secret, err := m.load(ctx, name, KindRegistry)
	if err != nil {
		return "", err
	}
	if host := ImageHost(image); host != c.Host {
		return "", fmt.Errorf("the image is on %s but connection %q is for %s", host, name, c.Host)
	}
	server := c.Host
	if server == "docker.io" {
		server = "https://index.docker.io/v1/"
	}
	doc, _ := json.Marshal(map[string]string{"username": c.Username, "password": secret, "serveraddress": server})
	return base64.URLEncoding.EncodeToString(doc), nil
}

// -- shared HTTP ---------------------------------------------------------------------

const maxAnswer = 4 << 20

func (m *Manager) getJSON(ctx context.Context, url string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "isogrid-nomad-agent")
	resp, err := m.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s did not answer: %w", req.URL.Host, scrub(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(req.URL.Host, resp)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAnswer)).Decode(out); err != nil {
		return fmt.Errorf("%s sent an answer the agent could not read", req.URL.Host)
	}
	return nil
}

func statusError(host string, resp *http.Response) error {
	var body struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	_ = json.Unmarshal(raw, &body)
	detail := body.Message
	if detail == "" {
		detail = body.Error
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s refused the credential (HTTP 401). Check the token in the agent console", host)
	case http.StatusForbidden:
		return fmt.Errorf("%s says the credential may not do this (HTTP 403): %s", host, strings.TrimSpace(detail))
	case http.StatusNotFound:
		return fmt.Errorf("%s does not know that, or the credential cannot see it (HTTP 404)", host)
	}
	return fmt.Errorf("%s answered HTTP %d: %s", host, resp.StatusCode, strings.TrimSpace(detail))
}

// scrub keeps an error from carrying a URL with credentials in it.
func scrub(err error) error {
	text := err.Error()
	if i := strings.Index(text, "\": "); i >= 0 {
		text = text[i+3:]
	}
	return errors.New(text)
}
