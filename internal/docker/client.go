// Package docker is the thin Engine API client the executors use: a few
// endpoints over the manager's socket, with the standard library only. It
// speaks to the daemon the way the CLI does, through the versioned HTTP API,
// so what the agent does is exactly what an operator could do by hand and
// nothing more.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIVersion is the lowest Engine API the agent needs (Docker 25+ serves it).
const APIVersion = "v1.44"

// Error is a daemon refusal with the HTTP status and the daemon's message.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("docker: %s (HTTP %d)", e.Message, e.Status) }

// IsNotFound reports whether the daemon answered 404.
func IsNotFound(err error) bool {
	var de *Error
	return errors.As(err, &de) && de.Status == http.StatusNotFound
}

// Client talks to one daemon.
type Client struct {
	http *http.Client
	base string
	// dial opens a raw connection to the daemon, for the one call that
	// cannot go through net/http: feeding a container's stdin over a
	// hijacked attach.
	dial       func(ctx context.Context) (net.Conn, error)
	hostHeader string
}

// New connects to DOCKER_HOST-style endpoints: unix:///path or tcp://host:port.
func New(host string) (*Client, error) {
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("docker host: %w", err)
	}
	transport := &http.Transport{
		MaxIdleConns:        4,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	base := "http://docker/" + APIVersion
	hostHeader := "docker"
	var dial func(ctx context.Context) (net.Conn, error)
	switch u.Scheme {
	case "unix":
		path := u.Path
		if path == "" {
			path = u.Opaque
		}
		dial = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }
	case "tcp", "http":
		base = "http://" + u.Host + "/" + APIVersion
		hostHeader = u.Host
		host := u.Host
		dial = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", host)
		}
	default:
		return nil, fmt.Errorf("docker host: unsupported scheme %q", u.Scheme)
	}
	return &Client{http: &http.Client{Transport: transport}, base: base, dial: dial, hostHeader: hostHeader}, nil
}

// do performs one request. A non-2xx answer becomes *Error with the daemon's
// message; `out`, when given, receives the decoded JSON body.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	return c.doH(ctx, method, path, query, body, out, nil)
}

// doH is do with extra request headers (the registry credential on create
// and update travels in X-Registry-Auth for that one request).
func (c *Client) doH(ctx context.Context, method, path string, query url.Values, body any, out any, headers http.Header) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	target := c.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, values := range headers {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var msg struct {
			Message string `json:"message"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = json.Unmarshal(raw, &msg)
		if msg.Message == "" {
			msg.Message = strings.TrimSpace(string(raw))
		}
		if msg.Message == "" {
			msg.Message = resp.Status
		}
		return &Error{Status: resp.StatusCode, Message: msg.Message}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Info is the part of GET /info the agent reports.
type Info struct {
	ID            string `json:"ID"`
	Name          string `json:"Name"`
	ServerVersion string `json:"ServerVersion"`
	NCPU          int    `json:"NCPU"`
	MemTotal      int64  `json:"MemTotal"`
	Swarm         struct {
		NodeID           string `json:"NodeID"`
		LocalNodeState   string `json:"LocalNodeState"`
		ControlAvailable bool   `json:"ControlAvailable"`
		Nodes            int    `json:"Nodes"`
		Managers         int    `json:"Managers"`
	} `json:"Swarm"`
}

// Info describes the daemon and its Swarm membership.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	var info Info
	if err := c.do(ctx, http.MethodGet, "/info", nil, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Ping checks the daemon answers.
func (c *Client) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/_ping", nil, nil, nil)
}

func filters(kv map[string][]string) url.Values {
	data, _ := json.Marshal(kv)
	return url.Values{"filters": {string(data)}}
}
