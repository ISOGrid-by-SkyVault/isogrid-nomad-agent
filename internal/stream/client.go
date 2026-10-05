// Package stream is the agent's side of the ISOGrid control channel: one
// outbound WebSocket to the API, opened with a signed handshake, kept alive
// with heartbeats, and reopened with a backoff whenever it drops.
//
// Down the socket come intents; up go replies and heartbeats. The client
// knows nothing about what an intent means: it hands the body to a handler
// and sends back whatever the handler returns. Everything the operator may
// want to know about the channel is in Status.
package stream

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// Close codes the API uses, so the client can tell a refusal (which will not
// fix itself in a second) from an outage (which may).
const (
	CloseBadHello    websocket.StatusCode = 4000
	CloseRefused     websocket.StatusCode = 4003
	CloseIdle        websocket.StatusCode = 4008
	CloseUnavailable websocket.StatusCode = 4011
)

const (
	handshakeTimeout = 15 * time.Second
	dialTimeout      = 20 * time.Second
	writeTimeout     = 10 * time.Second
	minBackoff       = 2 * time.Second
	maxBackoff       = 60 * time.Second
	refusedBackoff   = 2 * time.Minute
	stableAfter      = 60 * time.Second
	maxMessageBytes  = 1 << 20
	maxInFlight      = 4
)

// State of the channel as the operator sees it.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateRefused      State = "refused"
	StateDisconnected State = "disconnected"
)

// Status is what the console and the health endpoint show.
type Status struct {
	State            State      `json:"state"`
	Since            time.Time  `json:"since"`
	Reason           string     `json:"reason,omitempty"`
	Attempts         int        `json:"attempts"`
	NextAttemptAt    *time.Time `json:"next_attempt_at,omitempty"`
	HeartbeatSeconds int        `json:"heartbeat_seconds,omitempty"`
	IntentsReceived  uint64     `json:"intents_received"`
	RepliesSent      uint64     `json:"replies_sent"`
	LastIntentAt     *time.Time `json:"last_intent_at,omitempty"`
	CertificateCN    string     `json:"certificate_cn,omitempty"`
	CertificateUntil time.Time  `json:"certificate_not_after"`
}

// Handler turns an intent body into a reply body. It must not panic and it
// should never return nil: the API drops replies that are not objects.
type Handler func(ctx context.Context, body json.RawMessage) any

// Options configure a Client.
type Options struct {
	URL            string
	CertFile       string
	KeyFile        string
	CAFile         string // optional private CA for the API's TLS
	ClusterID      string
	OrganizationID string
	Version        string
	Capabilities   []string
	Handle         Handler
	Logf           func(format string, args ...any)
	// Inventory reports what the platform should know about the cluster
	// without asking: today the overlay networks a service may attach to.
	// It is sent in the hello and again in a heartbeat whenever it changed.
	Inventory func(ctx context.Context) (any, error)
}

// Client keeps the channel open for the life of the agent.
type Client struct {
	opt     Options
	key     *ecdsa.PrivateKey
	certPEM string
	http    *http.Client

	mu       sync.Mutex
	status   Status
	intents  atomic.Uint64
	replies  atomic.Uint64
	lastSeen atomic.Int64
}

// New loads the identity files and prepares the client. It does not connect.
func New(opt Options) (*Client, error) {
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.Handle == nil {
		return nil, errors.New("stream: a handler is required")
	}
	key, err := LoadKey(opt.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("client key: %w", err)
	}
	certPEM, cert, err := LoadCertificate(opt.CertFile)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("the client key does not match the client certificate")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opt.CAFile != "" {
		pool := x509.NewCertPool()
		raw, err := os.ReadFile(opt.CAFile)
		if err != nil {
			return nil, fmt.Errorf("stream CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("stream CA: no certificate found in the file")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	c := &Client{
		opt:     opt,
		key:     key,
		certPEM: certPEM,
		http:    &http.Client{Transport: transport},
	}
	c.status = Status{
		State:            StateConnecting,
		Since:            time.Now(),
		CertificateCN:    cert.Subject.CommonName,
		CertificateUntil: cert.NotAfter,
	}
	return c, nil
}

// Status is a snapshot for the console.
func (c *Client) Status() Status {
	c.mu.Lock()
	s := c.status
	c.mu.Unlock()
	s.IntentsReceived = c.intents.Load()
	s.RepliesSent = c.replies.Load()
	if t := c.lastSeen.Load(); t > 0 {
		at := time.Unix(0, t)
		s.LastIntentAt = &at
	}
	return s
}

func (c *Client) set(state State, reason string, next *time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.State != state || c.status.Reason != reason {
		c.status.Since = time.Now()
	}
	c.status.State = state
	c.status.Reason = reason
	c.status.NextAttemptAt = next
}

// Run connects and reconnects until the context ends.
func (c *Client) Run(ctx context.Context) {
	backoff := minBackoff
	for {
		c.mu.Lock()
		c.status.Attempts++
		c.mu.Unlock()
		started := time.Now()
		err := c.session(ctx)
		if ctx.Err() != nil {
			c.set(StateDisconnected, "shutting down", nil)
			return
		}
		if time.Since(started) > stableAfter {
			backoff = minBackoff
		}
		state, reason, wait := classify(err, backoff)
		if state != StateRefused {
			backoff = min(backoff*2, maxBackoff)
		}
		wait += time.Duration(rand.Int64N(int64(wait / 4)))
		next := time.Now().Add(wait)
		c.set(state, reason, &next)
		c.opt.Logf("stream: %s (%s); next attempt in %s", state, reason, wait.Round(time.Second))
		select {
		case <-ctx.Done():
			c.set(StateDisconnected, "shutting down", nil)
			return
		case <-time.After(wait):
		}
	}
}

// classify turns the error that ended a session into what the operator sees
// and how long to wait before trying again.
func classify(err error, backoff time.Duration) (State, string, time.Duration) {
	if err == nil {
		return StateDisconnected, "closed by the platform", backoff
	}
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		reason := ce.Reason
		if reason == "" {
			reason = fmt.Sprintf("closed with code %d", ce.Code)
		}
		if ce.Code == CloseRefused {
			return StateRefused, reason, refusedBackoff
		}
		return StateDisconnected, reason, backoff
	}
	return StateDisconnected, err.Error(), backoff
}

type challenge struct {
	Type    string `json:"type"`
	Nonce   string `json:"nonce"`
	Version int    `json:"version"`
}

type welcome struct {
	Type             string `json:"type"`
	OrganizationID   string `json:"organization_id"`
	ClusterID        string `json:"cluster_id"`
	HeartbeatSeconds int    `json:"heartbeat_seconds"`
	Reason           string `json:"reason"`
}

type frame struct {
	Type   string          `json:"type"`
	Body   json.RawMessage `json:"body"`
	Reason string          `json:"reason"`
}

// session is one connection: handshake, then pumps until something ends it.
func (c *Client) session(ctx context.Context) error {
	c.set(StateConnecting, "", nil)
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, resp, err := websocket.Dial(dialCtx, c.opt.URL, &websocket.DialOptions{
		HTTPClient: c.http,
		HTTPHeader: http.Header{"User-Agent": {"isogrid-nomad-agent/" + c.opt.Version}},
	})
	cancel()
	if err != nil {
		if resp != nil {
			return fmt.Errorf("the API answered HTTP %d instead of upgrading", resp.StatusCode)
		}
		return err
	}
	defer conn.CloseNow() //nolint:errcheck
	conn.SetReadLimit(maxMessageBytes)

	var ch challenge
	if err := readJSON(ctx, conn, handshakeTimeout, &ch); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	if ch.Type != "challenge" || ch.Nonce == "" {
		return errors.New("the API did not send a challenge")
	}
	signature, err := Sign(c.key, []byte(ch.Nonce))
	if err != nil {
		return fmt.Errorf("sign the challenge: %w", err)
	}
	hello := map[string]any{
		"type":         "hello",
		"cluster_id":   c.opt.ClusterID,
		"certificate":  c.certPEM,
		"signature":    signature,
		"version":      c.opt.Version,
		"capabilities": c.opt.Capabilities,
	}
	lastInventory := ""
	if inv, digest, ok := c.inventory(ctx); ok {
		hello["inventory"] = inv
		lastInventory = digest
	}
	if err := writeJSON(ctx, conn, hello); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	var w welcome
	if err := readJSON(ctx, conn, handshakeTimeout, &w); err != nil {
		return fmt.Errorf("welcome: %w", err)
	}
	if w.Type == "error" {
		return errors.New(w.Reason)
	}
	if w.Type != "welcome" {
		return fmt.Errorf("expected a welcome, got %q", w.Type)
	}
	if w.ClusterID != c.opt.ClusterID || w.OrganizationID != c.opt.OrganizationID {
		return errors.New("the welcome names another cluster or organization")
	}
	heartbeat := time.Duration(w.HeartbeatSeconds) * time.Second
	if heartbeat <= 0 {
		heartbeat = 30 * time.Second
	}
	c.mu.Lock()
	c.status.HeartbeatSeconds = int(heartbeat / time.Second)
	c.mu.Unlock()
	c.set(StateConnected, "", nil)
	c.opt.Logf("stream: connected to %s as cluster %s", c.opt.URL, c.opt.ClusterID)

	sessionCtx, stop := context.WithCancel(ctx)
	defer stop()
	errs := make(chan error, 2)
	go func() { errs <- c.heartbeats(sessionCtx, conn, heartbeat, lastInventory) }()
	go func() { errs <- c.read(sessionCtx, conn) }()
	err = <-errs
	stop()
	if ctx.Err() != nil {
		_ = conn.Close(websocket.StatusNormalClosure, "shutting down")
	}
	return err
}

func (c *Client) heartbeats(ctx context.Context, conn *websocket.Conn, every time.Duration, lastInventory string) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			beat := map[string]any{"type": "heartbeat"}
			if inv, digest, ok := c.inventory(ctx); ok && digest != lastInventory {
				beat["inventory"] = inv
				lastInventory = digest
			}
			if err := writeJSON(ctx, conn, beat); err != nil {
				return fmt.Errorf("heartbeat: %w", err)
			}
		}
	}
}

// inventory calls the Inventory option and digests its JSON, so a heartbeat
// only repeats it when something changed. A failing inventory is logged and
// skipped: the channel matters more than the report.
func (c *Client) inventory(ctx context.Context) (any, string, bool) {
	if c.opt.Inventory == nil {
		return nil, "", false
	}
	invCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	inv, err := c.opt.Inventory(invCtx)
	if err != nil {
		c.opt.Logf("stream: inventory not read: %v", err)
		return nil, "", false
	}
	data, err := json.Marshal(inv)
	if err != nil {
		return nil, "", false
	}
	sum := sha256.Sum256(data)
	return inv, hex.EncodeToString(sum[:8]), true
}

func (c *Client) read(ctx context.Context, conn *websocket.Conn) error {
	inflight := make(chan struct{}, maxInFlight)
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var f frame
		if err := json.Unmarshal(data, &f); err != nil {
			// Not the agent's to interpret; the API never sends non-JSON.
			continue
		}
		switch f.Type {
		case "intent":
			c.intents.Add(1)
			c.lastSeen.Store(time.Now().UnixNano())
			select {
			case inflight <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			go func(body json.RawMessage) {
				defer func() { <-inflight }()
				reply := c.handle(ctx, body)
				if err := writeJSON(ctx, conn, map[string]any{"type": "reply", "body": reply}); err != nil {
					c.opt.Logf("stream: reply not sent: %v", err)
					return
				}
				c.replies.Add(1)
			}(f.Body)
		case "error":
			c.opt.Logf("stream: the API reports: %s", f.Reason)
		}
	}
}

// handle guards the handler: a panic becomes an error reply, never a crash of
// the channel.
func (c *Client) handle(ctx context.Context, body json.RawMessage) (reply any) {
	defer func() {
		if r := recover(); r != nil {
			c.opt.Logf("stream: handler panicked: %v", r)
			reply = map[string]any{"status": "error", "error": "the agent failed to handle the intent"}
		}
	}()
	return c.opt.Handle(ctx, body)
}

func readJSON(ctx context.Context, conn *websocket.Conn, timeout time.Duration, v any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(ctx context.Context, conn *websocket.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, data)
}
