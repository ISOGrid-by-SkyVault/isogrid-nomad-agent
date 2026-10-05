// Package executor turns a verified intent into work and a reply. Each intent
// kind has one handler; the executor owns nothing but the registry, so the
// Docker, Vault and build handlers plug in here as they are written.
//
// A reply never carries a secret value or a log line: status, a small result
// and, when refused, the reason.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/intent"
)

// Reply is what goes back up the stream for one intent.
type Reply struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind,omitempty"`
	ClusterID   string    `json:"cluster_id"`
	Status      string    `json:"status"` // ok | error | rejected | unsupported
	Result      any       `json:"result,omitempty"`
	Error       string    `json:"error,omitempty"`
	Code        string    `json:"code,omitempty"`
	Agent       string    `json:"agent_version"`
	CompletedAt time.Time `json:"completed_at"`
}

// Handler executes one kind of intent. It returns the result to report or an
// error that becomes the reply's message.
type Handler func(ctx context.Context, env *intent.Envelope) (any, error)

// Executor dispatches verified intents.
type Executor struct {
	verifier  *intent.Verifier
	version   string
	clusterID string

	mu       sync.RWMutex
	handlers map[string]Handler
	journal  Journal
	started  time.Time
	executed uint64
	refused  uint64
}

// Journal is the durable record of what the agent was asked. It makes "an
// intent id is executed at most once" survive a restart, and it is what the
// console shows as activity. Entries carry no payload and no result.
type Journal interface {
	Seen(ctx context.Context, id string) (bool, error)
	Record(ctx context.Context, entry JournalEntry)
}

// JournalEntry is one line of the journal.
type JournalEntry struct {
	ID         string
	Kind       string
	Status     string
	Subject    string
	Error      string
	ReceivedAt time.Time
	Duration   time.Duration
}

// SetJournal attaches the journal; without one the executor only keeps the
// verifier's in-memory replay set.
func (e *Executor) SetJournal(j Journal) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.journal = j
}

// New builds an executor with the handlers every agent has: ping and
// capabilities.describe.
func New(verifier *intent.Verifier, version, clusterID string) *Executor {
	e := &Executor{
		verifier:  verifier,
		version:   version,
		clusterID: clusterID,
		handlers:  make(map[string]Handler),
		started:   time.Now(),
	}
	e.Register("ping", e.ping)
	e.Register("capabilities.describe", e.describe)
	return e
}

// Register adds or replaces the handler for a kind.
func (e *Executor) Register(kind string, h Handler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[kind] = h
}

// Capabilities lists the kinds this agent executes, sorted; the stream sends
// it in the hello so the platform only offers what the agent can do.
func (e *Executor) Capabilities() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	kinds := make([]string, 0, len(e.handlers))
	for k := range e.handlers {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// Counts reports how many intents were executed and refused since start.
func (e *Executor) Counts() (executed, refused uint64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.executed, e.refused
}

// Handle is the stream's handler: verify, dispatch, and always answer.
func (e *Executor) Handle(ctx context.Context, body json.RawMessage) any {
	received := time.Now()
	reply := e.handle(ctx, body)
	e.mu.RLock()
	journal := e.journal
	e.mu.RUnlock()
	if journal != nil {
		entry := JournalEntry{
			ID: reply.ID, Kind: reply.Kind, Status: reply.Status, Error: reply.Error,
			Subject: subjectOf(body), ReceivedAt: received, Duration: time.Since(received),
		}
		if reply.Status == "rejected" {
			// A refused envelope must not occupy the id of a genuine one.
			entry.ID = fmt.Sprintf("refused-%d-%s", received.UnixNano(), reply.ID)
			entry.Subject = ""
		}
		journal.Record(ctx, entry)
	}
	return reply
}

func (e *Executor) handle(ctx context.Context, body json.RawMessage) Reply {
	reply := Reply{ClusterID: e.clusterID, Agent: e.version}
	env, err := e.verifier.Verify(body)
	if err == nil {
		e.mu.RLock()
		journal := e.journal
		e.mu.RUnlock()
		if journal != nil {
			if seen, jerr := journal.Seen(ctx, env.ID); jerr != nil {
				err = &intent.Error{Code: intent.CodeReplay, Message: "the journal could not be read, so the intent is not executed: " + jerr.Error()}
			} else if seen {
				err = &intent.Error{Code: intent.CodeReplay, Message: "intent " + env.ID + " was already executed"}
			}
		}
	}
	if err != nil {
		var ie *intent.Error
		if errors.As(err, &ie) {
			reply.Code = ie.Code
			reply.Error = ie.Message
		} else {
			reply.Code = intent.CodeMalformed
			reply.Error = err.Error()
		}
		reply.ID, reply.Kind = unverifiedIdentity(body)
		reply.Status = "rejected"
		e.count(false)
		return e.finish(reply)
	}
	reply.ID, reply.Kind = env.ID, env.Kind
	e.mu.RLock()
	h, ok := e.handlers[env.Kind]
	e.mu.RUnlock()
	if !ok {
		reply.Status = "unsupported"
		reply.Error = fmt.Sprintf("this agent does not execute %q", env.Kind)
		e.count(false)
		return e.finish(reply)
	}
	result, err := h(ctx, env)
	if err != nil {
		reply.Status = "error"
		reply.Error = err.Error()
	} else {
		reply.Status = "ok"
		reply.Result = result
	}
	e.count(true)
	return e.finish(reply)
}

func (e *Executor) finish(r Reply) Reply {
	r.CompletedAt = time.Now().UTC()
	return r
}

func (e *Executor) count(executed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if executed {
		e.executed++
	} else {
		e.refused++
	}
}

// subjectOf names what an intent is about, for the journal: the service
// name when the payload has one. Nothing else of the payload is kept.
func subjectOf(body json.RawMessage) string {
	var probe struct {
		Payload struct {
			Name string `json:"name"`
		} `json:"payload"`
	}
	_ = json.Unmarshal(body, &probe)
	if len(probe.Payload.Name) > 64 {
		return probe.Payload.Name[:64]
	}
	return probe.Payload.Name
}

// unverifiedIdentity pulls id and kind out of an envelope that failed
// verification, so the platform can match the refusal to what it sent. They
// are echoed, never acted on.
func unverifiedIdentity(body json.RawMessage) (string, string) {
	var probe struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(body, &probe)
	if len(probe.ID) > 64 {
		probe.ID = probe.ID[:64]
	}
	if len(probe.Kind) > 64 {
		probe.Kind = probe.Kind[:64]
	}
	return probe.ID, probe.Kind
}

func (e *Executor) ping(_ context.Context, env *intent.Envelope) (any, error) {
	var payload struct {
		Echo string `json:"echo"`
	}
	_ = json.Unmarshal(env.Payload, &payload)
	if len(payload.Echo) > 256 {
		payload.Echo = payload.Echo[:256]
	}
	return map[string]any{
		"echo":    payload.Echo,
		"time":    time.Now().UTC().Format(time.RFC3339),
		"uptime":  time.Since(e.started).Round(time.Second).String(),
		"version": e.version,
	}, nil
}

func (e *Executor) describe(_ context.Context, _ *intent.Envelope) (any, error) {
	return map[string]any{
		"version":      e.version,
		"capabilities": e.Capabilities(),
		"envelope":     intent.Version,
	}, nil
}
