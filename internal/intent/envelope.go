// Package intent checks what the control plane sends before anything acts on
// it. An intent is a signed envelope (intents/schema.json): the agent verifies
// the signature with ISOGrid's per-organization public key, then that the
// envelope is for this organization and this cluster, that it is fresh, and
// that its id has not been executed before. Only then is the payload looked
// at, by the executor.
//
// The signature covers the canonical JSON of every field but "signature":
// keys sorted by code point at every level, no whitespace, numbers exactly as
// written on the wire, strings escaped the way Python's json module does with
// ensure_ascii=False (only `"`, `\` and control characters). Both sides
// produce the same bytes from the same document, whatever key order or
// spacing the transport used.
package intent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Version of the envelope this agent understands.
const Version = 1

// Error codes, so a reply can say why an intent was not executed.
const (
	CodeMalformed   = "malformed"
	CodeVersion     = "version"
	CodeSignature   = "signature"
	CodeScope       = "scope"
	CodeExpired     = "expired"
	CodeNotYetValid = "not_yet_valid"
	CodeReplay      = "replay"
)

// Error is a refusal with a stable code and a sentence for the operator.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Envelope is a verified intent.
type Envelope struct {
	Version        int             `json:"version"`
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	OrganizationID string          `json:"organization_id"`
	ClusterID      string          `json:"cluster_id"`
	IssuedAt       time.Time       `json:"issued_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Nonce          string          `json:"nonce"`
	ReplyTo        string          `json:"reply_to,omitempty"`
	Payload        json.RawMessage `json:"payload"`
	Signature      string          `json:"signature"`
}

// LoadPublicKey reads the Ed25519 public key ISOGrid ships in the bundle
// (intent.pub, PEM "PUBLIC KEY").
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(raw)
}

// ParsePublicKey parses what LoadPublicKey reads.
func ParsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected an Ed25519 key, got %T", parsed)
	}
	return key, nil
}

// Verifier checks envelopes for one cluster.
type Verifier struct {
	public  ed25519.PublicKey
	org     string
	cluster string
	skew    time.Duration
	now     func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // id -> when it may be forgotten
}

// NewVerifier binds the organization's public key to this cluster. Clock
// skew up to five minutes is tolerated on issued_at.
func NewVerifier(public ed25519.PublicKey, organizationID, clusterID string) *Verifier {
	return &Verifier{
		public:  public,
		org:     organizationID,
		cluster: clusterID,
		skew:    5 * time.Minute,
		now:     time.Now,
		seen:    make(map[string]time.Time),
	}
}

// maxLifetime bounds how long an id is remembered, whatever expires_at says,
// so the replay set cannot grow without limit.
const maxLifetime = 24 * time.Hour

// Verify checks a raw envelope and records its id. It returns the envelope
// only when everything holds; the error says what did not.
func (v *Verifier) Verify(raw []byte) (*Envelope, error) {
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, &Error{CodeMalformed, "the envelope does not parse: " + err.Error()}
	}
	if env.Version != Version {
		return nil, &Error{CodeVersion, fmt.Sprintf("envelope version %d, this agent speaks %d", env.Version, Version)}
	}
	if env.ID == "" || env.Kind == "" || len(env.Nonce) < 16 || env.Payload == nil {
		return nil, &Error{CodeMalformed, "id, kind, nonce and payload are required"}
	}
	signature, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, &Error{CodeSignature, "the signature is not a base64 Ed25519 signature"}
	}
	canonical, err := Canonical(raw)
	if err != nil {
		return nil, &Error{CodeMalformed, err.Error()}
	}
	if !ed25519.Verify(v.public, canonical, signature) {
		return nil, &Error{CodeSignature, "the signature does not verify with the organization's key"}
	}
	if env.OrganizationID != v.org || env.ClusterID != v.cluster {
		return nil, &Error{CodeScope, "the intent is for another organization or cluster"}
	}
	now := v.now()
	if env.IssuedAt.After(now.Add(v.skew)) {
		return nil, &Error{CodeNotYetValid, "issued_at is in the future"}
	}
	if !env.ExpiresAt.After(now) {
		return nil, &Error{CodeExpired, "the intent expired at " + env.ExpiresAt.UTC().Format(time.RFC3339)}
	}
	forget := env.ExpiresAt
	if limit := now.Add(maxLifetime); forget.After(limit) {
		forget = limit
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, until := range v.seen {
		if !until.After(now) {
			delete(v.seen, id)
		}
	}
	if _, dup := v.seen[env.ID]; dup {
		return nil, &Error{CodeReplay, "intent " + env.ID + " was already executed"}
	}
	v.seen[env.ID] = forget
	return &env, nil
}

// Canonical returns the bytes the signature covers: the document without its
// "signature" member, in the canonical form described in the package comment.
func Canonical(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	top, ok := doc.(map[string]any)
	if !ok {
		return nil, errors.New("the envelope is not a JSON object")
	}
	delete(top, "signature")
	var buf bytes.Buffer
	if err := writeCanonical(&buf, top); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(string(x))
	case string:
		writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("cannot canonicalise %T", v)
	}
	return nil
}

// writeString escapes like Python's json.dumps(ensure_ascii=False): the quote,
// the backslash, \b \f \n \r \t by name and the other control characters as
// \u00XX. Everything else, non-ASCII included, is written as is.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				hex := strconv.FormatInt(int64(r), 16)
				if len(hex) == 1 {
					buf.WriteByte('0')
				}
				buf.WriteString(hex)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
