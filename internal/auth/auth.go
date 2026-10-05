// Package auth is the console's own authentication: a local operator account
// with an Argon2id-hashed password, an optional TOTP second factor, opaque
// session tokens, and a limiter that slows down guessing. It is the
// break-glass account; an identity provider in front of the console is the
// customer's to add.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is defined over HMAC-SHA1
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Password rules: long enough to resist guessing, bounded so hashing cannot
// be turned into a way to exhaust the agent.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
)

const (
	argonTime    = 3
	argonMemory  = 32 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// CheckPassword says why a new password is not acceptable, or nil.
func CheckPassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("the password needs at least %d characters", MinPasswordLength)
	}
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("the password is longer than %d characters", MaxPasswordLength)
	}
	return nil
}

// HashPassword returns an encoded Argon2id hash with its parameters and salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded hash in constant time.
func VerifyPassword(encoded, password string) bool {
	if len(password) > MaxPasswordLength {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	// Parameters come from our own database; bound them anyway.
	if memory > 1<<20 || iterations > 16 || threads == 0 || threads > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) == 0 || len(want) > 128 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// -- sessions ---------------------------------------------------------------------

// SessionLifetime is how long a console session lasts.
const SessionLifetime = 12 * time.Hour

// NewToken returns a random token and the hash to store for it.
func NewToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken is what the store keeps: a token read from the database cannot
// be replayed.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// -- TOTP -------------------------------------------------------------------------

const (
	totpStep   = 30 * time.Second
	totpDigits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 160-bit secret in base32.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// TOTPURI is what an authenticator app imports.
func TOTPURI(secret, account, issuer string) string {
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}

func totpAt(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", "")))
	if err != nil {
		return "", errors.New("the second-factor secret is not valid base32")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, value%1000000), nil
}

// TOTPCode is the code for a moment; exported for tests and tooling.
func TOTPCode(secret string, at time.Time) (string, error) {
	return totpAt(secret, uint64(at.Unix())/uint64(totpStep/time.Second))
}

// VerifyTOTP accepts the code of the current step and of its two neighbours,
// which covers a clock a few seconds off.
func VerifyTOTP(secret, code string, at time.Time) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return false
	}
	counter := uint64(at.Unix()) / uint64(totpStep/time.Second)
	ok := false
	for _, c := range []uint64{counter - 1, counter, counter + 1} {
		want, err := totpAt(secret, c)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			ok = true
		}
	}
	return ok
}

// -- limiter ----------------------------------------------------------------------

// Limiter slows down repeated failures for one key (an address and a
// username): after five, each further failure doubles a lock that starts at
// thirty seconds and stops at fifteen minutes.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*limitEntry
	now     func() time.Time
}

type limitEntry struct {
	failures int
	until    time.Time
	last     time.Time
}

const (
	limiterFree    = 5
	limiterBase    = 30 * time.Second
	limiterMax     = 15 * time.Minute
	limiterForget  = time.Hour
	limiterMaxKeys = 4096
)

// NewLimiter builds an empty limiter.
func NewLimiter() *Limiter {
	return &Limiter{entries: make(map[string]*limitEntry), now: time.Now}
}

// Blocked returns how long the key still has to wait, or zero.
func (l *Limiter) Blocked(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return 0
	}
	if wait := e.until.Sub(l.now()); wait > 0 {
		return wait
	}
	return 0
}

// Fail records a failure for the key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) >= limiterMaxKeys {
		for k, e := range l.entries {
			if now.Sub(e.last) > limiterForget {
				delete(l.entries, k)
			}
		}
		if len(l.entries) >= limiterMaxKeys {
			// Still full of live entries: forget everything rather than grow.
			l.entries = make(map[string]*limitEntry)
		}
	}
	e := l.entries[key]
	if e == nil || now.Sub(e.last) > limiterForget {
		e = &limitEntry{}
		l.entries[key] = e
	}
	e.failures++
	e.last = now
	if e.failures >= limiterFree {
		lock := limiterBase << min(e.failures-limiterFree, 10)
		if lock > limiterMax || lock <= 0 {
			lock = limiterMax
		}
		e.until = now.Add(lock)
	}
}

// Succeed clears the key.
func (l *Limiter) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
