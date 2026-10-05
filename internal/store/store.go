// Package store is everything the agent remembers, in one SQLite file under
// the data directory: the operators of its console and their sessions, the
// journal of intents it received, and the performance samples. The driver is
// pure Go, so the binary stays static.
//
// Nothing here is a secret value: passwords are stored hashed, session tokens
// hashed, and secrets live in the customer's Vault.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store is the agent's local database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS operators (
	id            INTEGER PRIMARY KEY,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	totp_secret   TEXT NOT NULL DEFAULT '',
	totp_enabled  INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash  TEXT PRIMARY KEY,
	operator_id INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS intents (
	id          TEXT PRIMARY KEY,
	kind        TEXT NOT NULL,
	status      TEXT NOT NULL,
	subject     TEXT NOT NULL DEFAULT '',
	error       TEXT NOT NULL DEFAULT '',
	received_at INTEGER NOT NULL,
	duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS intents_received ON intents(received_at DESC);
CREATE TABLE IF NOT EXISTS samples (
	service    TEXT NOT NULL,
	ts         INTEGER NOT NULL,
	cpu_milli  INTEGER NOT NULL,
	mem_bytes  INTEGER NOT NULL,
	mem_limit  INTEGER NOT NULL,
	containers INTEGER NOT NULL,
	PRIMARY KEY (service, ts)
) WITHOUT ROWID;
`

// Open opens (and creates) the database in dir.
func Open(dir string) (*Store, error) {
	dsn := "file:" + filepath.Join(dir, "agent.db") +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer at a time is all the agent needs and it keeps SQLite's
	// locking out of the picture.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// -- operators and sessions ---------------------------------------------------

// Operator is a console account.
type Operator struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	CreatedAt    time.Time
}

// OperatorCount tells whether the console still needs its first account.
func (s *Store) OperatorCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operators`).Scan(&n)
	return n, err
}

// CreateOperator adds an account.
func (s *Store) CreateOperator(ctx context.Context, username, passwordHash string) (*Operator, error) {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO operators (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, passwordHash, now.Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Operator{ID: id, Username: username, PasswordHash: passwordHash, CreatedAt: now}, nil
}

func scanOperator(row *sql.Row) (*Operator, error) {
	var o Operator
	var created int64
	var enabled int
	err := row.Scan(&o.ID, &o.Username, &o.PasswordHash, &o.TOTPSecret, &enabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	o.TOTPEnabled = enabled != 0
	o.CreatedAt = time.Unix(created, 0)
	return &o, nil
}

const operatorColumns = `id, username, password_hash, totp_secret, totp_enabled, created_at`

// OperatorByName finds an account by its username.
func (s *Store) OperatorByName(ctx context.Context, username string) (*Operator, error) {
	return scanOperator(s.db.QueryRowContext(ctx, `SELECT `+operatorColumns+` FROM operators WHERE username = ?`, username))
}

// SetPassword replaces an account's password hash.
func (s *Store) SetPassword(ctx context.Context, id int64, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE operators SET password_hash = ? WHERE id = ?`, passwordHash, id)
	return err
}

// SetTOTP stores the second-factor secret and whether it is required.
func (s *Store) SetTOTP(ctx context.Context, id int64, secret string, enabled bool) error {
	flag := 0
	if enabled {
		flag = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE operators SET totp_secret = ?, totp_enabled = ? WHERE id = ?`, secret, flag, id)
	return err
}

// CreateSession records a session by the hash of its token.
func (s *Store) CreateSession(ctx context.Context, tokenHash string, operatorID int64, expires time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, operator_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, operatorID, time.Now().Unix(), expires.Unix())
	return err
}

// SessionOperator returns the account a live session belongs to.
func (s *Store) SessionOperator(ctx context.Context, tokenHash string) (*Operator, error) {
	return scanOperator(s.db.QueryRowContext(ctx,
		`SELECT o.id, o.username, o.password_hash, o.totp_secret, o.totp_enabled, o.created_at
		   FROM sessions s JOIN operators o ON o.id = s.operator_id
		  WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, time.Now().Unix()))
}

// DeleteSession ends one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteOtherSessions ends every session of an account but one: what a
// password change does.
func (s *Store) DeleteOtherSessions(ctx context.Context, operatorID int64, keepTokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE operator_id = ? AND token_hash <> ?`, operatorID, keepTokenHash)
	return err
}

// -- the intent journal ---------------------------------------------------------

// IntentRecord is one line of the journal: what ISOGrid asked and how it
// ended. No payload and no result are kept, only what an operator needs to
// audit the channel.
type IntentRecord struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"`
	Subject    string    `json:"subject,omitempty"`
	Error      string    `json:"error,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	DurationMS int64     `json:"duration_ms"`
}

// IntentSeen reports whether an intent id was already executed. It is what
// makes "at most once" survive a restart of the agent.
func (s *Store) IntentSeen(ctx context.Context, id string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM intents WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// RecordIntent writes a journal line; a second line for the same id is ignored.
func (s *Store) RecordIntent(ctx context.Context, r IntentRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO intents (id, kind, status, subject, error, received_at, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Kind, r.Status, r.Subject, r.Error, r.ReceivedAt.Unix(), r.DurationMS)
	return err
}

// ListIntents returns the newest journal lines. Routine reads (status, ping,
// networks) are left out unless asked for: they are most of the traffic and
// none of the changes.
func (s *Store) ListIntents(ctx context.Context, limit int, includeReads bool) ([]IntentRecord, error) {
	query := `SELECT id, kind, status, subject, error, received_at, duration_ms FROM intents`
	if !includeReads {
		query += ` WHERE kind NOT IN ('service.status', 'ping', 'networks.list', 'capabilities.describe')`
	}
	query += ` ORDER BY received_at DESC, id LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IntentRecord{}
	for rows.Next() {
		var r IntentRecord
		var at int64
		if err := rows.Scan(&r.ID, &r.Kind, &r.Status, &r.Subject, &r.Error, &at, &r.DurationMS); err != nil {
			return nil, err
		}
		r.ReceivedAt = time.Unix(at, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// -- performance samples ----------------------------------------------------------

// Sample is one reading of a service: the sum over its containers on this node.
type Sample struct {
	Service    string `json:"-"`
	TS         int64  `json:"t"`
	CPUMilli   int64  `json:"cpu"`
	MemBytes   int64  `json:"mem"`
	MemLimit   int64  `json:"limit"`
	Containers int    `json:"n"`
}

// AddSamples stores one round of readings.
func (s *Store) AddSamples(ctx context.Context, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR REPLACE INTO samples (service, ts, cpu_milli, mem_bytes, mem_limit, containers) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, x := range samples {
		if _, err := stmt.ExecContext(ctx, x.Service, x.TS, x.CPUMilli, x.MemBytes, x.MemLimit, x.Containers); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SampledServices lists the services that have readings since a moment.
func (s *Store) SampledServices(ctx context.Context, since time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT service FROM samples WHERE ts >= ? ORDER BY service`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// Series returns a service's readings since a moment, averaged into buckets
// of the given width so a long range stays a few hundred points.
func (s *Store) Series(ctx context.Context, service string, since time.Time, bucket time.Duration) ([]Sample, error) {
	width := int64(bucket / time.Second)
	if width < 1 {
		width = 1
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT (ts / ?) * ?, CAST(AVG(cpu_milli) AS INTEGER), CAST(AVG(mem_bytes) AS INTEGER), MAX(mem_limit), MAX(containers)
		   FROM samples WHERE service = ? AND ts >= ? GROUP BY ts / ? ORDER BY 1`,
		width, width, service, since.Unix(), width)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Sample{}
	for rows.Next() {
		var x Sample
		if err := rows.Scan(&x.TS, &x.CPUMilli, &x.MemBytes, &x.MemLimit, &x.Containers); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// Prune drops what is past its retention: expired sessions, samples older
// than the sample retention, routine journal lines after a day and the rest
// of the journal after ninety days.
func (s *Store) Prune(ctx context.Context, sampleRetention time.Duration) error {
	now := time.Now()
	steps := []struct {
		query string
		arg   int64
	}{
		{`DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()},
		{`DELETE FROM samples WHERE ts < ?`, now.Add(-sampleRetention).Unix()},
		{`DELETE FROM intents WHERE kind IN ('service.status', 'ping', 'networks.list', 'capabilities.describe') AND received_at < ?`, now.Add(-24 * time.Hour).Unix()},
		{`DELETE FROM intents WHERE received_at < ?`, now.Add(-90 * 24 * time.Hour).Unix()},
	}
	for _, step := range steps {
		if _, err := s.db.ExecContext(ctx, step.query, step.arg); err != nil {
			return err
		}
	}
	return nil
}
