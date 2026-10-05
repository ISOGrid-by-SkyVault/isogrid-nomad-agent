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
CREATE TABLE IF NOT EXISTS connections (
	name       TEXT PRIMARY KEY,
	kind       TEXT NOT NULL,
	host       TEXT NOT NULL DEFAULT '',
	username   TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	created_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS builds (
	id          TEXT PRIMARY KEY,
	connection  TEXT NOT NULL,
	repository  TEXT NOT NULL,
	ref         TEXT NOT NULL,
	commit_sha  TEXT NOT NULL DEFAULT '',
	image       TEXT NOT NULL,
	digest      TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL,
	error       TEXT NOT NULL DEFAULT '',
	started_at  INTEGER NOT NULL,
	finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS builds_started ON builds(started_at DESC);
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

// DB exposes the handle to packages that keep their own tables' queries
// (connections), so the store does not have to import them.
func (s *Store) DB() *sql.DB { return s.db }

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
		query += ` WHERE kind NOT IN ('service.status', 'build.status', 'ping', 'networks.list', 'capabilities.describe', 'repositories.list', 'repository.refs', 'repository.commits', 'registry.images')`
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
		{`DELETE FROM intents WHERE kind IN ('service.status', 'build.status', 'ping', 'networks.list', 'capabilities.describe', 'repositories.list', 'repository.refs', 'repository.commits', 'registry.images') AND received_at < ?`, now.Add(-24 * time.Hour).Unix()},
		{`DELETE FROM intents WHERE received_at < ?`, now.Add(-90 * 24 * time.Hour).Unix()},
	}
	for _, step := range steps {
		if _, err := s.db.ExecContext(ctx, step.query, step.arg); err != nil {
			return err
		}
	}
	return nil
}

// -- builds -------------------------------------------------------------------------

// Build is one image build the agent ran. Its output is a file beside the
// database, never a column: it can be large and it never leaves this machine.
type Build struct {
	ID         string    `json:"id"`
	Connection string    `json:"connection"`
	Repository string    `json:"repository"`
	Ref        string    `json:"ref"`
	Commit     string    `json:"commit,omitempty"`
	Image      string    `json:"image"`
	Digest     string    `json:"digest,omitempty"`
	Status     string    `json:"status"` // running | succeeded | failed
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// CreateBuild records a build as it starts; false when the id already exists.
func (s *Store) CreateBuild(ctx context.Context, b Build) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO builds (id, connection, repository, ref, image, status, started_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.Connection, b.Repository, b.Ref, b.Image, b.Status, b.StartedAt.Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// UpdateBuild writes what a build learned or how it ended.
func (s *Store) UpdateBuild(ctx context.Context, b Build) error {
	finished := int64(0)
	if !b.FinishedAt.IsZero() {
		finished = b.FinishedAt.Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE builds SET commit_sha = ?, digest = ?, status = ?, error = ?, finished_at = ? WHERE id = ?`,
		b.Commit, b.Digest, b.Status, b.Error, finished, b.ID)
	return err
}

const buildColumns = `id, connection, repository, ref, commit_sha, image, digest, status, error, started_at, finished_at`

func scanBuild(scan func(dest ...any) error) (*Build, error) {
	var b Build
	var started, finished int64
	if err := scan(&b.ID, &b.Connection, &b.Repository, &b.Ref, &b.Commit, &b.Image, &b.Digest, &b.Status, &b.Error, &started, &finished); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	b.StartedAt = time.Unix(started, 0)
	if finished > 0 {
		b.FinishedAt = time.Unix(finished, 0)
	}
	return &b, nil
}

// GetBuild finds a build by id.
func (s *Store) GetBuild(ctx context.Context, id string) (*Build, error) {
	return scanBuild(s.db.QueryRowContext(ctx, `SELECT `+buildColumns+` FROM builds WHERE id = ?`, id).Scan)
}

// ListBuilds returns the newest builds.
func (s *Store) ListBuilds(ctx context.Context, limit int) ([]Build, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+buildColumns+` FROM builds ORDER BY started_at DESC, id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Build{}
	for rows.Next() {
		b, err := scanBuild(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// FailRunningBuilds marks builds left running by a previous process: the
// agent restarted under them and nothing will finish them.
func (s *Store) FailRunningBuilds(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE builds SET status = 'failed', error = 'The agent restarted while this build was running', finished_at = ? WHERE status = 'running'`,
		time.Now().Unix())
	return err
}
