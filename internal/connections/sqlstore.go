package connections

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SQLStore keeps connection descriptions in the agent's database.
type SQLStore struct {
	DB *sql.DB
}

func (s SQLStore) ListConnections(ctx context.Context) ([]Connection, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT name, kind, host, username, created_at, created_by FROM connections ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Connection{}
	for rows.Next() {
		var c Connection
		var created int64
		if err := rows.Scan(&c.Name, &c.Kind, &c.Host, &c.Username, &created, &c.CreatedBy); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(created, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s SQLStore) GetConnection(ctx context.Context, name string) (*Connection, error) {
	var c Connection
	var created int64
	err := s.DB.QueryRowContext(ctx, `SELECT name, kind, host, username, created_at, created_by FROM connections WHERE name = ?`, name).
		Scan(&c.Name, &c.Kind, &c.Host, &c.Username, &created, &c.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = time.Unix(created, 0)
	return &c, nil
}

func (s SQLStore) SaveConnection(ctx context.Context, c Connection) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO connections (name, kind, host, username, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET kind = excluded.kind, host = excluded.host, username = excluded.username`,
		c.Name, c.Kind, c.Host, c.Username, c.CreatedAt.Unix(), c.CreatedBy)
	return err
}

func (s SQLStore) DeleteConnection(ctx context.Context, name string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM connections WHERE name = ?`, name)
	return err
}
