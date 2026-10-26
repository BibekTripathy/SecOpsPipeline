// Package store persists identity and the held-push queue in SQLite.
//
// SQLite keeps the gateway a single binary plus a single file, which matters
// for a tool meant to be dropped in front of an existing remote. Every query
// goes through the methods here rather than through raw SQL at call sites, so
// moving to Postgres is a swap of this package, not a rewrite.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// DB wraps the SQLite connection.
type DB struct{ sql *sql.DB }

// Open opens the database and applies the schema.
//
// The pragmas matter: WAL lets a scan read while a push writes, busy_timeout
// stops concurrent pushes failing with SQLITE_BUSY, and foreign_keys is off
// by default in SQLite.
func Open(ctx context.Context, path string) (*DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if _, err := sqlDB.ExecContext(ctx, schema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &DB{sql: sqlDB}, nil
}

func (db *DB) Close() error { return db.sql.Close() }

// SQL exposes the underlying handle for tests and migrations.
func (db *DB) SQL() *sql.DB { return db.sql }

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid || s.String == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return nil, fmt.Errorf("parse timestamp %q: %w", s.String, err)
	}
	return &t, nil
}
