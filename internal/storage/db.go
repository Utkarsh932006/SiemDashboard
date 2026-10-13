package storage

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database connection.
type Store struct {
	db *sql.DB
}

// New opens a SQLite database at the given path and runs migrations.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Enable WAL mode for concurrent reads during writes
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return s, nil
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp  DATETIME NOT NULL,
		source_ip  TEXT NOT NULL DEFAULT '',
		host       TEXT NOT NULL DEFAULT '',
		program    TEXT NOT NULL DEFAULT '',
		facility   TEXT NOT NULL DEFAULT '',
		severity   TEXT NOT NULL DEFAULT 'INFO',
		event_type TEXT NOT NULL DEFAULT 'GENERIC',
		message    TEXT NOT NULL DEFAULT '',
		raw        TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
	CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
	CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

	CREATE TABLE IF NOT EXISTS alerts (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp  DATETIME NOT NULL,
		rule_id    TEXT NOT NULL,
		rule_name  TEXT NOT NULL,
		severity   TEXT NOT NULL,
		source_ip  TEXT NOT NULL DEFAULT '',
		count      INTEGER NOT NULL DEFAULT 0,
		message    TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
	CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
