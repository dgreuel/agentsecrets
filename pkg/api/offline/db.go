// Package offline implements an in-process, SQLite-backed Backend that
// satisfies api.Backend. It lets the CLI run with no network access — all
// state lives in ~/.agentsecrets/offline.db.
//
// The schema deliberately mirrors the cloud server's tables (users,
// workspaces, projects, secrets, allowlist) so a future `agentsecrets sync`
// command can push offline state to the cloud without translation.
package offline

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/glebarez/go-sqlite"
)

// DefaultDBPath returns the canonical offline database path.
func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("offline: cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".agentsecrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("offline: cannot create config directory: %w", err)
	}
	return filepath.Join(dir, "offline.db"), nil
}

// openDB opens (and lazily initialises) the SQLite database at the given path.
// Pass an empty string to use DefaultDBPath.
func openDB(path string) (*sql.DB, error) {
	if path == "" {
		var err error
		path, err = DefaultDBPath()
		if err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("offline: open sqlite: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("offline: init schema: %w", err)
	}
	return db, nil
}

// schema mirrors the cloud Postgres tables we care about for single-user use.
// Field names match the cloud API's JSON shapes so handlers can SELECT
// straight into response structs.
const schema = `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	email TEXT UNIQUE NOT NULL,
	public_key TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workspaces (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	type TEXT NOT NULL DEFAULT 'personal',
	owner_id TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workspace_members (
	workspace_id TEXT NOT NULL,
	user_id TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'owner',
	encrypted_workspace_key TEXT,
	PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS projects (
	id TEXT PRIMARY KEY,
	workspace_id TEXT NOT NULL,
	name TEXT NOT NULL,
	description TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE (workspace_id, name)
);

CREATE TABLE IF NOT EXISTS secrets (
	project_id TEXT NOT NULL,
	environment TEXT NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (project_id, environment, key)
);

CREATE TABLE IF NOT EXISTS allowlist_domains (
	workspace_id TEXT NOT NULL,
	domain TEXT NOT NULL,
	added_by_email TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (workspace_id, domain)
);

CREATE TABLE IF NOT EXISTS allowlist_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	workspace_id TEXT NOT NULL,
	action TEXT NOT NULL,
	domain TEXT NOT NULL,
	performed_by_email TEXT,
	performed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`
