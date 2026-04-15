package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

var db *sql.DB

func initDB(dsn string) error {
	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	return nil
}

func runMigrations() error {
	migrations := []string{
		// ── users ──────────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			email         TEXT UNIQUE NOT NULL,
			first_name    TEXT NOT NULL DEFAULT '',
			last_name     TEXT NOT NULL DEFAULT '',
			srp_salt      TEXT NOT NULL,
			srp_verifier  TEXT NOT NULL,
			public_key    TEXT NOT NULL,
			encrypted_private_key TEXT NOT NULL,
			key_salt      TEXT NOT NULL,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,

		// ── refresh_tokens ────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,

		// ── workspaces ────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS workspaces (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			type       TEXT NOT NULL DEFAULT 'shared',
			created_by TEXT NOT NULL REFERENCES users(id),
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,

		// ── workspace_members ─────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS workspace_members (
			id                      TEXT PRIMARY KEY,
			workspace_id            TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			user_id                 TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			email                   TEXT NOT NULL,
			role                    TEXT NOT NULL DEFAULT 'member',
			status                  TEXT NOT NULL DEFAULT 'active',
			encrypted_workspace_key TEXT NOT NULL,
			created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(workspace_id, user_id)
		)`,

		// ── projects ──────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS projects (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			description  TEXT NOT NULL DEFAULT '',
			workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(workspace_id, name)
		)`,

		// ── secrets ───────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS secrets (
			id          TEXT PRIMARY KEY,
			project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
			environment TEXT NOT NULL DEFAULT 'development',
			key         TEXT NOT NULL,
			value       TEXT NOT NULL,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(project_id, environment, key)
		)`,

		// ── allowlist_domains ─────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS allowlist_domains (
			id             TEXT PRIMARY KEY,
			workspace_id   TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			domain         TEXT NOT NULL,
			added_by_email TEXT NOT NULL,
			created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(workspace_id, domain)
		)`,

		// ── allowlist_log ─────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS allowlist_log (
			id                 TEXT PRIMARY KEY,
			workspace_id       TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			performed_by_email TEXT NOT NULL,
			action             TEXT NOT NULL,
			domain             TEXT NOT NULL,
			performed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,

		// ── agents ────────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS agents (
			id           TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			project_id   TEXT,
			name         TEXT NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_used    TIMESTAMPTZ
		)`,

		// ── agent_tokens ──────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS agent_tokens (
			id         TEXT PRIMARY KEY,
			agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL,
			label      TEXT NOT NULL DEFAULT '',
			status     TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			expires_at TIMESTAMPTZ,
			last_used  TIMESTAMPTZ
		)`,

		// ── audit_logs ────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id           TEXT PRIMARY KEY,
			user_id      TEXT,
			email        TEXT,
			workspace_id TEXT,
			project_id   TEXT,
			action       TEXT NOT NULL,
			resource     TEXT NOT NULL DEFAULT '',
			details      JSONB NOT NULL DEFAULT '{}',
			ip_address   TEXT NOT NULL DEFAULT '',
			created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	}

	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			log.Printf("migration failed: %s\nerror: %v", m[:80], err)
			return fmt.Errorf("migration: %w", err)
		}
	}
	return nil
}
