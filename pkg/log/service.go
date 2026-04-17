// Package log provides audit log querying for both local SQLite and remote API sources.
package log

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/proxy"
)

// Filter holds all options for querying audit logs.
type Filter struct {
	Agent       string
	Token       string
	Identity    string // "anonymous", "declared", "issued"
	Credential  string
	Domain      string
	Method      string
	Environment string // "development", "staging", "production"
	Status      int
	StatusClass string // "2xx", "4xx", "5xx", "error"
	Failed      bool
	Blocked     bool
	Redacted    bool
	ProjectID   string
	Since       time.Time
	Until       time.Time
	Limit       int
	Offset      int
}

// Service provides methods to query local and cloud audit logs.
type Service struct {
	client api.Backend
	db     *sql.DB
}

// NewService creates a new log service. If db is nil, it tries to connect to the default local SQLite DB.
func NewService(backend api.Backend, db *sql.DB) (*Service, error) {
	if db == nil {
		logger, err := proxy.NewAuditLogger("")
		if err != nil {
			return nil, err
		}
		db = logger.DB()
	}
	return &Service{
		client: backend,
		db:     db,
	}, nil
}

// Close closes the local database connection.
func (s *Service) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// QueryLocal fetches audit events from the local SQLite database.
func (s *Service) QueryLocal(f Filter) ([]proxy.AuditEvent, error) {
	query := "SELECT id, timestamp, COALESCE(environment, '') as environment, agent_id, identity_level, method, target_url, domain, status_code, duration_ms, status, reason, redacted, resolution_path, caller_role, workspace_id, project_id, token_id, secret_keys, auth_styles FROM audit_events WHERE 1=1"
	args := []interface{}{}

	if f.Agent != "" {
		if f.Agent == "anonymous" || f.Agent == "(anon)" || f.Agent == "(anonymous)" {
			query += " AND (agent_id = ? OR agent_id = '' OR agent_id IS NULL)"
			args = append(args, f.Agent)
		} else {
			query += " AND agent_id = ?"
			args = append(args, f.Agent)
		}
	}
	if f.Token != "" {
		query += " AND token_id = ?"
		args = append(args, f.Token)
	}
	if f.Identity != "" {
		if f.Identity == "anonymous" {
			query += " AND (identity_level = ? OR identity_level = '' OR identity_level IS NULL)"
			args = append(args, f.Identity)
		} else {
			query += " AND identity_level = ?"
			args = append(args, f.Identity)
		}
	}
	if f.Credential != "" {
		// SecretKeys is stored as a JSON string, e.g. ["STRIPE_KEY"]
		query += " AND secret_keys LIKE ?"
		args = append(args, "%\""+f.Credential+"\"%")
	}
	if f.Domain != "" {
		query += " AND domain = ?"
		args = append(args, f.Domain)
	}
	if f.Method != "" {
		query += " AND method = ?"
		args = append(args, f.Method)
	}
	if f.Status != 0 {
		query += " AND status_code = ?"
		args = append(args, f.Status)
	}
	if f.StatusClass != "" {
		switch f.StatusClass {
		case "2xx":
			query += " AND status_code >= 200 AND status_code < 300"
		case "3xx":
			query += " AND status_code >= 300 AND status_code < 400"
		case "4xx":
			query += " AND status_code >= 400 AND status_code < 500"
		case "5xx":
			query += " AND status_code >= 500 AND status_code < 600"
		case "error":
			query += " AND (status_code >= 400 OR status = 'BLOCKED')"
		}
	}
	if f.Failed {
		query += " AND (status_code >= 400 OR status = 'BLOCKED')"
	}
	if f.Blocked {
		query += " AND status = 'BLOCKED'"
	}
	if f.Redacted {
		query += " AND redacted = 1"
	}
	if f.ProjectID != "" {
		query += " AND project_id = ?"
		args = append(args, f.ProjectID)
	}
	if f.Environment != "" {
		query += " AND environment = ?"
		args = append(args, f.Environment)
	}
	if !f.Since.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, f.Since.UTC())
	}
	if !f.Until.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, f.Until.UTC())
	}

	query += " ORDER BY timestamp DESC"

	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
	} else {
		query += " LIMIT 50"
	}

	if f.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		// If table doesn't exist, just return empty
		if err.Error() == "no such table: audit_events" {
			return nil, nil
		}
		return nil, fmt.Errorf("local db query failed: %w", err)
	}
	defer rows.Close()

	var results []proxy.AuditEvent
	for rows.Next() {
		var ev proxy.AuditEvent
		var secretKeysJSON, authStylesJSON string
		var environment, agentID, identityLevel, method, targetURL, domain, status, reason, resolutionPath, callerRole, workspaceID, projectID, tokenID sql.NullString
		
		err := rows.Scan(
			&ev.ID,
			&ev.Timestamp,
			&environment,
			&agentID,
			&identityLevel,
			&method,
			&targetURL,
			&domain,
			&ev.StatusCode,
			&ev.DurationMs,
			&status,
			&reason,
			&ev.Redacted,
			&resolutionPath,
			&callerRole,
			&workspaceID,
			&projectID,
			&tokenID,
			&secretKeysJSON,
			&authStylesJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}

		if environment.Valid { ev.Environment = environment.String }
		if agentID.Valid { ev.AgentID = agentID.String }
		if identityLevel.Valid { ev.IdentityLevel = identityLevel.String }
		if method.Valid { ev.Method = method.String }
		if targetURL.Valid { ev.TargetURL = targetURL.String }
		if domain.Valid { ev.Domain = domain.String }
		if status.Valid { ev.Status = status.String }
		if reason.Valid { ev.Reason = reason.String }
		if resolutionPath.Valid { ev.ResolutionPath = resolutionPath.String }
		if callerRole.Valid { ev.CallerRole = callerRole.String }
		if workspaceID.Valid { ev.WorkspaceID = workspaceID.String }
		if projectID.Valid { ev.ProjectID = projectID.String }
		if tokenID.Valid { ev.TokenID = tokenID.String }

		_ = json.Unmarshal([]byte(secretKeysJSON), &ev.SecretKeys)
		if ev.SecretKeys == nil { ev.SecretKeys = []string{} }

		_ = json.Unmarshal([]byte(authStylesJSON), &ev.AuthStyles)
		if ev.AuthStyles == nil { ev.AuthStyles = []string{} }

		results = append(results, ev)
	}
	return results, nil
}

// GetLog returns a single log entry by ID.
func (s *Service) GetLog(id string) (*proxy.AuditEvent, error) {
	// Simple wrapper around QueryLocal assuming single DB for now,
	// unless cloud fallback is needed.
	_, err := s.QueryLocal(Filter{Limit: 1})
	if err != nil {
		return nil, err
	}
	// Note: above filter is wrong for exact ID, need custom DB query.
	query := "SELECT id, timestamp, COALESCE(environment, '') as environment, agent_id, identity_level, method, target_url, domain, status_code, duration_ms, status, reason, redacted, resolution_path, caller_role, workspace_id, project_id, token_id, secret_keys, auth_styles FROM audit_events WHERE id = ?"
	rows, err := s.db.Query(query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var ev proxy.AuditEvent
		var secretKeysJSON, authStylesJSON string
		var environment, agentID, identityLevel, method, targetURL, domain, status, reason, resolutionPath, callerRole, workspaceID, projectID, tokenID sql.NullString
		
		err := rows.Scan(
			&ev.ID,
			&ev.Timestamp,
			&environment,
			&agentID,
			&identityLevel,
			&method,
			&targetURL,
			&domain,
			&ev.StatusCode,
			&ev.DurationMs,
			&status,
			&reason,
			&ev.Redacted,
			&resolutionPath,
			&callerRole,
			&workspaceID,
			&projectID,
			&tokenID,
			&secretKeysJSON,
			&authStylesJSON,
		)
		if err != nil {
			return nil, err
		}

		if environment.Valid { ev.Environment = environment.String }
		if agentID.Valid { ev.AgentID = agentID.String }
		if identityLevel.Valid { ev.IdentityLevel = identityLevel.String }
		if method.Valid { ev.Method = method.String }
		if targetURL.Valid { ev.TargetURL = targetURL.String }
		if domain.Valid { ev.Domain = domain.String }
		if status.Valid { ev.Status = status.String }
		if reason.Valid { ev.Reason = reason.String }
		if resolutionPath.Valid { ev.ResolutionPath = resolutionPath.String }
		if callerRole.Valid { ev.CallerRole = callerRole.String }
		if workspaceID.Valid { ev.WorkspaceID = workspaceID.String }
		if projectID.Valid { ev.ProjectID = projectID.String }
		if tokenID.Valid { ev.TokenID = tokenID.String }

		_ = json.Unmarshal([]byte(secretKeysJSON), &ev.SecretKeys)
		_ = json.Unmarshal([]byte(authStylesJSON), &ev.AuthStyles)

		return &ev, nil
	}

	return nil, fmt.Errorf("log entry not found locally: %s", id)
}
