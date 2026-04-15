package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ── POST /api/workspaces/{workspace_id}/agents/ ─────────────────────────────
// ── POST /api/workspaces/{workspace_id}/projects/{project_id}/agents/ ───────

func handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	projectID := r.PathValue("project_id") // empty for workspace-level

	var req struct {
		Name        string `json:"name"`
		ProjectID   string `json:"project_id"`
		Environment string `json:"environment"`
		Label       string `json:"label"`
		ExpiresIn   string `json:"expires_in"`
	}
	if err := decodeBody(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Use URL project_id if present, else body field.
	if projectID == "" {
		projectID = req.ProjectID
	}

	agentID := uuid.New().String()
	_, err := db.Exec(
		`INSERT INTO agents (id, workspace_id, project_id, name) VALUES ($1, $2, $3, $4)`,
		agentID, wsID, nullIfEmpty(projectID), req.Name,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	// Generate the first token automatically.
	tokenPlain := generateAgentToken()
	tokenHash := hashToken(tokenPlain)
	tokenID := uuid.New().String()

	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		dur := parseDuration(req.ExpiresIn)
		if dur > 0 {
			t := time.Now().Add(dur)
			expiresAt = &t
		}
	}

	_, err = db.Exec(
		`INSERT INTO agent_tokens (id, agent_id, token_hash, label, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		tokenID, agentID, tokenHash, req.Label, expiresAt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create agent token")
		return
	}

	agentResp := map[string]interface{}{
		"id":           agentID,
		"name":         req.Name,
		"workspace_id": wsID,
		"created_at":   time.Now().Format(time.RFC3339),
		"token_count":  1,
	}
	if projectID != "" {
		agentResp["project_id"] = projectID
	}

	resp := map[string]interface{}{
		"agent": agentResp,
		"token": tokenPlain,
	}
	if req.Label != "" {
		resp["label"] = req.Label
	}
	if expiresAt != nil {
		resp["expires_at"] = expiresAt.Format(time.RFC3339)
	}

	auditLog(r, "agent.register", "workspace:"+wsID, map[string]interface{}{"name": req.Name, "agent_id": agentID})
	writeData(w, http.StatusOK, resp)
}

// ── GET /api/workspaces/{workspace_id}/agents/ ──────────────────────────────
// ── GET /api/workspaces/{workspace_id}/projects/{project_id}/agents/ ────────

func handleListAgents(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	projectID := r.PathValue("project_id")

	var rows_ interface{ Close() error }
	type agentItem struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		WorkspaceID string  `json:"workspace_id"`
		ProjectID   *string `json:"project_id,omitempty"`
		CreatedAt   string  `json:"created_at"`
		TokenCount  int     `json:"token_count"`
		LastUsed    *string `json:"last_used,omitempty"`
	}

	var agents []agentItem
	var err error

	if projectID != "" {
		rows, qErr := db.Query(
			`SELECT a.id, a.name, a.workspace_id, a.project_id, a.created_at, a.last_used,
			        (SELECT COUNT(*) FROM agent_tokens WHERE agent_id=a.id) as token_count
			 FROM agents a WHERE a.workspace_id=$1 AND a.project_id=$2 ORDER BY a.created_at`, wsID, projectID,
		)
		err = qErr
		if err == nil {
			rows_ = rows
			for rows.Next() {
				var a agentItem
				var ct, lu interface{}
				var pid *string
				if err := rows.Scan(&a.ID, &a.Name, &a.WorkspaceID, &pid, &ct, &lu, &a.TokenCount); err != nil {
					continue
				}
				a.ProjectID = pid
				a.CreatedAt = formatTime(ct)
				if lu != nil {
					s := formatTime(lu)
					a.LastUsed = &s
				}
				agents = append(agents, a)
			}
		}
	} else {
		rows, qErr := db.Query(
			`SELECT a.id, a.name, a.workspace_id, a.project_id, a.created_at, a.last_used,
			        (SELECT COUNT(*) FROM agent_tokens WHERE agent_id=a.id) as token_count
			 FROM agents a WHERE a.workspace_id=$1 ORDER BY a.created_at`, wsID,
		)
		err = qErr
		if err == nil {
			rows_ = rows
			for rows.Next() {
				var a agentItem
				var ct, lu interface{}
				var pid *string
				if err := rows.Scan(&a.ID, &a.Name, &a.WorkspaceID, &pid, &ct, &lu, &a.TokenCount); err != nil {
					continue
				}
				a.ProjectID = pid
				a.CreatedAt = formatTime(ct)
				if lu != nil {
					s := formatTime(lu)
					a.LastUsed = &s
				}
				agents = append(agents, a)
			}
		}
	}
	if rows_ != nil {
		rows_.Close()
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if agents == nil {
		agents = []agentItem{}
	}
	writeData(w, http.StatusOK, agents)
}

// ── DELETE /api/workspaces/{workspace_id}/agents/{registration_id}/ ─────────

func handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	agentID := r.PathValue("registration_id")

	result, err := db.Exec(
		`DELETE FROM agents WHERE id=$1 AND workspace_id=$2`, agentID, wsID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete agent")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	auditLog(r, "agent.delete", "workspace:"+wsID, map[string]interface{}{"agent_id": agentID})
	writeOK(w)
}

// ── POST /api/workspaces/{workspace_id}/agents/{registration_id}/tokens/ ────

func handleIssueAgentToken(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("registration_id")

	var req struct {
		Environment string `json:"environment"`
		Label       string `json:"label"`
		ExpiresIn   string `json:"expires_in"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	tokenPlain := generateAgentToken()
	tokenHash := hashToken(tokenPlain)
	tokenID := uuid.New().String()

	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		dur := parseDuration(req.ExpiresIn)
		if dur > 0 {
			t := time.Now().Add(dur)
			expiresAt = &t
		}
	}

	_, err := db.Exec(
		`INSERT INTO agent_tokens (id, agent_id, token_hash, label, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		tokenID, agentID, tokenHash, req.Label, expiresAt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	resp := map[string]interface{}{
		"token_id": tokenID,
		"token":    tokenPlain,
	}
	if req.Label != "" {
		resp["label"] = req.Label
	}
	if expiresAt != nil {
		resp["expires_at"] = expiresAt.Format(time.RFC3339)
	}

	auditLog(r, "agent.token_issue", "agent:"+agentID, nil)
	writeData(w, http.StatusOK, resp)
}

// ── GET /api/workspaces/{workspace_id}/agents/{registration_id}/tokens/ ─────

func handleListAgentTokens(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("registration_id")

	rows, err := db.Query(
		`SELECT id, agent_id, label, created_at, expires_at, last_used, status
		 FROM agent_tokens WHERE agent_id=$1 ORDER BY created_at`, agentID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type tokenItem struct {
		ID        string  `json:"id"`
		AgentID   string  `json:"agent_id"`
		Label     string  `json:"label"`
		CreatedAt string  `json:"created_at"`
		ExpiresAt *string `json:"expires_at,omitempty"`
		LastUsed  *string `json:"last_used,omitempty"`
		Status    string  `json:"status"`
	}

	var tokens []tokenItem
	for rows.Next() {
		var t tokenItem
		var ct, ea, lu interface{}
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Label, &ct, &ea, &lu, &t.Status); err != nil {
			continue
		}
		t.CreatedAt = formatTime(ct)
		if ea != nil {
			s := formatTime(ea)
			t.ExpiresAt = &s
		}
		if lu != nil {
			s := formatTime(lu)
			t.LastUsed = &s
		}
		tokens = append(tokens, t)
	}
	if tokens == nil {
		tokens = []tokenItem{}
	}
	writeData(w, http.StatusOK, tokens)
}

// ── DELETE /api/workspaces/{workspace_id}/agents/{registration_id}/tokens/{token_id}/ ──

func handleRevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	tokenID := r.PathValue("token_id")

	_, err := db.Exec(`UPDATE agent_tokens SET status='revoked' WHERE id=$1`, tokenID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}

	auditLog(r, "agent.token_revoke", "token:"+tokenID, nil)
	writeOK(w)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func generateAgentToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "as_" + hex.EncodeToString(b)
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func parseDuration(s string) time.Duration {
	// Parse simple duration strings like "30d", "7d", "24h".
	if len(s) < 2 {
		return 0
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	var num int
	for _, c := range numStr {
		if c < '0' || c > '9' {
			return 0
		}
		num = num*10 + int(c-'0')
	}
	switch unit {
	case 'd':
		return time.Duration(num) * 24 * time.Hour
	case 'h':
		return time.Duration(num) * time.Hour
	case 'm':
		return time.Duration(num) * time.Minute
	default:
		return 0
	}
}
