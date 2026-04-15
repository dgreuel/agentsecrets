package main

import (
	"net/http"

	"github.com/google/uuid"
)

// ── POST /api/workspaces/ ───────────────────────────────────────────────────

func handleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                  string `json:"name"`
		EncryptedWorkspaceKey string `json:"encrypted_workspace_key"`
	}
	if err := decodeBody(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	userID := getUserID(r)
	email := getUserEmail(r)
	wsID := uuid.New().String()
	memberID := uuid.New().String()

	tx, err := db.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO workspaces (id, name, type, created_by) VALUES ($1, $2, 'shared', $3)`,
		wsID, req.Name, userID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create workspace")
		return
	}

	// Creator becomes owner.
	_, err = tx.Exec(
		`INSERT INTO workspace_members (id, workspace_id, user_id, email, role, encrypted_workspace_key)
		 VALUES ($1, $2, $3, $4, 'owner', $5)`,
		memberID, wsID, userID, email, req.EncryptedWorkspaceKey,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to add owner membership")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "transaction failed")
		return
	}

	auditLog(r, "workspace.create", "workspace:"+wsID, map[string]interface{}{"name": req.Name})
	writeData(w, http.StatusCreated, map[string]interface{}{
		"id":   wsID,
		"type": "shared",
		"role": "owner",
	})
}

// ── GET /api/workspaces/ ────────────────────────────────────────────────────

func handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	rows, err := db.Query(
		`SELECT w.id, w.name, w.type, wm.role, wm.encrypted_workspace_key
		 FROM workspace_members wm
		 JOIN workspaces w ON w.id = wm.workspace_id
		 WHERE wm.user_id = $1 AND wm.status = 'active'`, userID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type wsItem struct {
		ID                    string `json:"id"`
		Name                  string `json:"name"`
		Type                  string `json:"type"`
		Role                  string `json:"role"`
		EncryptedWorkspaceKey string `json:"encrypted_workspace_key"`
	}
	var items []wsItem
	for rows.Next() {
		var ws wsItem
		if err := rows.Scan(&ws.ID, &ws.Name, &ws.Type, &ws.Role, &ws.EncryptedWorkspaceKey); err != nil {
			continue
		}
		items = append(items, ws)
	}
	if items == nil {
		items = []wsItem{}
	}
	writeData(w, http.StatusOK, items)
}

// ── GET /api/workspaces/{workspace_id}/ ─────────────────────────────────────

func handleGetWorkspace(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	userID := getUserID(r)

	var name, wsType, role string
	err := db.QueryRow(
		`SELECT w.name, w.type, wm.role
		 FROM workspaces w
		 JOIN workspace_members wm ON wm.workspace_id = w.id
		 WHERE w.id = $1 AND wm.user_id = $2 AND wm.status = 'active'`,
		wsID, userID,
	).Scan(&name, &wsType, &role)
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	writeData(w, http.StatusOK, map[string]string{
		"id":   wsID,
		"name": name,
		"type": wsType,
		"role": role,
	})
}

// ── PUT /api/workspaces/{workspace_id}/ ─────────────────────────────────────

func handleUpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	userID := getUserID(r)

	if !isWorkspaceAdmin(wsID, userID) {
		writeError(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := decodeBody(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	_, err := db.Exec(`UPDATE workspaces SET name=$1 WHERE id=$2`, req.Name, wsID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update workspace")
		return
	}

	auditLog(r, "workspace.update", "workspace:"+wsID, map[string]interface{}{"name": req.Name})
	writeOK(w)
}

// ── DELETE /api/workspaces/{workspace_id}/ ──────────────────────────────────

func handleDeleteWorkspace(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	userID := getUserID(r)

	if !isWorkspaceOwner(wsID, userID) {
		writeError(w, http.StatusForbidden, "owner role required")
		return
	}

	_, err := db.Exec(`DELETE FROM workspaces WHERE id=$1`, wsID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete workspace")
		return
	}

	auditLog(r, "workspace.delete", "workspace:"+wsID, nil)
	writeOK(w)
}

// ── GET /api/workspaces/{workspace_id}/members/ ─────────────────────────────

func handleListMembers(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")

	rows, err := db.Query(
		`SELECT id, user_id, email, role, status FROM workspace_members WHERE workspace_id=$1`, wsID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type member struct {
		ID     string `json:"id"`
		UserID string `json:"user_id"`
		Email  string `json:"email"`
		Role   string `json:"role"`
		Status string `json:"status"`
	}
	var members []member
	for rows.Next() {
		var m member
		if err := rows.Scan(&m.ID, &m.UserID, &m.Email, &m.Role, &m.Status); err != nil {
			continue
		}
		members = append(members, m)
	}
	if members == nil {
		members = []member{}
	}
	writeData(w, http.StatusOK, members)
}

// ── POST /api/workspaces/{workspace_id}/members/ (invite) ───────────────────

func handleInviteMember(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	userID := getUserID(r)

	if !isWorkspaceAdmin(wsID, userID) {
		writeError(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	var req struct {
		Email                 string `json:"email"`
		Role                  string `json:"role"`
		EncryptedWorkspaceKey string `json:"encrypted_workspace_key"`
	}
	if err := decodeBody(r, &req); err != nil || req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}

	// Find the invitee user.
	var inviteeID string
	err := db.QueryRow(`SELECT id FROM users WHERE email=$1`, req.Email).Scan(&inviteeID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	// Check if already a member.
	var exists bool
	db.QueryRow(`SELECT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=$1 AND user_id=$2)`, wsID, inviteeID).Scan(&exists)
	if exists {
		writeError(w, http.StatusConflict, "user is already a member")
		return
	}

	memberID := uuid.New().String()
	_, err = db.Exec(
		`INSERT INTO workspace_members (id, workspace_id, user_id, email, role, encrypted_workspace_key)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		memberID, wsID, inviteeID, req.Email, req.Role, req.EncryptedWorkspaceKey,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to add member")
		return
	}

	auditLog(r, "workspace.invite", "workspace:"+wsID, map[string]interface{}{"email": req.Email, "role": req.Role})
	writeData(w, http.StatusCreated, map[string]string{"status": "invited"})
}

// ── DELETE /api/workspaces/{workspace_id}/members/{user_id}/ ────────────────

func handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	targetUserID := r.PathValue("user_id")
	currentUserID := getUserID(r)

	if !isWorkspaceAdmin(wsID, currentUserID) {
		writeError(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	_, err := db.Exec(
		`DELETE FROM workspace_members WHERE workspace_id=$1 AND user_id=$2`, wsID, targetUserID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove member")
		return
	}

	auditLog(r, "workspace.remove_member", "workspace:"+wsID, map[string]interface{}{"removed_user_id": targetUserID})
	writeOK(w)
}

// ── POST /api/workspaces/{workspace_id}/members/{user_id}/role/ ─────────────

func handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	targetUserID := r.PathValue("user_id")
	currentUserID := getUserID(r)

	if !isWorkspaceOwner(wsID, currentUserID) {
		writeError(w, http.StatusForbidden, "owner role required")
		return
	}

	var req struct {
		Action string `json:"action"`
	}
	if err := decodeBody(r, &req); err != nil || req.Action == "" {
		writeError(w, http.StatusBadRequest, "action is required")
		return
	}

	newRole := "member"
	if req.Action == "promote" {
		newRole = "admin"
	}

	_, err := db.Exec(
		`UPDATE workspace_members SET role=$1 WHERE workspace_id=$2 AND user_id=$3`,
		newRole, wsID, targetUserID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update role")
		return
	}

	auditLog(r, "workspace.role_update", "workspace:"+wsID, map[string]interface{}{
		"target_user_id": targetUserID, "action": req.Action, "new_role": newRole,
	})
	writeOK(w)
}

// ── GET /api/workspaces/{workspace_id}/allowlist/ ───────────────────────────

func handleListAllowlist(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	rows, err := db.Query(
		`SELECT domain, added_by_email, created_at FROM allowlist_domains WHERE workspace_id=$1 ORDER BY created_at`, wsID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type entry struct {
		Domain       string `json:"domain"`
		AddedByEmail string `json:"added_by_email"`
		CreatedAt    string `json:"created_at"`
	}
	var entries []entry
	for rows.Next() {
		var e entry
		var t interface{}
		if err := rows.Scan(&e.Domain, &e.AddedByEmail, &t); err != nil {
			continue
		}
		e.CreatedAt = formatTime(t)
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []entry{}
	}
	writeData(w, http.StatusOK, entries)
}

// ── POST /api/workspaces/{workspace_id}/allowlist/ ──────────────────────────

func handleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	userID := getUserID(r)
	email := getUserEmail(r)

	if !isWorkspaceAdmin(wsID, userID) {
		writeError(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	var req struct {
		Domains []string `json:"domains"`
	}
	if err := decodeBody(r, &req); err != nil || len(req.Domains) == 0 {
		writeError(w, http.StatusBadRequest, "domains list is required")
		return
	}

	for _, domain := range req.Domains {
		id := uuid.New().String()
		_, err := db.Exec(
			`INSERT INTO allowlist_domains (id, workspace_id, domain, added_by_email)
			 VALUES ($1, $2, $3, $4) ON CONFLICT (workspace_id, domain) DO NOTHING`,
			id, wsID, domain, email,
		)
		if err != nil {
			continue
		}
		// Log entry.
		logID := uuid.New().String()
		_, _ = db.Exec(
			`INSERT INTO allowlist_log (id, workspace_id, performed_by_email, action, domain)
			 VALUES ($1, $2, $3, 'ADDED', $4)`,
			logID, wsID, email, domain,
		)
	}

	auditLog(r, "allowlist.add", "workspace:"+wsID, map[string]interface{}{"domains": req.Domains})
	writeData(w, http.StatusCreated, map[string]string{"status": "added"})
}

// ── DELETE /api/workspaces/{workspace_id}/allowlist/{domain}/ ────────────────

func handleRemoveAllowlist(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	domain := r.PathValue("domain")
	userID := getUserID(r)
	email := getUserEmail(r)

	if !isWorkspaceAdmin(wsID, userID) {
		writeError(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	_, err := db.Exec(
		`DELETE FROM allowlist_domains WHERE workspace_id=$1 AND domain=$2`, wsID, domain,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove domain")
		return
	}

	// Log entry.
	logID := uuid.New().String()
	_, _ = db.Exec(
		`INSERT INTO allowlist_log (id, workspace_id, performed_by_email, action, domain)
		 VALUES ($1, $2, $3, 'REMOVED', $4)`,
		logID, wsID, email, domain,
	)

	auditLog(r, "allowlist.remove", "workspace:"+wsID, map[string]interface{}{"domain": domain})
	writeOK(w)
}

// ── GET /api/workspaces/{workspace_id}/allowlist/log/ ───────────────────────

func handleAllowlistLog(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	rows, err := db.Query(
		`SELECT performed_at, performed_by_email, action, domain
		 FROM allowlist_log WHERE workspace_id=$1 ORDER BY performed_at DESC`, wsID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type logEntry struct {
		PerformedAt      string `json:"performed_at"`
		PerformedByEmail string `json:"performed_by_email"`
		Action           string `json:"action"`
		Domain           string `json:"domain"`
	}
	var entries []logEntry
	for rows.Next() {
		var e logEntry
		var t interface{}
		if err := rows.Scan(&t, &e.PerformedByEmail, &e.Action, &e.Domain); err != nil {
			continue
		}
		e.PerformedAt = formatTime(t)
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []logEntry{}
	}
	writeData(w, http.StatusOK, entries)
}

// ── Authorization helpers ───────────────────────────────────────────────────

func isWorkspaceAdmin(wsID, userID string) bool {
	var role string
	err := db.QueryRow(
		`SELECT role FROM workspace_members WHERE workspace_id=$1 AND user_id=$2 AND status='active'`,
		wsID, userID,
	).Scan(&role)
	return err == nil && (role == "admin" || role == "owner")
}

func isWorkspaceOwner(wsID, userID string) bool {
	var role string
	err := db.QueryRow(
		`SELECT role FROM workspace_members WHERE workspace_id=$1 AND user_id=$2 AND status='active'`,
		wsID, userID,
	).Scan(&role)
	return err == nil && role == "owner"
}

func isWorkspaceMember(wsID, userID string) bool {
	var exists bool
	db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=$1 AND user_id=$2 AND status='active')`,
		wsID, userID,
	).Scan(&exists)
	return exists
}
