package main

import (
	"net/http"

	"github.com/google/uuid"
)

// ── GET /api/projects/ ──────────────────────────────────────────────────────

func handleListProjects(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)

	rows, err := db.Query(
		`SELECT p.id, p.name, p.description, p.workspace_id
		 FROM projects p
		 JOIN workspace_members wm ON wm.workspace_id = p.workspace_id
		 WHERE wm.user_id = $1 AND wm.status = 'active'
		 ORDER BY p.name`, userID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type proj struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		WorkspaceID string `json:"workspace_id"`
	}
	var projects []proj
	for rows.Next() {
		var p proj
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.WorkspaceID); err != nil {
			continue
		}
		projects = append(projects, p)
	}
	if projects == nil {
		projects = []proj{}
	}
	writeData(w, http.StatusOK, projects)
}

// ── POST /api/projects/ ─────────────────────────────────────────────────────

func handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		WorkspaceID string `json:"workspace_id"`
		Description string `json:"description"`
	}
	if err := decodeBody(r, &req); err != nil || req.Name == "" || req.WorkspaceID == "" {
		writeError(w, http.StatusBadRequest, "name and workspace_id are required")
		return
	}

	userID := getUserID(r)
	if !isWorkspaceMember(req.WorkspaceID, userID) {
		writeError(w, http.StatusForbidden, "not a member of this workspace")
		return
	}

	projectID := uuid.New().String()
	_, err := db.Exec(
		`INSERT INTO projects (id, name, description, workspace_id) VALUES ($1, $2, $3, $4)`,
		projectID, req.Name, req.Description, req.WorkspaceID,
	)
	if err != nil {
		writeError(w, http.StatusConflict, "project already exists in this workspace")
		return
	}

	auditLog(r, "project.create", "project:"+projectID, map[string]interface{}{
		"name": req.Name, "workspace_id": req.WorkspaceID,
	})
	writeData(w, http.StatusCreated, map[string]string{
		"id":           projectID,
		"name":         req.Name,
		"description":  req.Description,
		"workspace_id": req.WorkspaceID,
	})
}

// ── GET /api/projects/{workspace_id}/{project_name}/ ────────────────────────

func handleGetProject(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	projectName := r.PathValue("project_name")

	var id, description string
	err := db.QueryRow(
		`SELECT id, description FROM projects WHERE workspace_id=$1 AND name=$2`,
		wsID, projectName,
	).Scan(&id, &description)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}

	writeData(w, http.StatusOK, map[string]string{
		"id":           id,
		"name":         projectName,
		"description":  description,
		"workspace_id": wsID,
	})
}

// ── PATCH /api/projects/{workspace_id}/{project_name}/ ──────────────────────

func handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	projectName := r.PathValue("project_name")
	userID := getUserID(r)

	if !isWorkspaceMember(wsID, userID) {
		writeError(w, http.StatusForbidden, "not a member of this workspace")
		return
	}

	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Build update query dynamically.
	if req.Name != nil {
		_, err := db.Exec(
			`UPDATE projects SET name=$1 WHERE workspace_id=$2 AND name=$3`,
			*req.Name, wsID, projectName,
		)
		if err != nil {
			writeError(w, http.StatusConflict, "project name conflict")
			return
		}
		projectName = *req.Name
	}
	if req.Description != nil {
		_, _ = db.Exec(
			`UPDATE projects SET description=$1 WHERE workspace_id=$2 AND name=$3`,
			*req.Description, wsID, projectName,
		)
	}

	auditLog(r, "project.update", "workspace:"+wsID+"/project:"+projectName, nil)
	writeOK(w)
}

// ── DELETE /api/projects/{workspace_id}/{project_name}/ ─────────────────────

func handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	projectName := r.PathValue("project_name")
	userID := getUserID(r)

	if !isWorkspaceAdmin(wsID, userID) {
		writeError(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	result, err := db.Exec(
		`DELETE FROM projects WHERE workspace_id=$1 AND name=$2`, wsID, projectName,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete project")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}

	auditLog(r, "project.delete", "workspace:"+wsID+"/project:"+projectName, nil)
	writeOK(w)
}

// ── POST /api/projects/{workspace_id}/{project_name}/invite/ ────────────────

func handleProjectInvite(w http.ResponseWriter, r *http.Request) {
	wsID := r.PathValue("workspace_id")
	projectName := r.PathValue("project_name")
	userID := getUserID(r)

	if !isWorkspaceAdmin(wsID, userID) {
		writeError(w, http.StatusForbidden, "admin or owner role required")
		return
	}

	var req struct {
		Email                       string              `json:"email"`
		Role                        string              `json:"role"`
		EncryptedWorkspaceKeyInvitee string             `json:"encrypted_workspace_key_invitee"`
		EncryptedWorkspaceKeyOwner   string             `json:"encrypted_workspace_key_owner"`
		Secrets                      []map[string]string `json:"secrets"`
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

	// If they're not already a workspace member, add them.
	if !isWorkspaceMember(wsID, inviteeID) {
		memberID := uuid.New().String()
		ewk := req.EncryptedWorkspaceKeyInvitee
		_, _ = db.Exec(
			`INSERT INTO workspace_members (id, workspace_id, user_id, email, role, encrypted_workspace_key)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			memberID, wsID, inviteeID, req.Email, req.Role, ewk,
		)
	}

	// Get workspace name.
	var wsName string
	_ = db.QueryRow(`SELECT name FROM workspaces WHERE id=$1`, wsID).Scan(&wsName)

	auditLog(r, "project.invite", "workspace:"+wsID+"/project:"+projectName, map[string]interface{}{
		"email": req.Email, "role": req.Role,
	})

	writeData(w, http.StatusOK, map[string]interface{}{
		"workspace_id":   wsID,
		"workspace_name": wsName,
	})
}
