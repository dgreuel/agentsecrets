package main

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ── GET /api/secrets/{project_id}/ ──────────────────────────────────────────

func handleListSecrets(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	environment := r.URL.Query().Get("environment")
	if environment == "" {
		environment = "development"
	}

	rows, err := db.Query(
		`SELECT key, value, updated_at FROM secrets
		 WHERE project_id=$1 AND environment=$2 ORDER BY key`,
		projectID, environment,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type secretItem struct {
		Key       string `json:"key"`
		Value     string `json:"value"`
		UpdatedAt string `json:"updated_at"`
	}
	var secrets []secretItem
	for rows.Next() {
		var s secretItem
		var t time.Time
		if err := rows.Scan(&s.Key, &s.Value, &t); err != nil {
			continue
		}
		s.UpdatedAt = t.Format(time.RFC3339)
		secrets = append(secrets, s)
	}
	if secrets == nil {
		secrets = []secretItem{}
	}

	writeData(w, http.StatusOK, map[string]interface{}{
		"secrets": secrets,
	})
}

// ── POST /api/secrets/ ──────────────────────────────────────────────────────

func handleCreateSecrets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID   string            `json:"project_id"`
		Environment string            `json:"environment"`
		Secrets     map[string]string `json:"secrets"`
	}
	if err := decodeBody(r, &req); err != nil || req.ProjectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	if req.Environment == "" {
		req.Environment = "development"
	}

	now := time.Now()
	for key, value := range req.Secrets {
		id := uuid.New().String()
		_, err := db.Exec(
			`INSERT INTO secrets (id, project_id, environment, key, value, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $6)
			 ON CONFLICT (project_id, environment, key)
			 DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
			id, req.ProjectID, req.Environment, key, value, now,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to store secret: "+key)
			return
		}
	}

	auditLog(r, "secrets.create", "project:"+req.ProjectID, map[string]interface{}{
		"environment": req.Environment, "count": len(req.Secrets),
	})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

// ── GET /api/secrets/{project_id}/{environment}/{key}/ ──────────────────────

func handleGetSecret(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	environment := r.PathValue("environment")
	key := r.PathValue("key")

	var value string
	err := db.QueryRow(
		`SELECT value FROM secrets WHERE project_id=$1 AND environment=$2 AND key=$3`,
		projectID, environment, key,
	).Scan(&value)
	if err != nil {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}

	auditLog(r, "secrets.get", "project:"+projectID, map[string]interface{}{
		"environment": environment, "key": key,
	})
	writeData(w, http.StatusOK, map[string]string{"value": value})
}

// ── PUT /api/secrets/{project_id}/{environment}/{key}/ ──────────────────────

func handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	environment := r.PathValue("environment")
	key := r.PathValue("key")

	var req struct {
		Value string `json:"value"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := db.Exec(
		`UPDATE secrets SET value=$1, updated_at=$2 WHERE project_id=$3 AND environment=$4 AND key=$5`,
		req.Value, time.Now(), projectID, environment, key,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update secret")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}

	auditLog(r, "secrets.update", "project:"+projectID, map[string]interface{}{
		"environment": environment, "key": key,
	})
	writeOK(w)
}

// ── DELETE /api/secrets/{project_id}/{environment}/{key}/ ────────────────────

func handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	environment := r.PathValue("environment")
	key := r.PathValue("key")

	result, err := db.Exec(
		`DELETE FROM secrets WHERE project_id=$1 AND environment=$2 AND key=$3`,
		projectID, environment, key,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}

	auditLog(r, "secrets.delete", "project:"+projectID, map[string]interface{}{
		"environment": environment, "key": key,
	})
	writeOK(w)
}
