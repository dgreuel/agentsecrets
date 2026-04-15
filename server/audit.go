package main

import (
	"encoding/json"
	"net/http"
)

// ── GET /api/audit/logs/ ────────────────────────────────────────────────────

func handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)

	// Optional query filters.
	wsID := r.URL.Query().Get("workspace_id")
	action := r.URL.Query().Get("action")
	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "100"
	}

	query := `SELECT id, user_id, email, workspace_id, project_id, action, resource, details, ip_address, created_at
	          FROM audit_logs WHERE user_id=$1`
	args := []interface{}{userID}
	argIdx := 2

	if wsID != "" {
		query += ` AND workspace_id=$` + itoa(argIdx)
		args = append(args, wsID)
		argIdx++
	}
	if action != "" {
		query += ` AND action=$` + itoa(argIdx)
		args = append(args, action)
		argIdx++
	}
	query += ` ORDER BY created_at DESC LIMIT $` + itoa(argIdx)
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type logEntry struct {
		ID          string      `json:"id"`
		UserID      *string     `json:"user_id,omitempty"`
		Email       *string     `json:"email,omitempty"`
		WorkspaceID *string     `json:"workspace_id,omitempty"`
		ProjectID   *string     `json:"project_id,omitempty"`
		Action      string      `json:"action"`
		Resource    string      `json:"resource"`
		Details     interface{} `json:"details"`
		IPAddress   string      `json:"ip_address"`
		CreatedAt   string      `json:"created_at"`
	}

	var entries []logEntry
	for rows.Next() {
		var e logEntry
		var uid, em, wid, pid *string
		var details string
		var ct interface{}
		if err := rows.Scan(&e.ID, &uid, &em, &wid, &pid, &e.Action, &e.Resource, &details, &e.IPAddress, &ct); err != nil {
			continue
		}
		e.UserID = uid
		e.Email = em
		e.WorkspaceID = wid
		e.ProjectID = pid
		e.CreatedAt = formatTime(ct)

		var d interface{}
		if err := json.Unmarshal([]byte(details), &d); err == nil {
			e.Details = d
		} else {
			e.Details = details
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []logEntry{}
	}
	writeData(w, http.StatusOK, entries)
}

// ── GET /api/audit/logs/{log_id}/ ───────────────────────────────────────────

func handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	logID := r.PathValue("log_id")

	var id, action, resource, details, ipAddr string
	var uid, em, wid, pid *string
	var ct interface{}

	err := db.QueryRow(
		`SELECT id, user_id, email, workspace_id, project_id, action, resource, details, ip_address, created_at
		 FROM audit_logs WHERE id=$1`, logID,
	).Scan(&id, &uid, &em, &wid, &pid, &action, &resource, &details, &ipAddr, &ct)
	if err != nil {
		writeError(w, http.StatusNotFound, "log entry not found")
		return
	}

	entry := map[string]interface{}{
		"id":         id,
		"action":     action,
		"resource":   resource,
		"ip_address": ipAddr,
		"created_at": formatTime(ct),
	}
	if uid != nil {
		entry["user_id"] = *uid
	}
	if em != nil {
		entry["email"] = *em
	}
	if wid != nil {
		entry["workspace_id"] = *wid
	}
	if pid != nil {
		entry["project_id"] = *pid
	}
	var d interface{}
	if err := json.Unmarshal([]byte(details), &d); err == nil {
		entry["details"] = d
	}

	writeData(w, http.StatusOK, entry)
}

// ── GET /api/audit/summary/ ─────────────────────────────────────────────────

func handleAuditSummary(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)

	rows, err := db.Query(
		`SELECT action, COUNT(*) as count FROM audit_logs WHERE user_id=$1 GROUP BY action ORDER BY count DESC`,
		userID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type summaryItem struct {
		Action string `json:"action"`
		Count  int    `json:"count"`
	}
	var items []summaryItem
	for rows.Next() {
		var s summaryItem
		if err := rows.Scan(&s.Action, &s.Count); err != nil {
			continue
		}
		items = append(items, s)
	}
	if items == nil {
		items = []summaryItem{}
	}
	writeData(w, http.StatusOK, items)
}

// ── GET /api/audit/export/ ──────────────────────────────────────────────────

func handleAuditExport(w http.ResponseWriter, r *http.Request) {
	// Reuse the list handler with a high limit for export.
	r.URL.RawQuery = r.URL.RawQuery + "&limit=10000"
	handleListAuditLogs(w, r)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}
