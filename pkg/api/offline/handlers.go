package offline

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// handlers maps endpoint keys (matching pkg/api.endpointMap) to in-process
// implementations. Keys absent from this map fall through to a generic
// 404-style "unknown endpoint" response in Backend.Call.
var handlers = map[string]handler{
	// --- Auth ---------------------------------------------------------------
	// The auth.Service shortcuts SRP entirely in offline mode (see
	// pkg/auth/offline.go), so these are defensive fallbacks.
	"auth.signup":       notAvailable("offline signup goes through auth.Service.Signup directly"),
	"auth.login_init":   notAvailable("offline login goes through auth.Service.PerformLogin directly"),
	"auth.login_verify": notAvailable("offline login goes through auth.Service.PerformLogin directly"),
	"auth.refresh":      offlineRefresh,
	"auth.logout":       offlineLogout,

	// --- Secrets ------------------------------------------------------------
	"secrets.list":   listSecrets,
	"secrets.create": createSecrets,
	"secrets.get":    getSecret,
	"secrets.update": updateSecret,
	"secrets.delete": deleteSecret,

	// --- Projects -----------------------------------------------------------
	"projects.list":   listProjects,
	"projects.create": createProject,
	"projects.get":    getProject,
	"projects.update": updateProject,
	"projects.delete": deleteProject,
	"projects.invite": notAvailable("project invites"),

	// --- Workspaces ---------------------------------------------------------
	"workspaces.list":             listWorkspaces,
	"workspaces.create":           createWorkspace,
	"workspaces.get":              notAvailable("workspace lookup"),
	"workspaces.update":           notAvailable("workspace updates"),
	"workspaces.delete":           notAvailable("workspace deletion"),
	"workspaces.members":          notAvailable("workspace members"),
	"workspaces.invite":           notAvailable("workspace invites"),
	"workspaces.remove_member":    notAvailable("workspace member removal"),
	"workspaces.role_update":      notAvailable("workspace role updates"),
	"workspaces.allowlist_list":   listAllowlist,
	"workspaces.allowlist_add":    addAllowlist,
	"workspaces.allowlist_remove": removeAllowlist,
	"workspaces.allowlist_log":    logAllowlist,

	// --- Agents (multi-user / token issuance) -------------------------------
	"agents.list":             notAvailable("agent registry"),
	"agents.register":         notAvailable("agent registration"),
	"agents.list_project":     notAvailable("agent registry"),
	"agents.register_project": notAvailable("agent registration"),
	"agents.delete":           notAvailable("agent deletion"),
	"agents.token_issue":      notAvailable("agent tokens"),
	"agents.token_list":       notAvailable("agent tokens"),
	"agents.token_revoke":     notAvailable("agent tokens"),

	// --- Cloud audit log (server-side ledger) -------------------------------
	// `agentsecrets log` still works for the local proxy SQLite log because
	// the log.Service queries that database directly without going through
	// the Backend. These handlers cover the cloud-only summary/export paths.
	"log.list":    notAvailable("cloud audit log"),
	"log.detail":  notAvailable("cloud audit log"),
	"log.summary": notAvailable("cloud audit log"),
	"log.export":  notAvailable("cloud audit log"),

	// --- Users --------------------------------------------------------------
	"users.public_key": notAvailable("user directory lookup"),
}

// ─── Auth ────────────────────────────────────────────────────────────────────

func offlineRefresh(_ *Backend, _ string, _ interface{}, _, _ map[string]string) (*http.Response, error) {
	// Tokens are synthetic in offline mode; emit a fresh one so callers that
	// auto-refresh stay happy.
	return jsonResponse(http.StatusOK, map[string]interface{}{
		"data": map[string]string{
			"access":     "offline-session",
			"refresh":    "offline-session",
			"expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		},
	})
}

func offlineLogout(_ *Backend, _ string, _ interface{}, _, _ map[string]string) (*http.Response, error) {
	return jsonResponse(http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Secrets ─────────────────────────────────────────────────────────────────

type secretRow struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

func listSecrets(b *Backend, _ string, _ interface{}, urlParams, queryParams map[string]string) (*http.Response, error) {
	projectID := urlParams["project_id"]
	env := queryParams["environment"]
	if env == "" {
		env = "development"
	}

	rows, err := b.db.Query(
		`SELECT key, value, updated_at FROM secrets WHERE project_id = ? AND environment = ? ORDER BY key`,
		projectID, env,
	)
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	defer rows.Close()

	out := []secretRow{}
	for rows.Next() {
		var r secretRow
		if err := rows.Scan(&r.Key, &r.Value, &r.UpdatedAt); err != nil {
			return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
		}
		out = append(out, r)
	}
	return jsonResponse(http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{"secrets": out},
	})
}

func createSecrets(b *Backend, _ string, data interface{}, _, _ map[string]string) (*http.Response, error) {
	body, err := decodeData(data)
	if err != nil {
		return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
	}

	projectID := asString(body, "project_id")
	env := asString(body, "environment")
	if projectID == "" || env == "" {
		return jsonResponse(http.StatusBadRequest, errorBody("project_id and environment are required"))
	}

	// The cloud accepts both a flat map ({key: value, ...}) and a list of
	// {key, value} objects (used by the workspace migration flow). Handle both.
	secretsField, ok := body["secrets"]
	if !ok {
		return jsonResponse(http.StatusBadRequest, errorBody("missing secrets payload"))
	}

	tx, err := b.db.Begin()
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}

	upsert := `
		INSERT INTO secrets (project_id, environment, key, value, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(project_id, environment, key) DO UPDATE SET
			value = excluded.value,
			updated_at = CURRENT_TIMESTAMP`

	switch v := secretsField.(type) {
	case map[string]interface{}:
		for k, val := range v {
			s, _ := val.(string)
			if _, err := tx.Exec(upsert, projectID, env, k, s); err != nil {
				_ = tx.Rollback()
				return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
			}
		}
	case []interface{}:
		for _, item := range v {
			m, _ := item.(map[string]interface{})
			if _, err := tx.Exec(upsert, projectID, env, asString(m, "key"), asString(m, "value")); err != nil {
				_ = tx.Rollback()
				return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
			}
		}
	default:
		_ = tx.Rollback()
		return jsonResponse(http.StatusBadRequest, errorBody("secrets payload must be an object or array"))
	}

	if err := tx.Commit(); err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusCreated, map[string]string{"status": "ok"})
}

func getSecret(b *Backend, _ string, _ interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	var value, updatedAt string
	err := b.db.QueryRow(
		`SELECT value, updated_at FROM secrets WHERE project_id = ? AND environment = ? AND key = ?`,
		urlParams["project_id"], urlParams["environment"], urlParams["key"],
	).Scan(&value, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return jsonResponse(http.StatusNotFound, errorBody("secret not found"))
	}
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusOK, map[string]interface{}{
		"data": map[string]string{"value": value, "updated_at": updatedAt},
	})
}

func updateSecret(b *Backend, _ string, data interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	body, err := decodeData(data)
	if err != nil {
		return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
	}
	value := asString(body, "value")
	if _, err := b.db.Exec(
		`INSERT INTO secrets (project_id, environment, key, value, updated_at)
		 VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(project_id, environment, key) DO UPDATE SET
		   value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
		urlParams["project_id"], urlParams["environment"], urlParams["key"], value,
	); err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusOK, map[string]string{"status": "ok"})
}

func deleteSecret(b *Backend, _ string, _ interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	if _, err := b.db.Exec(
		`DELETE FROM secrets WHERE project_id = ? AND environment = ? AND key = ?`,
		urlParams["project_id"], urlParams["environment"], urlParams["key"],
	); err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Projects ────────────────────────────────────────────────────────────────

type projectRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	WorkspaceID string `json:"workspace_id"`
}

func listProjects(b *Backend, _ string, _ interface{}, _, _ map[string]string) (*http.Response, error) {
	rows, err := b.db.Query(`SELECT id, name, COALESCE(description, ''), workspace_id FROM projects ORDER BY name`)
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	defer rows.Close()

	out := []projectRow{}
	for rows.Next() {
		var p projectRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.WorkspaceID); err != nil {
			return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
		}
		out = append(out, p)
	}
	return jsonResponse(http.StatusOK, map[string]interface{}{"data": out})
}

func createProject(b *Backend, _ string, data interface{}, _, _ map[string]string) (*http.Response, error) {
	body, err := decodeData(data)
	if err != nil {
		return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
	}
	name := asString(body, "name")
	wsID := asString(body, "workspace_id")
	desc := asString(body, "description")
	if name == "" || wsID == "" {
		return jsonResponse(http.StatusBadRequest, errorBody("name and workspace_id are required"))
	}

	id := uuid.New().String()
	if _, err := b.db.Exec(
		`INSERT INTO projects (id, workspace_id, name, description) VALUES (?, ?, ?, ?)`,
		id, wsID, name, desc,
	); err != nil {
		return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusCreated, map[string]interface{}{
		"data": projectRow{ID: id, Name: name, Description: desc, WorkspaceID: wsID},
	})
}

func getProject(b *Backend, _ string, _ interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	var p projectRow
	err := b.db.QueryRow(
		`SELECT id, name, COALESCE(description, ''), workspace_id FROM projects WHERE workspace_id = ? AND name = ?`,
		urlParams["workspace_id"], urlParams["project_name"],
	).Scan(&p.ID, &p.Name, &p.Description, &p.WorkspaceID)
	if errors.Is(err, sql.ErrNoRows) {
		return jsonResponse(http.StatusNotFound, errorBody("project not found"))
	}
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusOK, map[string]interface{}{"data": p})
}

func updateProject(b *Backend, _ string, data interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	body, err := decodeData(data)
	if err != nil {
		return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
	}
	wsID := urlParams["workspace_id"]
	oldName := urlParams["project_name"]

	if newName := asString(body, "name"); newName != "" {
		if _, err := b.db.Exec(
			`UPDATE projects SET name = ? WHERE workspace_id = ? AND name = ?`,
			newName, wsID, oldName,
		); err != nil {
			return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
		}
		oldName = newName
	}
	if desc := asString(body, "description"); desc != "" {
		if _, err := b.db.Exec(
			`UPDATE projects SET description = ? WHERE workspace_id = ? AND name = ?`,
			desc, wsID, oldName,
		); err != nil {
			return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
		}
	}
	return jsonResponse(http.StatusOK, map[string]string{"status": "ok"})
}

func deleteProject(b *Backend, _ string, _ interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	wsID := urlParams["workspace_id"]
	name := urlParams["project_name"]

	tx, err := b.db.Begin()
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	row := tx.QueryRow(`SELECT id FROM projects WHERE workspace_id = ? AND name = ?`, wsID, name)
	var id string
	if err := row.Scan(&id); err != nil {
		_ = tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return jsonResponse(http.StatusNotFound, errorBody("project not found"))
		}
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	if _, err := tx.Exec(`DELETE FROM secrets WHERE project_id = ?`, id); err != nil {
		_ = tx.Rollback()
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	if _, err := tx.Exec(`DELETE FROM projects WHERE id = ?`, id); err != nil {
		_ = tx.Rollback()
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	if err := tx.Commit(); err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Workspaces ──────────────────────────────────────────────────────────────

type workspaceRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Role string `json:"role"`
}

func listWorkspaces(b *Backend, _ string, _ interface{}, _, _ map[string]string) (*http.Response, error) {
	rows, err := b.db.Query(`
		SELECT w.id, w.name, w.type, COALESCE(m.role, 'owner')
		FROM workspaces w
		LEFT JOIN workspace_members m ON m.workspace_id = w.id
		ORDER BY w.created_at`)
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	defer rows.Close()

	out := []workspaceRow{}
	for rows.Next() {
		var w workspaceRow
		if err := rows.Scan(&w.ID, &w.Name, &w.Type, &w.Role); err != nil {
			return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
		}
		out = append(out, w)
	}
	return jsonResponse(http.StatusOK, map[string]interface{}{"data": out})
}

func createWorkspace(b *Backend, _ string, data interface{}, _, _ map[string]string) (*http.Response, error) {
	body, err := decodeData(data)
	if err != nil {
		return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
	}
	name := asString(body, "name")
	if name == "" {
		return jsonResponse(http.StatusBadRequest, errorBody("name is required"))
	}

	// Single-user offline mode pins ownership to the local user, looked up by
	// the unique email in the users table.
	var ownerID, ownerEmail string
	if err := b.db.QueryRow(`SELECT id, email FROM users LIMIT 1`).Scan(&ownerID, &ownerEmail); err != nil {
		return jsonResponse(http.StatusBadRequest, errorBody("no local user — run `agentsecrets init` first"))
	}
	_ = ownerEmail

	id := uuid.New().String()
	tx, err := b.db.Begin()
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	if _, err := tx.Exec(
		`INSERT INTO workspaces (id, name, type, owner_id) VALUES (?, ?, 'shared', ?)`,
		id, name, ownerID,
	); err != nil {
		_ = tx.Rollback()
		return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
	}
	encKey := asString(body, "encrypted_workspace_key")
	if _, err := tx.Exec(
		`INSERT INTO workspace_members (workspace_id, user_id, role, encrypted_workspace_key)
		 VALUES (?, ?, 'owner', ?)`,
		id, ownerID, encKey,
	); err != nil {
		_ = tx.Rollback()
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	if err := tx.Commit(); err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}

	return jsonResponse(http.StatusCreated, map[string]interface{}{
		"data": workspaceRow{ID: id, Name: name, Type: "shared", Role: "owner"},
	})
}

// ─── Allowlist ───────────────────────────────────────────────────────────────

type allowlistRow struct {
	Domain    string `json:"domain"`
	AddedBy   string `json:"added_by_email"`
	CreatedAt string `json:"created_at"`
}

func listAllowlist(b *Backend, _ string, _ interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	rows, err := b.db.Query(
		`SELECT domain, COALESCE(added_by_email, ''), created_at FROM allowlist_domains WHERE workspace_id = ? ORDER BY domain`,
		urlParams["workspace_id"],
	)
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	defer rows.Close()
	out := []allowlistRow{}
	for rows.Next() {
		var r allowlistRow
		if err := rows.Scan(&r.Domain, &r.AddedBy, &r.CreatedAt); err != nil {
			return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
		}
		out = append(out, r)
	}
	return jsonResponse(http.StatusOK, map[string]interface{}{"data": out})
}

func addAllowlist(b *Backend, _ string, data interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	body, err := decodeData(data)
	if err != nil {
		return jsonResponse(http.StatusBadRequest, errorBody(err.Error()))
	}
	wsID := urlParams["workspace_id"]
	email := localUserEmail(b)

	domains, _ := body["domains"].([]interface{})
	tx, err := b.db.Begin()
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	for _, d := range domains {
		ds, _ := d.(string)
		if ds == "" {
			continue
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO allowlist_domains (workspace_id, domain, added_by_email) VALUES (?, ?, ?)`,
			wsID, ds, email,
		); err != nil {
			_ = tx.Rollback()
			return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
		}
		if _, err := tx.Exec(
			`INSERT INTO allowlist_log (workspace_id, action, domain, performed_by_email) VALUES (?, 'ADDED', ?, ?)`,
			wsID, ds, email,
		); err != nil {
			_ = tx.Rollback()
			return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
		}
	}
	if err := tx.Commit(); err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusCreated, map[string]string{"status": "ok"})
}

func removeAllowlist(b *Backend, _ string, _ interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	wsID := urlParams["workspace_id"]
	domain := urlParams["domain"]
	email := localUserEmail(b)

	tx, err := b.db.Begin()
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	if _, err := tx.Exec(`DELETE FROM allowlist_domains WHERE workspace_id = ? AND domain = ?`, wsID, domain); err != nil {
		_ = tx.Rollback()
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	if _, err := tx.Exec(
		`INSERT INTO allowlist_log (workspace_id, action, domain, performed_by_email) VALUES (?, 'REMOVED', ?, ?)`,
		wsID, domain, email,
	); err != nil {
		_ = tx.Rollback()
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	if err := tx.Commit(); err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	return jsonResponse(http.StatusOK, map[string]string{"status": "ok"})
}

type allowlistLogRow struct {
	PerformedAt      string `json:"performed_at"`
	PerformedByEmail string `json:"performed_by_email"`
	Action           string `json:"action"`
	Domain           string `json:"domain"`
}

func logAllowlist(b *Backend, _ string, _ interface{}, urlParams, _ map[string]string) (*http.Response, error) {
	rows, err := b.db.Query(
		`SELECT performed_at, COALESCE(performed_by_email, ''), action, domain
		 FROM allowlist_log WHERE workspace_id = ? ORDER BY performed_at DESC`,
		urlParams["workspace_id"],
	)
	if err != nil {
		return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
	}
	defer rows.Close()
	out := []allowlistLogRow{}
	for rows.Next() {
		var r allowlistLogRow
		if err := rows.Scan(&r.PerformedAt, &r.PerformedByEmail, &r.Action, &r.Domain); err != nil {
			return jsonResponse(http.StatusInternalServerError, errorBody(err.Error()))
		}
		out = append(out, r)
	}
	return jsonResponse(http.StatusOK, map[string]interface{}{"data": out})
}

// localUserEmail returns the single user's email for audit attribution; "" if absent.
func localUserEmail(b *Backend) string {
	var email string
	_ = b.db.QueryRow(`SELECT email FROM users LIMIT 1`).Scan(&email)
	return email
}
