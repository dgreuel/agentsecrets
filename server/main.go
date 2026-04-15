package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	// ── Configuration ───────────────────────────────────────────────────────
	port := envOr("PORT", "8080")
	dsn := envOr("DATABASE_URL", "postgres://localhost:5432/agentsecrets?sslmode=disable")
	secret := envOr("JWT_SECRET", "dev-secret-change-in-production")

	jwtSecret = []byte(secret)

	// ── Database ────────────────────────────────────────────────────────────
	if err := initDB(dsn); err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	if err := runMigrations(); err != nil {
		log.Fatalf("migrations: %v", err)
	}
	log.Println("database ready")

	// Start SRP session cleanup goroutine.
	startSRPCleanup()

	// ── Router ──────────────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Public auth endpoints (no token required).
	mux.HandleFunc("POST /api/auth/srp/register/", handleSRPRegister)
	mux.HandleFunc("POST /api/auth/srp/init/", handleSRPInit)
	mux.HandleFunc("POST /api/auth/srp/verify/", handleSRPVerify)
	mux.HandleFunc("POST /api/auth/refresh/", handleRefresh)

	// Protected auth endpoints.
	mux.Handle("POST /api/auth/logout/", requireAuth(http.HandlerFunc(handleLogout)))

	// Workspaces.
	mux.Handle("GET /api/workspaces/", requireAuth(http.HandlerFunc(handleListWorkspaces)))
	mux.Handle("POST /api/workspaces/", requireAuth(http.HandlerFunc(handleCreateWorkspace)))
	mux.Handle("GET /api/workspaces/{workspace_id}/", requireAuth(http.HandlerFunc(handleGetWorkspace)))
	mux.Handle("PUT /api/workspaces/{workspace_id}/", requireAuth(http.HandlerFunc(handleUpdateWorkspace)))
	mux.Handle("DELETE /api/workspaces/{workspace_id}/", requireAuth(http.HandlerFunc(handleDeleteWorkspace)))

	// Workspace members.
	mux.Handle("GET /api/workspaces/{workspace_id}/members/", requireAuth(http.HandlerFunc(handleListMembers)))
	mux.Handle("POST /api/workspaces/{workspace_id}/members/", requireAuth(http.HandlerFunc(handleInviteMember)))
	mux.Handle("DELETE /api/workspaces/{workspace_id}/members/{user_id}/", requireAuth(http.HandlerFunc(handleRemoveMember)))
	mux.Handle("POST /api/workspaces/{workspace_id}/members/{user_id}/role/", requireAuth(http.HandlerFunc(handleUpdateRole)))

	// Workspace allowlist.
	mux.Handle("GET /api/workspaces/{workspace_id}/allowlist/", requireAuth(http.HandlerFunc(handleListAllowlist)))
	mux.Handle("POST /api/workspaces/{workspace_id}/allowlist/", requireAuth(http.HandlerFunc(handleAddAllowlist)))
	mux.Handle("DELETE /api/workspaces/{workspace_id}/allowlist/{domain}/", requireAuth(http.HandlerFunc(handleRemoveAllowlist)))
	mux.Handle("GET /api/workspaces/{workspace_id}/allowlist/log/", requireAuth(http.HandlerFunc(handleAllowlistLog)))

	// Projects.
	mux.Handle("GET /api/projects/", requireAuth(http.HandlerFunc(handleListProjects)))
	mux.Handle("POST /api/projects/", requireAuth(http.HandlerFunc(handleCreateProject)))
	mux.Handle("GET /api/projects/{workspace_id}/{project_name}/", requireAuth(http.HandlerFunc(handleGetProject)))
	mux.Handle("PATCH /api/projects/{workspace_id}/{project_name}/", requireAuth(http.HandlerFunc(handleUpdateProject)))
	mux.Handle("DELETE /api/projects/{workspace_id}/{project_name}/", requireAuth(http.HandlerFunc(handleDeleteProject)))
	mux.Handle("POST /api/projects/{workspace_id}/{project_name}/invite/", requireAuth(http.HandlerFunc(handleProjectInvite)))

	// Secrets.
	mux.Handle("GET /api/secrets/{project_id}/", requireAuth(http.HandlerFunc(handleListSecrets)))
	mux.Handle("POST /api/secrets/", requireAuth(http.HandlerFunc(handleCreateSecrets)))
	mux.Handle("GET /api/secrets/{project_id}/{environment}/{key}/", requireAuth(http.HandlerFunc(handleGetSecret)))
	mux.Handle("PUT /api/secrets/{project_id}/{environment}/{key}/", requireAuth(http.HandlerFunc(handleUpdateSecret)))
	mux.Handle("DELETE /api/secrets/{project_id}/{environment}/{key}/", requireAuth(http.HandlerFunc(handleDeleteSecret)))

	// Agents.
	mux.Handle("GET /api/workspaces/{workspace_id}/agents/", requireAuth(http.HandlerFunc(handleListAgents)))
	mux.Handle("POST /api/workspaces/{workspace_id}/agents/", requireAuth(http.HandlerFunc(handleRegisterAgent)))
	mux.Handle("GET /api/workspaces/{workspace_id}/projects/{project_id}/agents/", requireAuth(http.HandlerFunc(handleListAgents)))
	mux.Handle("POST /api/workspaces/{workspace_id}/projects/{project_id}/agents/", requireAuth(http.HandlerFunc(handleRegisterAgent)))
	mux.Handle("DELETE /api/workspaces/{workspace_id}/agents/{registration_id}/", requireAuth(http.HandlerFunc(handleDeleteAgent)))
	mux.Handle("POST /api/workspaces/{workspace_id}/agents/{registration_id}/tokens/", requireAuth(http.HandlerFunc(handleIssueAgentToken)))
	mux.Handle("GET /api/workspaces/{workspace_id}/agents/{registration_id}/tokens/", requireAuth(http.HandlerFunc(handleListAgentTokens)))
	mux.Handle("DELETE /api/workspaces/{workspace_id}/agents/{registration_id}/tokens/{token_id}/", requireAuth(http.HandlerFunc(handleRevokeAgentToken)))

	// Users.
	mux.Handle("GET /api/users/{email}/public-key/", requireAuth(http.HandlerFunc(handleGetPublicKey)))

	// Audit logs.
	mux.Handle("GET /api/audit/logs/", requireAuth(http.HandlerFunc(handleListAuditLogs)))
	mux.Handle("GET /api/audit/logs/{log_id}/", requireAuth(http.HandlerFunc(handleGetAuditLog)))
	mux.Handle("GET /api/audit/summary/", requireAuth(http.HandlerFunc(handleAuditSummary)))
	mux.Handle("GET /api/audit/export/", requireAuth(http.HandlerFunc(handleAuditExport)))

	// Health check.
	mux.HandleFunc("GET /api/health/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})

	// ── Server ──────────────────────────────────────────────────────────────
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      logRequests(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("AgentSecrets API server listening on :%s", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func formatTime(v interface{}) string {
	switch t := v.(type) {
	case time.Time:
		return t.Format(time.RFC3339)
	case *time.Time:
		if t != nil {
			return t.Format(time.RFC3339)
		}
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	}
	return ""
}
