package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/google/uuid"
)

// ── In-memory SRP session store ─────────────────────────────────────────────

type srpSession struct {
	state     *crypto.SRPServerState
	email     string
	userID    string
	createdAt time.Time
}

var (
	srpSessions   = make(map[string]*srpSession)
	srpSessionsMu sync.Mutex
)

// cleanupSRPSessions removes expired sessions (called periodically).
func cleanupSRPSessions() {
	srpSessionsMu.Lock()
	defer srpSessionsMu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, s := range srpSessions {
		if s.createdAt.Before(cutoff) {
			delete(srpSessions, k)
		}
	}
}

func startSRPCleanup() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			cleanupSRPSessions()
		}
	}()
}

// ── POST /api/auth/srp/register/ ────────────────────────────────────────────

func handleSRPRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FirstName          string `json:"first_name"`
		LastName           string `json:"last_name"`
		Email              string `json:"email"`
		SRPSalt            string `json:"srp_salt"`
		SRPVerifier        string `json:"srp_verifier"`
		PublicKey          string `json:"public_key"`
		EncryptedPrivateKey string `json:"encrypted_private_key"`
		KeySalt            string `json:"key_salt"`
		TermsAgreement     bool   `json:"terms_agreement"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.SRPSalt == "" || req.SRPVerifier == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	// Check for existing user.
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&exists); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if exists {
		writeError(w, http.StatusConflict, "user already exists")
		return
	}

	userID := uuid.New().String()
	_, err := db.Exec(
		`INSERT INTO users (id, email, first_name, last_name, srp_salt, srp_verifier, public_key, encrypted_private_key, key_salt)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		userID, email, req.FirstName, req.LastName, req.SRPSalt, req.SRPVerifier, req.PublicKey, req.EncryptedPrivateKey, req.KeySalt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	auditLog(r, "user.signup", "user:"+userID, map[string]interface{}{"email": email})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

// ── POST /api/auth/srp/init/ ────────────────────────────────────────────────

func handleSRPInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}

	var userID, srpSalt, srpVerifier string
	err := db.QueryRow(
		`SELECT id, srp_salt, srp_verifier FROM users WHERE email=$1`, email,
	).Scan(&userID, &srpSalt, &srpVerifier)
	if err != nil {
		// Don't reveal whether user exists — return a fake challenge.
		writeJSON(w, http.StatusOK, map[string]string{
			"srp_salt":         "0000000000000000000000000000000000000000",
			"server_ephemeral": "0000000000000000000000000000000000000000",
		})
		return
	}

	state, serverEphemeral, err := crypto.SRPServerInit(srpSalt, srpVerifier)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SRP init failed")
		return
	}

	// Store session keyed by email (one per user at a time).
	sessionID := email
	srpSessionsMu.Lock()
	srpSessions[sessionID] = &srpSession{
		state:     state,
		email:     email,
		userID:    userID,
		createdAt: time.Now(),
	}
	srpSessionsMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"srp_salt":         srpSalt,
		"server_ephemeral": serverEphemeral,
	})
}

// ── POST /api/auth/srp/verify/ ──────────────────────────────────────────────

func handleSRPVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email           string `json:"email"`
		ClientEphemeral string `json:"client_ephemeral"`
		ClientProof     string `json:"client_proof"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Retrieve and consume SRP session.
	srpSessionsMu.Lock()
	session, ok := srpSessions[email]
	if ok {
		delete(srpSessions, email)
	}
	srpSessionsMu.Unlock()

	if !ok {
		writeError(w, http.StatusBadRequest, "no SRP session — call /auth/srp/init/ first")
		return
	}

	// Verify client proof M1, get server proof M2.
	serverProof, err := crypto.SRPServerVerify(session.state, email, req.ClientEphemeral, req.ClientProof)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	// Generate tokens.
	accessToken, expiresAt, err := generateAccessToken(session.userID, email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate access token")
		return
	}

	refreshPlain, refreshHash := generateRefreshToken()
	refreshExpiry := time.Now().Add(7 * 24 * time.Hour)
	refreshID := uuid.New().String()
	_, err = db.Exec(
		`INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		refreshID, session.userID, refreshHash, refreshExpiry,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store refresh token")
		return
	}

	// Load user's key material.
	var publicKey, encryptedPrivateKey, keySalt string
	err = db.QueryRow(
		`SELECT public_key, encrypted_private_key, key_salt FROM users WHERE id=$1`, session.userID,
	).Scan(&publicKey, &encryptedPrivateKey, &keySalt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load user data")
		return
	}

	// Load workspace memberships.
	rows, err := db.Query(
		`SELECT w.id, w.name, wm.encrypted_workspace_key, wm.role, w.type
		 FROM workspace_members wm
		 JOIN workspaces w ON w.id = wm.workspace_id
		 WHERE wm.user_id = $1 AND wm.status = 'active'`, session.userID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load workspaces")
		return
	}
	defer rows.Close()

	type wsEntry struct {
		ID                    string `json:"id"`
		Name                  string `json:"name"`
		EncryptedWorkspaceKey string `json:"encrypted_workspace_key"`
		Role                  string `json:"role"`
		Type                  string `json:"type"`
	}
	var workspaces []wsEntry
	for rows.Next() {
		var ws wsEntry
		if err := rows.Scan(&ws.ID, &ws.Name, &ws.EncryptedWorkspaceKey, &ws.Role, &ws.Type); err != nil {
			continue
		}
		workspaces = append(workspaces, ws)
	}
	if workspaces == nil {
		workspaces = []wsEntry{}
	}

	auditLog(r, "user.login", "user:"+session.userID, map[string]interface{}{"email": email})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"server_proof": serverProof,
		"data": map[string]interface{}{
			"access":                accessToken,
			"refresh":               refreshPlain,
			"expires_at":            expiresAt,
			"encrypted_private_key": encryptedPrivateKey,
			"key_salt":              keySalt,
			"user": map[string]string{
				"public_key": publicKey,
				"email":      email,
			},
			"workspaces": workspaces,
		},
	})
}

// ── POST /api/auth/logout/ ──────────────────────────────────────────────────

func handleLogout(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	// Revoke all refresh tokens for this user.
	_, _ = db.Exec(`DELETE FROM refresh_tokens WHERE user_id=$1`, userID)
	auditLog(r, "user.logout", "user:"+userID, nil)
	writeOK(w)
}

// ── POST /api/auth/refresh/ ─────────────────────────────────────────────────

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeBody(r, &req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	tokenHash := hashToken(req.RefreshToken)
	var tokenID, userID string
	var expiresAt time.Time
	err := db.QueryRow(
		`SELECT id, user_id, expires_at FROM refresh_tokens WHERE token_hash=$1`, tokenHash,
	).Scan(&tokenID, &userID, &expiresAt)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	if time.Now().After(expiresAt) {
		_, _ = db.Exec(`DELETE FROM refresh_tokens WHERE id=$1`, tokenID)
		writeError(w, http.StatusUnauthorized, "refresh token expired")
		return
	}

	// Delete old token (rotation).
	_, _ = db.Exec(`DELETE FROM refresh_tokens WHERE id=$1`, tokenID)

	// Look up email.
	var email string
	_ = db.QueryRow(`SELECT email FROM users WHERE id=$1`, userID).Scan(&email)

	// Issue new tokens.
	accessToken, newExpiresAt, err := generateAccessToken(userID, email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	newRefreshPlain, newRefreshHash := generateRefreshToken()
	newRefreshExpiry := time.Now().Add(7 * 24 * time.Hour)
	newRefreshID := uuid.New().String()
	_, _ = db.Exec(
		`INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		newRefreshID, userID, newRefreshHash, newRefreshExpiry,
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"access":     accessToken,
			"refresh":    newRefreshPlain,
			"expires_at": newExpiresAt,
		},
	})
}
