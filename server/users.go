package main

import (
	"net/http"
	"strings"
)

// ── GET /api/users/{email}/public-key/ ──────────────────────────────────────

func handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.PathValue("email")))
	if email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}

	var publicKey string
	err := db.QueryRow(`SELECT public_key FROM users WHERE email=$1`, email).Scan(&publicKey)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeData(w, http.StatusOK, map[string]string{
		"public_key": publicKey,
	})
}
