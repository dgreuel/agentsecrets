package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Context keys.
type ctxKey string

const (
	ctxUserID ctxKey = "user_id"
	ctxEmail  ctxKey = "email"
)

// jwtSecret is loaded from config at startup.
var jwtSecret []byte

// ── JWT helpers ─────────────────────────────────────────────────────────────

func generateAccessToken(userID, email string) (string, string, error) {
	exp := time.Now().Add(15 * time.Minute)
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     exp.Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}
	return signed, exp.Format(time.RFC3339), nil
}

func generateRefreshToken() (plain, hash string) {
	plain = uuid.New().String() + "-" + uuid.New().String()
	h := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(h[:])
	return
}

func hashToken(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

func parseAccessToken(tokenStr string) (userID, email string, err error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return "", "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", fmt.Errorf("invalid token")
	}
	uid, _ := claims["user_id"].(string)
	em, _ := claims["email"].(string)
	return uid, em, nil
}

// ── Auth middleware ─────────────────────────────────────────────────────────

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		userID, email, err := parseAccessToken(tokenStr)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		ctx := context.WithValue(r.Context(), ctxUserID, userID)
		ctx = context.WithValue(ctx, ctxEmail, email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getUserID(r *http.Request) string {
	v, _ := r.Context().Value(ctxUserID).(string)
	return v
}

func getUserEmail(r *http.Request) string {
	v, _ := r.Context().Value(ctxEmail).(string)
	return v
}

// ── Response helpers ────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

func writeData(w http.ResponseWriter, status int, data interface{}) {
	writeJSON(w, status, map[string]interface{}{"data": data})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeOK(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Request helpers ─────────────────────────────────────────────────────────

func decodeBody(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// ── Audit logger ────────────────────────────────────────────────────────────

func auditLog(r *http.Request, action, resource string, details map[string]interface{}) {
	userID := getUserID(r)
	email := getUserEmail(r)
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = strings.Split(xff, ",")[0]
	}

	detailsJSON, _ := json.Marshal(details)
	_, err := db.Exec(
		`INSERT INTO audit_logs (id, user_id, email, action, resource, details, ip_address)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		uuid.New().String(), userID, email, action, resource, string(detailsJSON), ip,
	)
	if err != nil {
		log.Printf("audit log error: %v", err)
	}
}

// ── Logging middleware ──────────────────────────────────────────────────────

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
