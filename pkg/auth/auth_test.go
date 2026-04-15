package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
)

// srpMockServer runs a minimal in-memory SRP server that correctly computes
// verifier / challenge / proof values.  It stores registration data across
// handler invocations via shared state protected by a mutex.
type srpMockServer struct {
	mu          sync.Mutex
	salt        string
	verifier    string
	serverState *crypto.SRPServerState
}

func (m *srpMockServer) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	// ── Registration ───────────────────────────────────────────────────────────
	case "/auth/srp/register/":
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		m.salt, _ = body["srp_salt"].(string)
		m.verifier, _ = body["srp_verifier"].(string)
		m.mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "User created",
			"data":    map[string]string{"id": "user-123"},
		})

	// ── SRP init: return challenge ─────────────────────────────────────────────
	case "/auth/srp/init/":
		m.mu.Lock()
		salt := m.salt
		verifier := m.verifier
		m.mu.Unlock()

		state, serverEphemeral, err := crypto.SRPServerInit(salt, verifier)
		if err != nil {
			http.Error(w, "srp init error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		m.mu.Lock()
		m.serverState = state
		m.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"srp_salt":         salt,
			"server_ephemeral": serverEphemeral,
		})

	// ── SRP verify: check M1, return M2 + tokens ──────────────────────────────
	case "/auth/srp/verify/":
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		email, _ := body["email"].(string)
		clientEphemeral, _ := body["client_ephemeral"].(string)
		clientProof, _ := body["client_proof"].(string)

		m.mu.Lock()
		state := m.serverState
		m.mu.Unlock()

		serverProof, err := crypto.SRPServerVerify(state, email, clientEphemeral, clientProof)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"server_proof":  serverProof,
			"access_token":  "access-123",
			"refresh_token": "refresh-456",
			"expires_at":    "2099-01-01T00:00:00Z",
			"data": map[string]interface{}{
				"access":     "access-123",
				"refresh":    "refresh-456",
				"expires_at": "2099-01-01T00:00:00Z",
			},
		})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestSignupFlow(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { config.HomeDirHook = oldHome }()

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig: %v", err)
	}

	mock := &srpMockServer{}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()

	client := api.NewClient(func() string { return "" })
	client.BaseURL = srv.URL
	svc := NewService(client)

	err := svc.Signup(SignupRequest{
		FirstName: "Test",
		LastName:  "User",
		Email:     "test@example.com",
		Password:  "password123",
	})
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}

	if config.GetEmail() != "test@example.com" {
		t.Error("email not stored in config after signup")
	}

	// Confirm tokens were stored.
	if config.GetAccessToken() != "access-123" {
		t.Errorf("access token not stored: got %q", config.GetAccessToken())
	}
}

func TestLoginFlow(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { config.HomeDirHook = oldHome }()

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig: %v", err)
	}

	const email = "login@example.com"
	const password = "hunter2"

	// Pre-register so the mock server has a valid verifier.
	saltHex, verifierHex, err := crypto.GenerateSRPVerifier(email, password)
	if err != nil {
		t.Fatalf("GenerateSRPVerifier: %v", err)
	}

	mock := &srpMockServer{salt: saltHex, verifier: verifierHex}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()

	client := api.NewClient(func() string { return "" })
	client.BaseURL = srv.URL
	svc := NewService(client)

	// Pass pre-computed dummy keys to skip key decryption (mimics signup path).
	dummyKey := make([]byte, 32)
	if err := svc.PerformLogin(email, password, dummyKey, dummyKey); err != nil {
		t.Fatalf("PerformLogin: %v", err)
	}

	if config.GetAccessToken() != "access-123" {
		t.Errorf("access token not stored correctly: got %q", config.GetAccessToken())
	}
}

func TestLoginFailure(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { config.HomeDirHook = oldHome }()

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig: %v", err)
	}

	const email = "fail@example.com"

	// Register with one password.
	saltHex, verifierHex, _ := crypto.GenerateSRPVerifier(email, "correct-password")
	mock := &srpMockServer{salt: saltHex, verifier: verifierHex}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()

	client := api.NewClient(func() string { return "" })
	client.BaseURL = srv.URL
	svc := NewService(client)

	// Login with a different (wrong) password.
	dummyKey := make([]byte, 32)
	err := svc.PerformLogin(email, "wrong-password", dummyKey, dummyKey)
	if err == nil {
		t.Fatal("PerformLogin should have failed with wrong password")
	}
}
