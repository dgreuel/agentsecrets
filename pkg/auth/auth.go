// Package auth orchestrates the authentication flows (init, login, logout).
//
// SRP-6a protocol (RFC 5054 / RFC 2945):
//
//	Registration (Signup):
//	  1. Generate X25519 keypair; encrypt private key with Argon2id-derived AES key.
//	  2. Derive SRP verifier: v = g^H(salt||H(email:password)) mod N.
//	  3. POST srp_salt + srp_verifier to server — plaintext password NEVER sent.
//	  4. Auto-login via the two-step SRP handshake below.
//
//	Login:
//	  1. POST email → server returns srp_salt + server_ephemeral B.
//	  2. Client computes ephemeral A and proof M1; sends A + M1 to server.
//	  3. Server verifies M1, returns M2 + tokens + encrypted key material.
//	  4. Client verifies M2 (MITM protection).
//	  5. Client decrypts private key with Argon2id(password, key_salt) — local, never sent.
//	  6. Store tokens + keypair + workspace keys.
//
// The Argon2id key derivation (key_salt → AES key → decrypt private key) is
// entirely client-side and UNCHANGED from the previous design.  Only the
// authentication layer is replaced.
package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// Service provides authentication operations.
type Service struct {
	API api.Backend
}

// NewService creates a new auth service with the given API backend.
func NewService(backend api.Backend) *Service {
	return &Service{API: backend}
}

// SignupRequest contains the information needed to create a new account.
type SignupRequest struct {
	FirstName string
	LastName  string
	Email     string
	Password  string
}

// Signup creates a new user account and performs auto-login.
//
// The plaintext password is NEVER sent to the server.  Instead:
//   - srp_verifier  (one-way, cannot be reversed by server)
//   - srp_salt      (used by client to derive SRP private key x)
//   - encrypted_private_key + key_salt  (Argon2id-protected, server cannot decrypt)
func (s *Service) Signup(req SignupRequest) error {
	if config.IsOfflineMode() {
		return s.offlineSignup(req)
	}
	// 1. Generate X25519 keypair and encrypt private key with Argon2id key.
	keys, err := crypto.SetupUser(req.Password)
	if err != nil {
		return fmt.Errorf("signup: %w", err)
	}

	// 2. Derive SRP verifier — one-way function; server cannot recover password.
	srpSalt, srpVerifier, err := crypto.GenerateSRPVerifier(req.Email, req.Password)
	if err != nil {
		return fmt.Errorf("signup: SRP verifier: %w", err)
	}

	// 3. Register — no "password" field in this request.
	data := map[string]interface{}{
		"first_name":            req.FirstName,
		"last_name":             req.LastName,
		"email":                 req.Email,
		"srp_salt":              srpSalt,
		"srp_verifier":          srpVerifier,
		"public_key":            base64.StdEncoding.EncodeToString(keys.PublicKey),
		"encrypted_private_key": keys.EncryptedPrivateKey,
		"key_salt":              keys.Salt,
		"terms_agreement":       true,
	}

	resp, err := s.API.Call("auth.signup", "POST", data, nil, nil)
	if err != nil {
		return fmt.Errorf("signup: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return s.API.DecodeError(resp)
	}

	// 4. Auto-login: reuse the just-generated keypair so we skip key decryption.
	return s.PerformLogin(req.Email, req.Password, keys.PrivateKey, keys.PublicKey)
}

// PerformLogin completes the SRP login flow: handshake → key decryption →
// credential storage → workspace caching.
//
// Parameters:
//   - email, password: user credentials (password stays client-side)
//   - privateKey, publicKey: pre-computed keypair (signup path only).
//     Pass nil for both during a normal login; they will be decrypted locally.
func (s *Service) PerformLogin(email, password string, privateKey, publicKey []byte) error {
	if config.IsOfflineMode() {
		return s.offlineLogin(email, password)
	}
	// ── Step 1: Request SRP challenge ──────────────────────────────────────────
	initResp, err := s.API.Call("auth.login_init", "POST", map[string]string{
		"email": email,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("login: SRP init failed: %w", err)
	}
	defer initResp.Body.Close()

	if initResp.StatusCode != http.StatusOK {
		return s.API.DecodeError(initResp)
	}

	var challenge srpChallenge
	if err := json.NewDecoder(initResp.Body).Decode(&challenge); err != nil {
		return fmt.Errorf("login: failed to parse SRP challenge: %w", err)
	}
	if challenge.SRPSalt == "" || challenge.ServerEphemeral == "" {
		return fmt.Errorf("login: SRP challenge missing srp_salt or server_ephemeral")
	}

	// ── Step 2: Compute client ephemeral A and proof M1 ───────────────────────
	// The password is used only for this local computation — it never leaves.
	srpState, clientEphemeral, err := crypto.SRPClientInit(email, password, challenge.SRPSalt)
	if err != nil {
		return fmt.Errorf("login: SRP client init: %w", err)
	}
	clientProof, err := crypto.SRPClientFinish(srpState, challenge.ServerEphemeral)
	if err != nil {
		return fmt.Errorf("login: SRP client proof: %w", err)
	}

	// ── Step 3: Send proof; receive session tokens + encrypted key material ───
	verifyResp, err := s.API.Call("auth.login_verify", "POST", map[string]interface{}{
		"email":            email,
		"client_ephemeral": clientEphemeral,
		"client_proof":     clientProof,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("login: SRP verify failed: %w", err)
	}
	defer verifyResp.Body.Close()

	if verifyResp.StatusCode != http.StatusOK {
		return s.API.DecodeError(verifyResp)
	}

	var loginResp srpLoginResponse
	if err := json.NewDecoder(verifyResp.Body).Decode(&loginResp); err != nil {
		return fmt.Errorf("login: failed to parse login response: %w", err)
	}

	// ── Step 4: Verify server proof M2 (MITM protection) ─────────────────────
	if err := crypto.SRPClientVerifyServer(srpState, loginResp.ServerProof); err != nil {
		return fmt.Errorf("login: %w", err)
	}

	// ── Step 5: Decrypt private key (login path) ──────────────────────────────
	// On the signup path the caller passes the fresh keypair; skip decryption.
	// On the login path the server returns the encrypted private key; decrypt
	// it locally using Argon2id(password, key_salt) — server never sees this.
	if privateKey == nil {
		encPrivKey := loginResp.Data.EncryptedPrivateKey
		salt := loginResp.Data.KeySalt
		pubKeyB64 := loginResp.Data.User.PublicKey

		if encPrivKey == "" || salt == "" || pubKeyB64 == "" {
			return fmt.Errorf("login: encryption keys missing from server response")
		}

		privateKey, err = crypto.DecryptPrivateKey(encPrivKey, password, salt)
		if err != nil {
			return fmt.Errorf("login: %w", err)
		}

		publicKey, err = base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return fmt.Errorf("login: invalid public key in response: %w", err)
		}
	}

	// ── Step 6: Persist email and session tokens ───────────────────────────────
	if err := config.SetEmail(email); err != nil {
		return fmt.Errorf("login: failed to save email: %w", err)
	}

	globalCfg, _ := config.LoadGlobalConfig()
	if globalCfg == nil {
		globalCfg = &config.GlobalConfig{}
	}
	globalCfg.Email = email

	// Derive and store the local auth token so offline allowlist verification
	// uses Argon2id instead of a bare SHA-256 hash.
	localAuthSalt, localAuthToken, err := crypto.DeriveLocalAuthToken(password)
	if err != nil {
		return fmt.Errorf("login: failed to derive local auth token: %w", err)
	}
	globalCfg.LocalAuthSalt = localAuthSalt
	globalCfg.LocalAuthToken = localAuthToken

	if err := config.SaveGlobalConfig(globalCfg); err != nil {
		return fmt.Errorf("login: failed to save global config: %w", err)
	}

	accessToken := coalesce(loginResp.AccessToken, loginResp.Data.Access)
	if err := config.StoreTokens(
		accessToken,
		coalesce(loginResp.RefreshToken, loginResp.Data.Refresh),
		coalesce(loginResp.ExpiresAt, loginResp.Data.ExpiresAt),
	); err != nil {
		return fmt.Errorf("login: failed to save tokens: %w", err)
	}

	if err := keyring.StoreKeypair(email, privateKey, publicKey); err != nil {
		return fmt.Errorf("login: failed to save keypair: %w", err)
	}

	// ── Step 7: Decrypt and cache workspace keys ───────────────────────────────
	workspaceCache := make(map[string]config.WorkspaceCacheEntry)

	for _, ws := range loginResp.Data.Workspaces {
		encryptedWsKey, err := base64.StdEncoding.DecodeString(ws.EncryptedWorkspaceKey)
		if err != nil {
			continue
		}
		wsKey, err := crypto.DecryptFromUser(privateKey, publicKey, encryptedWsKey)
		if err != nil {
			continue
		}
		workspaceCache[ws.ID] = config.WorkspaceCacheEntry{
			Name: ws.Name,
			Key:  base64.StdEncoding.EncodeToString(wsKey),
			Role: ws.Role,
			Type: ws.Type,
		}
	}

	if len(workspaceCache) == 0 {
		return nil
	}

	if err := config.StoreWorkspaceCache(workspaceCache); err != nil {
		return fmt.Errorf("login: failed to cache workspace keys: %w", err)
	}

	// ── Step 8: Set personal workspace as default (if none selected) ───────────
	if config.GetSelectedWorkspaceID() == "" {
		id := ""
		for k, ws := range workspaceCache {
			if id == "" || ws.Type == "personal" {
				id = k
			}
			if ws.Type == "personal" {
				break
			}
		}
		if id != "" {
			_ = config.SetSelectedWorkspaceID(id)
		}
	}

	return nil
}

// Logout clears stored credentials and (for online mode) invalidates the server session.
// In offline mode it only clears session tokens so that mode, email, and local auth
// material are preserved — the user can unlock again without re-running init.
func (s *Service) Logout() error {
	if config.IsOfflineMode() {
		return config.StoreTokens("", "", "")
	}

	email := config.GetEmail()

	// Best-effort: tell server to invalidate tokens.
	_, _ = s.API.Call("auth.logout", "POST", nil, nil, nil)

	if email != "" {
		_ = keyring.DeleteKeypair(email)
	}

	return config.ClearSession()
}

// ── SRP response types ───────────────────────────────────────────────────────

// srpChallenge is the server response to /auth/srp/init/.
type srpChallenge struct {
	SRPSalt         string `json:"srp_salt"`
	ServerEphemeral string `json:"server_ephemeral"`
}

// srpLoginResponse is the server response to /auth/srp/verify/.
type srpLoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    string    `json:"expires_at"`
	ServerProof  string    `json:"server_proof"`
	Data         loginData `json:"data"`
}

type loginData struct {
	Access              string           `json:"access"`
	Refresh             string           `json:"refresh"`
	ExpiresAt           string           `json:"expires_at"`
	EncryptedPrivateKey string           `json:"encrypted_private_key"`
	KeySalt             string           `json:"key_salt"`
	User                loginUser        `json:"user"`
	Workspaces          []loginWorkspace `json:"workspaces"`
}

type loginUser struct {
	PublicKey string `json:"public_key"`
	Email     string `json:"email"`
}

type loginWorkspace struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	EncryptedWorkspaceKey string `json:"encrypted_workspace_key"`
	Role                  string `json:"role"`
	Type                  string `json:"type"`
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// coalesce returns the first non-empty string.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
