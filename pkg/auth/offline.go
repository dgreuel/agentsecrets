package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/The-17/agentsecrets/pkg/api/offline"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

func decodeJSON(resp *http.Response, target interface{}) error {
	return json.NewDecoder(resp.Body).Decode(target)
}

// offlineSessionToken is the synthetic access token written to token.json so
// config.IsAuthenticated() returns true without a server roundtrip.
const offlineSessionToken = "offline-session"

// offlineSignup creates the local single-user identity and a personal
// workspace, all without touching the network. It mirrors the cloud Signup
// flow's persistence steps so subsequent CLI commands behave identically.
func (s *Service) offlineSignup(req SignupRequest) error {
	be, ok := s.API.(*offline.Backend)
	if !ok {
		return fmt.Errorf("offline signup requires the offline backend")
	}

	// 1. Generate keypair (private key never leaves this process).
	keys, err := crypto.SetupUser(req.Password)
	if err != nil {
		return fmt.Errorf("offline signup: %w", err)
	}

	// 2. Register the user in the offline DB so it can own a workspace.
	userID, err := be.EnsureLocalUser(
		uuid.New().String(),
		req.Email,
		base64.StdEncoding.EncodeToString(keys.PublicKey),
	)
	if err != nil {
		return fmt.Errorf("offline signup: %w", err)
	}
	_ = userID

	// 3. Generate a personal workspace key and seal it for the user so the
	//    persisted shape matches cloud — this is what makes "two-way door"
	//    sync feasible later: we can ship the encrypted blob unmodified.
	wsKey, err := crypto.GenerateWorkspaceKey()
	if err != nil {
		return fmt.Errorf("offline signup: workspace key: %w", err)
	}
	encWsKey, err := crypto.EncryptForUser(keys.PublicKey, wsKey)
	if err != nil {
		return fmt.Errorf("offline signup: encrypt workspace key: %w", err)
	}

	resp, err := be.Call("workspaces.create", "POST", map[string]interface{}{
		"name":                    "Personal",
		"encrypted_workspace_key": base64.StdEncoding.EncodeToString(encWsKey),
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("offline signup: create workspace: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return be.DecodeError(resp)
	}
	var wsRes struct {
		Data struct {
			ID   string `json:"id"`
			Type string `json:"type"`
			Role string `json:"role"`
		} `json:"data"`
	}
	if err := decodeJSON(resp, &wsRes); err != nil {
		return fmt.Errorf("offline signup: parse workspace: %w", err)
	}

	// 4. Persist the same client-side state the cloud login flow writes:
	//    email, local-auth token, synthetic session token, keypair, and the
	//    decrypted workspace cache.
	if err := persistOfflineSession(req.Email, req.Password, keys.PrivateKey, keys.PublicKey, wsRes.Data.ID, "Personal", wsKey); err != nil {
		return err
	}
	return nil
}

// offlineLogin re-validates the password locally (Argon2id against the stored
// LocalAuthToken) and refreshes the synthetic session. It does NOT recreate
// the user — that's what offlineSignup is for. If no local user exists yet the
// caller is told to run `agentsecrets init`.
func (s *Service) offlineLogin(email, password string) error {
	cfg, err := config.LoadGlobalConfig()
	if err != nil || cfg == nil || cfg.Email == "" {
		return fmt.Errorf("no offline account found — run `agentsecrets init` to create one")
	}
	if email != "" && email != cfg.Email {
		return fmt.Errorf("offline mode has a single user (%s); supplied email did not match", cfg.Email)
	}
	if cfg.LocalAuthSalt == "" || cfg.LocalAuthToken == "" {
		return fmt.Errorf("offline account is missing its local auth token; run `agentsecrets init --force`")
	}
	if err := crypto.VerifyLocalAuthToken(password, cfg.LocalAuthSalt, cfg.LocalAuthToken); err != nil {
		return fmt.Errorf("invalid password")
	}

	return config.StoreTokens(
		offlineSessionToken,
		offlineSessionToken,
		time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
	)
}

// persistOfflineSession writes the client-side state that the rest of the CLI
// expects after a successful login (cloud or offline): email, local auth
// token, session tokens, OS keychain keypair, and the workspace cache used by
// subsequent encryption operations.
func persistOfflineSession(email, password string, privKey, pubKey []byte, workspaceID, workspaceName string, wsKey []byte) error {
	cfg, _ := config.LoadGlobalConfig()
	if cfg == nil {
		cfg = &config.GlobalConfig{}
	}
	cfg.Email = email
	cfg.Mode = config.ModeOffline

	salt, token, err := crypto.DeriveLocalAuthToken(password)
	if err != nil {
		return fmt.Errorf("offline signup: derive local auth: %w", err)
	}
	cfg.LocalAuthSalt = salt
	cfg.LocalAuthToken = token

	if cfg.Workspaces == nil {
		cfg.Workspaces = make(map[string]config.WorkspaceCacheEntry)
	}
	cfg.Workspaces[workspaceID] = config.WorkspaceCacheEntry{
		Name: workspaceName,
		Key:  base64.StdEncoding.EncodeToString(wsKey),
		Role: "owner",
		Type: "personal",
	}
	cfg.SelectedWorkspaceID = workspaceID

	if err := config.SaveGlobalConfig(cfg); err != nil {
		return fmt.Errorf("offline signup: save config: %w", err)
	}
	if err := config.StoreTokens(
		offlineSessionToken,
		offlineSessionToken,
		time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("offline signup: store tokens: %w", err)
	}
	if err := keyring.StoreKeypair(email, privKey, pubKey); err != nil {
		return fmt.Errorf("offline signup: store keypair: %w", err)
	}
	return nil
}
