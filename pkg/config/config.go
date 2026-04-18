// Package config manages all configuration files for AgentSecrets.
//
// This mirrors the Python SecretsCLI's config.py and parts of credentials.py.
//
// File layout:
//
//	~/.agentsecrets/
//	├── config.json     # User email, workspace cache, selected workspace
//	└── token.json      # JWT access/refresh tokens
//
//	./.agentsecrets/
//	└── project.json    # Project binding for current directory
//
// Note: Private key is stored in OS keychain (see pkg/keyring), not in files.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// GlobalConfig represents ~/.agentsecrets/config.json
type GlobalConfig struct {
	Email               string                         `json:"email,omitempty"`
	SelectedWorkspaceID string                         `json:"selected_workspace_id,omitempty"`
	SelectedProjectID   string                         `json:"selected_project_id,omitempty"`
	SelectedEnvironment string                         `json:"selected_environment,omitempty"` // "development", "staging", "production"
	Workspaces          map[string]WorkspaceCacheEntry `json:"workspaces,omitempty"`
	// LocalAuthSalt and LocalAuthToken replace the old plain SHA-256 PasswordHash.
	// LocalAuthToken = Argon2id(password, LocalAuthSalt) — used by offline
	// operations (e.g. allowlist modifications) to verify the user's password
	// without a network round-trip.  The server never sees these values.
	LocalAuthSalt  string `json:"local_auth_salt,omitempty"`
	LocalAuthToken string `json:"local_auth_token,omitempty"`
	DefaultStorageMode int    `json:"default_storage_mode"`   // 1 = keychain (default), 2 = env_file, 3 = 1password
	OnePasswordVault   string `json:"onepassword_vault,omitempty"` // Vault name for storage mode 3
	APIBaseURL         string `json:"api_base_url,omitempty"` // Override backend API URL; precedence: CLI flag > env var > this config > default
	// Mode selects the backend transport. "" / "online" use the cloud HTTP API.
	// "offline" routes everything through the in-process SQLite-backed backend
	// in pkg/api/offline.  See ResolveMode() for precedence.
	Mode               string `json:"mode,omitempty"`
	LastUpdateCheck    int64 `json:"last_update_check,omitempty"`
	LatestVersion      string `json:"latest_version,omitempty"`
}

// ModeOnline routes API calls to the remote AgentSecrets cloud server.
const ModeOnline = "online"

// ModeOffline routes API calls to a local SQLite-backed backend; no network is used.
const ModeOffline = "offline"

// WorkspaceCacheEntry is a cached workspace with its decrypted key
type WorkspaceCacheEntry struct {
	Name string `json:"name"`
	Key  string `json:"key"`  // Base64-encoded decrypted workspace key
	Role string `json:"role"` // "owner", "admin", "member"
	Type string `json:"type"` // "personal", "shared"
}

// TokenConfig represents ~/.agentsecrets/token.json
type TokenConfig struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

// ProjectConfig represents ./.agentsecrets/project.json
type ProjectConfig struct {
	ProjectID     string `json:"project_id"`
	ProjectName   string `json:"project_name"`
	Description   string `json:"description"`
	Environment   string `json:"environment"` // "development", "staging", "production"
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceName string `json:"workspace_name"`
	LastPull      string `json:"last_pull"`
	LastPush      string `json:"last_push"`
	StorageMode   int    `json:"storage_mode"`
}

// Paths returns the standard config file paths
type Paths struct {
	GlobalDir  string // ~/.agentsecrets/
	ConfigFile string // ~/.agentsecrets/config.json
	TokenFile  string // ~/.agentsecrets/token.json
}

// HomeDirHook is used to determine the user's home directory.
// It can be overridden in tests to redirect config files.
var HomeDirHook = os.UserHomeDir

// GetPaths returns the standard config paths based on the user's home directory.
func GetPaths() (*Paths, error) {
	home, err := HomeDirHook()
	if err != nil {
		return nil, fmt.Errorf("could not determine home directory: %w", err)
	}

	globalDir := filepath.Join(home, ".agentsecrets")
	return &Paths{
		GlobalDir:  globalDir,
		ConfigFile: filepath.Join(globalDir, "config.json"),
		TokenFile:  filepath.Join(globalDir, "token.json"),
	}, nil
}

// GlobalConfigExists returns true if ~/.agentsecrets/config.json already exists.
func GlobalConfigExists() bool {
	paths, err := GetPaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(paths.ConfigFile)
	return err == nil
}

// InitGlobalConfig creates the ~/.agentsecrets/ directory and default config files.
func InitGlobalConfig() error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}

	// Create directory
	if err := os.MkdirAll(paths.GlobalDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create config.json if it doesn't exist
	if _, err := os.Stat(paths.ConfigFile); os.IsNotExist(err) {
		if err := writeJSON(paths.ConfigFile, &GlobalConfig{}, 0600); err != nil {
			return err
		}
	}

	// Create token.json with restricted permissions if it doesn't exist
	if _, err := os.Stat(paths.TokenFile); os.IsNotExist(err) {
		if err := writeJSON(paths.TokenFile, &TokenConfig{}, 0600); err != nil {
			return err
		}
	}

	return nil
}

// InitProjectConfig creates .agentsecrets/project.json in the current directory.
func InitProjectConfig(storageMode int) error {
	projectDir := filepath.Join(".", ".agentsecrets")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		return fmt.Errorf("failed to create project config directory: %w", err)
	}

	projectFile := filepath.Join(projectDir, "project.json")
	if _, err := os.Stat(projectFile); os.IsNotExist(err) {
		defaultConfig := &ProjectConfig{
			Environment: "development",
			StorageMode: storageMode,
		}
		if err := writeJSON(projectFile, defaultConfig, 0644); err != nil {
			return err
		}
	} else {
		// Update existing if it exists (for force re-init cases)
		pc, err := LoadProjectConfig()
		if err == nil && pc != nil {
			pc.StorageMode = storageMode
			return SaveProjectConfig(pc)
		}
	}

	return nil
}

// LoadGlobalConfig reads ~/.agentsecrets/config.json
func LoadGlobalConfig() (*GlobalConfig, error) {
	paths, err := GetPaths()
	if err != nil {
		return nil, err
	}
	
	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		return nil, err
	}

	var config GlobalConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Migration: If default_storage_mode is 0, check for legacy storage_mode key
	if config.DefaultStorageMode == 0 {
		var legacy struct {
			StorageMode int `json:"storage_mode"`
		}
		if err := json.Unmarshal(data, &legacy); err == nil && legacy.StorageMode != 0 {
			config.DefaultStorageMode = legacy.StorageMode
		} else {
			// Ensure it's never 0 (default to 1)
			config.DefaultStorageMode = 1
		}
	}

	return &config, nil
}

// SaveGlobalConfig writes ~/.agentsecrets/config.json
func SaveGlobalConfig(config *GlobalConfig) error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}
	return writeJSON(paths.ConfigFile, config, 0600)
}

// LoadTokens reads ~/.agentsecrets/token.json
func LoadTokens() (*TokenConfig, error) {
	paths, err := GetPaths()
	if err != nil {
		return nil, err
	}
	var tokens TokenConfig
	if err := readJSON(paths.TokenFile, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

// SaveTokens writes ~/.agentsecrets/token.json
func SaveTokens(tokens *TokenConfig) error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}
	return writeJSON(paths.TokenFile, tokens, 0600)
}

// GetProjectRoot walks up the directory tree from the current working directory.
// It returns the absolute or relative path to the nearest directory containing
// '.agentsecrets/project.json'.
// If none is found before reaching the filesystem root, it returns an empty string.
func GetProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		projectFile := filepath.Join(dir, ".agentsecrets", "project.json")
		if _, err := os.Stat(projectFile); err == nil {
			return dir, nil
		}

		parentDir := filepath.Dir(dir)
		// If we've reached the root directory (or if Dir() returns the same dir)
		if parentDir == dir || parentDir == "" || parentDir == string(filepath.Separator) {
			return "", nil
		}
		dir = parentDir
	}
}

// LoadProjectConfig reads .agentsecrets/project.json from the nearest project root.
func LoadProjectConfig() (*ProjectConfig, error) {
	root, err := GetProjectRoot()
	if err != nil {
		return nil, err
	}
	if root == "" {
		return nil, fmt.Errorf("no AgentSecrets project found in this directory or any parent directory.\nRun `agentsecrets init` from your project root to initialise a project")
	}

	projectFile := filepath.Join(root, ".agentsecrets", "project.json")
	var config ProjectConfig
	if err := readJSON(projectFile, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// SaveProjectConfig writes .agentsecrets/project.json to the nearest project root.
func SaveProjectConfig(config *ProjectConfig) error {
	root, err := GetProjectRoot()
	if err != nil {
		return err
	}
	// If root is empty (e.g., initial project creation), write to current directory
	if root == "" {
		root = "."
	}

	projectFile := filepath.Join(root, ".agentsecrets", "project.json")
	return writeJSON(projectFile, config, 0644)
}

// --- Helper functions ---

func writeJSON(path string, data interface{}, perm os.FileMode) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(path, jsonData, perm); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func readJSON(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Return zero-value target if file doesn't exist
		}
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return nil
}

// --- Convenience functions (mirrors Python's CredentialsManager) ---

// GetEmail returns the stored user email, or empty string if not logged in.
func GetEmail() string {
	config, err := LoadGlobalConfig()
	if err != nil {
		return ""
	}
	return config.Email
}

// SetEmail stores the user's email in global config.
func SetEmail(email string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.Email = email
	return SaveGlobalConfig(c)
}

// GetAccessToken returns the current access token, or empty string.
func GetAccessToken() string {
	tokens, err := LoadTokens()
	if err != nil {
		return ""
	}
	return tokens.AccessToken
}

// StoreTokens saves authentication tokens.
func StoreTokens(accessToken, refreshToken, expiresAt string) error {
	return SaveTokens(&TokenConfig{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	})
}

// GetSelectedWorkspaceID returns the selected workspace for new project creation.
func GetSelectedWorkspaceID() string {
	config, err := LoadGlobalConfig()
	if err != nil {
		return ""
	}
	return config.SelectedWorkspaceID
}

// SetSelectedWorkspaceID sets the selected workspace for new project creation.
func SetSelectedWorkspaceID(id string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.SelectedWorkspaceID = id
	return SaveGlobalConfig(c)
}

// GetSelectedProjectID returns the globally selected project ID.
func GetSelectedProjectID() string {
	config, err := LoadGlobalConfig()
	if err != nil {
		return ""
	}
	return config.SelectedProjectID
}

// SetSelectedProjectID sets the globally selected project ID.
func SetSelectedProjectID(id string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.SelectedProjectID = id
	return SaveGlobalConfig(c)
}

// StoreWorkspaceCache saves decrypted workspace keys to global config.
func StoreWorkspaceCache(workspaces map[string]WorkspaceCacheEntry) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.Workspaces = workspaces
	return SaveGlobalConfig(c)
}

// GetWorkspaceKey returns the decrypted workspace key for a given workspace ID.
func GetWorkspaceKey(workspaceID string) ([]byte, error) {
	config, err := LoadGlobalConfig()
	if err != nil {
		return nil, err
	}
	ws, ok := config.Workspaces[workspaceID]
	if !ok || ws.Key == "" {
		return nil, fmt.Errorf("workspace key not found for %s", workspaceID)
	}

	// First level of decoding (from config.json)
	key, err := base64.StdEncoding.DecodeString(ws.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode workspace key: %w", err)
	}

	// Compatibility: the original Python CLI uses Fernet keys, which are 32-byte keys
	// encoded in base64 (44 chars). When the API sends them asymmetrically encrypted,
	// the "plaintext" inside the box is often the 44-char base64 string rather than the raw 32 bytes.
	if len(key) == 44 {
		// Try standard base64
		if decoded, err := base64.StdEncoding.DecodeString(string(key)); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
		// Try URL-safe base64 (Fernet uses this)
		if decoded, err := base64.URLEncoding.DecodeString(string(key)); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}

	return key, nil
}

// GetProjectWorkspaceKey returns the workspace key for the current project directory.
func GetProjectWorkspaceKey() ([]byte, error) {
	p, err := LoadProjectConfig()
	if err != nil || p.WorkspaceID == "" {
		return nil, fmt.Errorf("no project configured in current directory")
	}
	return GetWorkspaceKey(p.WorkspaceID)
}

// IsAuthenticated checks if the user has a valid session (token + email present).
func IsAuthenticated() bool {
	return GetAccessToken() != "" && GetEmail() != ""
}

// ClearSession removes all stored credentials (logout).
// Does NOT clear project.json.
func ClearSession() error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}

	// Reset config to empty (preserves the file)
	if err := writeJSON(paths.ConfigFile, &GlobalConfig{}, 0600); err != nil {
		return err
	}

	// Reset tokens to empty
	if err := writeJSON(paths.TokenFile, &TokenConfig{}, 0600); err != nil {
		return err
	}

	return nil
}

// ClearProjectConfig resets the local .agentsecrets/project.json file.
func ClearProjectConfig() error {
	root, _ := GetProjectRoot()
	if root == "" {
		return nil // nothing to clear
	}

	projectFile := filepath.Join(root, ".agentsecrets", "project.json")
	
	// Check if it exists first
	if _, err := os.Stat(projectFile); os.IsNotExist(err) {
		return nil
	}

	defaultConfig := &ProjectConfig{Environment: "development"}
	return writeJSON(projectFile, defaultConfig, 0644)
}

// GetStorageMode returns the configured storage mode (1: keychain, 2: env_file).
// Resolution order:
// 1. AGENTSECRETS_STORAGE_MODE environment variable
// 2. .agentsecrets/project.json storage_mode
// 3. ~/.agentsecrets/config.json default_storage_mode
// 4. Default to 1 (keychain)
func GetStorageMode() int {
	// 1. Env var
	if env := os.Getenv("AGENTSECRETS_STORAGE_MODE"); env != "" {
		switch env {
		case "2":
			return 2
		case "3":
			return 3
		default:
			return 1
		}
	}

	// 2. Project config
	if pc, err := LoadProjectConfig(); err == nil && pc.StorageMode != 0 {
		return pc.StorageMode
	}

	// 3. Global config
	if gc, err := LoadGlobalConfig(); err == nil && gc.DefaultStorageMode != 0 {
		return gc.DefaultStorageMode
	}

	return 1 // Default to keychain
}

// SetStorageMode updates the default storage mode in the global config.
func SetStorageMode(mode int) error {
	c, err := LoadGlobalConfig()
	if err != nil || c == nil {
		c = &GlobalConfig{}
	}
	c.DefaultStorageMode = mode
	return SaveGlobalConfig(c)
}

// GetOnePasswordVault returns the configured 1Password vault name, or "AgentSecrets" as default.
func GetOnePasswordVault() string {
	c, err := LoadGlobalConfig()
	if err != nil || c.OnePasswordVault == "" {
		return "AgentSecrets"
	}
	return c.OnePasswordVault
}

// SetOnePasswordVault stores the 1Password vault name in the global config.
func SetOnePasswordVault(vault string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.OnePasswordVault = vault
	return SaveGlobalConfig(c)
}

// SetProjectStorageMode updates the storage mode in the local project config.
func SetProjectStorageMode(mode int) error {
	pc, err := LoadProjectConfig()
	if err != nil || pc == nil {
		// If project config doesn't exist, we fallback to global
		// But usually we set this during init
		return nil
	}
	pc.StorageMode = mode
	return SaveProjectConfig(pc)
}

// --- Environment Resolution ---

// ValidEnvironments is the list of valid environment names.
var ValidEnvironments = []string{"development", "staging", "production"}

// IsValidEnvironment returns true if the given string is a valid environment name.
func IsValidEnvironment(env string) bool {
	switch env {
	case "development", "staging", "production":
		return true
	}
	return false
}

// ResolveEnvironment returns the active environment for the current context.
// Resolution order:
// 1. AGENTSECRETS_ENV environment variable
// 2. .agentsecrets/project.json environment field (walk up from cwd)
// 3. ~/.agentsecrets/config.json selected_environment
// 4. "development" (hardcoded default)
func ResolveEnvironment() string {
	env, _ := ResolveEnvironmentWithSource()
	return env
}

// ResolveEnvironmentWithSource returns the active environment and its source.
// Sources: "AGENTSECRETS_ENV", "project.json", "global config", "default"
func ResolveEnvironmentWithSource() (string, string) {
	// 1. Check env var
	if env := os.Getenv("AGENTSECRETS_ENV"); env != "" {
		if !IsValidEnvironment(env) {
			fmt.Fprintf(os.Stderr, "Warning: AGENTSECRETS_ENV=%s is not a valid environment. Using development.\nValid environments: development, staging, production\n", env)
			return "development", "default"
		}
		return env, "AGENTSECRETS_ENV"
	}

	// 2. Check project.json (use existing project root walk-up logic)
	if p, err := LoadProjectConfig(); err == nil && p != nil {
		if p.Environment != "" && IsValidEnvironment(p.Environment) {
			return p.Environment, "project.json"
		}
	}

	// 3. Check global config
	if c, err := LoadGlobalConfig(); err == nil && c != nil {
		if c.SelectedEnvironment != "" && IsValidEnvironment(c.SelectedEnvironment) {
			return c.SelectedEnvironment, "global config"
		}
	}

	// 4. Default
	return "development", "default"
}

// GetSelectedEnvironment returns the globally selected environment.
func GetSelectedEnvironment() string {
	config, err := LoadGlobalConfig()
	if err != nil || config.SelectedEnvironment == "" {
		return "development"
	}
	return config.SelectedEnvironment
}

// SetSelectedEnvironment sets the globally selected environment.
func SetSelectedEnvironment(env string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.SelectedEnvironment = env
	return SaveGlobalConfig(c)
}

// ResolveAPIBaseURL returns the API base URL with the following precedence:
// 1. AGENTSECRETS_API_URL environment variable
// 2. ~/.agentsecrets/config.json api_base_url
// 3. Default hardcoded URL
func ResolveAPIBaseURL() string {
	url, _ := ResolveAPIBaseURLWithSource()
	return url
}

// ResolveAPIBaseURLWithSource returns the API base URL and its source.
// Sources: "AGENTSECRETS_API_URL", "global config", "default"
func ResolveAPIBaseURLWithSource() (string, string) {
	const defaultURL = "https://secrets-api-orpin.vercel.app/api"

	// 1. Check env var
	if url := os.Getenv("AGENTSECRETS_API_URL"); url != "" {
		return url, "AGENTSECRETS_API_URL"
	}

	// 2. Check global config
	if c, err := LoadGlobalConfig(); err == nil && c != nil && c.APIBaseURL != "" {
		return c.APIBaseURL, "global config"
	}

	// 3. Default
	return defaultURL, "default"
}

// SetAPIBaseURL updates the stored API base URL in the global config.
func SetAPIBaseURL(url string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.APIBaseURL = url
	return SaveGlobalConfig(c)
}

// modeOverride lets tests force a mode without touching the on-disk config.
var modeOverride string

// SetModeOverride is used by tests to pin the resolved mode.
// Pass an empty string to clear.
func SetModeOverride(mode string) {
	modeOverride = mode
}

// ResolveMode returns the active mode (ModeOnline or ModeOffline) with this
// precedence:
//  1. Test override via SetModeOverride
//  2. AGENTSECRETS_MODE environment variable
//  3. ~/.agentsecrets/config.json mode field (set by `agentsecrets init`)
//  4. ModeOnline
func ResolveMode() string {
	mode, _ := ResolveModeWithSource()
	return mode
}

// ResolveModeWithSource returns the active mode and the source that supplied it.
// Sources: "override", "AGENTSECRETS_MODE", "global config", "default".
func ResolveModeWithSource() (string, string) {
	if modeOverride != "" {
		return normalizeMode(modeOverride), "override"
	}
	if env := os.Getenv("AGENTSECRETS_MODE"); env != "" {
		return normalizeMode(env), "AGENTSECRETS_MODE"
	}
	if c, err := LoadGlobalConfig(); err == nil && c != nil && c.Mode != "" {
		return normalizeMode(c.Mode), "global config"
	}
	return ModeOnline, "default"
}

// IsOfflineMode is a convenience wrapper around ResolveMode.
func IsOfflineMode() bool {
	return ResolveMode() == ModeOffline
}

// SetMode persists the mode to the global config.
func SetMode(mode string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.Mode = normalizeMode(mode)
	return SaveGlobalConfig(c)
}

func normalizeMode(s string) string {
	switch s {
	case ModeOffline, "off", "local", "single-user":
		return ModeOffline
	default:
		return ModeOnline
	}
}
