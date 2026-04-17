// Package secrets orchestrates encrypted secret storage, retrieval, and synchronisation with the cloud API.
package secrets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// Service coordinates all secret-related operations.
type Service struct {
	API *api.Client
	Env *EnvManager
}

// NewService creates a new secrets service.
func NewService(apiClient *api.Client) *Service {
	return &Service{
		API: apiClient,
		Env: NewEnvManager(),
	}
}

// Set adds or updates a single secret.
func (s *Service) Set(key, value string) error {
	return s.BatchSet(map[string]string{key: value}, "")
}

// BatchSet adds or updates multiple secrets in a single API call.
// If environment is empty, it uses the currently resolved environment.
func (s *Service) BatchSet(kv map[string]string, environment string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("batch set: no project configured in current directory")
	}

	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return fmt.Errorf("batch set: %w", err)
	}

	env := environment
	if env == "" {
		env = config.ResolveEnvironment()
	}
	
	apiSecrets := make(map[string]string)
	for k, v := range kv {
		// 1. Encrypt for cloud
		encryptedValue, err := crypto.EncryptSecret(v, workspaceKey)
		if err != nil {
			return fmt.Errorf("batch set: encryption failed for %s: %w", k, err)
		}
		apiSecrets[k] = encryptedValue

		// 2. Store in OS Keychain (for Proxy support)
		_ = keyring.SetSecret(project.ProjectID, project.ProjectName, env, k, v)
	}

	// 3. Sync to cloud (Single bulk call with dictionary)
	data := map[string]interface{}{
		"project_id":  project.ProjectID,
		"environment": env,
		"secrets":     apiSecrets,
	}

	resp, err := s.API.Call("secrets.create", "POST", data, nil, nil)
	if err != nil {
		return fmt.Errorf("batch set: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	// 4. Write to .env
	if err := s.Env.Write(kv); err != nil {
		return fmt.Errorf("batch set: failed to update .env: %w", err)
	}

	// Update .env.example
	_ = s.UpdateEnvExample()

	return nil
}

// BatchSetLocal updates local storage (keychain and .env) without calling the API.
// Used during merge/copy flows if needed, or by Pull.
func (s *Service) BatchSetLocal(kv map[string]string, env string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("batch set local: no project configured")
	}

	for k, v := range kv {
		_ = keyring.SetSecret(project.ProjectID, project.ProjectName, env, k, v)
	}
	
	// We only write to .env if the environment matches the current active one
	if env == config.ResolveEnvironment() {
		_ = s.Env.Write(kv)
	}
	
	_ = s.UpdateEnvExample()
	return nil
}

// Get retrieves and decrypts a single secret.
func (s *Service) Get(key string) (string, error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return "", fmt.Errorf("get secret: no project configured in current directory")
	}

	env := config.ResolveEnvironment()

	// Try keychain first (fast paths)
	if val, err := keyring.GetSecret(project.ProjectID, project.ProjectName, env, key); err == nil {
		return val, nil
	}

	// Fallback to API
	resp, err := s.API.Call("secrets.get", "GET", nil, map[string]string{
		"project_id":  project.ProjectID,
		"environment": env,
		"key":         key,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("get secret: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", s.API.DecodeError(resp)
	}

	var res struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("get secret: decode response: %w", err)
	}

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return "", err
	}

	plaintext, err := crypto.DecryptSecret(res.Data.Value, wsKey)
	if err != nil {
		return "", fmt.Errorf("get secret: decrypt: %w", err)
	}

	// Cache in keychain
	_ = keyring.SetSecret(project.ProjectID, project.ProjectName, env, key, plaintext)

	return plaintext, nil
}

// SecretMetadata holds the secret metadata from the API.
type SecretMetadata struct {
	Key       string `json:"key"`
	Value     string `json:"value,omitempty"` // Encrypted value
	UpdatedAt string `json:"updated_at"`
}

// List returns all secret keys for the project in the active environment.
func (s *Service) List() ([]SecretMetadata, error) {
	return s.ListForEnv(config.ResolveEnvironment())
}

// ListForEnv returns all secret keys for the project in the specified environment.
func (s *Service) ListForEnv(env string) ([]SecretMetadata, error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return nil, fmt.Errorf("list secrets: no project configured in current directory")
	}

	resp, err := s.API.Call("secrets.list", "GET", nil, map[string]string{
		"project_id": project.ProjectID,
	}, map[string]string{
		"environment": env,
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var res struct {
		Data struct {
			Secrets []SecretMetadata `json:"secrets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("list secrets: failed to parse response: %w", err)
	}

	return res.Data.Secrets, nil
}

// Pull downloads secrets from the cloud and updates .env + Keychain.
// If targetKeys is nil, all secrets are pulled.
// If targetKeys is non-nil (even if empty), only those specific keys are pulled.
func (s *Service) Pull(targetKeys []string) error {
	isSelective := targetKeys != nil
	if isSelective && len(targetKeys) == 0 {
		return nil
	}

	secrets, err := s.List()
	if err != nil {
		return err
	} 

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return err
	}
	filter := make(map[string]bool)
	for _, k := range targetKeys {
		filter[k] = true
	}

	project, _ := config.LoadProjectConfig()
	env := config.ResolveEnvironment()
	mode := config.GetStorageMode()
	secretsMap := make(map[string]string)
	for _, s := range secrets {
		if isSelective && !filter[s.Key] {
			continue
		}
		plaintext, err := crypto.DecryptSecret(s.Value, wsKey)
		if err != nil {
			continue
		}
		secretsMap[s.Key] = plaintext
		if setErr := keyring.SetSecret(project.ProjectID, project.ProjectName, env, s.Key, plaintext); setErr != nil && mode == 3 {
			return fmt.Errorf("pull: write %q to 1Password: %w", s.Key, setErr)
		}
	}

	if isSelective && len(secretsMap) == 0 {
		// Even if empty, we want to ensure .env footprint is laid down
	}

	if err := s.Env.Write(secretsMap); err != nil {
		return fmt.Errorf("pull: failed to update local files: %w", err)
	}

	// Update project last_pull timestamp
	project.LastPull = time.Now().Format(time.RFC3339)
	_ = config.SaveProjectConfig(project)

	_ = s.UpdateEnvExample()
	return nil
}

// Push uploads all local secrets (.env or keychain) to the cloud.
func (s *Service) Push() error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("push secrets: no project configured in current directory")
	}

	var localSecrets map[string]string
	env := config.ResolveEnvironment()

	if config.GetStorageMode() != 2 {
		localSecrets, err = keyring.GetAllProjectSecrets(project.ProjectID, project.ProjectName, env)
	} else {
		localSecrets, err = s.Env.Read()
	}

	if err != nil {
		return err
	}

	if len(localSecrets) == 0 {
		return nil
	}

	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return fmt.Errorf("push secrets: %w", err)
	}

	apiSet := make(map[string]string)
	for k, v := range localSecrets {
		encrypted, err := crypto.EncryptSecret(v, workspaceKey)
		if err != nil {
			return fmt.Errorf("push secrets: encryption failed for key %s: %w", k, err)
		}
		apiSet[k] = encrypted
		
		// 1. Sync to keychain
		_ = keyring.SetSecret(project.ProjectID, project.ProjectName, env, k, v)
	}

	// 2. Sync to cloud (Bulk dictionary format)
	data := map[string]interface{}{
		"project_id":  project.ProjectID,
		"environment": env,
		"secrets":     apiSet,
	}

	resp, err := s.API.Call("secrets.create", "POST", data, nil, nil)
	if err != nil {
		return fmt.Errorf("push secrets: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	// Update project last_push timestamp
	project.LastPush = time.Now().Format(time.RFC3339)
	_ = config.SaveProjectConfig(project)

	_ = s.UpdateEnvExample()
	return nil
}

// Delete removes a secret from cloud, .env, and Keychain.
func (s *Service) Delete(key string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("delete secret: no project configured in current directory")
	}

	// 1. Delete from API
	env := config.ResolveEnvironment()
	resp, err := s.API.Call("secrets.delete", "DELETE", nil, map[string]string{
		"project_id":  project.ProjectID,
		"environment": env,
		"key":         key,
	}, nil)
	if err != nil {
		return fmt.Errorf("delete secret: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	// 2. Delete from .env
	if err := s.Env.Delete(key); err != nil {
		return fmt.Errorf("delete secret: failed to update .env: %w", err)
	}

	// 3. Delete from Keychain
	_ = keyring.DeleteSecret(project.ProjectID, project.ProjectName, env, key)

	_ = s.UpdateEnvExample()
	return nil
}

// DiffResult holds the differences between local and cloud secrets.
type DiffResult struct {
	Added    []string            // Keys only in .env
	Removed  []string            // Keys only in Cloud
	Changed  map[string][2]string // Key -> [LocalVal, CloudVal]
	Unchanged []string
}


// Diff returns the differences between a source and a target.
// If fromEnv is "", source is local (.env or keychain).
// If toEnv is "", target is cloud active environment.
func (s *Service) Diff(fromEnv, toEnv string) (*DiffResult, error) {
	var source map[string]string
	var target map[string]string
	var err error

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return nil, err
	}

	// 1. Resolve Source
	if fromEnv != "" {
		// Source is Cloud(fromEnv)
		list, err := s.ListForEnv(fromEnv)
		if err != nil {
			return nil, err
		}
		source = make(map[string]string)
		for _, m := range list {
			if p, err := crypto.DecryptSecret(m.Value, wsKey); err == nil {
				source[m.Key] = p
			}
		}
	} else {
		// Source is Local
		if config.GetStorageMode() != 2 {
			project, _ := config.LoadProjectConfig()
			env := config.ResolveEnvironment()
			source, err = keyring.GetAllProjectSecrets(project.ProjectID, project.ProjectName, env)
		} else {
			source, err = s.Env.Read()
		}
		if err != nil {
			return nil, err
		}
	}

	// 2. Resolve Target
	targetEnv := toEnv
	if targetEnv == "" {
		targetEnv = config.ResolveEnvironment()
	}
	list, err := s.ListForEnv(targetEnv)
	if err != nil {
		return nil, err
	}
	target = make(map[string]string)
	for _, m := range list {
		if p, err := crypto.DecryptSecret(m.Value, wsKey); err == nil {
			target[m.Key] = p
		}
	}

	// 3. Compare Source vs Target
	res := &DiffResult{
		Changed: make(map[string][2]string),
	}

	for k, v := range source {
		if targetVal, ok := target[k]; ok {
			if v != targetVal {
				res.Changed[k] = [2]string{v, targetVal}
			} else {
				res.Unchanged = append(res.Unchanged, k)
			}
			delete(target, k)
		} else {
			res.Added = append(res.Added, k)
		}
	}

	// Remaining keys in target are removed in source (relative to target)
	for k := range target {
		res.Removed = append(res.Removed, k)
	}

	return res, nil
}

// UpdateEnvExample fetches secrets across development, staging, and production 
// and regenerates .env.example with correct environment scopes.
func (s *Service) UpdateEnvExample() error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return nil
	}
	
	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return err
	}

	environments := []string{"development", "staging", "production"}
	keyEnvValues := make(map[string]map[string]string)
	allKeys := make(map[string]bool)

	for _, env := range environments {
		resp, err := s.API.Call("secrets.list", "GET", nil, map[string]string{
			"project_id": project.ProjectID,
		}, map[string]string{
			"environment": env,
		})
		
		if err == nil && resp.StatusCode == http.StatusOK {
			var res struct {
				Data struct {
					Secrets []SecretMetadata `json:"secrets"`
				} `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&res); err == nil {
				for _, secret := range res.Data.Secrets {
					if plaintext, err := crypto.DecryptSecret(secret.Value, wsKey); err == nil {
						if keyEnvValues[secret.Key] == nil {
							keyEnvValues[secret.Key] = make(map[string]string)
						}
						keyEnvValues[secret.Key][env] = plaintext
						allKeys[secret.Key] = true
					}
				}
			}
			resp.Body.Close()
		}
	}

	var lines []string
	lines = append(lines, "# AgentSecrets — generated by agentsecrets secrets pull")
	lines = append(lines, "# Keys marked [all] exist in all three environments")
	lines = append(lines, "# Environment-specific keys show which environments they belong to\n")

	for key := range allKeys {
		envsMap := keyEnvValues[key]
		
		valDev, hasDev := envsMap["development"]
		valStg, hasStg := envsMap["staging"]
		valPrd, hasPrd := envsMap["production"]

		allThree := hasDev && hasStg && hasPrd
		sameValue := allThree && (valDev == valStg) && (valStg == valPrd)

		var annotation string
		if sameValue {
			annotation = "[all]"
		} else {
			var segments []string
			if hasDev { segments = append(segments, "[development]") }
			if hasStg { segments = append(segments, "[staging]") }
			if hasPrd { segments = append(segments, "[production]") }
			annotation = strings.Join(segments, " ")
		}

		lines = append(lines, fmt.Sprintf("%-24s # %s", key+"=", annotation))
	}

	return s.Env.WriteEnvExample(strings.Join(lines, "\n") + "\n")
}
