// Package onepassword integrates with the 1Password CLI (op) to provide
// a secrets backend for AgentSecrets.
//
// Secrets are stored as individual Password items in a dedicated 1Password vault:
//
//	Item title:  agentsecrets/{projectID}/{environment}/{key}
//	Field:       password (type: concealed)
//	Tags:        agentsecrets
//
// Authentication is handled entirely by the op CLI — interactive sessions use
// biometric/system auth, and headless/CI environments use the
// OP_SERVICE_ACCOUNT_TOKEN environment variable (standard 1Password pattern).
// AgentSecrets stores no 1Password credentials of its own.
package onepassword

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Client wraps the 1Password CLI (op) for secret CRUD operations.
type Client struct {
	Vault string // 1Password vault name or ID
}

// NewClient creates a Client targeting the given vault.
// If vault is empty, it defaults to "AgentSecrets".
func NewClient(vault string) *Client {
	if vault == "" {
		vault = "AgentSecrets"
	}
	return &Client{Vault: vault}
}

// IsAvailable reports whether the op CLI is installed and reachable.
func IsAvailable() bool {
	_, err := exec.LookPath("op")
	return err == nil
}

// CheckSignedIn returns nil if the op CLI is signed in to at least one account.
func CheckSignedIn() error {
	_, err := runOP("whoami")
	if err != nil {
		return fmt.Errorf("not signed in to 1Password — run 'op signin' or ensure OP_SERVICE_ACCOUNT_TOKEN is set: %w", err)
	}
	return nil
}

// ListVaults returns the names of all vaults the current account can access.
func ListVaults() ([]string, error) {
	out, err := runOP("vault", "list", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}
	var vaults []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &vaults); err != nil {
		return nil, fmt.Errorf("list vaults: parse: %w", err)
	}
	names := make([]string, len(vaults))
	for i, v := range vaults {
		names[i] = v.Name
	}
	return names, nil
}

// itemTitle constructs the 1Password item title for a given secret.
// projectRef is the human-readable project name (or ID as fallback).
// Format: agentsecrets/{projectRef}/{environment}/{key}
func itemTitle(projectRef, environment, key string) string {
	return fmt.Sprintf("agentsecrets/%s/%s/%s", projectRef, environment, key)
}

// itemPrefix returns the title prefix for all secrets in a project+environment.
func itemPrefix(projectRef, environment string) string {
	return fmt.Sprintf("agentsecrets/%s/%s/", projectRef, environment)
}

// GetSecret retrieves a secret value from 1Password.
func (c *Client) GetSecret(projectID, environment, key string) (string, error) {
	title := itemTitle(projectID, environment, key)
	out, err := runOP("item", "get", title,
		"--vault="+c.Vault,
		"--fields", "label=password",
		"--reveal",
	)
	if err != nil {
		return "", fmt.Errorf("1password get %q: %w", key, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// SetSecret creates or updates a secret in 1Password.
// It attempts an edit first; if the item does not exist, it creates it.
func (c *Client) SetSecret(projectID, environment, key, value string) error {
	title := itemTitle(projectID, environment, key)
	fieldAssignment := "password=" + value

	// Try editing the existing item first (common case for updates).
	_, err := runOP("item", "edit", title,
		"--vault="+c.Vault,
		fieldAssignment,
	)
	if err == nil {
		return nil
	}

	// Item not found — create it.
	_, createErr := runOP("item", "create",
		"--category=password",
		"--title="+title,
		"--vault="+c.Vault,
		"--tags=agentsecrets",
		fieldAssignment,
	)
	if createErr != nil {
		if strings.Contains(createErr.Error(), "(101)") {
			return fmt.Errorf("no write permission for vault %q — run 'agentsecrets 1password setup' and choose a vault you own", c.Vault)
		}
		return fmt.Errorf("1password set %q: edit: %v, create: %w", key, err, createErr)
	}
	return nil
}

// DeleteSecret removes a secret item from 1Password.
func (c *Client) DeleteSecret(projectID, environment, key string) error {
	title := itemTitle(projectID, environment, key)
	_, err := runOP("item", "delete", title, "--vault="+c.Vault)
	if err != nil {
		return fmt.Errorf("1password delete %q: %w", key, err)
	}
	return nil
}

// CheckVaultWritable verifies that the current account can create items in the vault.
// It creates a temporary item and immediately deletes it.
func (c *Client) CheckVaultWritable() error {
	testTitle := "agentsecrets/__write_test__"
	_, err := runOP("item", "create",
		"--category=password",
		"--title="+testTitle,
		"--vault="+c.Vault,
		"password=test",
	)
	if err != nil {
		if strings.Contains(err.Error(), "(101)") {
			return fmt.Errorf("no write permission for vault %q — you need Editor or higher access.\nCreate a personal vault with: op vault create \"AgentSecrets\"", c.Vault)
		}
		return fmt.Errorf("vault %q write test failed: %w", c.Vault, err)
	}
	_, _ = runOP("item", "delete", testTitle, "--vault="+c.Vault)
	return nil
}


type opListItem struct {
	Title string `json:"title"`
}

// ListSecretKeys returns the secret key names for a project+environment.
// It lists all items in the vault and filters by title prefix, avoiding
// any dependency on tag indexing which varies across op CLI versions.
func (c *Client) ListSecretKeys(projectID, environment string) ([]string, error) {
	prefix := itemPrefix(projectID, environment)

	out, err := runOP("item", "list",
		"--vault="+c.Vault,
		"--format=json",
	)
	if err != nil {
		return nil, fmt.Errorf("1password list: %w", err)
	}

	var items []opListItem
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("1password list: parse: %w", err)
	}

	var keys []string
	for _, item := range items {
		if strings.HasPrefix(item.Title, prefix) {
			k := strings.TrimPrefix(item.Title, prefix)
			if k != "" {
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}

// GetAllSecrets returns all secrets for a project+environment as a map.
func (c *Client) GetAllSecrets(projectID, environment string) (map[string]string, error) {
	keys, err := c.ListSecretKeys(projectID, environment)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(keys))
	for _, key := range keys {
		val, err := c.GetSecret(projectID, environment, key)
		if err != nil {
			// Non-fatal: skip unreadable items rather than aborting the whole batch.
			continue
		}
		result[key] = val
	}
	return result, nil
}

// runOP executes the op CLI with the given arguments and returns stdout.
// stderr from a failed run is included in the returned error.
func runOP(args ...string) ([]byte, error) {
	cmd := exec.Command("op", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			if stderr != "" {
				return nil, fmt.Errorf("%s", stderr)
			}
		}
		return nil, err
	}
	return out, nil
}
