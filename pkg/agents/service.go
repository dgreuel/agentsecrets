// Package agents handles agent identity registration, token issuance, and lifecycle management.
package agents

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
)

// Agent represents a registered agent identity.
type Agent struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	WorkspaceID string    `json:"workspace_id"`
	ProjectID   *string   `json:"project_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	TokenCount  int       `json:"token_count"`
	LastUsed    *time.Time`json:"last_used"`
}

// Token represents a token issued to an agent.
type Token struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt *time.Time`json:"expires_at,omitempty"`
	LastUsed  *time.Time`json:"last_used,omitempty"`
	Status    string    `json:"status"` // e.g., "active", "revoked", "expired"
}

// RegisterRequest holds data to register a new agent.
type RegisterRequest struct {
	Name        string `json:"name"`
	WorkspaceID string `json:"-"` // used for routing, not sent in body
	ProjectID   string `json:"project_id,omitempty"`
	Environment string `json:"environment,omitempty"` // development, staging, production
	Label       string `json:"label,omitempty"`
	ExpiresIn   string `json:"expires_in,omitempty"` // e.g., "30d"
}

// RegisterResponse is returned when registering a new agent (contains the cleartext token).
type RegisterResponse struct {
	Agent Agent  `json:"agent"`
	Token string `json:"token"`           // The cleartext token (only shown once)
	Label string `json:"label,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IssueTokenRequest holds data to issue a new token.
type IssueTokenRequest struct {
	Environment string `json:"environment,omitempty"`
	Label       string `json:"label,omitempty"`
	ExpiresIn   string `json:"expires_in,omitempty"`
}

// IssueTokenResponse is returned when issuing a new token.
type IssueTokenResponse struct {
	TokenID   string `json:"token_id"`
	Token     string `json:"token"`           // The cleartext token
	Label     string `json:"label,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Service provides methods to interact with agent resources.
type Service struct {
	client api.Backend
}


func NewService(backend api.Backend) *Service {
	return &Service{client: backend}
}

// Register registers a new agent and issues its first token.
// req.WorkspaceID is required; set req.ProjectID to scope the agent to a project.
func (s *Service) Register(req RegisterRequest) (*RegisterResponse, error) {
	if req.WorkspaceID == "" {
		return nil, fmt.Errorf("WorkspaceID is required to register an agent")
	}

	endpointKey := "agents.register"
	urlParams := map[string]string{"workspace_id": req.WorkspaceID}
	if req.ProjectID != "" {
		endpointKey = "agents.register_project"
		urlParams["project_id"] = req.ProjectID
	}

	resp, err := s.client.Call(endpointKey, "POST", req, urlParams, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to register agent request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, s.client.DecodeError(resp)
	}

	var wrapper struct {
		Data RegisterResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &wrapper.Data, nil
}

// List returns agents scoped to the given workspace (or project if projectID is non-empty).
func (s *Service) List(workspaceID, projectID string) ([]Agent, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("workspaceID is required to list agents")
	}

	endpointKey := "agents.list"
	urlParams := map[string]string{"workspace_id": workspaceID}
	if projectID != "" {
		endpointKey = "agents.list_project"
		urlParams["project_id"] = projectID
	}

	resp, err := s.client.Call(endpointKey, "GET", nil, urlParams, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, s.client.DecodeError(resp)
	}

	var wrapper struct {
		Data []Agent `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return wrapper.Data, nil
}

// GetByName returns an agent by its exact name within the given workspace.
func (s *Service) GetByName(workspaceID, name string) (*Agent, error) {
	agents, err := s.List(workspaceID, "")
	if err != nil {
		return nil, err
	}
	for _, a := range agents {
		if a.Name == name {
			return &a, nil
		}
	}
	return nil, fmt.Errorf("agent '%s' not found in this workspace", name)
}

// TokenIssue issues a new token for an existing agent.
func (s *Service) TokenIssue(workspaceID, registrationID string, req IssueTokenRequest) (*IssueTokenResponse, error) {
	resp, err := s.client.Call("agents.token_issue", "POST", req, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to issue token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, s.client.DecodeError(resp)
	}

	var wrapper struct {
		Data IssueTokenResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &wrapper.Data, nil
}

// TokenList lists all tokens for an agent.
func (s *Service) TokenList(workspaceID, registrationID string) ([]Token, error) {
	resp, err := s.client.Call("agents.token_list", "GET", nil, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, s.client.DecodeError(resp)
	}

	var wrapper struct {
		Data []Token `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return wrapper.Data, nil
}

// TokenRevoke revokes a single token.
func (s *Service) TokenRevoke(workspaceID, registrationID string, tokenID string) error {
	resp, err := s.client.Call("agents.token_revoke", "DELETE", nil, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
		"token_id":        tokenID,
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return s.client.DecodeError(resp)
	}
	return nil
}

// TokenRevokeAll revokes all active tokens for an agent by listing then deleting each.
func (s *Service) TokenRevokeAll(workspaceID, registrationID string) error {
	tokens, err := s.TokenList(workspaceID, registrationID)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Status == "active" {
			if err = s.TokenRevoke(workspaceID, registrationID, t.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Delete revokes all tokens for an agent then deletes the registration.
// This first revokes all active tokens then issues a DELETE to the workspace agent route.
func (s *Service) Delete(workspaceID, registrationID string) error {
	if workspaceID == "" {
		return fmt.Errorf("workspaceID is required to delete an agent")
	}

	if err := s.TokenRevokeAll(workspaceID, registrationID); err != nil {
		return fmt.Errorf("failed to revoke tokens before delete: %w", err)
	}

	resp, err := s.client.Call("agents.delete", "DELETE", nil, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to delete agent registration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return s.client.DecodeError(resp)
	}
	return nil
}
