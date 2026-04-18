package offline

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func newTestBackend(t *testing.T) *Backend {
	t.Helper()
	be, err := New(filepath.Join(t.TempDir(), "offline.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	return be
}

func decodeBody(t *testing.T, resp *http.Response, target interface{}) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		return
	}
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode body %q: %v", string(body), err)
	}
}

func TestSecretsCRUD(t *testing.T) {
	be := newTestBackend(t)
	pid := "proj-1"

	// Empty list returns an empty slice, not null.
	resp, err := be.Call("secrets.list", "GET", nil, map[string]string{"project_id": pid}, map[string]string{"environment": "development"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	var listResp struct {
		Data struct {
			Secrets []struct {
				Key, Value string
			} `json:"secrets"`
		} `json:"data"`
	}
	decodeBody(t, resp, &listResp)
	if len(listResp.Data.Secrets) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(listResp.Data.Secrets))
	}

	// Bulk upsert.
	resp, err = be.Call("secrets.create", "POST", map[string]interface{}{
		"project_id":  pid,
		"environment": "development",
		"secrets":     map[string]interface{}{"FOO": "bar", "BAZ": "qux"},
	}, nil, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}

	// List should now show two entries.
	resp, _ = be.Call("secrets.list", "GET", nil, map[string]string{"project_id": pid}, map[string]string{"environment": "development"})
	decodeBody(t, resp, &listResp)
	if len(listResp.Data.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(listResp.Data.Secrets))
	}

	// Get a single secret.
	resp, _ = be.Call("secrets.get", "GET", nil, map[string]string{
		"project_id": pid, "environment": "development", "key": "FOO",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", resp.StatusCode)
	}
	var getResp struct {
		Data struct{ Value string } `json:"data"`
	}
	decodeBody(t, resp, &getResp)
	if getResp.Data.Value != "bar" {
		t.Fatalf("get value = %q, want %q", getResp.Data.Value, "bar")
	}

	// Delete it.
	resp, _ = be.Call("secrets.delete", "DELETE", nil, map[string]string{
		"project_id": pid, "environment": "development", "key": "FOO",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}

	// 404 for missing key after delete.
	resp, _ = be.Call("secrets.get", "GET", nil, map[string]string{
		"project_id": pid, "environment": "development", "key": "FOO",
	}, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("post-delete get status = %d, want 404", resp.StatusCode)
	}

	// Different environments are isolated.
	resp, _ = be.Call("secrets.list", "GET", nil,
		map[string]string{"project_id": pid},
		map[string]string{"environment": "production"})
	decodeBody(t, resp, &listResp)
	if len(listResp.Data.Secrets) != 0 {
		t.Fatalf("production env expected empty, got %d", len(listResp.Data.Secrets))
	}
}

func TestProjectsAndWorkspaceFlow(t *testing.T) {
	be := newTestBackend(t)

	// A workspace requires a user (offline pins ownership to the local user).
	if _, err := be.EnsureLocalUser("user-1", "me@example.com", ""); err != nil {
		t.Fatalf("EnsureLocalUser: %v", err)
	}

	// Create workspace.
	resp, _ := be.Call("workspaces.create", "POST", map[string]interface{}{"name": "Personal"}, nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("workspace create status = %d", resp.StatusCode)
	}
	var wsResp struct {
		Data struct{ ID string } `json:"data"`
	}
	decodeBody(t, resp, &wsResp)
	if wsResp.Data.ID == "" {
		t.Fatal("expected workspace id in response")
	}
	wsID := wsResp.Data.ID

	// Create project in that workspace.
	resp, _ = be.Call("projects.create", "POST", map[string]interface{}{
		"name": "demo", "workspace_id": wsID, "description": "test",
	}, nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("project create status = %d", resp.StatusCode)
	}

	// Get by name.
	resp, _ = be.Call("projects.get", "GET", nil, map[string]string{
		"workspace_id": wsID, "project_name": "demo",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("project get status = %d", resp.StatusCode)
	}
	var pResp struct {
		Data struct {
			ID, Name, Description string
		} `json:"data"`
	}
	decodeBody(t, resp, &pResp)
	if pResp.Data.Name != "demo" {
		t.Fatalf("project name = %q", pResp.Data.Name)
	}
}

func TestStubsReturn501(t *testing.T) {
	be := newTestBackend(t)

	for _, ep := range []string{
		"workspaces.invite",
		"workspaces.members",
		"projects.invite",
		"agents.register",
		"users.public_key",
		"log.list",
	} {
		resp, err := be.Call(ep, "GET", nil, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", ep, err)
		}
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("%s: status = %d, want 501", ep, resp.StatusCode)
		}
		// The DecodeError should surface the user-friendly message.
		if msg := be.DecodeError(resp).Error(); !strings.Contains(msg, "offline mode") {
			t.Errorf("%s: error = %q, want offline-mode message", ep, msg)
		}
	}
}

// Regression: BatchSet hands us `"secrets": map[string]string{...}` rather
// than `map[string]interface{}`. The handler must treat both as equivalent
// because that's what a real HTTP request would deliver.
func TestSecretsCreateAcceptsTypedStringMap(t *testing.T) {
	be := newTestBackend(t)
	resp, err := be.Call("secrets.create", "POST", map[string]interface{}{
		"project_id":  "proj-typed",
		"environment": "development",
		"secrets":     map[string]string{"A": "1", "B": "2"},
	}, nil, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}

	resp, _ = be.Call("secrets.list", "GET", nil,
		map[string]string{"project_id": "proj-typed"},
		map[string]string{"environment": "development"})
	var listResp struct {
		Data struct {
			Secrets []struct{ Key, Value string } `json:"secrets"`
		} `json:"data"`
	}
	decodeBody(t, resp, &listResp)
	if len(listResp.Data.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(listResp.Data.Secrets))
	}
}

func TestUnknownEndpoint(t *testing.T) {
	be := newTestBackend(t)
	resp, _ := be.Call("nope.nope", "GET", nil, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAllowlistRoundtrip(t *testing.T) {
	be := newTestBackend(t)
	if _, err := be.EnsureLocalUser("u1", "me@example.com", ""); err != nil {
		t.Fatalf("EnsureLocalUser: %v", err)
	}
	wsID := "ws-1"

	resp, _ := be.Call("workspaces.allowlist_add", "POST", map[string]interface{}{
		"domains": []interface{}{"api.stripe.com", "api.openai.com"},
	}, map[string]string{"workspace_id": wsID}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("allowlist add status = %d", resp.StatusCode)
	}

	resp, _ = be.Call("workspaces.allowlist_list", "GET", nil, map[string]string{"workspace_id": wsID}, nil)
	var listResp struct {
		Data []struct {
			Domain  string `json:"domain"`
			AddedBy string `json:"added_by_email"`
		} `json:"data"`
	}
	decodeBody(t, resp, &listResp)
	if len(listResp.Data) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(listResp.Data))
	}

	resp, _ = be.Call("workspaces.allowlist_remove", "DELETE", nil, map[string]string{
		"workspace_id": wsID, "domain": "api.stripe.com",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowlist remove status = %d", resp.StatusCode)
	}

	resp, _ = be.Call("workspaces.allowlist_log", "GET", nil, map[string]string{"workspace_id": wsID}, nil)
	var logResp struct {
		Data []struct {
			Action, Domain string
		} `json:"data"`
	}
	decodeBody(t, resp, &logResp)
	// Two ADDED + one REMOVED = 3 entries.
	if len(logResp.Data) != 3 {
		t.Fatalf("expected 3 log rows, got %d", len(logResp.Data))
	}
}
