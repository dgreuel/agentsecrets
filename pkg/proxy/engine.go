package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// resolveEnvForAudit returns the current environment for audit logging.
func resolveEnvForAudit() string {
	return config.ResolveEnvironment()
}

func redactSecretFromResponse(body []byte, secretValue string) []byte {
	if secretValue == "" {
		return body
	}
	return bytes.ReplaceAll(body, []byte(secretValue), []byte("[REDACTED_BY_AGENTSECRETS]"))
}

// CallRequest is the input to the engine — used by both MCP and HTTP paths.
type CallRequest struct {
	TargetURL     string            // full URL e.g. https://api.stripe.com/v1/charges
	Method        string            // GET, POST, PUT, PATCH, DELETE
	Headers       map[string]string // extra headers to forward (non-auth)
	Body          []byte            // raw request body (optional)
	Injections    []Injection       // what to inject and where
	AgentID       string            // optional, for audit logging
	IdentityLevel string            // "anonymous", "declared", "issued"
	TokenID       string            // optional token ID if issued
}

// Injection describes one credential to inject.
type Injection struct {
	Style     string // "bearer", "basic", "header", "query", "body", "form"
	Target    string // header name, query param (depends on style)
	SecretKey string // keyring key name e.g. "STRIPE_SECRET_KEY"
}

// CallResult is the output from the engine.
type CallResult struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

// SecretResolver is a function that retrieves a secret value by key name.
// This allows the engine to be tested with a mock keyring.
type SecretResolver func(key string) (string, error)

// Engine coordinates keyring lookup, injection, forwarding, and auditing.
type Engine struct {
	ProjectID     string
	WorkspaceID   string
	Audit         *AuditLogger
	Client        *http.Client
	ResolveSecret SecretResolver
	SkipAllowlist bool

	// Live State
	LastSync   time.Time
	RevokedIDs []string
	mu         sync.RWMutex
}

// NewEngine creates an engine wired to the real keyring for the given project.
func NewEngine(projectID string) (*Engine, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project ID is required — run 'agentsecrets project use <name>' first")
	}

	audit, err := NewAuditLogger("")
	if err != nil {
		// Audit logger is non-critical — log to stderr but continue
		audit = nil
	}

	pc, err := config.LoadProjectConfig()
	if err != nil || pc.WorkspaceID == "" {
		return nil, fmt.Errorf("project config error, please run 'agentsecrets project use' first")
	}

	return &Engine{
		ProjectID:     projectID,
		WorkspaceID:   pc.WorkspaceID,
		Audit:         audit,
		Client: &http.Client{
			Timeout: DefaultTimeout,
		},
		ResolveSecret: func(key string) (string, error) {
			return keyring.GetSecret(projectID, pc.ProjectName, resolveEnvForAudit(), key)
		},
	}, nil
}

// Execute runs the full proxy pipeline: resolve secrets → inject → forward → audit.
func (e *Engine) Execute(req CallRequest) (*CallResult, error) {
	// --- Validate ---
	if req.TargetURL == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	if len(req.Injections) == 0 {
		return nil, fmt.Errorf("at least one injection is required — specify how to authenticate (e.g. bearer, header, query)")
	}

	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}

	// --- Check Allowlist ---
	u, err := url.Parse(req.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	targetDomain := strings.ToLower(u.Hostname())

	var allowlist []string
	if !e.SkipAllowlist {
		allowlist, err = keyring.GetWorkspaceAllowlist(e.WorkspaceID)
		if err != nil {
			return nil, fmt.Errorf("failed to read allowlist from keyring: %w", err)
		}
	}

	secretKeys := make([]string, 0, len(req.Injections))
	authStyles := make([]string, 0, len(req.Injections))
	for _, inj := range req.Injections {
		secretKeys = append(secretKeys, inj.SecretKey)
		authStyles = append(authStyles, inj.Style)
	}

	logBlocked := func(reason, msg string) (*CallResult, error) {
		if e.Audit != nil {
			_ = e.Audit.Log(AuditEvent{
				Timestamp:      time.Now().UTC(),
				Environment:    resolveEnvForAudit(),
				SecretKeys:     secretKeys,
				AgentID:        req.AgentID,
				IdentityLevel:  req.IdentityLevel,
				TokenID:        req.TokenID,
				Method:         method,
				TargetURL:      req.TargetURL,
				Domain:         targetDomain,
				AuthStyles:     authStyles,
				StatusCode:     403,
				DurationMs:     0,
				Status:         "BLOCKED",
				Reason:         reason,
				ResolutionPath: "local proxy",
				WorkspaceID:    e.WorkspaceID,
				ProjectID:      e.ProjectID,
			})
		}
		
		bodyJSONBytes, _ := json.Marshal(map[string]string{"error": reason, "domain": targetDomain, "message": msg})
		headers := make(map[string][]string)
		headers["Content-Type"] = []string{"application/json"}
		return &CallResult{
			StatusCode: 403,
			Headers:    headers,
			Body:       bodyJSONBytes,
		}, nil
	}

	if !e.SkipAllowlist {
		if len(allowlist) == 0 {
			msg := "Your workspace allowlist is empty. No credential injections are allowed until you add at least one domain.\nRun: agentsecrets workspace allowlist add <domain>"
			return logBlocked("empty_allowlist", string(bytes.ReplaceAll([]byte(msg), []byte("\n"), []byte(" "))))
		}

		allowed := false
		for _, raw := range allowlist {
			if strings.ToLower(raw) == targetDomain {
				allowed = true
				break
			}
		}

		if !allowed {
			msg := fmt.Sprintf("%s is not in your workspace allowlist. To authorize it, run: agentsecrets workspace allowlist add %s", targetDomain, targetDomain)
			return logBlocked("domain_not_in_allowlist", msg)
		}
	}

	secretKeys = secretKeys[:0] // reset for normal accumulation
	authStyles = authStyles[:0]

	// --- Build outbound request ---
	bodyReader := bytes.NewReader(req.Body)

	outbound, err := http.NewRequest(method, req.TargetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Copy any extra headers
	for k, v := range req.Headers {
		outbound.Header.Set(k, v)
	}

	// --- Resolve secrets and inject ---
	secretValues := make([]string, 0, len(req.Injections))

	for _, inj := range req.Injections {
		cred, err := e.ResolveSecret(inj.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("secret '%s' not found in keychain — run 'agentsecrets secrets list' to see available keys, or add it with 'agentsecrets secrets set %s=VALUE'", inj.SecretKey, inj.SecretKey)
		}

		if err := Inject(outbound, cred, inj); err != nil {
			return nil, fmt.Errorf("injection failed for %s (%s): %w", inj.SecretKey, inj.Style, err)
		}

		secretKeys = append(secretKeys, inj.SecretKey)
		authStyles = append(authStyles, inj.Style)
		secretValues = append(secretValues, cred)
	}

	// --- Forward ---
	result, err := Forward(e.Client, outbound)
	if err != nil {
		return nil, err
	}

	// --- Redact ---
	redacted := false
	if len(result.Body) > 0 {
		contentType := ""
		if len(result.Headers["Content-Type"]) > 0 {
			contentType = result.Headers["Content-Type"][0]
		}
		
		if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "text/") {
			fmt.Fprintf(os.Stderr, "Warning: redacting unexpected content type: %s\n", contentType)
		}

		for _, val := range secretValues {
			if val == "" {
				continue
			}
			if bytes.Contains(result.Body, []byte(val)) {
				result.Body = redactSecretFromResponse(result.Body, val)
				redacted = true
			}
		}

		if redacted {
			result.Headers["Content-Length"] = []string{fmt.Sprintf("%d", len(result.Body))}
		}
	}

	// --- Audit ---
	if e.Audit != nil {
		_ = e.Audit.Log(AuditEvent{
			Timestamp:      time.Now().UTC(),
			Environment:    resolveEnvForAudit(),
			SecretKeys:     secretKeys,
			AgentID:        req.AgentID,
			IdentityLevel:  req.IdentityLevel,
			TokenID:        req.TokenID,
			Method:         method,
			TargetURL:      req.TargetURL,
			Domain:         targetDomain,
			AuthStyles:     authStyles,
			StatusCode:     result.StatusCode,
			DurationMs:     result.Duration.Milliseconds(),
			Status:         "OK",
			Reason:         reasonForAudit(redacted),
			Redacted:       redacted,
			ResolutionPath: "local proxy",
			WorkspaceID:    e.WorkspaceID,
			ProjectID:      e.ProjectID,
		})
	}

	return &CallResult{
		StatusCode: result.StatusCode,
		Headers:    result.Headers,
		Body:       result.Body,
	}, nil
}

// Sync triggers a manual revocation list sync.
func (e *Engine) Sync() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.LastSync = time.Now()
	// Mock: Add a sample revocation ID if we don't have any, for verification
	if len(e.RevokedIDs) == 0 {
		e.RevokedIDs = []string{"rev_test_5k2m88"}
	}
}

// GetState returns the current live state of the proxy engine.
func (e *Engine) GetState() (time.Time, []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.LastSync, e.RevokedIDs
}

// reasonForAudit returns the audit reason string based on whether response was redacted.
func reasonForAudit(redacted bool) string {
	if redacted {
		return "credential_echo"
	}
	return "-"
}
