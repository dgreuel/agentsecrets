package offline

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Backend is the in-process implementation of api.Backend backed by SQLite.
type Backend struct {
	db *sql.DB
	mu sync.Mutex
}

// New opens (or creates) the offline database at the given path.
// Pass an empty string to use ~/.agentsecrets/offline.db.
func New(dbPath string) (*Backend, error) {
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	return &Backend{db: db}, nil
}

// Close releases the underlying database handle.
func (b *Backend) Close() error {
	if b.db == nil {
		return nil
	}
	return b.db.Close()
}

// DB exposes the underlying database handle for callers that need direct
// access (auth bootstrap, sync). Callers must not close it.
func (b *Backend) DB() *sql.DB { return b.db }

// EnsureLocalUser inserts the single offline user record if one doesn't
// already exist with that email, and returns its id. The auth flow calls this
// during signup so a freshly-installed offline backend has an owner to anchor
// workspaces and audit attribution to.
func (b *Backend) EnsureLocalUser(id, email, publicKey string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var existingID string
	err := b.db.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&existingID)
	if err == nil {
		return existingID, nil
	}
	if _, err := b.db.Exec(
		`INSERT INTO users (id, email, public_key) VALUES (?, ?, ?)`,
		id, email, publicKey,
	); err != nil {
		return "", fmt.Errorf("offline: insert user: %w", err)
	}
	return id, nil
}

// LocalUserExists reports whether the offline DB has any user record. The
// auth-bypass middleware uses it to gate offline-mode commands when the user
// hasn't run `agentsecrets init` yet.
func (b *Backend) LocalUserExists() bool {
	var n int
	_ = b.db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&n)
	return n > 0
}

// Call dispatches a service-layer endpoint key (e.g. "secrets.list") to the
// matching in-process handler and returns a synthetic *http.Response so
// existing service code paths work unchanged.
func (b *Backend) Call(endpointKey, method string, data interface{}, urlParams, queryParams map[string]string) (*http.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	h, ok := handlers[endpointKey]
	if !ok {
		return jsonResponse(http.StatusNotFound, errorBody("offline backend: unknown endpoint "+endpointKey))
	}
	return h(b, method, data, urlParams, queryParams)
}

// DecodeError mirrors api.Client.DecodeError so service code can call it
// without caring which backend it received.
func (b *Backend) DecodeError(resp *http.Response) error {
	var body struct {
		Message string `json:"message"`
		Error   string `json:"error"`
		Detail  string `json:"detail"`
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("offline request failed with status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(bodyBytes, &body); err == nil {
		for _, msg := range []string{body.Message, body.Error, body.Detail} {
			if msg != "" {
				return fmt.Errorf("%s (status %d)", msg, resp.StatusCode)
			}
		}
	}
	snippet := string(bodyBytes)
	if len(snippet) > 100 {
		snippet = snippet[:100] + "..."
	}
	if snippet != "" {
		return fmt.Errorf("offline request failed with status %d: %s", resp.StatusCode, snippet)
	}
	return fmt.Errorf("offline request failed with status %d", resp.StatusCode)
}

// jsonResponse constructs a minimal *http.Response carrying a JSON body.
func jsonResponse(status int, body interface{}) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, fmt.Errorf("offline: encode response: %w", err)
		}
	}
	return &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(&buf),
		ContentLength: int64(buf.Len()),
	}, nil
}

func errorBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}

// decodeData coerces the service-layer `data` argument into a generic map by
// round-tripping through JSON. This matches what a real HTTP request would
// deliver — concretely, typed containers like `map[string]string` become
// `map[string]interface{}` with string-typed values — so handlers can rely on
// a single shape regardless of how the caller spelled the payload.
func decodeData(data interface{}) (map[string]interface{}, error) {
	if data == nil {
		return nil, nil
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("offline: marshal request: %w", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("offline: unmarshal request: %w", err)
	}
	return out, nil
}

// notAvailable returns a 501 Not Implemented response with a friendly message.
// Used for endpoints that inherently require multi-user / cloud infrastructure.
func notAvailable(feature string) handler {
	return func(_ *Backend, _ string, _ interface{}, _, _ map[string]string) (*http.Response, error) {
		return jsonResponse(http.StatusNotImplemented, errorBody(
			feature+" is not available in offline mode. Run with --online or unset AGENTSECRETS_MODE to use the cloud backend.",
		))
	}
}

// asString safely extracts a string field from a map[string]interface{}.
func asString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// joinPath is used for tests / future routing if needed.
func joinPath(parts ...string) string {
	return strings.Join(parts, "/")
}

// handler is the signature for every endpoint implementation.
type handler func(b *Backend, method string, data interface{}, urlParams, queryParams map[string]string) (*http.Response, error)
