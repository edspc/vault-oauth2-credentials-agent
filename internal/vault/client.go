// Package vault implements the small part of the HashiCorp Vault HTTP API the
// agent needs: logging in with one of three auth methods, keeping the client
// token alive, and reading and writing KV v2 secrets.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Authentication methods supported by the client.
const (
	MethodToken      = "token"
	MethodAppRole    = "approle"
	MethodKubernetes = "kubernetes"
)

// maxResponseBody bounds how much of a Vault response is read into memory.
const maxResponseBody = 4 << 20

// Config describes how to reach and authenticate against Vault.
type Config struct {
	Address   string
	Namespace string
	Timeout   time.Duration
	Auth      AuthConfig
}

// AuthConfig selects the authentication method and its parameters.
type AuthConfig struct {
	Method     string
	Token      string
	AppRole    AppRoleConfig
	Kubernetes KubernetesConfig
}

// AppRoleConfig configures an auth/approle login.
type AppRoleConfig struct {
	Mount    string
	RoleID   string
	SecretID string
}

// KubernetesConfig configures an auth/kubernetes login.
type KubernetesConfig struct {
	Mount   string
	Role    string
	JWTPath string
}

// Client is a Vault API client holding a single client token.
type Client struct {
	address    string
	namespace  string
	httpClient *http.Client
	logger     *slog.Logger
	now        func() time.Time

	login loginFunc
	// canRelogin reports whether a fresh token can be obtained on demand.
	// A statically configured token cannot be reissued by the agent.
	canRelogin bool

	mu        sync.RWMutex
	token     string
	lease     time.Duration
	renewable bool
	// issuedAt is when the current token was obtained or last renewed.
	issuedAt time.Time
}

// loginFunc obtains a fresh client token.
type loginFunc func(ctx context.Context, c *Client) (*authInfo, error)

// authInfo is the outcome of a successful login or renewal.
type authInfo struct {
	Token     string
	Lease     time.Duration
	Renewable bool
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client, mainly for tests.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		if c != nil {
			cl.httpClient = c
		}
	}
}

// WithLogger sets the logger used by the token renewal loop.
func WithLogger(l *slog.Logger) Option {
	return func(cl *Client) {
		if l != nil {
			cl.logger = l
		}
	}
}

// WithClock overrides the clock. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(cl *Client) {
		if now != nil {
			cl.now = now
		}
	}
}

// New builds a Client for cfg. It does not contact Vault; call Login first.
func New(cfg Config, opts ...Option) (*Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: address must not be empty")
	}
	if _, err := url.Parse(cfg.Address); err != nil {
		return nil, fmt.Errorf("vault: invalid address %q: %w", cfg.Address, err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c := &Client{
		address:    strings.TrimSuffix(cfg.Address, "/"),
		namespace:  cfg.Namespace,
		httpClient: &http.Client{Timeout: timeout},
		logger:     slog.Default(),
		now:        time.Now,
	}
	login, err := newLoginFunc(cfg.Auth)
	if err != nil {
		return nil, err
	}
	c.login = login
	c.canRelogin = cfg.Auth.Method != MethodToken
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Login authenticates against Vault and stores the resulting client token.
func (c *Client) Login(ctx context.Context) error {
	auth, err := c.login(ctx, c)
	if err != nil {
		return err
	}
	c.setAuth(auth)
	c.logger.Info("authenticated to vault",
		slog.Duration("lease", auth.Lease),
		slog.Bool("renewable", auth.Renewable))
	return nil
}

// Authenticated reports whether the client currently holds a token.
func (c *Client) Authenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token != ""
}

func (c *Client) setAuth(auth *authInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = auth.Token
	c.lease = auth.Lease
	c.renewable = auth.Renewable
	c.issuedAt = c.now()
}

func (c *Client) currentToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// request performs a Vault API call with the currently held client token.
func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	return c.do(ctx, method, path, c.currentToken(), body, out)
}

// do performs a Vault API call authenticated with the given token, which may
// be empty for unauthenticated endpoints such as the login routes. body, when
// non-nil, is JSON-encoded; out, when non-nil, receives the decoded response.
func (c *Client) do(ctx context.Context, method, path, token string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vault: encode request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.address+path, reader)
	if err != nil {
		return fmt.Errorf("vault: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return fmt.Errorf("vault: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return newAPIError(resp.StatusCode, raw)
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("vault: decode response of %s %s: %w", method, path, err)
	}
	return nil
}

// requestWithReauth runs request and, if the token was rejected, logs in once
// more and retries. This covers a token that expired or was revoked between
// two calls.
func (c *Client) requestWithReauth(ctx context.Context, method, path string, body, out any) error {
	err := c.request(ctx, method, path, body, out)
	if err == nil || !isPermissionDenied(err) {
		return err
	}
	c.logger.Warn("vault rejected the client token, authenticating again",
		slog.String("path", path))
	if loginErr := c.Login(ctx); loginErr != nil {
		return fmt.Errorf("%w (re-login failed: %v)", err, loginErr)
	}
	return c.request(ctx, method, path, body, out)
}

func newAPIError(status int, body []byte) error {
	apiErr := &APIError{StatusCode: status}
	var payload struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		apiErr.Errors = payload.Errors
	}
	return apiErr
}

// TokenValid reports whether the client holds a token that has not expired
// according to its last known lease. It backs the readiness probe: once the
// renewal loop stops keeping up, the agent stops reporting itself as ready.
func (c *Client) TokenValid() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token == "" {
		return false
	}
	if c.lease <= 0 {
		return true
	}
	return c.now().Before(c.issuedAt.Add(c.lease))
}

// TokenExpiry reports when the current client token expires. It returns the
// zero time when no token is held or when the token has no lease.
func (c *Client) TokenExpiry() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token == "" || c.lease <= 0 {
		return time.Time{}
	}
	return c.issuedAt.Add(c.lease)
}
