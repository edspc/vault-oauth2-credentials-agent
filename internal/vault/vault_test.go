package vault

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestClient(t *testing.T, address string, auth AuthConfig) *Client {
	t.Helper()
	client, err := New(Config{Address: address, Auth: auth}, WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func TestLoginWithToken(t *testing.T) {
	var gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			t.Errorf("path = %q, want the lookup-self path", r.URL.Path)
		}
		gotToken = r.Header.Get("X-Vault-Token")
		writeJSON(t, w, http.StatusOK, map[string]any{
			"data": map[string]any{"ttl": 3600, "renewable": true},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{Method: MethodToken, Token: "s.static"})
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if gotToken != "s.static" {
		t.Errorf("X-Vault-Token = %q, want s.static", gotToken)
	}
	if !client.Authenticated() {
		t.Error("Authenticated() = false, want true")
	}
	if client.lease != time.Hour {
		t.Errorf("lease = %s, want 1h", client.lease)
	}
	if client.canRelogin {
		t.Error("canRelogin = true, want false for a statically configured token")
	}
}

func TestLoginWithTokenRejectsInvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{Method: MethodToken, Token: "s.bad"})
	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() error = nil, want a permission error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %v, want it to mention the Vault message", err)
	}
}

func TestLoginWithAppRole(t *testing.T) {
	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/custom-approle/login" {
			t.Errorf("path = %q, want the configured mount", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"auth": map[string]any{
				"client_token": "s.approle", "lease_duration": 600, "renewable": true,
			},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{
		Method:  MethodAppRole,
		AppRole: AppRoleConfig{Mount: "custom-approle", RoleID: "role", SecretID: "secret"},
	})
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if gotBody["role_id"] != "role" || gotBody["secret_id"] != "secret" {
		t.Errorf("login body = %v, want role_id and secret_id", gotBody)
	}
	if client.currentToken() != "s.approle" {
		t.Errorf("token = %q, want s.approle", client.currentToken())
	}
	if !client.canRelogin {
		t.Error("canRelogin = false, want true for approle")
	}
}

func TestLoginWithKubernetes(t *testing.T) {
	jwtPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtPath, []byte("the-jwt\n"), 0o600); err != nil {
		t.Fatalf("write jwt: %v", err)
	}

	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"auth": map[string]any{"client_token": "s.k8s", "lease_duration": 300},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{
		Method:     MethodKubernetes,
		Kubernetes: KubernetesConfig{Role: "agent", JWTPath: jwtPath},
	})
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if gotBody["jwt"] != "the-jwt" {
		t.Errorf("jwt = %q, want the file content without trailing newline", gotBody["jwt"])
	}
	if gotBody["role"] != "agent" {
		t.Errorf("role = %q, want agent", gotBody["role"])
	}
}

func TestNewRejectsUnknownAuthMethod(t *testing.T) {
	_, err := New(Config{Address: "https://vault.example.com", Auth: AuthConfig{Method: "ldap"}})
	if err == nil {
		t.Fatal("New() error = nil, want an unknown method error")
	}
}

// kvServer is a minimal in-memory KV v2 backend.
type kvServer struct {
	t        *testing.T
	data     map[string]any
	version  int
	requests int
	// namespace records the last X-Vault-Namespace header seen.
	namespace string
}

func (s *kvServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.requests++
		s.namespace = r.Header.Get("X-Vault-Namespace")
		switch r.Method {
		case http.MethodGet:
			if s.data == nil {
				writeJSON(s.t, w, http.StatusNotFound, map[string]any{"errors": []string{}})
				return
			}
			writeJSON(s.t, w, http.StatusOK, map[string]any{
				"data": map[string]any{
					"data":     s.data,
					"metadata": map[string]any{"version": s.version},
				},
			})
		case http.MethodPost:
			var body struct {
				Data    map[string]any `json:"data"`
				Options struct {
					CAS *int `json:"cas"`
				} `json:"options"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				s.t.Errorf("decode write body: %v", err)
			}
			if body.Options.CAS == nil || *body.Options.CAS != s.version {
				writeJSON(s.t, w, http.StatusBadRequest, map[string]any{
					"errors": []string{"check-and-set parameter did not match the current version"},
				})
				return
			}
			s.data = body.Data
			s.version++
			writeJSON(s.t, w, http.StatusOK, map[string]any{
				"data": map[string]any{"version": s.version},
			})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func TestReadKV2NotFound(t *testing.T) {
	backend := &kvServer{t: t}
	server := httptest.NewServer(backend.handler())
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{Method: MethodToken, Token: "s.token"})
	_, err := client.ReadKV2(context.Background(), "secret", "oauth2/example")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("ReadKV2() error = %v, want ErrSecretNotFound", err)
	}
}

func TestReadKV2TreatsNullDataAsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"data": map[string]any{
				"data":     nil,
				"metadata": map[string]any{"version": 3},
			},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{Method: MethodToken, Token: "s.token"})
	if _, err := client.ReadKV2(context.Background(), "secret", "p"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("ReadKV2() error = %v, want ErrSecretNotFound", err)
	}
}

func TestWriteAndReadKV2(t *testing.T) {
	backend := &kvServer{t: t}
	server := httptest.NewServer(backend.handler())
	defer server.Close()

	client, err := New(Config{
		Address:   server.URL,
		Namespace: "team-a",
		Auth:      AuthConfig{Method: MethodToken, Token: "s.token"},
	}, WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	version, err := client.WriteKV2(ctx, "secret", "oauth2/example", map[string]any{"access_token": "at"}, 0)
	if err != nil {
		t.Fatalf("WriteKV2() error = %v", err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}
	if backend.namespace != "team-a" {
		t.Errorf("X-Vault-Namespace = %q, want team-a", backend.namespace)
	}

	secret, err := client.ReadKV2(ctx, "secret", "oauth2/example")
	if err != nil {
		t.Fatalf("ReadKV2() error = %v", err)
	}
	if secret.Version != 1 {
		t.Errorf("Version = %d, want 1", secret.Version)
	}
	if secret.Data["access_token"] != "at" {
		t.Errorf("Data = %v, want access_token=at", secret.Data)
	}
}

func TestWriteKV2CASMismatch(t *testing.T) {
	backend := &kvServer{t: t, data: map[string]any{"access_token": "old"}, version: 7}
	server := httptest.NewServer(backend.handler())
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{Method: MethodToken, Token: "s.token"})
	_, err := client.WriteKV2(context.Background(), "secret", "p", map[string]any{"access_token": "new"}, 3)
	if !errors.Is(err, ErrCASMismatch) {
		t.Fatalf("WriteKV2() error = %v, want ErrCASMismatch", err)
	}
}

func TestRequestRetriesAfterTokenRejection(t *testing.T) {
	var reads, logins int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/login"):
			logins++
			writeJSON(t, w, http.StatusOK, map[string]any{
				"auth": map[string]any{"client_token": "s.fresh", "lease_duration": 600},
			})
		default:
			reads++
			if r.Header.Get("X-Vault-Token") != "s.fresh" {
				writeJSON(t, w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
				return
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{
					"data":     map[string]any{"access_token": "at"},
					"metadata": map[string]any{"version": 2},
				},
			})
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{
		Method:  MethodAppRole,
		AppRole: AppRoleConfig{RoleID: "r", SecretID: "s"},
	})
	// Start from a stale token so that the first read is rejected.
	client.setAuth(&authInfo{Token: "s.stale", Lease: time.Hour})

	secret, err := client.ReadKV2(context.Background(), "secret", "p")
	if err != nil {
		t.Fatalf("ReadKV2() error = %v", err)
	}
	if secret.Data["access_token"] != "at" {
		t.Errorf("Data = %v, want access_token=at", secret.Data)
	}
	if logins != 1 {
		t.Errorf("logins = %d, want exactly one re-login", logins)
	}
	if reads != 2 {
		t.Errorf("reads = %d, want the read to be retried once", reads)
	}
}

func TestRenewOrLoginRenewsRenewableToken(t *testing.T) {
	var renewals int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/renew-self" {
			t.Errorf("path = %q, want renew-self", r.URL.Path)
		}
		renewals++
		writeJSON(t, w, http.StatusOK, map[string]any{
			"auth": map[string]any{"client_token": "s.renewed", "lease_duration": 1200, "renewable": true},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{
		Method:  MethodAppRole,
		AppRole: AppRoleConfig{RoleID: "r", SecretID: "s"},
	})
	client.setAuth(&authInfo{Token: "s.old", Lease: 600 * time.Second, Renewable: true})

	if err := client.renewOrLogin(context.Background()); err != nil {
		t.Fatalf("renewOrLogin() error = %v", err)
	}
	if renewals != 1 {
		t.Errorf("renewals = %d, want 1", renewals)
	}
	if client.currentToken() != "s.renewed" {
		t.Errorf("token = %q, want s.renewed", client.currentToken())
	}
}

func TestRenewOrLoginRefusesNonRenewableStaticToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"data": map[string]any{"ttl": 60, "renewable": false},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AuthConfig{Method: MethodToken, Token: "s.static"})
	client.setAuth(&authInfo{Token: "s.static", Lease: time.Minute, Renewable: false})

	err := client.renewOrLogin(context.Background())
	if !errors.Is(err, errTokenNotRenewable) {
		t.Fatalf("renewOrLogin() error = %v, want errTokenNotRenewable", err)
	}
}

func TestTimeUntilRenew(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	client := newTestClient(t, "https://vault.example.com",
		AuthConfig{Method: MethodToken, Token: "s.token"})
	client.now = func() time.Time { return now }

	if _, expires := client.timeUntilRenew(); expires {
		t.Error("timeUntilRenew() reports an expiry without a lease, want none")
	}

	client.setAuth(&authInfo{Token: "s.token", Lease: time.Hour})
	wait, expires := client.timeUntilRenew()
	if !expires {
		t.Fatal("timeUntilRenew() reports no expiry, want one")
	}
	if wait != 30*time.Minute {
		t.Errorf("wait = %s, want half the lease", wait)
	}

	now = now.Add(time.Hour)
	if wait, _ := client.timeUntilRenew(); wait != 0 {
		t.Errorf("wait = %s, want 0 once the renewal time has passed", wait)
	}
}

func TestTokenValid(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	client := newTestClient(t, "https://vault.example.com",
		AuthConfig{Method: MethodToken, Token: "s.token"})
	client.now = func() time.Time { return now }

	if client.TokenValid() {
		t.Error("TokenValid() = true before login, want false")
	}

	client.setAuth(&authInfo{Token: "s.token", Lease: time.Minute})
	if !client.TokenValid() {
		t.Error("TokenValid() = false with a fresh lease, want true")
	}

	now = now.Add(2 * time.Minute)
	if client.TokenValid() {
		t.Error("TokenValid() = true after the lease elapsed, want false")
	}

	client.setAuth(&authInfo{Token: "s.root", Lease: 0})
	if !client.TokenValid() {
		t.Error("TokenValid() = false for a token without a lease, want true")
	}
}

func TestMaintainTokenStopsOnContextCancel(t *testing.T) {
	client := newTestClient(t, "https://vault.example.com",
		AuthConfig{Method: MethodToken, Token: "s.token"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		client.MaintainToken(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("MaintainToken() did not return after the context was cancelled")
	}
}

func TestKV2PathEscaping(t *testing.T) {
	tests := []struct{ mount, path, want string }{
		{"secret", "oauth2/example", "/v1/secret/data/oauth2/example"},
		{"kv/nested", "a/b/c", "/v1/kv/nested/data/a/b/c"},
		{"secret", "with space", "/v1/secret/data/with%20space"},
	}
	for _, tt := range tests {
		if got := kv2DataPath(tt.mount, tt.path); got != tt.want {
			t.Errorf("kv2DataPath(%q, %q) = %q, want %q", tt.mount, tt.path, got, tt.want)
		}
	}
}

func TestAPIErrorMessage(t *testing.T) {
	err := &APIError{StatusCode: 400, Errors: []string{"first", "second"}}
	if !strings.Contains(err.Error(), "first; second") {
		t.Errorf("Error() = %q, want it to join the messages", err.Error())
	}
	bare := &APIError{StatusCode: 500}
	if !strings.Contains(bare.Error(), "500") {
		t.Errorf("Error() = %q, want it to mention the status", bare.Error())
	}
}
