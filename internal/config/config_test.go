package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

const minimalConfig = `
vault:
  address: "https://vault.example.com"
  auth:
    method: token
    token: "s.example"
entries:
  - id: example
    auth_url: "https://provider.example.com/authorize"
    token_url: "https://provider.example.com/token"
    client_id: "client"
    redirect_url: "https://agent.example.com/callback"
    vault:
      path: oauth2/example
`

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimalConfig))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if cfg.Server.Listen != ":8080" {
		t.Errorf("Server.Listen = %q, want %q", cfg.Server.Listen, ":8080")
	}
	if cfg.Server.CallbackPath != "/callback" {
		t.Errorf("Server.CallbackPath = %q, want %q", cfg.Server.CallbackPath, "/callback")
	}
	if got := cfg.Refresh.Interval.Duration(); got != time.Minute {
		t.Errorf("Refresh.Interval = %s, want 1m", got)
	}
	if got := cfg.Refresh.BeforeExpiry.Duration(); got != 10*time.Minute {
		t.Errorf("Refresh.BeforeExpiry = %s, want 10m", got)
	}
	if got := cfg.Vault.Timeout.Duration(); got != 10*time.Second {
		t.Errorf("Vault.Timeout = %s, want 10s", got)
	}

	entry := cfg.Entries[0]
	if entry.Vault.Mount != "secret" {
		t.Errorf("entry Vault.Mount = %q, want %q", entry.Vault.Mount, "secret")
	}
	if entry.AuthStyle != "auto" {
		t.Errorf("entry AuthStyle = %q, want %q", entry.AuthStyle, "auto")
	}
	if !entry.PKCEEnabled() {
		t.Error("entry PKCEEnabled() = false, want true by default")
	}
}

func TestParseDerivesRedirectURLFromBaseURL(t *testing.T) {
	doc := strings.Replace(minimalConfig,
		`    redirect_url: "https://agent.example.com/callback"`+"\n", "", 1)
	doc = "server:\n  base_url: \"https://agent.example.com/\"\n  callback_path: /oauth/callback\n" + doc

	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	const want = "https://agent.example.com/oauth/callback"
	if got := cfg.Entries[0].RedirectURL; got != want {
		t.Errorf("RedirectURL = %q, want %q", got, want)
	}
}

func TestParseDisablesPKCEExplicitly(t *testing.T) {
	doc := strings.Replace(minimalConfig,
		"    client_id: \"client\"\n", "    client_id: \"client\"\n    pkce: false\n", 1)

	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Entries[0].PKCEEnabled() {
		t.Error("PKCEEnabled() = true, want false")
	}
}

func TestParseRejectsTheRemovedIndexOption(t *testing.T) {
	// The agent no longer serves an overview page; a config still carrying
	// the option must fail loudly rather than be silently ignored.
	_, err := Parse([]byte("server:\n  index: true\n" + minimalConfig))
	if err == nil {
		t.Fatal("Parse() error = nil, want the unknown field to be rejected")
	}
}

func TestParseExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("TEST_CLIENT_SECRET", "s3cr3t")
	t.Setenv("TEST_VAULT_TOKEN", "s.token")

	doc := strings.Replace(minimalConfig, `    token: "s.example"`,
		`    token: "${TEST_VAULT_TOKEN}"`, 1)
	doc = strings.Replace(doc, `    client_id: "client"`,
		"    client_id: \"client\"\n    client_secret: \"${TEST_CLIENT_SECRET}\"", 1)

	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Vault.Auth.Token != "s.token" {
		t.Errorf("Vault.Auth.Token = %q, want %q", cfg.Vault.Auth.Token, "s.token")
	}
	if cfg.Entries[0].ClientSecret != "s3cr3t" {
		t.Errorf("ClientSecret = %q, want %q", cfg.Entries[0].ClientSecret, "s3cr3t")
	}
}

func TestParseRejectsUnsetEnvironmentVariable(t *testing.T) {
	if _, ok := os.LookupEnv("TEST_DEFINITELY_UNSET"); ok {
		t.Skip("TEST_DEFINITELY_UNSET is set in the environment")
	}
	doc := strings.Replace(minimalConfig, `    client_id: "client"`,
		"    client_id: \"client\"\n    client_secret: \"${TEST_DEFINITELY_UNSET}\"", 1)

	_, err := Parse([]byte(doc))
	if err == nil {
		t.Fatal("Parse() error = nil, want an error about the unset variable")
	}
	if !strings.Contains(err.Error(), "TEST_DEFINITELY_UNSET") {
		t.Errorf("error = %v, want it to name the missing variable", err)
	}
}

func TestParseExpandsOnlyTheSelectedAuthMethod(t *testing.T) {
	t.Setenv("TEST_ROLE_ID", "role")
	t.Setenv("TEST_SECRET_ID", "secret")

	doc := strings.Replace(minimalConfig, "    method: token\n    token: \"s.example\"",
		"    method: approle\n    token: \"${TEST_UNUSED_TOKEN_VAR}\"\n"+
			"    approle:\n      role_id: \"${TEST_ROLE_ID}\"\n      secret_id: \"${TEST_SECRET_ID}\"", 1)

	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse() error = %v, want the unused token field to be ignored", err)
	}
	if cfg.Vault.Auth.AppRole.RoleID != "role" {
		t.Errorf("AppRole.RoleID = %q, want %q", cfg.Vault.Auth.AppRole.RoleID, "role")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	doc := minimalConfig + "unexpected: true\n"
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("Parse() error = nil, want an error about the unknown field")
	}
}

func TestParseValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantMsg string
	}{
		{
			name: "duplicate entry id",
			mutate: func(doc string) string {
				return doc + `  - id: example
    auth_url: "https://other.example.com/authorize"
    token_url: "https://other.example.com/token"
    client_id: "client"
    redirect_url: "https://agent.example.com/callback"
    vault:
      path: oauth2/other
`
			},
			wantMsg: "duplicate id",
		},
		{
			name: "duplicate vault path",
			mutate: func(doc string) string {
				return doc + `  - id: other
    auth_url: "https://other.example.com/authorize"
    token_url: "https://other.example.com/token"
    client_id: "client"
    redirect_url: "https://agent.example.com/callback"
    vault:
      path: oauth2/example
`
			},
			wantMsg: "already used by",
		},
		{
			name: "empty vault path",
			mutate: func(doc string) string {
				return strings.Replace(doc, "      path: oauth2/example", `      path: ""`, 1)
			},
			wantMsg: "vault.path must not be empty",
		},
		{
			name:    "unclean vault path",
			mutate:  func(doc string) string { return strings.Replace(doc, "oauth2/example", "oauth2/../example", 1) },
			wantMsg: "must be a clean path",
		},
		{
			name: "plain http endpoint",
			mutate: func(doc string) string {
				return strings.Replace(doc, "https://provider.example.com/token", "http://provider.example.com/token", 1)
			},
			wantMsg: "only allowed for loopback",
		},
		{
			name:    "no entries",
			mutate:  func(doc string) string { return doc[:strings.Index(doc, "entries:")] },
			wantMsg: "at least one entry is required",
		},
		{
			name:    "before_expiry not greater than interval",
			mutate:  func(doc string) string { return "refresh:\n  interval: 10m\n  before_expiry: 5m\n" + doc },
			wantMsg: "must be greater than refresh.interval",
		},
		{
			name: "unknown auth style",
			mutate: func(doc string) string {
				return strings.Replace(doc, `    client_id: "client"`, "    client_id: \"client\"\n    auth_style: basic", 1)
			},
			wantMsg: "auth_style",
		},
		{
			name: "reserved auth param",
			mutate: func(doc string) string {
				return strings.Replace(doc, `    client_id: "client"`, "    client_id: \"client\"\n    extra_auth_params:\n      state: fixed", 1)
			},
			wantMsg: "must not be overridden",
		},
		{
			name:    "reserved callback path",
			mutate:  func(doc string) string { return "server:\n  callback_path: /healthz\n" + doc },
			wantMsg: "is reserved",
		},
		{
			name:    "approle without credentials",
			mutate:  func(doc string) string { return strings.Replace(doc, "method: token", "method: approle", 1) },
			wantMsg: "role_id must not be empty",
		},
		{
			name:    "invalid entry id",
			mutate:  func(doc string) string { return strings.Replace(doc, "id: example", `id: "bad id"`, 1) },
			wantMsg: "must start with a letter or digit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.mutate(minimalConfig)))
			if err == nil {
				t.Fatalf("Parse() error = nil, want an error containing %q", tt.wantMsg)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Parse() error = %v, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

func TestParseAllowsLoopbackOverHTTP(t *testing.T) {
	doc := strings.ReplaceAll(minimalConfig, "https://provider.example.com", "http://127.0.0.1:9000")
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatalf("Parse() error = %v, want loopback http to be accepted", err)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv("VAULT_ROLE_ID", "role")
	t.Setenv("VAULT_SECRET_ID", "secret")
	t.Setenv("GITHUB_CLIENT_SECRET", "github-secret")
	t.Setenv("GOOGLE_CLIENT_ID", "google-id")
	t.Setenv("GOOGLE_CLIENT_SECRET", "google-secret")

	cfg, err := Load("../../configs/config.example.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Entries) != 2 {
		t.Fatalf("len(Entries) = %d, want 2", len(cfg.Entries))
	}
	if _, ok := cfg.Entry("github-ci"); !ok {
		t.Error(`Entry("github-ci") not found`)
	}
	if _, ok := cfg.Entry("missing"); ok {
		t.Error(`Entry("missing") found, want not found`)
	}
}

func TestDurationUnmarshal(t *testing.T) {
	doc := strings.Replace(minimalConfig, `  address: "https://vault.example.com"`,
		"  address: \"https://vault.example.com\"\n  timeout: 2m30s", 1)

	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := cfg.Vault.Timeout.Duration(); got != 150*time.Second {
		t.Errorf("Vault.Timeout = %s, want 2m30s", got)
	}
	if got := cfg.Vault.Timeout.String(); got != "2m30s" {
		t.Errorf("Duration.String() = %q, want %q", got, "2m30s")
	}
}

func TestDurationRejectsNonString(t *testing.T) {
	doc := strings.Replace(minimalConfig, `  address: "https://vault.example.com"`,
		"  address: \"https://vault.example.com\"\n  timeout: 30", 1)

	_, err := Parse([]byte(doc))
	if err == nil {
		t.Fatal("Parse() error = nil, want a duration parse error")
	}
}
