// Package config defines the YAML configuration of the agent, together with
// its defaults and validation rules.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Vault authentication methods supported by the agent.
const (
	AuthMethodToken      = "token"
	AuthMethodAppRole    = "approle"
	AuthMethodKubernetes = "kubernetes"
)

// Config is the root of the configuration file.
type Config struct {
	Server  Server  `yaml:"server"`
	Vault   Vault   `yaml:"vault"`
	Refresh Refresh `yaml:"refresh"`
	Entries []Entry `yaml:"entries"`
}

// Server configures the HTTP listener used for the authorization flow.
type Server struct {
	Listen  string `yaml:"listen"`
	BaseURL string `yaml:"base_url"`
	// CallbackPath is the single OAuth2 redirect path served by the agent;
	// the entry a callback belongs to is resolved from the state parameter.
	CallbackPath      string   `yaml:"callback_path"`
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	ShutdownTimeout   Duration `yaml:"shutdown_timeout"`
}

// Vault configures access to the HashiCorp Vault instance holding the tokens.
type Vault struct {
	Address   string    `yaml:"address"`
	Namespace string    `yaml:"namespace"`
	Auth      VaultAuth `yaml:"auth"`
	Timeout   Duration  `yaml:"timeout"`
}

// VaultAuth selects and configures the Vault authentication method.
type VaultAuth struct {
	Method     string         `yaml:"method"`
	Token      string         `yaml:"token"`
	AppRole    AppRoleAuth    `yaml:"approle"`
	Kubernetes KubernetesAuth `yaml:"kubernetes"`
}

// AppRoleAuth configures the auth/approle login.
type AppRoleAuth struct {
	Mount    string `yaml:"mount"`
	RoleID   string `yaml:"role_id"`
	SecretID string `yaml:"secret_id"`
}

// KubernetesAuth configures the auth/kubernetes login.
type KubernetesAuth struct {
	Mount   string `yaml:"mount"`
	Role    string `yaml:"role"`
	JWTPath string `yaml:"jwt_path"`
}

// Refresh configures the background refresher.
type Refresh struct {
	// Interval is how often stored credentials are inspected.
	Interval Duration `yaml:"interval"`
	// BeforeExpiry triggers a refresh once the access token expires sooner
	// than this.
	BeforeExpiry Duration `yaml:"before_expiry"`
	// MaxBackoff caps the retry delay after a failed refresh.
	MaxBackoff Duration `yaml:"max_backoff"`
}

// Entry is a single OAuth2 credential managed by the agent.
type Entry struct {
	ID           string `yaml:"id"`
	AuthURL      string `yaml:"auth_url"`
	TokenURL     string `yaml:"token_url"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// RedirectURL must match the value registered with the provider. It
	// defaults to server.base_url joined with server.callback_path.
	RedirectURL string   `yaml:"redirect_url"`
	Scopes      []string `yaml:"scopes"`
	// PKCE enables the S256 code challenge. Defaults to true.
	PKCE *bool `yaml:"pkce"`
	// AuthStyle selects how client credentials are presented to the token
	// endpoint: "auto", "header" or "params".
	AuthStyle string `yaml:"auth_style"`
	// ExtraAuthParams are appended to the authorization request, for
	// provider-specific options such as Google's access_type=offline.
	ExtraAuthParams map[string]string `yaml:"extra_auth_params"`
	Vault           EntryVault        `yaml:"vault"`
}

// PKCEEnabled reports whether the entry uses a PKCE code challenge.
func (e Entry) PKCEEnabled() bool { return e.PKCE == nil || *e.PKCE }

// EntryVault is the KV v2 location the entry's tokens are stored at.
type EntryVault struct {
	Mount string `yaml:"mount"`
	Path  string `yaml:"path"`
}

// Entry returns the entry with the given id.
func (c *Config) Entry(id string) (Entry, bool) {
	for _, e := range c.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes, expands, defaults and validates a configuration document.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	// Defaults first: they can introduce values, such as a derived
	// redirect_url, that themselves contain ${VAR} references.
	cfg.applyDefaults()
	if err := cfg.expandEnv(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// envTarget is a configuration field eligible for ${VAR} expansion.
type envTarget struct {
	name string
	ptr  *string
}

// expandEnv substitutes ${VAR} references in the fields that are expected to
// carry secrets or deployment-specific values. An unset variable is a startup
// error rather than a silently empty credential.
func (c *Config) expandEnv() error {
	targets := []envTarget{
		{"server.base_url", &c.Server.BaseURL},
		{"vault.address", &c.Vault.Address},
		{"vault.namespace", &c.Vault.Namespace},
	}
	// Only the selected authentication method is expanded, so that a config
	// listing every method does not demand the variables of the unused ones.
	switch c.Vault.Auth.Method {
	case AuthMethodToken:
		targets = append(targets, envTarget{"vault.auth.token", &c.Vault.Auth.Token})
	case AuthMethodAppRole:
		targets = append(targets,
			envTarget{"vault.auth.approle.role_id", &c.Vault.Auth.AppRole.RoleID},
			envTarget{"vault.auth.approle.secret_id", &c.Vault.Auth.AppRole.SecretID})
	case AuthMethodKubernetes:
		targets = append(targets, envTarget{"vault.auth.kubernetes.role", &c.Vault.Auth.Kubernetes.Role})
	}
	for i := range c.Entries {
		e := &c.Entries[i]
		prefix := fmt.Sprintf("entries[%d]", i)
		targets = append(targets,
			envTarget{prefix + ".client_id", &e.ClientID},
			envTarget{prefix + ".client_secret", &e.ClientSecret},
			envTarget{prefix + ".redirect_url", &e.RedirectURL},
		)
	}
	for _, t := range targets {
		v, err := expandValue(t.name, *t.ptr)
		if err != nil {
			return err
		}
		*t.ptr = v
	}
	return nil
}

func expandValue(field, value string) (string, error) {
	var missing []string
	out := envRef.ReplaceAllStringFunc(value, func(match string) string {
		name := envRef.FindStringSubmatch(match)[1]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return ""
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("%s references unset environment variable(s): %s",
			field, strings.Join(missing, ", "))
	}
	return out, nil
}

func (c *Config) applyDefaults() {
	setString(&c.Server.Listen, ":8080")
	setString(&c.Server.CallbackPath, "/callback")
	setDuration(&c.Server.ReadHeaderTimeout, 10*time.Second)
	setDuration(&c.Server.ShutdownTimeout, 15*time.Second)

	setString(&c.Vault.Auth.Method, AuthMethodToken)
	setString(&c.Vault.Auth.AppRole.Mount, "approle")
	setString(&c.Vault.Auth.Kubernetes.Mount, "kubernetes")
	setString(&c.Vault.Auth.Kubernetes.JWTPath, "/var/run/secrets/kubernetes.io/serviceaccount/token")
	setDuration(&c.Vault.Timeout, 10*time.Second)

	setDuration(&c.Refresh.Interval, time.Minute)
	setDuration(&c.Refresh.BeforeExpiry, 10*time.Minute)
	setDuration(&c.Refresh.MaxBackoff, 30*time.Minute)

	for i := range c.Entries {
		e := &c.Entries[i]
		setString(&e.AuthStyle, "auto")
		setString(&e.Vault.Mount, "secret")
		if e.RedirectURL == "" && c.Server.BaseURL != "" {
			e.RedirectURL = strings.TrimSuffix(c.Server.BaseURL, "/") + c.Server.CallbackPath
		}
	}
}

func setString(dst *string, def string) {
	if *dst == "" {
		*dst = def
	}
}

func setDuration(dst *Duration, def time.Duration) {
	if *dst == 0 {
		*dst = Duration(def)
	}
}
