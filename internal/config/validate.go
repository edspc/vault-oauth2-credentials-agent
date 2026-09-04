package config

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

// reservedPaths are served by the agent itself and cannot be reused as the
// OAuth2 callback path.
var reservedPaths = []string{"/", "/authorize", "/healthz", "/readyz"}

var entryIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

var validAuthStyles = []string{"auto", "header", "params"}

func (c *Config) validate() error {
	if err := c.Server.validate(); err != nil {
		return err
	}
	if err := c.Vault.validate(); err != nil {
		return err
	}
	if err := c.Refresh.validate(); err != nil {
		return err
	}
	if err := c.Metrics.validate(c.Server.CallbackPath); err != nil {
		return err
	}
	if len(c.Entries) == 0 {
		return fmt.Errorf("entries: at least one entry is required")
	}
	seenIDs := make(map[string]int, len(c.Entries))
	seenPaths := make(map[string]int, len(c.Entries))
	for i, e := range c.Entries {
		field := fmt.Sprintf("entries[%d]", i)
		if err := e.validate(field); err != nil {
			return err
		}
		if prev, ok := seenIDs[e.ID]; ok {
			return fmt.Errorf("%s.id: duplicate id %q, already used by entries[%d]", field, e.ID, prev)
		}
		seenIDs[e.ID] = i

		location := e.Vault.Mount + "/" + e.Vault.Path
		if prev, ok := seenPaths[location]; ok {
			return fmt.Errorf("%s.vault: path %q is already used by entries[%d]; "+
				"entries sharing a path would overwrite each other", field, location, prev)
		}
		seenPaths[location] = i
	}
	return nil
}

func (s Server) validate() error {
	if s.Listen == "" {
		return fmt.Errorf("server.listen must not be empty")
	}
	if s.BaseURL != "" {
		if err := validateHTTPURL("server.base_url", s.BaseURL); err != nil {
			return err
		}
	}
	if err := validateURLPath("server.callback_path", s.CallbackPath); err != nil {
		return err
	}
	if slices.Contains(reservedPaths, s.CallbackPath) {
		return fmt.Errorf("server.callback_path %q is reserved by the agent", s.CallbackPath)
	}
	if err := requirePositive("server.read_header_timeout", s.ReadHeaderTimeout); err != nil {
		return err
	}
	return requirePositive("server.shutdown_timeout", s.ShutdownTimeout)
}

func (m Metrics) validate(callbackPath string) error {
	if m.Path == "" {
		return nil
	}
	if err := validateURLPath("metrics.path", m.Path); err != nil {
		return err
	}
	if slices.Contains(reservedPaths, m.Path) {
		return fmt.Errorf("metrics.path %q is reserved by the agent", m.Path)
	}
	if m.Path == callbackPath {
		return fmt.Errorf("metrics.path %q collides with server.callback_path", m.Path)
	}
	return nil
}

func (v Vault) validate() error {
	if v.Address == "" {
		return fmt.Errorf("vault.address must not be empty")
	}
	if err := validateHTTPURL("vault.address", v.Address); err != nil {
		return err
	}
	if err := requirePositive("vault.timeout", v.Timeout); err != nil {
		return err
	}
	switch v.Auth.Method {
	case AuthMethodToken:
		if v.Auth.Token == "" {
			return fmt.Errorf("vault.auth.token must not be empty when method is %q", AuthMethodToken)
		}
	case AuthMethodAppRole:
		if err := validateVaultPath("vault.auth.approle.mount", v.Auth.AppRole.Mount); err != nil {
			return err
		}
		if v.Auth.AppRole.RoleID == "" {
			return fmt.Errorf("vault.auth.approle.role_id must not be empty")
		}
		if v.Auth.AppRole.SecretID == "" {
			return fmt.Errorf("vault.auth.approle.secret_id must not be empty")
		}
	case AuthMethodKubernetes:
		if err := validateVaultPath("vault.auth.kubernetes.mount", v.Auth.Kubernetes.Mount); err != nil {
			return err
		}
		if v.Auth.Kubernetes.Role == "" {
			return fmt.Errorf("vault.auth.kubernetes.role must not be empty")
		}
		if v.Auth.Kubernetes.JWTPath == "" {
			return fmt.Errorf("vault.auth.kubernetes.jwt_path must not be empty")
		}
	default:
		return fmt.Errorf("vault.auth.method %q is not one of %q, %q, %q",
			v.Auth.Method, AuthMethodToken, AuthMethodAppRole, AuthMethodKubernetes)
	}
	return nil
}

func (r Refresh) validate() error {
	if err := requirePositive("refresh.interval", r.Interval); err != nil {
		return err
	}
	if err := requirePositive("refresh.before_expiry", r.BeforeExpiry); err != nil {
		return err
	}
	if err := requirePositive("refresh.max_backoff", r.MaxBackoff); err != nil {
		return err
	}
	if r.BeforeExpiry <= r.Interval {
		return fmt.Errorf("refresh.before_expiry (%s) must be greater than refresh.interval (%s), "+
			"otherwise a token can expire between two ticks", r.BeforeExpiry, r.Interval)
	}
	if r.MaxBackoff < r.Interval {
		return fmt.Errorf("refresh.max_backoff (%s) must not be smaller than refresh.interval (%s)",
			r.MaxBackoff, r.Interval)
	}
	return nil
}

func (e Entry) validate(field string) error {
	if e.ID == "" {
		return fmt.Errorf("%s.id must not be empty", field)
	}
	if !entryIDPattern.MatchString(e.ID) {
		return fmt.Errorf("%s.id %q must start with a letter or digit and contain only "+
			"letters, digits, '.', '_' or '-'", field, e.ID)
	}
	if err := validateHTTPURL(field+".auth_url", e.AuthURL); err != nil {
		return err
	}
	if err := validateHTTPURL(field+".token_url", e.TokenURL); err != nil {
		return err
	}
	if e.ClientID == "" {
		return fmt.Errorf("%s.client_id must not be empty", field)
	}
	if e.RedirectURL == "" {
		return fmt.Errorf("%s.redirect_url must not be empty; set it explicitly or "+
			"configure server.base_url", field)
	}
	if err := validateHTTPURL(field+".redirect_url", e.RedirectURL); err != nil {
		return err
	}
	for i, scope := range e.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\n") {
			return fmt.Errorf("%s.scopes[%d]: scope must be non-empty and must not contain whitespace", field, i)
		}
	}
	if !slices.Contains(validAuthStyles, e.AuthStyle) {
		return fmt.Errorf("%s.auth_style %q is not one of %s", field, e.AuthStyle,
			strings.Join(validAuthStyles, ", "))
	}
	for k := range e.ExtraAuthParams {
		if isReservedAuthParam(k) {
			return fmt.Errorf("%s.extra_auth_params: %q is set by the agent and must not be overridden", field, k)
		}
	}
	if err := validateVaultPath(field+".vault.mount", e.Vault.Mount); err != nil {
		return err
	}
	return validateVaultPath(field+".vault.path", e.Vault.Path)
}

// isReservedAuthParam reports whether the authorization request parameter is
// produced by the agent and therefore cannot be supplied by the config.
func isReservedAuthParam(name string) bool {
	switch name {
	case "response_type", "client_id", "redirect_uri", "scope", "state",
		"code_challenge", "code_challenge_method":
		return true
	}
	return false
}

// validateHTTPURL requires an absolute https URL. Plain http is tolerated for
// loopback hosts so that the agent can be exercised locally and in tests.
func validateHTTPURL(field, raw string) error {
	if raw == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: invalid URL %q: %w", field, raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%s: URL %q must be absolute and include a host", field, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%s: %q uses http; plain http is only allowed for loopback hosts", field, raw)
	default:
		return fmt.Errorf("%s: URL %q must use http or https, got scheme %q", field, raw, u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateURLPath(field, p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%s %q must start with '/'", field, p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("%s %q must be a clean path such as %q", field, p, path.Clean(p))
	}
	return nil
}

// validateVaultPath checks a Vault mount or secret path: a clean, relative,
// slash-separated path without a trailing slash.
func validateVaultPath(field, p string) error {
	if p == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("%s %q must not start or end with '/'", field, p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("%s %q must be a clean path such as %q", field, p, path.Clean(p))
	}
	return nil
}

func requirePositive(field string, d Duration) error {
	if d <= 0 {
		return fmt.Errorf("%s must be positive, got %s", field, d)
	}
	return nil
}
