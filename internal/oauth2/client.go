// Package oauth2 implements the parts of the OAuth2 authorization code grant
// the agent needs: building the authorization request, exchanging the code and
// refreshing an access token. It deliberately depends on the standard library
// only.
package oauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthStyle selects how client credentials are presented to the token endpoint.
type AuthStyle int

const (
	// AuthStyleAuto tries HTTP Basic first and falls back to request body
	// parameters if the provider rejects it, caching whichever worked.
	AuthStyleAuto AuthStyle = iota
	// AuthStyleInHeader sends the credentials as HTTP Basic authentication.
	AuthStyleInHeader
	// AuthStyleInParams sends the credentials in the request body.
	AuthStyleInParams
)

func (s AuthStyle) String() string {
	switch s {
	case AuthStyleInHeader:
		return "header"
	case AuthStyleInParams:
		return "params"
	default:
		return "auto"
	}
}

// ParseAuthStyle converts the configuration value into an AuthStyle.
func ParseAuthStyle(s string) (AuthStyle, error) {
	switch s {
	case "", "auto":
		return AuthStyleAuto, nil
	case "header":
		return AuthStyleInHeader, nil
	case "params":
		return AuthStyleInParams, nil
	default:
		return AuthStyleAuto, fmt.Errorf("oauth2: unknown auth style %q", s)
	}
}

// Config describes a single OAuth2 client registration.
type Config struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	RedirectURL  string
	Scopes       []string
	// ExtraAuthParams are appended to the authorization request only.
	ExtraAuthParams map[string]string
	AuthStyle       AuthStyle
}

// maxResponseBody bounds how much of a token endpoint response is read.
const maxResponseBody = 1 << 20

// Client performs the token endpoint calls for one Config.
type Client struct {
	cfg        Config
	httpClient *http.Client
	now        func() time.Time

	mu sync.Mutex
	// style is the authentication style currently believed to work; it is
	// resolved on the first successful call when the config says "auto".
	style AuthStyle
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client used for token endpoint calls.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		if c != nil {
			cl.httpClient = c
		}
	}
}

// WithClock overrides the clock, which is used to turn expires_in into an
// absolute expiry. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(cl *Client) {
		if now != nil {
			cl.now = now
		}
	}
}

// NewClient builds a Client for cfg.
func NewClient(cfg Config, opts ...Option) *Client {
	c := &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		now:        time.Now,
		style:      cfg.AuthStyle,
	}
	// Without a client secret there is nothing to put into a Basic header,
	// so the only workable style is sending client_id in the body.
	if cfg.ClientSecret == "" {
		c.style = AuthStyleInParams
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// AuthCodeURL builds the URL the user is redirected to in order to grant
// access. codeChallenge may be empty to disable PKCE.
func (c *Client) AuthCodeURL(state, codeChallenge string) (string, error) {
	u, err := url.Parse(c.cfg.AuthURL)
	if err != nil {
		return "", fmt.Errorf("oauth2: invalid auth url: %w", err)
	}
	q := u.Query()
	for k, v := range c.cfg.ExtraAuthParams {
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("state", state)
	if len(c.cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", ChallengeMethodS256)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange trades an authorization code for a token. codeVerifier may be empty
// when PKCE is disabled.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.cfg.RedirectURL)
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}
	return c.token(ctx, form)
}

// Refresh obtains a new access token from a refresh token. Providers that
// rotate refresh tokens return a new one; those that do not leave the field
// empty and the caller keeps the previous value.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("oauth2: refresh token is empty")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	if len(c.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	return c.token(ctx, form)
}

// token posts to the token endpoint, retrying once with the other client
// authentication style when the style is not pinned by configuration.
func (c *Client) token(ctx context.Context, form url.Values) (*Token, error) {
	style := c.currentStyle()
	tok, err := c.tokenWithStyle(ctx, form, style)
	if err == nil {
		c.rememberStyle(style)
		return tok, nil
	}
	if c.cfg.AuthStyle != AuthStyleAuto || c.cfg.ClientSecret == "" || !isClientAuthRejected(err) {
		return nil, err
	}

	fallback := AuthStyleInParams
	if style == AuthStyleInParams {
		fallback = AuthStyleInHeader
	}
	tok, fallbackErr := c.tokenWithStyle(ctx, form, fallback)
	if fallbackErr != nil {
		// Report the original failure: it describes the configured style.
		return nil, err
	}
	c.rememberStyle(fallback)
	return tok, nil
}

func (c *Client) currentStyle() AuthStyle {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.style == AuthStyleAuto {
		return AuthStyleInHeader
	}
	return c.style
}

func (c *Client) rememberStyle(style AuthStyle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.style = style
}

func (c *Client) tokenWithStyle(ctx context.Context, form url.Values, style AuthStyle) (*Token, error) {
	body := url.Values{}
	for k, v := range form {
		body[k] = v
	}
	if style == AuthStyleInParams {
		body.Set("client_id", c.cfg.ClientID)
		if c.cfg.ClientSecret != "" {
			body.Set("client_secret", c.cfg.ClientSecret)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL,
		strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if style == AuthStyleInHeader {
		// RFC 6749 section 2.3.1 requires the credentials to be form-encoded
		// before being base64-encoded into the Basic header.
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2: token request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("oauth2: read token response: %w", err)
	}
	return parseTokenResponse(raw, resp.Header.Get("Content-Type"), resp.StatusCode, c.now())
}
