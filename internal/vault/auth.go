package vault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// authResponse is the shape of a Vault login or renewal response.
type authResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int64  `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

func (r authResponse) toAuthInfo() (*authInfo, error) {
	if r.Auth.ClientToken == "" {
		return nil, fmt.Errorf("vault: login response contains no client token")
	}
	return &authInfo{
		Token:     r.Auth.ClientToken,
		Lease:     time.Duration(r.Auth.LeaseDuration) * time.Second,
		Renewable: r.Auth.Renewable,
	}, nil
}

// newLoginFunc builds the login strategy for the configured auth method.
func newLoginFunc(cfg AuthConfig) (loginFunc, error) {
	switch cfg.Method {
	case MethodToken, "":
		if cfg.Token == "" {
			return nil, fmt.Errorf("vault: auth method %q requires a token", MethodToken)
		}
		token := cfg.Token
		return func(ctx context.Context, c *Client) (*authInfo, error) {
			return c.lookupSelf(ctx, token)
		}, nil

	case MethodAppRole:
		if cfg.AppRole.RoleID == "" || cfg.AppRole.SecretID == "" {
			return nil, fmt.Errorf("vault: auth method %q requires role_id and secret_id", MethodAppRole)
		}
		approle := cfg.AppRole
		path := loginPath(approle.Mount, "approle")
		return func(ctx context.Context, c *Client) (*authInfo, error) {
			body := map[string]string{
				"role_id":   approle.RoleID,
				"secret_id": approle.SecretID,
			}
			return c.loginAt(ctx, path, body)
		}, nil

	case MethodKubernetes:
		if cfg.Kubernetes.Role == "" {
			return nil, fmt.Errorf("vault: auth method %q requires a role", MethodKubernetes)
		}
		k8s := cfg.Kubernetes
		jwtPath := k8s.JWTPath
		if jwtPath == "" {
			jwtPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
		path := loginPath(k8s.Mount, "kubernetes")
		return func(ctx context.Context, c *Client) (*authInfo, error) {
			// The projected service account token is re-read on every login:
			// kubelet rotates the file in place.
			jwt, err := os.ReadFile(jwtPath)
			if err != nil {
				return nil, fmt.Errorf("vault: read service account token: %w", err)
			}
			body := map[string]string{
				"role": k8s.Role,
				"jwt":  strings.TrimSpace(string(jwt)),
			}
			return c.loginAt(ctx, path, body)
		}, nil

	default:
		return nil, fmt.Errorf("vault: unknown auth method %q", cfg.Method)
	}
}

func loginPath(mount, fallback string) string {
	if mount == "" {
		mount = fallback
	}
	return "/v1/auth/" + strings.Trim(mount, "/") + "/login"
}

// loginAt posts credentials to a login endpoint. Login endpoints are
// unauthenticated, so no client token is sent.
func (c *Client) loginAt(ctx context.Context, path string, body any) (*authInfo, error) {
	var resp authResponse
	if err := c.do(ctx, "POST", path, "", body, &resp); err != nil {
		return nil, fmt.Errorf("vault: login at %s: %w", path, err)
	}
	return resp.toAuthInfo()
}

// lookupSelf validates a statically configured token and reports its remaining
// lease, so that a revoked or expired token is detected at startup rather than
// on the first write.
func (c *Client) lookupSelf(ctx context.Context, token string) (*authInfo, error) {
	var resp struct {
		Data struct {
			TTL       int64 `json:"ttl"`
			Renewable bool  `json:"renewable"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/v1/auth/token/lookup-self", token, nil, &resp); err != nil {
		return nil, fmt.Errorf("vault: validate configured token: %w", err)
	}
	return &authInfo{
		Token:     token,
		Lease:     time.Duration(resp.Data.TTL) * time.Second,
		Renewable: resp.Data.Renewable,
	}, nil
}

// renewSelf extends the lease of the current token.
func (c *Client) renewSelf(ctx context.Context) (*authInfo, error) {
	var resp authResponse
	if err := c.request(ctx, "POST", "/v1/auth/token/renew-self", map[string]any{}, &resp); err != nil {
		return nil, fmt.Errorf("vault: renew token: %w", err)
	}
	return resp.toAuthInfo()
}

// errTokenNotRenewable means the token will expire and the agent has no way to
// obtain a replacement on its own.
var errTokenNotRenewable = errors.New("vault: token is neither renewable nor reissuable")

// maintainBackoffCap bounds the retry delay of the renewal loop.
const maintainBackoffCap = 5 * time.Minute

// MaintainToken keeps the Vault client token valid until ctx is cancelled. It
// renews the token halfway through its lease and falls back to a fresh login.
// It returns early when there is nothing to maintain.
func (c *Client) MaintainToken(ctx context.Context) {
	backoff := time.Second
	for {
		wait, expires := c.timeUntilRenew()
		if !expires {
			c.logger.Debug("vault token does not expire, renewal loop idle")
			<-ctx.Done()
			return
		}
		if !c.sleep(ctx, wait) {
			return
		}

		err := c.renewOrLogin(ctx)
		if err == nil {
			backoff = time.Second
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errTokenNotRenewable) {
			c.logger.Error("vault token cannot be renewed or reissued; " +
				"the agent will lose access when it expires")
			return
		}
		c.logger.Error("vault token renewal failed",
			slog.String("error", err.Error()),
			slog.Duration("retry_in", backoff))
		if !c.sleep(ctx, backoff) {
			return
		}
		if backoff *= 2; backoff > maintainBackoffCap {
			backoff = maintainBackoffCap
		}
	}
}

// timeUntilRenew reports how long to wait before renewing the token, and
// whether the token expires at all.
func (c *Client) timeUntilRenew() (time.Duration, bool) {
	c.mu.RLock()
	lease, issuedAt := c.lease, c.issuedAt
	c.mu.RUnlock()

	if lease <= 0 {
		return 0, false
	}
	wait := issuedAt.Add(lease / 2).Sub(c.now())
	if wait < 0 {
		wait = 0
	}
	return wait, true
}

func (c *Client) renewOrLogin(ctx context.Context) error {
	c.mu.RLock()
	renewable := c.renewable
	c.mu.RUnlock()

	if renewable {
		auth, err := c.renewSelf(ctx)
		if err == nil {
			c.setAuth(auth)
			c.logger.Debug("renewed vault token", slog.Duration("lease", auth.Lease))
			return nil
		}
		if !c.canRelogin {
			return err
		}
		c.logger.Warn("renewing the vault token failed, logging in again",
			slog.String("error", err.Error()))
	} else if !c.canRelogin {
		return errTokenNotRenewable
	}
	return c.Login(ctx)
}

// sleep waits for d, reporting false if ctx was cancelled first.
func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
