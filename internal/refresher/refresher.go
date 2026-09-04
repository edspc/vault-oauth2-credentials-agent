// Package refresher keeps the credentials stored in Vault valid by renewing
// them before their access token expires.
package refresher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/agent"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/metrics"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/oauth2"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/tokenstore"
)

// Config configures the refresh loop.
type Config struct {
	// Interval is how often the credentials are inspected.
	Interval time.Duration
	// BeforeExpiry triggers a refresh once the access token expires sooner
	// than this.
	BeforeExpiry time.Duration
	// MaxBackoff caps the retry delay after a failed refresh.
	MaxBackoff time.Duration
}

// Refresher renews stored credentials in the background.
type Refresher struct {
	entries  []agent.Entry
	store    *tokenstore.Store
	registry *agent.Registry
	cfg      Config
	logger   *slog.Logger
	now      func() time.Time
	// recorder is nil when metrics are disabled; its methods are no-ops then.
	recorder *metrics.Recorder

	// state is only touched from the single goroutine running the loop.
	state map[string]*entryState
}

// entryState carries the retry bookkeeping of one entry.
type entryState struct {
	failures    int
	nextAttempt time.Time
	// deadRefreshHash identifies the refresh token that was rejected as
	// invalid_grant. Retrying it is pointless until a new authorization
	// replaces it, which is detected by the hash changing.
	deadRefreshHash string
}

// Option customises a Refresher.
type Option func(*Refresher)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(r *Refresher) {
		if l != nil {
			r.logger = l
		}
	}
}

// WithClock overrides the clock. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Refresher) {
		if now != nil {
			r.now = now
		}
	}
}

// WithMetrics records refresh outcomes into the given recorder.
func WithMetrics(recorder *metrics.Recorder) Option {
	return func(r *Refresher) { r.recorder = recorder }
}

// New builds a Refresher for the given entries.
func New(entries []agent.Entry, store *tokenstore.Store, registry *agent.Registry, cfg Config, opts ...Option) *Refresher {
	r := &Refresher{
		entries:  entries,
		store:    store,
		registry: registry,
		cfg:      cfg,
		logger:   slog.Default(),
		now:      time.Now,
		state:    make(map[string]*entryState, len(entries)),
	}
	for _, e := range entries {
		r.state[e.ID] = &entryState{}
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Run inspects every entry immediately and then once per interval, until ctx
// is cancelled.
func (r *Refresher) Run(ctx context.Context) {
	r.RunOnce(ctx)

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.RunOnce(ctx)
		}
	}
}

// RunOnce performs a single pass over all entries.
func (r *Refresher) RunOnce(ctx context.Context) {
	for _, entry := range r.entries {
		if ctx.Err() != nil {
			return
		}
		r.process(ctx, entry)
	}
}

// process inspects one entry and refreshes it when it is about to expire.
func (r *Refresher) process(ctx context.Context, entry agent.Entry) {
	state := r.state[entry.ID]
	if !state.nextAttempt.IsZero() && r.now().Before(state.nextAttempt) {
		return
	}

	err := r.store.WithLock(entry.Location, func() error {
		return r.refresh(ctx, entry, state)
	})
	if err != nil && ctx.Err() == nil {
		r.logger.Error("refresh failed",
			slog.String("entry", entry.ID),
			slog.String("error", err.Error()))
	}
}

func (r *Refresher) refresh(ctx context.Context, entry agent.Entry, state *entryState) error {
	log := r.logger.With(slog.String("entry", entry.ID))

	record, err := r.store.Load(ctx, entry.Location)
	switch {
	case errors.Is(err, tokenstore.ErrNotFound):
		r.registry.SetState(entry.ID, agent.StateNeedsAuth)
		state.reset()
		return nil
	case err != nil:
		r.registry.SetState(entry.ID, agent.StateRefreshFailed)
		r.recorder.RefreshAttempt(entry.ID, metrics.ResultFailure)
		r.backoff(entry.ID, state, log, err)
		return err
	}

	if record.RefreshToken == "" {
		// Nothing to refresh with; the credential lives until it expires.
		r.registry.SetState(entry.ID, agent.StateNeedsAuth)
		state.reset()
		return nil
	}

	hash := hashToken(record.RefreshToken)
	if state.deadRefreshHash == hash {
		r.registry.SetState(entry.ID, agent.StateNeedsReauth)
		return nil
	}
	// A different refresh token means the credential was re-authorized.
	state.deadRefreshHash = ""

	now := r.now()
	if record.Expiry.IsZero() {
		// Without an expiry the agent cannot tell when to act, and refreshing
		// on every tick would hammer the provider.
		r.registry.SetAuthorized(entry.ID, time.Time{}, record.UpdatedAt)
		state.reset()
		return nil
	}
	if record.Expiry.After(now.Add(r.cfg.BeforeExpiry)) {
		r.registry.SetAuthorized(entry.ID, record.Expiry, record.UpdatedAt)
		state.reset()
		return nil
	}

	log.Info("refreshing credential", slog.Time("expiry", record.Expiry))
	token, err := entry.Client.Refresh(ctx, record.RefreshToken)
	if err != nil {
		if oauth2.IsInvalidGrant(err) {
			state.deadRefreshHash = hash
			state.reset()
			r.registry.SetState(entry.ID, agent.StateNeedsReauth)
			r.recorder.RefreshAttempt(entry.ID, metrics.ResultNeedsReauth)
			log.Error("refresh token was rejected, re-authorization required",
				slog.String("error", err.Error()))
			return nil
		}
		r.registry.SetState(entry.ID, agent.StateRefreshFailed)
		r.recorder.RefreshAttempt(entry.ID, metrics.ResultFailure)
		r.backoff(entry.ID, state, log, err)
		return err
	}

	saved, err := r.store.SaveRefreshed(ctx, entry.Location, entry.ID, token)
	if err != nil {
		r.registry.SetState(entry.ID, agent.StateRefreshFailed)
		r.recorder.RefreshAttempt(entry.ID, metrics.ResultFailure)
		r.backoff(entry.ID, state, log, err)
		return err
	}

	r.registry.SetAuthorized(entry.ID, saved.Expiry, saved.UpdatedAt)
	r.recorder.RefreshAttempt(entry.ID, metrics.ResultSuccess)
	state.reset()
	log.Info("credential refreshed", slog.Time("expiry", saved.Expiry))
	return nil
}

// backoff delays the next attempt for this entry, doubling the delay on every
// consecutive failure up to MaxBackoff.
func (r *Refresher) backoff(entryID string, state *entryState, log *slog.Logger, cause error) {
	state.failures++
	delay := r.cfg.Interval
	for i := 1; i < state.failures; i++ {
		if delay >= r.cfg.MaxBackoff/2 {
			delay = r.cfg.MaxBackoff
			break
		}
		delay *= 2
	}
	if delay > r.cfg.MaxBackoff {
		delay = r.cfg.MaxBackoff
	}
	state.nextAttempt = r.now().Add(delay)
	log.Warn("delaying next refresh attempt",
		slog.Int("failures", state.failures),
		slog.Duration("retry_in", delay),
		slog.String("error", cause.Error()))
}

func (s *entryState) reset() {
	s.failures = 0
	s.nextAttempt = time.Time{}
}

// hashToken identifies a refresh token without keeping its value around.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
