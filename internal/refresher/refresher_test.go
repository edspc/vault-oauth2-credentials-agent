package refresher

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/agent"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/metrics"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/oauth2"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/tokenstore"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/vault"
)

var (
	testLocation = tokenstore.Location{Mount: "secret", Path: "oauth2/example"}
	baseTime     = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
)

// fakeVault is an in-memory KV v2 backend with check-and-set semantics.
type fakeVault struct {
	mu      sync.Mutex
	data    map[string]any
	version int
	readErr error
}

func (f *fakeVault) ReadKV2(_ context.Context, _, _ string) (*vault.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.data == nil {
		return nil, vault.ErrSecretNotFound
	}
	copied := make(map[string]any, len(f.data))
	for k, v := range f.data {
		copied[k] = v
	}
	return &vault.Secret{Data: copied, Version: f.version}, nil
}

func (f *fakeVault) WriteKV2(_ context.Context, _, _ string, data map[string]any, cas int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cas != f.version {
		return 0, vault.ErrCASMismatch
	}
	f.data = data
	f.version++
	return f.version, nil
}

func (f *fakeVault) field(name string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data[name]
}

// harness wires a refresher against a fake Vault and a stub token endpoint.
type harness struct {
	t         *testing.T
	backend   *fakeVault
	store     *tokenstore.Store
	registry  *agent.Registry
	refresher *Refresher
	recorder  *metrics.Recorder
	exporter  *metrics.Exporter
	now       time.Time
	calls     int
}

// counter reads one refresh counter out of the exposition document.
func (h *harness) counter(result string) string {
	h.t.Helper()
	prefix := `oauth2_agent_refresh_attempts_total{entry="example",result="` + result + `"} `
	for _, line := range strings.Split(string(h.exporter.Gather()), "\n") {
		if value, ok := strings.CutPrefix(line, prefix); ok {
			return value
		}
	}
	h.t.Fatalf("no refresh counter for result %q", result)
	return ""
}

func newHarness(t *testing.T, tokenHandler http.HandlerFunc) *harness {
	t.Helper()
	h := &harness{t: t, backend: &fakeVault{}, now: baseTime}

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.calls++
		tokenHandler(w, r)
	}))
	t.Cleanup(provider.Close)

	clock := func() time.Time { return h.now }
	h.store = tokenstore.New(h.backend, tokenstore.WithClock(clock))

	entry := agent.Entry{
		ID:       "example",
		Location: testLocation,
		Client: oauth2.NewClient(oauth2.Config{
			ClientID:     "client",
			ClientSecret: "secret",
			AuthURL:      "https://provider.example.com/authorize",
			TokenURL:     provider.URL,
			RedirectURL:  "https://agent.example.com/callback",
		}, oauth2.WithClock(clock)),
	}
	entries := []agent.Entry{entry}
	h.registry = agent.NewRegistry(entries)
	h.recorder = metrics.NewRecorder(entries)
	h.exporter = metrics.NewExporter(entries, h.registry, nil, h.recorder,
		metrics.WithClock(clock))
	h.refresher = New(entries, h.store, h.registry, Config{
		Interval:     time.Minute,
		BeforeExpiry: 10 * time.Minute,
		MaxBackoff:   30 * time.Minute,
	},
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithClock(clock),
		WithMetrics(h.recorder))
	return h
}

// seed stores a credential expiring at the given time.
func (h *harness) seed(refreshToken string, expiry time.Time) {
	h.t.Helper()
	token := &oauth2.Token{AccessToken: "old-at", RefreshToken: refreshToken, Expiry: expiry}
	if _, err := h.store.SaveAuthorized(context.Background(), testLocation, "example", token); err != nil {
		h.t.Fatalf("seed store: %v", err)
	}
}

func (h *harness) state() agent.State {
	return h.registry.Get("example").State
}

func respondWithToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"access_token":"new-at","expires_in":3600}`)
}

func failWith(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestRunOnceMarksMissingCredentialAsNeedingAuth(t *testing.T) {
	h := newHarness(t, respondWithToken)

	h.refresher.RunOnce(context.Background())

	if got := h.state(); got != agent.StateNeedsAuth {
		t.Errorf("state = %q, want %q", got, agent.StateNeedsAuth)
	}
	if h.calls != 0 {
		t.Errorf("provider calls = %d, want none", h.calls)
	}
}

func TestRunOnceSkipsCredentialThatIsNotDueYet(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.seed("rt", baseTime.Add(time.Hour))

	h.refresher.RunOnce(context.Background())

	if h.calls != 0 {
		t.Errorf("provider calls = %d, want none while the token is still fresh", h.calls)
	}
	if got := h.state(); got != agent.StateAuthorized {
		t.Errorf("state = %q, want %q", got, agent.StateAuthorized)
	}
	if got := h.registry.Get("example").Expiry; !got.Equal(baseTime.Add(time.Hour)) {
		t.Errorf("reported expiry = %s, want the stored one", got)
	}
}

func TestRunOnceRefreshesExpiringCredential(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.seed("rt", baseTime.Add(5*time.Minute))

	h.refresher.RunOnce(context.Background())

	if h.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", h.calls)
	}
	if got := h.backend.field(tokenstore.FieldAccessToken); got != "new-at" {
		t.Errorf("stored access token = %v, want new-at", got)
	}
	if got := h.backend.field(tokenstore.FieldRefreshToken); got != "rt" {
		t.Errorf("stored refresh token = %v, want the previous rt to be kept", got)
	}
	if got := h.state(); got != agent.StateAuthorized {
		t.Errorf("state = %q, want %q", got, agent.StateAuthorized)
	}
}

func TestRunOnceSkipsCredentialWithoutExpiry(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.seed("rt", time.Time{})

	h.refresher.RunOnce(context.Background())

	if h.calls != 0 {
		t.Errorf("provider calls = %d, want none for a token without an expiry", h.calls)
	}
	if got := h.state(); got != agent.StateAuthorized {
		t.Errorf("state = %q, want %q", got, agent.StateAuthorized)
	}
}

func TestRunOnceSkipsCredentialWithoutRefreshToken(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.seed("", baseTime.Add(time.Minute))

	h.refresher.RunOnce(context.Background())

	if h.calls != 0 {
		t.Errorf("provider calls = %d, want none without a refresh token", h.calls)
	}
	if got := h.state(); got != agent.StateNeedsAuth {
		t.Errorf("state = %q, want %q", got, agent.StateNeedsAuth)
	}
}

func TestInvalidGrantStopsRetryingUntilReauthorization(t *testing.T) {
	h := newHarness(t, failWith(http.StatusBadRequest, `{"error":"invalid_grant"}`))
	h.seed("rt", baseTime.Add(time.Minute))
	ctx := context.Background()

	h.refresher.RunOnce(ctx)
	if h.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", h.calls)
	}
	if got := h.state(); got != agent.StateNeedsReauth {
		t.Errorf("state = %q, want %q", got, agent.StateNeedsReauth)
	}

	// Later passes must not keep hammering the provider with a dead token,
	// even once the backoff would have elapsed.
	h.now = h.now.Add(time.Hour)
	h.refresher.RunOnce(ctx)
	h.refresher.RunOnce(ctx)
	if h.calls != 1 {
		t.Errorf("provider calls = %d, want the dead refresh token not to be retried", h.calls)
	}
	if got := h.state(); got != agent.StateNeedsReauth {
		t.Errorf("state = %q, want %q", got, agent.StateNeedsReauth)
	}

	// A new authorization replaces the refresh token, which resumes refreshing.
	h.seed("rt-new", h.now.Add(time.Minute))
	h.refresher.RunOnce(ctx)
	if h.calls != 2 {
		t.Errorf("provider calls = %d, want the new refresh token to be tried", h.calls)
	}
}

func TestTransientFailureBacksOff(t *testing.T) {
	h := newHarness(t, failWith(http.StatusInternalServerError, `{}`))
	h.seed("rt", baseTime.Add(time.Minute))
	ctx := context.Background()

	h.refresher.RunOnce(ctx)
	if h.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", h.calls)
	}
	if got := h.state(); got != agent.StateRefreshFailed {
		t.Errorf("state = %q, want %q", got, agent.StateRefreshFailed)
	}

	// Still inside the backoff window: no further attempt.
	h.now = h.now.Add(30 * time.Second)
	h.refresher.RunOnce(ctx)
	if h.calls != 1 {
		t.Errorf("provider calls = %d, want the attempt to be delayed", h.calls)
	}

	// Backoff elapsed: try again, and double the delay after the new failure.
	h.now = h.now.Add(31 * time.Second)
	h.refresher.RunOnce(ctx)
	if h.calls != 2 {
		t.Errorf("provider calls = %d, want a retry after the backoff", h.calls)
	}
	if got := h.refresher.state["example"].failures; got != 2 {
		t.Errorf("failures = %d, want 2", got)
	}
	if want := h.now.Add(2 * time.Minute); !h.refresher.state["example"].nextAttempt.Equal(want) {
		t.Errorf("nextAttempt = %s, want %s", h.refresher.state["example"].nextAttempt, want)
	}
}

func TestBackoffIsCappedAndResetOnSuccess(t *testing.T) {
	h := newHarness(t, respondWithToken)
	state := h.refresher.state["example"]

	for range 20 {
		h.refresher.backoff("example", state, slog.New(slog.NewTextHandler(io.Discard, nil)),
			errors.New("boom"))
	}
	if want := h.now.Add(30 * time.Minute); !state.nextAttempt.Equal(want) {
		t.Errorf("nextAttempt = %s, want it capped at %s", state.nextAttempt, want)
	}

	h.seed("rt", baseTime.Add(time.Minute))
	state.nextAttempt = time.Time{}
	h.refresher.RunOnce(context.Background())

	if state.failures != 0 || !state.nextAttempt.IsZero() {
		t.Errorf("state = %+v, want the backoff reset after a success", state)
	}
}

func TestReadErrorIsReported(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.backend.readErr = errors.New("vault is sealed")

	h.refresher.RunOnce(context.Background())

	if got := h.state(); got != agent.StateRefreshFailed {
		t.Errorf("state = %q, want %q", got, agent.StateRefreshFailed)
	}
	if got := h.counter(metrics.ResultFailure); got != "1" {
		t.Errorf("failure counter = %s, want the read failure to be counted", got)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	h := newHarness(t, respondWithToken)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		h.refresher.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after the context was cancelled")
	}
}

func TestHashTokenIsStableAndDistinct(t *testing.T) {
	if hashToken("a") != hashToken("a") {
		t.Error("hashToken() is not stable for the same input")
	}
	if hashToken("a") == hashToken("b") {
		t.Error("hashToken() collides for different inputs")
	}
}

func TestRefreshOutcomesAreCounted(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.seed("rt", baseTime.Add(5*time.Minute))

	h.refresher.RunOnce(context.Background())

	if got := h.counter(metrics.ResultSuccess); got != "1" {
		t.Errorf("success counter = %s, want 1", got)
	}
	if got := h.counter(metrics.ResultFailure); got != "0" {
		t.Errorf("failure counter = %s, want 0", got)
	}
}

func TestSkippedCredentialIsNotCounted(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.seed("rt", baseTime.Add(time.Hour))

	h.refresher.RunOnce(context.Background())

	for _, result := range []string{metrics.ResultSuccess, metrics.ResultFailure, metrics.ResultNeedsReauth} {
		if got := h.counter(result); got != "0" {
			t.Errorf("%s counter = %s, want 0 when no refresh was due", result, got)
		}
	}
}

func TestInvalidGrantIsCountedAsNeedsReauth(t *testing.T) {
	h := newHarness(t, failWith(http.StatusBadRequest, `{"error":"invalid_grant"}`))
	h.seed("rt", baseTime.Add(time.Minute))

	h.refresher.RunOnce(context.Background())

	if got := h.counter(metrics.ResultNeedsReauth); got != "1" {
		t.Errorf("needs_reauth counter = %s, want 1", got)
	}
	if got := h.counter(metrics.ResultFailure); got != "0" {
		t.Errorf("failure counter = %s, want 0; invalid_grant is not a transient failure", got)
	}
}

func TestTransientFailureIsCounted(t *testing.T) {
	h := newHarness(t, failWith(http.StatusInternalServerError, `{}`))
	h.seed("rt", baseTime.Add(time.Minute))

	h.refresher.RunOnce(context.Background())

	if got := h.counter(metrics.ResultFailure); got != "1" {
		t.Errorf("failure counter = %s, want 1", got)
	}
}

func TestRefresherWithoutMetricsRecorder(t *testing.T) {
	h := newHarness(t, respondWithToken)
	// Metrics disabled: the refresher holds a nil recorder.
	WithMetrics(nil)(h.refresher)
	h.seed("rt", baseTime.Add(5*time.Minute))

	h.refresher.RunOnce(context.Background())

	if h.calls != 1 {
		t.Errorf("provider calls = %d, want the refresh to happen anyway", h.calls)
	}
	if got := h.state(); got != agent.StateAuthorized {
		t.Errorf("state = %q, want %q", got, agent.StateAuthorized)
	}
}
