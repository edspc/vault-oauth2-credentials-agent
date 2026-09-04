package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
}

func (f *fakeVault) ReadKV2(_ context.Context, _, _ string) (*vault.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

type harness struct {
	server   *Server
	handler  http.Handler
	backend  *fakeVault
	entries  []agent.Entry
	registry *agent.Registry
	provider *httptest.Server
	ready    bool
}

// enableMetrics turns on the exposition endpoint and returns the recorder the
// handlers write to.
func (h *harness) enableMetrics(path string) *metrics.Recorder {
	recorder := metrics.NewRecorder(h.entries)
	exporter := metrics.NewExporter(h.entries, h.registry, nil, recorder)
	h.server.cfg.MetricsPath = path
	WithMetrics(recorder, exporter)(h.server)
	h.handler = h.server.Handler()
	return recorder
}

func newHarness(t *testing.T, tokenHandler http.HandlerFunc, opts ...Option) *harness {
	t.Helper()
	h := &harness{backend: &fakeVault{}, ready: true}

	h.provider = httptest.NewServer(tokenHandler)
	t.Cleanup(h.provider.Close)

	clock := func() time.Time { return baseTime }
	store := tokenstore.New(h.backend, tokenstore.WithClock(clock))

	entries := []agent.Entry{{
		ID:       "example",
		PKCE:     true,
		Location: testLocation,
		Client: oauth2.NewClient(oauth2.Config{
			ClientID:     "client",
			ClientSecret: "secret",
			AuthURL:      "https://provider.example.com/authorize",
			TokenURL:     h.provider.URL,
			RedirectURL:  "https://agent.example.com/callback",
			Scopes:       []string{"repo"},
		}, oauth2.WithClock(clock)),
	}}
	h.entries = entries
	h.registry = agent.NewRegistry(entries)

	options := []Option{
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithClock(clock),
		WithReadyCheck(func() bool { return h.ready }),
	}
	h.server = New(entries, store, h.registry,
		Config{CallbackPath: "/callback"}, append(options, opts...)...)
	h.handler = h.server.Handler()
	return h
}

func (h *harness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// startFlow runs /authorize and returns the state parameter of the redirect.
func (h *harness) startFlow(t *testing.T) string {
	t.Helper()
	rec := h.get(t, PathAuthorize+"?entry=example")
	if rec.Code != http.StatusFound {
		t.Fatalf("/authorize status = %d, want 302", rec.Code)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	state := location.Query().Get("state")
	if state == "" {
		t.Fatal("redirect carries no state parameter")
	}
	return state
}

func respondWithToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"access_token":"the-access-token","refresh_token":"the-refresh-token",`+
		`"token_type":"Bearer","expires_in":3600}`)
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, respondWithToken)
	if rec := h.get(t, PathHealthz); rec.Code != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200", rec.Code)
	}
}

func TestReadyzReflectsVaultAuthentication(t *testing.T) {
	h := newHarness(t, respondWithToken)

	h.ready = false
	if rec := h.get(t, PathReadyz); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 503 before Vault authentication", rec.Code)
	}

	h.ready = true
	if rec := h.get(t, PathReadyz); rec.Code != http.StatusOK {
		t.Errorf("/readyz status = %d, want 200", rec.Code)
	}
}

func TestAuthorizeRedirectsWithStateAndChallenge(t *testing.T) {
	h := newHarness(t, respondWithToken)

	rec := h.get(t, PathAuthorize+"?entry=example")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if location.Host != "provider.example.com" {
		t.Errorf("redirect host = %q, want provider.example.com", location.Host)
	}
	query := location.Query()
	for _, key := range []string{"state", "code_challenge", "client_id", "redirect_uri", "scope"} {
		if query.Get(key) == "" {
			t.Errorf("redirect query %q is empty, want it set", key)
		}
	}
	if got := query.Get("code_challenge_method"); got != oauth2.ChallengeMethodS256 {
		t.Errorf("code_challenge_method = %q, want %q", got, oauth2.ChallengeMethodS256)
	}
	if h.server.states.Pending() != 1 {
		t.Errorf("pending states = %d, want 1", h.server.states.Pending())
	}

	// The stdlib would append an HTML body to a GET redirect; the agent serves
	// no HTML, and the browser only needs the Location header.
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Errorf("redirect body = %q, want it empty", body)
	}
}

func TestAuthorizeWithoutEntryParameter(t *testing.T) {
	h := newHarness(t, respondWithToken)
	rec := h.get(t, PathAuthorize)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "example") {
		t.Error("response does not list the known entries")
	}
}

func TestAuthorizeUnknownEntry(t *testing.T) {
	h := newHarness(t, respondWithToken)
	if rec := h.get(t, PathAuthorize+"?entry=missing"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestCallbackStoresCredential(t *testing.T) {
	h := newHarness(t, respondWithToken)
	state := h.startFlow(t)

	rec := h.get(t, "/callback?code=the-code&state="+url.QueryEscape(state))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if got := h.backend.field(tokenstore.FieldAccessToken); got != "the-access-token" {
		t.Errorf("stored access token = %v, want the-access-token", got)
	}
	if got := h.backend.field(tokenstore.FieldRefreshToken); got != "the-refresh-token" {
		t.Errorf("stored refresh token = %v, want the-refresh-token", got)
	}
	if got := h.registry.Get("example").State; got != agent.StateAuthorized {
		t.Errorf("state = %q, want %q", got, agent.StateAuthorized)
	}
	if body := rec.Body.String(); strings.Contains(body, "the-access-token") ||
		strings.Contains(body, "the-refresh-token") {
		t.Error("response contains token material, want it withheld")
	}
	if !strings.Contains(rec.Body.String(), "entry: example") {
		t.Errorf("response does not name the entry: %q", rec.Body.String())
	}
	if h.server.states.Pending() != 0 {
		t.Errorf("pending states = %d, want the state consumed", h.server.states.Pending())
	}
}

func TestCallbackSendsPKCEVerifier(t *testing.T) {
	var gotVerifier string
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		gotVerifier = form.Get("code_verifier")
		respondWithToken(w, r)
	})
	state := h.startFlow(t)

	if rec := h.get(t, "/callback?code=c&state="+url.QueryEscape(state)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotVerifier == "" {
		t.Error("code_verifier was not sent to the token endpoint")
	}
}

func TestCallbackRejectsUnknownState(t *testing.T) {
	h := newHarness(t, respondWithToken)

	rec := h.get(t, "/callback?code=c&state=forged")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if h.backend.data != nil {
		t.Error("a credential was stored for a forged state")
	}
}

func TestCallbackRejectsReplayedState(t *testing.T) {
	h := newHarness(t, respondWithToken)
	state := h.startFlow(t)
	target := "/callback?code=c&state=" + url.QueryEscape(state)

	if rec := h.get(t, target); rec.Code != http.StatusOK {
		t.Fatalf("first callback status = %d, want 200", rec.Code)
	}
	if rec := h.get(t, target); rec.Code != http.StatusBadRequest {
		t.Errorf("replayed callback status = %d, want 400", rec.Code)
	}
}

func TestCallbackWithoutState(t *testing.T) {
	h := newHarness(t, respondWithToken)
	if rec := h.get(t, "/callback?code=c"); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackWithProviderError(t *testing.T) {
	h := newHarness(t, respondWithToken)
	state := h.startFlow(t)

	rec := h.get(t, "/callback?error=access_denied&error_description=user+refused&state="+
		url.QueryEscape(state))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "access_denied") {
		t.Error("response does not report the provider error")
	}
	if got := h.registry.Get("example").State; got != agent.StateUnknown {
		t.Errorf("state = %q, want it left at %q; the failure changed nothing in Vault",
			got, agent.StateUnknown)
	}
}

func TestCallbackWithoutCode(t *testing.T) {
	h := newHarness(t, respondWithToken)
	state := h.startFlow(t)

	rec := h.get(t, "/callback?state="+url.QueryEscape(state))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackReportsTokenEndpointFailure(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	})
	state := h.startFlow(t)

	rec := h.get(t, "/callback?code=c&state="+url.QueryEscape(state))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if h.backend.data != nil {
		t.Error("a credential was stored despite the failed exchange")
	}
	if got := h.registry.Get("example").State; got != agent.StateUnknown {
		t.Errorf("state = %q, want it left at %q; the failure changed nothing in Vault",
			got, agent.StateUnknown)
	}
}

func TestCallbackNeutralisesProviderSuppliedText(t *testing.T) {
	h := newHarness(t, respondWithToken)
	state := h.startFlow(t)

	rec := h.get(t, "/callback?error=%3Cscript%3Ealert(1)%3C%2Fscript%3E"+
		"&error_description=first%0D%0Asecond&state="+url.QueryEscape(state))

	// The text is echoed verbatim but served as plain text with nosniff, so a
	// browser cannot be talked into executing it.
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}

	// Control characters are dropped so the provider cannot forge extra lines.
	body := rec.Body.String()
	if strings.Count(strings.TrimSuffix(body, "\n"), "\n") != 1 {
		t.Errorf("response spans unexpected lines: %q", body)
	}
	if !strings.Contains(body, "first second") {
		t.Errorf("body = %q, want the newline in the description collapsed", body)
	}
}

func TestLongProviderTextIsBounded(t *testing.T) {
	h := newHarness(t, respondWithToken)
	state := h.startFlow(t)

	rec := h.get(t, "/callback?error=denied&error_description="+
		strings.Repeat("x", 5000)+"&state="+url.QueryEscape(state))

	if body := rec.Body.String(); len(body) > maxMessageLen+64 {
		t.Errorf("response is %d bytes, want it bounded near %d", len(body), maxMessageLen)
	}
}

func TestRootIsNotServed(t *testing.T) {
	h := newHarness(t, respondWithToken)

	// The agent has no user interface; only the four functional routes exist.
	if rec := h.get(t, "/"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 at the root", rec.Code)
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	h := newHarness(t, respondWithToken)
	if rec := h.get(t, "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestNoResponseIsHTML(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.enableMetrics("/metrics")
	state := h.startFlow(t)

	targets := []string{
		"/", "/nope", PathHealthz, PathReadyz, "/metrics",
		PathAuthorize, PathAuthorize + "?entry=missing", PathAuthorize + "?entry=example",
		"/callback?state=forged",
		"/callback?code=c&state=" + url.QueryEscape(state),
	}
	for _, target := range targets {
		rec := h.get(t, target)
		contentType := rec.Header().Get("Content-Type")
		if strings.Contains(contentType, "html") {
			t.Errorf("%s served %q, want no HTML anywhere", target, contentType)
		}
		if strings.Contains(rec.Body.String(), "<") {
			t.Errorf("%s body contains markup: %q", target, rec.Body.String())
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t, respondWithToken)
	rec := h.get(t, PathHealthz)

	want := map[string]string{
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

func TestCustomCallbackPath(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.server.cfg.CallbackPath = "/oauth/done"
	handler := h.server.Handler()

	state := ""
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathAuthorize+"?entry=example", nil))
	if location, err := url.Parse(rec.Header().Get("Location")); err == nil {
		state = location.Query().Get("state")
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/oauth/done?code=c&state="+url.QueryEscape(state), nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 on the configured callback path", rec.Code)
	}
}

func TestMetricsEndpointIsNotRegisteredByDefault(t *testing.T) {
	h := newHarness(t, respondWithToken)
	if rec := h.get(t, "/metrics"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 while no metrics path is configured", rec.Code)
	}
}

func TestMetricsEndpointServesExposition(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.enableMetrics("/metrics")

	rec := h.get(t, "/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != metrics.ContentType {
		t.Errorf("Content-Type = %q, want %q", got, metrics.ContentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `oauth2_agent_credential_state{entry="example",state="unknown"} 1`) {
		t.Errorf("exposition does not report the entry state:\n%s", body)
	}
}

func TestMetricsEndpointOnACustomPath(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.enableMetrics("/internal/metrics")

	if rec := h.get(t, "/internal/metrics"); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 on the configured path", rec.Code)
	}
	if rec := h.get(t, "/metrics"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 on the default path", rec.Code)
	}
}

func TestSuccessfulAuthorizationIsCounted(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.enableMetrics("/metrics")

	state := h.startFlow(t)
	if rec := h.get(t, "/callback?code=c&state="+url.QueryEscape(state)); rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", rec.Code)
	}

	body := h.get(t, "/metrics").Body.String()
	if !strings.Contains(body, `oauth2_agent_authorizations_total{entry="example",result="success"} 1`) {
		t.Errorf("successful authorization was not counted:\n%s", body)
	}
	if !strings.Contains(body, `oauth2_agent_credential_state{entry="example",state="authorized"} 1`) {
		t.Errorf("state was not reported as authorized:\n%s", body)
	}
	if !strings.Contains(body, "oauth2_agent_credential_expires_at_timestamp_seconds{entry=\"example\"}") {
		t.Errorf("expiry timestamp is missing:\n%s", body)
	}
}

func TestRefusedAuthorizationIsCounted(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.enableMetrics("/metrics")

	state := h.startFlow(t)
	if rec := h.get(t, "/callback?error=access_denied&state="+url.QueryEscape(state)); rec.Code != http.StatusBadRequest {
		t.Fatalf("callback status = %d, want 400", rec.Code)
	}

	body := h.get(t, "/metrics").Body.String()
	if !strings.Contains(body, `oauth2_agent_authorizations_total{entry="example",result="failure"} 1`) {
		t.Errorf("refused authorization was not counted:\n%s", body)
	}
}

func TestAuthorizationIsNotCountedWithoutMetrics(t *testing.T) {
	h := newHarness(t, respondWithToken)
	state := h.startFlow(t)

	// The handlers hold a nil recorder here; the flow must still complete.
	if rec := h.get(t, "/callback?code=c&state="+url.QueryEscape(state)); rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, want 200 with metrics disabled", rec.Code)
	}
}

func TestFailedReauthorizationKeepsTheReportedState(t *testing.T) {
	h := newHarness(t, respondWithToken)
	h.enableMetrics("/metrics")

	// A valid credential is already stored and reported as such.
	state := h.startFlow(t)
	if rec := h.get(t, "/callback?code=c&state="+url.QueryEscape(state)); rec.Code != http.StatusOK {
		t.Fatalf("first callback status = %d, want 200", rec.Code)
	}

	// The user starts a re-authorization and the provider refuses it. The
	// stored credential is untouched, so the reported state must not claim
	// that authorization is missing.
	state = h.startFlow(t)
	if rec := h.get(t, "/callback?error=access_denied&state="+url.QueryEscape(state)); rec.Code != http.StatusBadRequest {
		t.Fatalf("second callback status = %d, want 400", rec.Code)
	}

	if got := h.registry.Get("example").State; got != agent.StateAuthorized {
		t.Errorf("state = %q, want %q; a refused re-authorization must not downgrade it",
			got, agent.StateAuthorized)
	}
	body := h.get(t, "/metrics").Body.String()
	if !strings.Contains(body, `oauth2_agent_authorizations_total{entry="example",result="failure"} 1`) {
		t.Error("the refused authorization was not counted")
	}
}
