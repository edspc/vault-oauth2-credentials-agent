// Package httpapi serves the agent's HTTP surface: the endpoint that starts an
// authorization, the OAuth2 redirect that completes it and the health probes.
// Every response is plain text; the agent has no user interface.
package httpapi

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/agent"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/oauth2"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/tokenstore"
)

// Paths served by the agent besides the configurable callback path. PathRoot
// is not served; it only anchors the catch-all route.
const (
	PathRoot      = "/"
	PathAuthorize = "/authorize"
	PathHealthz   = "/healthz"
	PathReadyz    = "/readyz"
)

// DefaultStateTTL is how long a started authorization flow stays valid.
const DefaultStateTTL = 10 * time.Minute

// Config configures the HTTP surface.
type Config struct {
	// CallbackPath is the OAuth2 redirect path; it is shared by all entries
	// and the entry is resolved from the state parameter.
	CallbackPath string
	// StateTTL bounds how long a user has to complete an authorization.
	StateTTL time.Duration
}

// Server implements the authorization endpoints.
type Server struct {
	entries  []agent.Entry
	byID     map[string]agent.Entry
	store    *tokenstore.Store
	registry *agent.Registry
	states   *stateStore
	cfg      Config
	logger   *slog.Logger
	now      func() time.Time
	ready    func() bool
}

// Option customises a Server.
type Option func(*Server)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithClock overrides the clock. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Server) {
		if now != nil {
			s.now = now
		}
	}
}

// WithReadyCheck sets the readiness probe, which reports whether the agent has
// authenticated to Vault.
func WithReadyCheck(ready func() bool) Option {
	return func(s *Server) {
		if ready != nil {
			s.ready = ready
		}
	}
}

// New builds a Server.
func New(entries []agent.Entry, store *tokenstore.Store, registry *agent.Registry, cfg Config, opts ...Option) *Server {
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = "/callback"
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = DefaultStateTTL
	}
	s := &Server{
		entries:  entries,
		byID:     make(map[string]agent.Entry, len(entries)),
		store:    store,
		registry: registry,
		cfg:      cfg,
		logger:   slog.Default(),
		now:      time.Now,
		ready:    func() bool { return true },
	}
	for _, e := range entries {
		s.byID[e.ID] = e
	}
	s.states = newStateStore(cfg.StateTTL, func() time.Time { return s.now() })
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Handler returns the router with the agent's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathHealthz, s.handleHealthz)
	mux.HandleFunc("GET "+PathReadyz, s.handleReadyz)
	mux.HandleFunc("GET "+PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("GET "+s.cfg.CallbackPath, s.handleCallback)
	mux.HandleFunc("GET "+PathRoot, s.handleNotFound)
	return securityHeaders(mux)
}

// securityHeaders keeps the authorization code out of Referer headers, and
// keeps responses that echo provider-supplied text from being cached or
// sniffed out of text/plain into a type a browser would execute.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writePlain(w, http.StatusOK, "ok")
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !s.ready() {
		writePlain(w, http.StatusServiceUnavailable, "not authenticated to vault")
		return
	}
	writePlain(w, http.StatusOK, "ready")
}

// handleAuthorize starts an authorization flow and redirects the user to the
// provider.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	entryID := r.URL.Query().Get("entry")
	if entryID == "" {
		s.respond(w, http.StatusBadRequest, "",
			"missing entry parameter; use "+PathAuthorize+"?entry=ID with one of: "+s.knownEntryIDs())
		return
	}
	entry, ok := s.byID[entryID]
	if !ok {
		s.respond(w, http.StatusNotFound, "",
			fmt.Sprintf("unknown entry %q; configured entries: %s", entryID, s.knownEntryIDs()))
		return
	}

	var verifier, challenge string
	if entry.PKCE {
		var err error
		if verifier, challenge, err = oauth2.GeneratePKCE(); err != nil {
			s.internalError(w, entry.ID, "generate pkce challenge", err)
			return
		}
	}
	state, err := s.states.Create(entry.ID, verifier)
	if err != nil {
		s.internalError(w, entry.ID, "create authorization state", err)
		return
	}
	target, err := entry.Client.AuthCodeURL(state, challenge)
	if err != nil {
		s.internalError(w, entry.ID, "build authorization url", err)
		return
	}

	s.logger.Info("starting authorization flow", slog.String("entry", entry.ID))
	// http.Redirect appends an HTML body to a GET redirect unless a content
	// type is already set. Setting one keeps the agent free of HTML: the
	// browser follows the Location header and never needs a body.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Redirect(w, r, target, http.StatusFound)
}

// handleCallback completes an authorization flow and stores the credential.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	state, ok := s.states.Consume(query.Get("state"))
	if !ok {
		// Either a replayed callback, an expired flow, or a request that never
		// started at this agent. All of them are refused the same way.
		s.logger.Warn("rejected callback with unknown state")
		s.respond(w, http.StatusBadRequest, "",
			"the authorization state is unknown or has expired; start the flow again")
		return
	}
	entry, ok := s.byID[state.EntryID]
	if !ok {
		s.respond(w, http.StatusNotFound, state.EntryID,
			"the entry this flow belongs to is no longer configured")
		return
	}

	if providerErr := query.Get("error"); providerErr != "" {
		description := query.Get("error_description")
		s.logger.Warn("provider refused the authorization",
			slog.String("entry", entry.ID),
			slog.String("error", providerErr),
			slog.String("description", description))
		// The stored credential is untouched by a refused authorization, so
		// the reported state is not downgraded: it describes what is in
		// Vault, not how the last attempt went.
		s.respond(w, http.StatusBadRequest, entry.ID,
			"the provider refused the authorization: "+strings.TrimSpace(providerErr+" "+description))
		return
	}

	code := query.Get("code")
	if code == "" {
		s.respond(w, http.StatusBadRequest, entry.ID,
			"the provider returned no authorization code")
		return
	}

	var record *tokenstore.Record
	err := s.store.WithLock(entry.Location, func() error {
		token, err := entry.Client.Exchange(r.Context(), code, state.Verifier)
		if err != nil {
			return fmt.Errorf("exchange authorization code: %w", err)
		}
		if token.RefreshToken == "" {
			s.logger.Warn("provider returned no refresh token; "+
				"the credential cannot be refreshed automatically",
				slog.String("entry", entry.ID))
		}
		record, err = s.store.SaveAuthorized(r.Context(), entry.Location, entry.ID, token)
		if err != nil {
			return fmt.Errorf("store credential: %w", err)
		}
		return nil
	})
	if err != nil {
		// As above: a failed exchange leaves whatever is stored in place.
		s.logger.Error("authorization failed",
			slog.String("entry", entry.ID),
			slog.String("error", err.Error()))
		s.respond(w, http.StatusBadGateway, entry.ID,
			"could not complete the authorization; see the agent logs for details")
		return
	}

	s.registry.SetAuthorized(entry.ID, record.Expiry, record.UpdatedAt)
	s.logger.Info("credential authorized and stored",
		slog.String("entry", entry.ID),
		slog.String("vault_path", entry.Location.String()),
		slog.Time("expiry", record.Expiry))
	s.respond(w, http.StatusOK, entry.ID,
		"authorization complete; the credential was stored in Vault at "+entry.Location.String())
}

// handleNotFound answers any path the agent does not serve. It is reached
// through the "/" catch-all route, which also covers the root itself: the
// agent has no user interface to put there.
func (s *Server) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	writePlain(w, http.StatusNotFound, "not found")
}

func (s *Server) knownEntryIDs() string {
	ids := make([]string, 0, len(s.entries))
	for _, e := range s.entries {
		ids = append(ids, e.ID)
	}
	return strings.Join(ids, ", ")
}

func (s *Server) internalError(w http.ResponseWriter, entryID, what string, err error) {
	s.logger.Error("request failed",
		slog.String("entry", entryID),
		slog.String("operation", what),
		slog.String("error", err.Error()))
	s.respond(w, http.StatusInternalServerError, entryID,
		"could not "+what+"; see the agent logs for details")
}

// respond writes the outcome of a request as plain text. entryID may be empty
// when the request never got as far as naming an entry.
func (s *Server) respond(w http.ResponseWriter, status int, entryID, message string) {
	body := sanitize(message)
	if entryID != "" {
		body += "\nentry: " + sanitize(entryID)
	}
	writePlain(w, status, body)
}

func writePlain(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, message+"\n")
}

// maxMessageLen bounds how much provider-supplied text is echoed back.
const maxMessageLen = 300

// sanitize makes text that came from the provider or the query string safe to
// echo: control characters are dropped so the response cannot be made to span
// lines the agent did not intend, and the result is bounded. Together with the
// text/plain content type and the nosniff header, markup in such text is inert.
func sanitize(text string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, text)
	cleaned = strings.Join(strings.Fields(cleaned), " ")

	if len(cleaned) > maxMessageLen {
		// Cut on a rune boundary so the response stays valid UTF-8.
		cut := maxMessageLen
		for cut > 0 && !utf8.RuneStart(cleaned[cut]) {
			cut--
		}
		cleaned = cleaned[:cut] + "..."
	}
	return cleaned
}
