package tokenstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/oauth2"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/vault"
)

// ErrNotFound is returned when no credential has been stored yet, which means
// the entry still has to go through the authorization flow.
var ErrNotFound = errors.New("tokenstore: no credential stored")

// Location is the KV v2 path a credential is stored at.
type Location struct {
	Mount string
	Path  string
}

func (l Location) String() string { return l.Mount + "/" + l.Path }

// API is the subset of the Vault client the store depends on.
type API interface {
	ReadKV2(ctx context.Context, mount, path string) (*vault.Secret, error)
	WriteKV2(ctx context.Context, mount, path string, data map[string]any, cas int) (int, error)
}

// Store reads and writes credentials in Vault.
type Store struct {
	api API
	now func() time.Time

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// Option customises a Store.
type Option func(*Store)

// WithClock overrides the clock. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// New builds a Store on top of a Vault client.
func New(api API, opts ...Option) *Store {
	s := &Store{
		api:   api,
		now:   time.Now,
		locks: make(map[string]*sync.Mutex),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithLock serialises the callers operating on one location, so that the
// background refresher and an interactive authorization do not race on the
// same credential. Check-and-set still guards against writers in other
// processes.
func (s *Store) WithLock(loc Location, fn func() error) error {
	mu := s.lockFor(loc)
	mu.Lock()
	defer mu.Unlock()
	return fn()
}

func (s *Store) lockFor(loc Location) *sync.Mutex {
	key := loc.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	mu, ok := s.locks[key]
	if !ok {
		mu = &sync.Mutex{}
		s.locks[key] = mu
	}
	return mu
}

// Load returns the stored credential, or ErrNotFound.
func (s *Store) Load(ctx context.Context, loc Location) (*Record, error) {
	rec, _, err := s.load(ctx, loc)
	return rec, err
}

func (s *Store) load(ctx context.Context, loc Location) (*Record, int, error) {
	secret, err := s.api.ReadKV2(ctx, loc.Mount, loc.Path)
	if err != nil {
		if errors.Is(err, vault.ErrSecretNotFound) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	rec, err := decodeRecord(secret.Data)
	if err != nil {
		return nil, secret.Version, err
	}
	return rec, secret.Version, nil
}

// SaveAuthorized stores a credential obtained from a fresh authorization,
// resetting the obtained_at marker.
func (s *Store) SaveAuthorized(ctx context.Context, loc Location, entryID string, tok *oauth2.Token) (*Record, error) {
	return s.save(ctx, loc, entryID, tok, true)
}

// SaveRefreshed stores a credential obtained by refreshing an existing one.
// The refresh token of the previous record is kept when the provider did not
// issue a new one, and obtained_at is preserved.
func (s *Store) SaveRefreshed(ctx context.Context, loc Location, entryID string, tok *oauth2.Token) (*Record, error) {
	return s.save(ctx, loc, entryID, tok, false)
}

// save performs a read-modify-write cycle guarded by check-and-set, retrying
// once when a concurrent writer bumped the version in between.
func (s *Store) save(ctx context.Context, loc Location, entryID string, tok *oauth2.Token, authorized bool) (*Record, error) {
	const attempts = 2
	var lastErr error
	for attempt := range attempts {
		previous, version, err := s.load(ctx, loc)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}

		rec := s.merge(previous, entryID, tok, authorized)
		data, err := rec.encode()
		if err != nil {
			return nil, err
		}
		if _, err = s.api.WriteKV2(ctx, loc.Mount, loc.Path, data, version); err != nil {
			if errors.Is(err, vault.ErrCASMismatch) && attempt < attempts-1 {
				lastErr = err
				continue
			}
			return nil, err
		}
		return rec, nil
	}
	return nil, fmt.Errorf("tokenstore: write %s: %w", loc, lastErr)
}

// merge builds the record to store from the new token and, where the provider
// left fields out, the previously stored credential.
func (s *Store) merge(previous *Record, entryID string, tok *oauth2.Token, authorized bool) *Record {
	now := s.now().UTC()
	rec := &Record{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
		Scope:        tok.Scope,
		EntryID:      entryID,
		Extra:        tok.Extra,
		ObtainedAt:   now,
		UpdatedAt:    now,
	}
	if previous == nil {
		return rec
	}
	// Providers that do not rotate refresh tokens omit the field entirely;
	// dropping the old one would break every later refresh.
	if rec.RefreshToken == "" {
		rec.RefreshToken = previous.RefreshToken
	}
	if rec.Scope == "" {
		rec.Scope = previous.Scope
	}
	if !authorized && !previous.ObtainedAt.IsZero() {
		rec.ObtainedAt = previous.ObtainedAt
	}
	return rec
}
