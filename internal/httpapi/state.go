package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// maxPendingStates bounds the memory a caller can occupy by starting
// authorization flows without ever completing them. The endpoint is
// unauthenticated, so the oldest pending flow is evicted once the limit is hit.
const maxPendingStates = 1024

// authState is the server-side half of one in-flight authorization flow.
type authState struct {
	EntryID string
	// Verifier is the PKCE code verifier, empty when PKCE is disabled.
	Verifier  string
	CreatedAt time.Time
}

// stateStore keeps in-flight authorization flows in memory. The agent runs as
// a single replica, so there is nothing to share between processes; a restart
// simply invalidates the flows that were in progress.
type stateStore struct {
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	states map[string]authState
}

func newStateStore(ttl time.Duration, now func() time.Time) *stateStore {
	if now == nil {
		now = time.Now
	}
	return &stateStore{ttl: ttl, now: now, states: make(map[string]authState)}
}

// Create registers a new flow and returns its opaque state parameter.
func (s *stateStore) Create(entryID, verifier string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	s.states[state] = authState{EntryID: entryID, Verifier: verifier, CreatedAt: s.now()}
	return state, nil
}

// Consume looks a state up and removes it, so that a replayed callback is
// rejected. The lookup is constant-time with respect to the stored values to
// keep it from leaking valid states through timing.
func (s *stateStore) Consume(state string) (authState, bool) {
	if state == "" {
		return authState{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()

	for candidate, value := range s.states {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(state)) == 1 {
			delete(s.states, candidate)
			return value, true
		}
	}
	return authState{}, false
}

// Pending reports how many authorization flows are currently in flight.
func (s *stateStore) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.states)
}

// purgeLocked drops expired flows and, if the store is still full, the oldest
// remaining one. The caller must hold the mutex.
func (s *stateStore) purgeLocked() {
	deadline := s.now().Add(-s.ttl)
	for key, value := range s.states {
		if value.CreatedAt.Before(deadline) {
			delete(s.states, key)
		}
	}
	for len(s.states) >= maxPendingStates {
		oldestKey := ""
		var oldestAt time.Time
		for key, value := range s.states {
			if oldestKey == "" || value.CreatedAt.Before(oldestAt) {
				oldestKey, oldestAt = key, value.CreatedAt
			}
		}
		delete(s.states, oldestKey)
	}
}
