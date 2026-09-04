package agent

import (
	"sync"
	"time"
)

// State is the lifecycle state of a credential as last observed by the agent.
type State string

// State values are stable identifiers: they are exported as a metric label
// and must not be reworded for presentation. Use Description for that.
const (
	// StateUnknown means the credential has not been inspected yet.
	StateUnknown State = "unknown"
	// StateNeedsAuth means no usable credential is stored; a user has to run
	// the authorization flow.
	StateNeedsAuth State = "needs_auth"
	// StateAuthorized means a valid credential is stored in Vault.
	StateAuthorized State = "authorized"
	// StateNeedsReauth means the refresh token was rejected and only a new
	// authorization can restore the credential.
	StateNeedsReauth State = "needs_reauth"
	// StateRefreshFailed means the last refresh attempt failed and will be
	// retried.
	StateRefreshFailed State = "refresh_failed"
)

// States returns every state in a stable order, so that exporters can emit a
// row for each of them and the series exist before a state is first reached.
func States() []State {
	return []State{
		StateUnknown,
		StateNeedsAuth,
		StateAuthorized,
		StateNeedsReauth,
		StateRefreshFailed,
	}
}

// Status is the observable state of one entry. It carries only what the
// metrics endpoint reports, never token values; the reason behind a failure
// belongs in the logs, where it is not bounded to a label.
type Status struct {
	State State
	// Expiry is the expiry of the stored access token, zero when unknown.
	Expiry time.Time
	// LastSuccess is when the credential was last written successfully.
	LastSuccess time.Time
}

// Registry holds the status of every entry.
type Registry struct {
	mu       sync.RWMutex
	statuses map[string]Status
}

// NewRegistry returns a registry with every entry in StateUnknown.
func NewRegistry(entries []Entry) *Registry {
	r := &Registry{statuses: make(map[string]Status, len(entries))}
	for _, e := range entries {
		r.statuses[e.ID] = Status{State: StateUnknown}
	}
	return r
}

// Get returns the status of an entry.
func (r *Registry) Get(id string) Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.statuses[id]
}

// SetAuthorized records a successful authorization or refresh.
func (r *Registry) SetAuthorized(id string, expiry, at time.Time) {
	r.set(id, Status{State: StateAuthorized, Expiry: expiry, LastSuccess: at})
}

// SetState moves an entry to a new state, keeping the timestamps of the last
// successful write.
func (r *Registry) SetState(id string, state State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.statuses[id]
	current.State = state
	r.statuses[id] = current
}

func (r *Registry) set(id string, s Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses[id] = s
}
