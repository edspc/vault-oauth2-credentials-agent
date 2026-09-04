package metrics

import (
	"sort"
	"sync/atomic"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/agent"
)

// Result values of a refresh or authorization attempt.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	// ResultNeedsReauth marks a refresh the provider refused with
	// invalid_grant, which only a new authorization can repair.
	ResultNeedsReauth = "needs_reauth"
)

var (
	refreshResults       = []string{ResultSuccess, ResultFailure, ResultNeedsReauth}
	authorizationResults = []string{ResultSuccess, ResultFailure}
)

// counter is one counter series.
type counter struct {
	entry  string
	result string
	value  atomic.Int64
}

// counterVec holds every (entry, result) series of one counter family. All
// series are created up front, so the map is never written to afterwards and
// can be read without synchronisation, and a series exists at zero before the
// first event rather than appearing out of nowhere.
type counterVec struct {
	byKey map[string]*counter
	all   []*counter
}

func newCounterVec(entries []agent.Entry, results []string) *counterVec {
	v := &counterVec{byKey: make(map[string]*counter, len(entries)*len(results))}
	for _, entry := range entries {
		for _, result := range results {
			c := &counter{entry: entry.ID, result: result}
			v.byKey[counterKey(entry.ID, result)] = c
			v.all = append(v.all, c)
		}
	}
	sort.Slice(v.all, func(i, j int) bool {
		if v.all[i].entry != v.all[j].entry {
			return v.all[i].entry < v.all[j].entry
		}
		return v.all[i].result < v.all[j].result
	})
	return v
}

func (v *counterVec) inc(entryID, result string) {
	if c, ok := v.byKey[counterKey(entryID, result)]; ok {
		c.value.Add(1)
	}
}

func counterKey(entryID, result string) string { return entryID + "\x00" + result }

// Recorder counts the events the agent produces. A nil *Recorder is a working
// no-op, which is what the agent uses when metrics are disabled: the call
// sites stay free of conditionals and nothing is measured.
type Recorder struct {
	refreshes      *counterVec
	authorizations *counterVec
}

// NewRecorder returns a recorder with a zeroed series for every entry.
func NewRecorder(entries []agent.Entry) *Recorder {
	return &Recorder{
		refreshes:      newCounterVec(entries, refreshResults),
		authorizations: newCounterVec(entries, authorizationResults),
	}
}

// RefreshAttempt records the outcome of a background refresh.
func (r *Recorder) RefreshAttempt(entryID, result string) {
	if r == nil {
		return
	}
	r.refreshes.inc(entryID, result)
}

// Authorization records the outcome of an interactive authorization.
func (r *Recorder) Authorization(entryID, result string) {
	if r == nil {
		return
	}
	r.authorizations.inc(entryID, result)
}
