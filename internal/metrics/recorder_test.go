package metrics

import (
	"sync"
	"testing"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/agent"
)

func TestNilRecorderIsANoOp(t *testing.T) {
	var recorder *Recorder
	// The agent passes a nil recorder when metrics are disabled; the calls
	// must stay safe rather than being guarded at every call site.
	recorder.RefreshAttempt("github-ci", ResultSuccess)
	recorder.Authorization("github-ci", ResultFailure)
}

func TestRecorderIgnoresUnknownSeries(t *testing.T) {
	recorder := NewRecorder([]agent.Entry{{ID: "github-ci"}})
	recorder.RefreshAttempt("not-configured", ResultSuccess)
	recorder.RefreshAttempt("github-ci", "not-a-result")

	for _, c := range recorder.refreshes.all {
		if got := c.value.Load(); got != 0 {
			t.Errorf("counter %s/%s = %d, want 0", c.entry, c.result, got)
		}
	}
}

func TestRecorderIsConcurrencySafe(t *testing.T) {
	recorder := NewRecorder([]agent.Entry{{ID: "a"}, {ID: "b"}})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				recorder.RefreshAttempt("a", ResultSuccess)
				recorder.Authorization("b", ResultFailure)
			}
		}()
	}
	wg.Wait()

	if got := recorder.refreshes.byKey[counterKey("a", ResultSuccess)].value.Load(); got != 800 {
		t.Errorf("refresh counter = %d, want 800", got)
	}
	if got := recorder.authorizations.byKey[counterKey("b", ResultFailure)].value.Load(); got != 800 {
		t.Errorf("authorization counter = %d, want 800", got)
	}
}

func TestCounterSeriesAreOrdered(t *testing.T) {
	recorder := NewRecorder([]agent.Entry{{ID: "zulu"}, {ID: "alpha"}})

	var previous string
	for _, c := range recorder.refreshes.all {
		key := c.entry + "/" + c.result
		if key <= previous {
			t.Errorf("series %q follows %q, want a stable ascending order", key, previous)
		}
		previous = key
	}
}
