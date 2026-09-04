package metrics

import (
	"net/http"
	"runtime"
	"runtime/debug"
	rtmetrics "runtime/metrics"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/agent"
)

// Metric names. The namespace keeps the agent's series apart from anything
// else scraped from the same target.
const (
	metricCredentialState  = "oauth2_agent_credential_state"
	metricCredentialExpiry = "oauth2_agent_credential_expires_at_timestamp_seconds"
	metricCredentialUpdate = "oauth2_agent_credential_last_success_timestamp_seconds"
	metricRefreshAttempts  = "oauth2_agent_refresh_attempts_total"
	metricAuthorizations   = "oauth2_agent_authorizations_total"
	metricVaultAuth        = "oauth2_agent_vault_authenticated"
	metricVaultExpiry      = "oauth2_agent_vault_token_expires_at_timestamp_seconds"
	metricBuildInfo        = "oauth2_agent_build_info"
	metricGoroutines       = "go_goroutines"
	metricHeapAlloc        = "go_memstats_heap_alloc_bytes"
	metricStartTime        = "process_start_time_seconds"
)

// heapObjectsMetric is the runtime/metrics counterpart of MemStats.HeapAlloc.
// Reading it does not stop the world, unlike runtime.ReadMemStats.
const heapObjectsMetric = "/memory/classes/heap/objects:bytes"

// ContentType is the media type of the exposition format the exporter emits.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// VaultStatus reports the state of the agent's own Vault session.
type VaultStatus interface {
	// Authenticated reports whether a client token is held.
	Authenticated() bool
	// TokenExpiry is when that token expires, zero when it does not.
	TokenExpiry() time.Time
}

// Exporter serves the agent's metrics. Gauges are derived from the current
// state at scrape time; only the counters are accumulated as events happen.
type Exporter struct {
	entries   []agent.Entry
	statuses  *agent.Registry
	vault     VaultStatus
	recorder  *Recorder
	now       func() time.Time
	startedAt time.Time
}

// Option customises an Exporter.
type Option func(*Exporter)

// WithClock overrides the clock. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(e *Exporter) {
		if now != nil {
			e.now = now
		}
	}
}

// NewExporter builds an exporter over the agent's runtime state.
func NewExporter(entries []agent.Entry, statuses *agent.Registry, vault VaultStatus, recorder *Recorder, opts ...Option) *Exporter {
	e := &Exporter{
		entries:  entries,
		statuses: statuses,
		vault:    vault,
		recorder: recorder,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(e)
	}
	e.startedAt = e.now()
	return e
}

// ServeHTTP writes the exposition document.
func (e *Exporter) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	body := e.Gather()
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Gather renders the exposition document. ServeHTTP writes exactly this.
func (e *Exporter) Gather() []byte {
	var out writer
	e.writeCredentials(&out)
	e.writeCounters(&out)
	e.writeVault(&out)
	e.writeProcess(&out)
	return out.Bytes()
}

// writeCredentials emits the per-credential gauges: the lifecycle state and
// the point in time the access token stops being usable.
func (e *Exporter) writeCredentials(out *writer) {
	out.family(metricCredentialState,
		"Lifecycle state of a credential; 1 for the state it is currently in, 0 for the others.",
		typeGauge)
	for _, entry := range e.entries {
		current := e.statuses.Get(entry.ID).State
		if current == "" {
			current = agent.StateUnknown
		}
		for _, state := range agent.States() {
			value := 0.0
			if state == current {
				value = 1
			}
			out.sample(metricCredentialState, value,
				label{"entry", entry.ID}, label{"state", string(state)})
		}
	}

	out.family(metricCredentialExpiry,
		"Unix time at which the stored access token expires. Absent while no expiry is known.",
		typeGauge)
	for _, entry := range e.entries {
		if expiry := e.statuses.Get(entry.ID).Expiry; !expiry.IsZero() {
			out.sample(metricCredentialExpiry, timestamp(expiry), label{"entry", entry.ID})
		}
	}

	out.family(metricCredentialUpdate,
		"Unix time at which the credential was last written to Vault successfully.",
		typeGauge)
	for _, entry := range e.entries {
		if at := e.statuses.Get(entry.ID).LastSuccess; !at.IsZero() {
			out.sample(metricCredentialUpdate, timestamp(at), label{"entry", entry.ID})
		}
	}
}

func (e *Exporter) writeCounters(out *writer) {
	out.family(metricRefreshAttempts,
		"Background refresh cycles by outcome.", typeCounter)
	if e.recorder != nil {
		for _, c := range e.recorder.refreshes.all {
			out.sample(metricRefreshAttempts, float64(c.value.Load()),
				label{"entry", c.entry}, label{"result", c.result})
		}
	}

	out.family(metricAuthorizations,
		"Interactive authorizations completed through the callback, by outcome.", typeCounter)
	if e.recorder != nil {
		for _, c := range e.recorder.authorizations.all {
			out.sample(metricAuthorizations, float64(c.value.Load()),
				label{"entry", c.entry}, label{"result", c.result})
		}
	}
}

func (e *Exporter) writeVault(out *writer) {
	out.family(metricVaultAuth,
		"Whether the agent currently holds a Vault client token.", typeGauge)
	authenticated := 0.0
	var expiry time.Time
	if e.vault != nil {
		if e.vault.Authenticated() {
			authenticated = 1
		}
		expiry = e.vault.TokenExpiry()
	}
	out.sample(metricVaultAuth, authenticated)

	out.family(metricVaultExpiry,
		"Unix time at which the agent's Vault token expires. Absent for a token without a lease.",
		typeGauge)
	if !expiry.IsZero() {
		out.sample(metricVaultExpiry, timestamp(expiry))
	}
}

func (e *Exporter) writeProcess(out *writer) {
	out.family(metricBuildInfo, "Build information of the running agent.", typeGauge)
	goVersion, revision := buildInfo()
	out.sample(metricBuildInfo, 1,
		label{"go_version", goVersion}, label{"revision", revision})

	out.family(metricStartTime, "Unix time at which the agent started.", typeGauge)
	out.sample(metricStartTime, timestamp(e.startedAt))

	out.family(metricGoroutines, "Number of goroutines that currently exist.", typeGauge)
	out.sample(metricGoroutines, float64(runtime.NumGoroutine()))

	out.family(metricHeapAlloc, "Number of bytes allocated in heap objects.", typeGauge)
	samples := []rtmetrics.Sample{{Name: heapObjectsMetric}}
	rtmetrics.Read(samples)
	if samples[0].Value.Kind() == rtmetrics.KindUint64 {
		out.sample(metricHeapAlloc, float64(samples[0].Value.Uint64()))
	}
}

// timestamp renders a time as fractional Unix seconds.
func timestamp(t time.Time) float64 {
	return float64(t.UnixNano()) / float64(time.Second)
}

// buildInfo reports the Go toolchain and the VCS revision the binary was
// built from, both empty-safe when the binary was built without VCS stamping.
func buildInfo() (goVersion, revision string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return runtime.Version(), ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			revision = setting.Value
			break
		}
	}
	return info.GoVersion, revision
}
