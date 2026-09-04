package metrics

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/agent"
)

var baseTime = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

// fakeVault reports a fixed Vault session state.
type fakeVault struct {
	authenticated bool
	expiry        time.Time
}

func (f fakeVault) Authenticated() bool    { return f.authenticated }
func (f fakeVault) TokenExpiry() time.Time { return f.expiry }

// scrape parses an exposition document into series keyed by their full
// "name{labels}" identity, so assertions do not depend on line order.
func scrape(t *testing.T, body string) map[string]string {
	t.Helper()
	series := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("malformed sample line %q", line)
		}
		if _, duplicate := series[key]; duplicate {
			t.Errorf("series %q emitted twice", key)
		}
		series[key] = value
	}
	return series
}

func testEntries() []agent.Entry {
	return []agent.Entry{{ID: "github-ci"}, {ID: "google-reports"}}
}

func newTestExporter(t *testing.T, vault VaultStatus) (*Exporter, *agent.Registry, *Recorder) {
	t.Helper()
	entries := testEntries()
	registry := agent.NewRegistry(entries)
	recorder := NewRecorder(entries)
	exporter := NewExporter(entries, registry, vault, recorder,
		WithClock(func() time.Time { return baseTime }))
	return exporter, registry, recorder
}

func TestCredentialStateIsOneHot(t *testing.T) {
	exporter, registry, _ := newTestExporter(t, fakeVault{authenticated: true})
	registry.SetAuthorized("github-ci", baseTime.Add(time.Hour), baseTime)
	registry.SetState("google-reports", agent.StateNeedsReauth)

	series := scrape(t, string(exporter.Gather()))

	// Every entry carries a row for every state, so the series exist before a
	// state is ever reached and alerts do not depend on a missing series.
	for _, entry := range []string{"github-ci", "google-reports"} {
		var active []string
		for _, state := range agent.States() {
			key := metricCredentialState + `{entry="` + entry + `",state="` + string(state) + `"}`
			value, ok := series[key]
			if !ok {
				t.Errorf("missing series %s", key)
				continue
			}
			if value == "1" {
				active = append(active, string(state))
			} else if value != "0" {
				t.Errorf("%s = %s, want 0 or 1", key, value)
			}
		}
		if len(active) != 1 {
			t.Errorf("entry %q has %v active states, want exactly one", entry, active)
		}
	}

	if got := series[metricCredentialState+`{entry="github-ci",state="authorized"}`]; got != "1" {
		t.Errorf("authorized state = %s, want 1", got)
	}
	if got := series[metricCredentialState+`{entry="google-reports",state="needs_reauth"}`]; got != "1" {
		t.Errorf("needs_reauth state = %s, want 1", got)
	}
}

func TestCredentialStateCoversTheThreeLifecycleCases(t *testing.T) {
	exporter, registry, _ := newTestExporter(t, fakeVault{authenticated: true})

	tests := []struct {
		name  string
		state agent.State
	}{
		{"no authorization at all", agent.StateNeedsAuth},
		{"authorized and valid", agent.StateAuthorized},
		{"stored but not renewable", agent.StateNeedsReauth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry.SetState("github-ci", tt.state)
			series := scrape(t, string(exporter.Gather()))
			key := metricCredentialState + `{entry="github-ci",state="` + string(tt.state) + `"}`
			if got := series[key]; got != "1" {
				t.Errorf("%s = %s, want 1", key, got)
			}
		})
	}
}

func TestUnknownStateBeforeFirstInspection(t *testing.T) {
	exporter, _, _ := newTestExporter(t, fakeVault{})
	series := scrape(t, string(exporter.Gather()))

	key := metricCredentialState + `{entry="github-ci",state="unknown"}`
	if got := series[key]; got != "1" {
		t.Errorf("%s = %s, want 1 before the first inspection", key, got)
	}
}

func TestCredentialExpiryTimestamp(t *testing.T) {
	exporter, registry, _ := newTestExporter(t, fakeVault{})
	expiry := baseTime.Add(90 * time.Minute)
	registry.SetAuthorized("github-ci", expiry, baseTime)

	series := scrape(t, string(exporter.Gather()))

	key := metricCredentialExpiry + `{entry="github-ci"}`
	want := strconv.FormatInt(expiry.Unix(), 10)
	if got := series[key]; got != want {
		t.Errorf("%s = %s, want %s (%s)", key, got, want, expiry.Format(time.RFC3339))
	}

	// An entry whose expiry is unknown must not report a zero timestamp,
	// which would read as 1970 and fire every expiry alert.
	if _, ok := series[metricCredentialExpiry+`{entry="google-reports"}`]; ok {
		t.Error("an entry without a known expiry emitted a timestamp, want the series omitted")
	}
}

func TestLastSuccessTimestamp(t *testing.T) {
	exporter, registry, _ := newTestExporter(t, fakeVault{})
	registry.SetAuthorized("github-ci", baseTime.Add(time.Hour), baseTime)

	series := scrape(t, string(exporter.Gather()))
	if _, ok := series[metricCredentialUpdate+`{entry="github-ci"}`]; !ok {
		t.Error("missing last success timestamp")
	}
	if _, ok := series[metricCredentialUpdate+`{entry="google-reports"}`]; ok {
		t.Error("an entry that was never written emitted a last success timestamp")
	}
}

func TestCountersStartAtZeroAndAccumulate(t *testing.T) {
	exporter, _, recorder := newTestExporter(t, fakeVault{})

	series := scrape(t, string(exporter.Gather()))
	for _, result := range refreshResults {
		key := metricRefreshAttempts + `{entry="github-ci",result="` + result + `"}`
		if got, ok := series[key]; !ok || got != "0" {
			t.Errorf("%s = %q (present=%v), want 0", key, got, ok)
		}
	}

	recorder.RefreshAttempt("github-ci", ResultSuccess)
	recorder.RefreshAttempt("github-ci", ResultSuccess)
	recorder.RefreshAttempt("github-ci", ResultNeedsReauth)
	recorder.Authorization("google-reports", ResultFailure)

	series = scrape(t, string(exporter.Gather()))
	if got := series[metricRefreshAttempts+`{entry="github-ci",result="success"}`]; got != "2" {
		t.Errorf("success counter = %s, want 2", got)
	}
	if got := series[metricRefreshAttempts+`{entry="github-ci",result="needs_reauth"}`]; got != "1" {
		t.Errorf("needs_reauth counter = %s, want 1", got)
	}
	if got := series[metricAuthorizations+`{entry="google-reports",result="failure"}`]; got != "1" {
		t.Errorf("authorization counter = %s, want 1", got)
	}
}

func TestVaultGauges(t *testing.T) {
	expiry := baseTime.Add(30 * time.Minute)
	exporter, _, _ := newTestExporter(t, fakeVault{authenticated: true, expiry: expiry})

	series := scrape(t, string(exporter.Gather()))
	if got := series[metricVaultAuth]; got != "1" {
		t.Errorf("%s = %s, want 1", metricVaultAuth, got)
	}
	if _, ok := series[metricVaultExpiry]; !ok {
		t.Errorf("missing %s", metricVaultExpiry)
	}

	// A token without a lease has no expiry to report.
	exporter, _, _ = newTestExporter(t, fakeVault{authenticated: true})
	series = scrape(t, string(exporter.Gather()))
	if _, ok := series[metricVaultExpiry]; ok {
		t.Errorf("%s emitted for a token without a lease", metricVaultExpiry)
	}
}

func TestProcessMetrics(t *testing.T) {
	exporter, _, _ := newTestExporter(t, fakeVault{})
	series := scrape(t, string(exporter.Gather()))

	if want := strconv.FormatInt(baseTime.Unix(), 10); series[metricStartTime] != want {
		t.Errorf("%s = %s, want the fixed clock value %s",
			metricStartTime, series[metricStartTime], want)
	}
	for _, name := range []string{metricGoroutines, metricHeapAlloc} {
		if _, ok := series[name]; !ok {
			t.Errorf("missing %s", name)
		}
	}
	if key, ok := buildInfoSeries(series); !ok {
		t.Errorf("missing %s", metricBuildInfo)
	} else if !strings.Contains(key, `version="`+DefaultVersion+`"`) {
		t.Errorf("%s carries no default version label: %s", metricBuildInfo, key)
	}
}

// buildInfoSeries returns the full identity of the build info series.
func buildInfoSeries(series map[string]string) (string, bool) {
	for key := range series {
		if strings.HasPrefix(key, metricBuildInfo+"{") {
			return key, true
		}
	}
	return "", false
}

func TestBuildInfoReportsTheStampedVersion(t *testing.T) {
	entries := testEntries()
	exporter := NewExporter(entries, agent.NewRegistry(entries), fakeVault{}, nil,
		WithClock(func() time.Time { return baseTime }),
		WithVersion("v1.2.3"))

	key, ok := buildInfoSeries(scrape(t, string(exporter.Gather())))
	if !ok {
		t.Fatalf("missing %s", metricBuildInfo)
	}
	if !strings.Contains(key, `version="v1.2.3"`) {
		t.Errorf("%s = %s, want the stamped version", metricBuildInfo, key)
	}
	// The label sits alongside the build facts the toolchain reports.
	if !strings.Contains(key, "go_version=") || !strings.Contains(key, "revision=") {
		t.Errorf("%s = %s, want go_version and revision kept", metricBuildInfo, key)
	}
}

func TestWithVersionIgnoresAnEmptyValue(t *testing.T) {
	entries := testEntries()
	exporter := NewExporter(entries, agent.NewRegistry(entries), fakeVault{}, nil,
		WithClock(func() time.Time { return baseTime }),
		WithVersion(""))

	key, _ := buildInfoSeries(scrape(t, string(exporter.Gather())))
	if !strings.Contains(key, `version="`+DefaultVersion+`"`) {
		t.Errorf("%s = %s, want the default version kept", metricBuildInfo, key)
	}
}

func TestEveryFamilyIsDeclared(t *testing.T) {
	exporter, _, _ := newTestExporter(t, fakeVault{authenticated: true})
	body := string(exporter.Gather())

	declared := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		if name, ok := strings.CutPrefix(line, "# TYPE "); ok {
			declared[strings.Fields(name)[0]] = true
		}
	}
	for key := range scrape(t, body) {
		name, _, _ := strings.Cut(key, "{")
		if !declared[name] {
			t.Errorf("series %q has no # TYPE declaration", name)
		}
	}
}

func TestServeHTTP(t *testing.T) {
	exporter, registry, _ := newTestExporter(t, fakeVault{authenticated: true})
	registry.SetAuthorized("github-ci", baseTime.Add(time.Hour), baseTime)

	rec := httptest.NewRecorder()
	exporter.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != ContentType {
		t.Errorf("Content-Type = %q, want %q", got, ContentType)
	}
	if !strings.Contains(rec.Body.String(), metricCredentialState) {
		t.Error("body does not contain the credential state metric")
	}
}

func TestExporterWithoutRecorder(t *testing.T) {
	entries := testEntries()
	exporter := NewExporter(entries, agent.NewRegistry(entries), fakeVault{}, nil,
		WithClock(func() time.Time { return baseTime }))

	body := string(exporter.Gather())
	if !strings.Contains(body, "# TYPE "+metricRefreshAttempts+" counter") {
		t.Error("counter family header is missing without a recorder")
	}
	if strings.Contains(body, metricRefreshAttempts+"{") {
		t.Error("counter series emitted without a recorder, want none")
	}
}
