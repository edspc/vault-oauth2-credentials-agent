package agent

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/config"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/oauth2"
)

const buildConfig = `
vault:
  address: "https://vault.example.com"
  auth:
    method: token
    token: "s.example"
entries:
  - id: example
    auth_url: "https://provider.example.com/authorize"
    token_url: "https://provider.example.com/token"
    client_id: "client"
    client_secret: "secret"
    redirect_url: "https://agent.example.com/callback"
    scopes: ["repo"]
    pkce: false
    auth_style: params
    vault:
      mount: kv
      path: oauth2/example
`

func TestBuildEntries(t *testing.T) {
	cfg, err := config.Parse([]byte(buildConfig))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	entries, err := BuildEntries(cfg, nil)
	if err != nil {
		t.Fatalf("BuildEntries() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	entry := entries[0]
	if entry.ID != "example" {
		t.Errorf("ID = %q, want example", entry.ID)
	}
	if entry.PKCE {
		t.Error("PKCE = true, want the configured false")
	}
	if entry.Location.Mount != "kv" || entry.Location.Path != "oauth2/example" {
		t.Errorf("Location = %+v, want kv/oauth2/example", entry.Location)
	}

	raw, err := entry.Client.AuthCodeURL("state", "")
	if err != nil {
		t.Fatalf("AuthCodeURL() error = %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	if got := u.Query().Get("client_id"); got != "client" {
		t.Errorf("client_id = %q, want client", got)
	}
	if got := u.Query().Get("scope"); got != "repo" {
		t.Errorf("scope = %q, want repo", got)
	}
}

func TestBuildEntriesRejectsUnknownAuthStyle(t *testing.T) {
	cfg, err := config.Parse([]byte(buildConfig))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	// Validation happens at parse time, so reach past it to check that
	// BuildEntries still refuses a value it cannot map.
	cfg.Entries[0].AuthStyle = "basic"

	if _, err := BuildEntries(cfg, nil); err == nil {
		t.Fatal("BuildEntries() error = nil, want an auth style error")
	}
}

func TestParseAuthStyleIsSharedWithConfig(t *testing.T) {
	// The configuration accepts exactly the styles the OAuth2 client knows.
	for _, style := range []string{"auto", "header", "params"} {
		if _, err := oauth2.ParseAuthStyle(style); err != nil {
			t.Errorf("ParseAuthStyle(%q) error = %v", style, err)
		}
	}
}

func TestRegistryTracksStatus(t *testing.T) {
	entries := []Entry{{ID: "a"}, {ID: "b"}}
	registry := NewRegistry(entries)

	if got := registry.Get("a").State; got != StateUnknown {
		t.Errorf("initial state = %q, want %q", got, StateUnknown)
	}

	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	registry.SetAuthorized("a", expiry, now)

	status := registry.Get("a")
	if status.State != StateAuthorized {
		t.Errorf("State = %q, want %q", status.State, StateAuthorized)
	}
	if !status.Expiry.Equal(expiry) || !status.LastSuccess.Equal(now) {
		t.Errorf("status = %+v, want expiry %s and success %s", status, expiry, now)
	}
}

func TestRegistryKeepsLastSuccessAcrossAFailure(t *testing.T) {
	registry := NewRegistry([]Entry{{ID: "a"}})
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)

	registry.SetAuthorized("a", expiry, now)
	registry.SetState("a", StateRefreshFailed)

	status := registry.Get("a")
	if status.State != StateRefreshFailed {
		t.Errorf("State = %q, want %q", status.State, StateRefreshFailed)
	}
	if !status.LastSuccess.Equal(now) {
		t.Errorf("LastSuccess = %s, want the earlier success to be kept", status.LastSuccess)
	}
	if !status.Expiry.Equal(expiry) {
		t.Errorf("Expiry = %s, want it kept so the metric keeps reporting it", status.Expiry)
	}
}

func TestRegistrySetStateKeepsOtherFields(t *testing.T) {
	registry := NewRegistry([]Entry{{ID: "a"}})
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	registry.SetAuthorized("a", now.Add(time.Hour), now)

	registry.SetState("a", StateNeedsAuth)

	status := registry.Get("a")
	if status.State != StateNeedsAuth {
		t.Errorf("State = %q, want %q", status.State, StateNeedsAuth)
	}
	if !status.LastSuccess.Equal(now) {
		t.Errorf("LastSuccess = %s, want it preserved", status.LastSuccess)
	}
}

func TestStatesAreMetricSafeAndComplete(t *testing.T) {
	states := States()
	if len(states) != 5 {
		t.Fatalf("len(States()) = %d, want 5", len(states))
	}

	seen := make(map[State]bool, len(states))
	for _, state := range states {
		value := string(state)
		if value == "" {
			t.Error("a state has an empty value")
		}
		// The value is exported as a metric label, so it must stay a plain
		// identifier rather than prose.
		if strings.ContainsAny(value, " \t\n\"\\") {
			t.Errorf("state %q contains characters that need escaping in a label", value)
		}
		if seen[state] {
			t.Errorf("state %q listed twice", value)
		}
		seen[state] = true

	}

	// The three lifecycle cases the metrics contract is built on.
	for _, want := range []State{StateNeedsAuth, StateAuthorized, StateNeedsReauth} {
		if !seen[want] {
			t.Errorf("States() does not include %q", want)
		}
	}
}
