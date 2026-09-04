# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

README.md documents what the agent does, its configuration, its HTTP surface,
the shape of the secret it writes and the metrics it exposes. Read it first.
This file covers only what it does not: the architecture, the invariants behind
it, and the conventions to follow when changing it.

## Commands

README.md lists the everyday targets. Beyond those:

```sh
go test ./... -race -count=1                                   # before any concurrency change
go test ./internal/refresher -run TestInvalidGrant -v          # a single test
go test ./internal/config -run 'TestParseValidationErrors/duplicate' # a single subtest
```

`make lint` fails on unformatted files rather than fixing them; run `make fmt`
first.

The one third-party dependency is `gopkg.in/yaml.v3`, for the config file.
The OAuth2 flow and the Vault client are written against `net/http` rather than
pulled in: both are a few hundred lines of the thing this agent exists to do,
and neither library would have been used for more than a fraction of itself.
Adding a second dependency is a deliberate decision, not a default.

## Releases

`.github/workflows/release.yml` fires on a `v*` tag and runs lint and tests
before building, so a tag cannot publish something CI would have rejected.

The build is `make dist`, not a script in the workflow: the flags live in one
place, so a binary built by hand is the one a tag would publish. `CGO_ENABLED=0`
is what lets one runner cross-compile every target — keep the project pure Go.
`-trimpath` keeps local paths out and makes the build reproducible, and it does
not disturb the VCS stamping, so `build_info` still reports the revision.

The version is stamped with `-X main.version`, defaulting to `"dev"` so an
unstamped binary never claims to be a release. Artifacts are named without the
version: on a release page the tag already says which version they are.

## Architecture

```
cmd/agent  (flags, wiring, signals)
   ├── internal/config      YAML schema, ${VAR} expansion, validation
   ├── internal/vault       login, token renewal, KV v2 with check-and-set
   ├── internal/oauth2      authorization code + refresh, PKCE, on net/http
   ├── internal/tokenstore  token <-> KV v2 secret, per-location locking
   ├── internal/agent       runtime entries + the observable status registry
   ├── internal/httpapi     /authorize, the callback, the probes
   ├── internal/refresher   the background renewal loop
   └── internal/metrics     Prometheus exposition, written by hand
```

`agent` is the shared runtime model: `httpapi`, `refresher` and `metrics` all
depend on it and never on each other. Keep it that way — a dependency between
the HTTP layer and the refresher is what would make either untestable.

Everything the agent knows lives in Vault. The status registry is a cache of
what was last observed, not a source of truth; losing it on restart costs one
refresh cycle and nothing else.

### `internal/config`

- **Defaults are applied before `${VAR}` expansion**, because a default can
  introduce a value that itself contains a reference — `redirect_url` derived
  from `base_url` is exactly that. Do not reorder `Parse`.
- Only the fields of the **selected** auth method are expanded. A config that
  documents all three methods would otherwise demand the variables of the two
  it does not use.
- `KnownFields(true)` is on, so a removed option fails the start instead of
  being ignored. When an option is dropped, that is the desired behaviour: a
  config still carrying it is a config whose author expects it to do something.
- Two entries pointing at one Vault path is a validation error, not a warning.
  They would overwrite each other, and the failure would look like a provider
  problem.
- Plain `http` is allowed only for loopback hosts, so tests and local runs work
  without weakening the rule for anything deployed.

### `internal/oauth2`

- Token responses are parsed as **both JSON and form-encoded**. GitHub answers
  with a form body unless asked otherwise, and a provider that ignores the
  `Accept` header is not a bug worth failing on.
- `auth_style: auto` tries HTTP Basic, falls back to body parameters on
  `invalid_client`/401, and caches whichever worked. A client with no secret is
  pinned to body parameters: there is nothing to put in a Basic header.
- `Expiry` is **zero when the provider reported no `expires_in`**, and zero
  means "unknown", never "expired". `Expired` returns false for it, the
  refresher skips it, and the metric omits the series. Do not paper over this
  by defaulting to a duration.
- Errors are typed so `IsInvalidGrant` can separate "this credential is dead"
  from "try again later". That distinction drives the refresher's whole retry
  policy.
- A non-2xx body that parsed but carries no OAuth2 error object is reported by
  status alone — it may still contain credential material.

### `internal/vault`

- Writes are check-and-set. `ReadKV2` returns the version and `WriteKV2` sends
  it back, so a concurrent writer loses rather than silently winning. Vault
  reports a CAS failure as a plain 400 with a message, not a dedicated status,
  which is why `isCASMismatch` matches on the text.
- A rejected client token triggers **one** re-login and retry
  (`requestWithReauth`). One, because a genuinely revoked token would otherwise
  spin.
- `MaintainToken` renews at half the lease and falls back to a fresh login. A
  statically configured token cannot be reissued by the agent, so when it is
  also not renewable the loop reports that once and stops instead of spinning
  against a wall (`canRelogin`, `errTokenNotRenewable`).
- `TokenValid` backs `/readyz`; `TokenExpiry` backs the metric. Both exist
  because a probe wants a yes/no and a dashboard wants the time.
- Path segments are escaped individually, so an unusual character in a
  configured path cannot alter the request shape.

### `internal/tokenstore`

- `save` is a read-modify-write guarded by CAS with **one** retry. Two attempts
  is enough for the race it exists for — the refresher and a callback touching
  one entry — and an endless loop would hide a real conflict.
- **A provider that does not rotate refresh tokens omits the field**, so the
  previous one is carried over. Dropping it would break every later refresh.
  The same applies to `scope`.
- `obtained_at` survives a refresh and is reset only by a new authorization; it
  answers "when did a person last approve this", which is a different question
  from `updated_at`.
- Unknown fields in a stored secret are ignored on read, so a secret written by
  a newer build still loads.
- `WithLock` serialises callers on one location. It is an optimisation, not the
  correctness mechanism — CAS is. Callers wrap the whole read-refresh-write
  cycle so a refresh and an authorization do not duplicate work.

### `internal/agent`

- **`State` values are metric labels.** They are stable identifiers precisely
  so they can be compared and exported; rewording one changes an alert. They
  were prose once, for a page that no longer exists, and going back would break
  every query.
- `States()` returns them in a fixed order so the exporter can emit a row for
  each and the series exist before a state is first reached.
- `Status` holds only what the metrics report — state, expiry, last success. It
  deliberately does **not** keep the reason for a failure: that belongs in the
  logs, where it is not bounded to a label and not exposed on an
  unauthenticated endpoint.

### `internal/httpapi`

- **There is no HTML anywhere.** The agent has no user interface: four routes,
  every response `text/plain`, and `/` only anchors a catch-all that answers
  404. A content type is set before `http.Redirect` specifically to suppress the
  HTML body the standard library appends to a GET redirect.
- Provider-supplied text is echoed so a refusal stays legible, but control
  characters are stripped and the length is bounded, and `text/plain` with
  `nosniff` is what keeps markup in it inert. Do not switch to escaping-by-
  template; the content type is the guarantee.
- `Referrer-Policy: no-referrer` is not decoration — the callback URL carries
  the authorization code.
- The state store is in memory, single-use and capped. Single-use so a replayed
  callback is refused; capped because the endpoint is unauthenticated and an
  uncompleted flow would otherwise grow the map without bound. **This is what
  makes the agent single-replica** — two replicas would need sticky sessions.
- **A failed authorization does not change the reported state.** A refused
  re-authorization leaves the stored credential untouched, so claiming
  authorization is missing would raise a false alarm until the next refresh
  cycle corrected it. Only success calls `SetAuthorized`.
- Handlers hold a nil `*metrics.Recorder` when metrics are off. That is a
  working no-op by design, so no call site needs a conditional.

### `internal/refresher`

- One goroutine, entries processed in order. The work is bounded by the HTTP
  timeout and the tick is a minute; concurrency here would buy nothing and cost
  the simple reasoning.
- **A refresh token rejected with `invalid_grant` is not retried** until a new
  authorization replaces it. The rejected token is remembered by SHA-256 hash,
  never by value, and a different hash is what tells the loop to try again — no
  cross-layer signal from the HTTP handler is needed.
- A credential with no known expiry is reported authorized and skipped. Without
  an expiry there is no moment to act on, and refreshing every tick would hammer
  the provider.
- Backoff doubles from `interval` to `max_backoff` and resets on success.

### `internal/metrics`

- The exposition format is written by hand. The agent publishes about ten
  series; a client library would be the largest dependency in the tree for
  that. `writer` owns the escaping rules — HELP escapes backslash and newline,
  label values also escape the quote — and `formatValue` prints whole numbers in
  full so a timestamp stays readable when the endpoint is read by a person.
- `credential_state` is one-hot: every entry emits a row for every state, one
  of them 1. That is what lets an alert be written for a state before it first
  occurs.
- **Timestamp series are omitted, never zeroed**, when the value is unknown. A
  zero reads as 1970 and fires every expiry alert.
- Counters are created up front for every (entry, result) pair, so the map is
  never written to after construction and can be read without synchronisation,
  and a series exists at zero rather than appearing out of nowhere.
- A nil `*Recorder` is a working no-op. `metrics.path` unset means the agent
  measures nothing at all, and that is implemented by passing nil rather than by
  branching at the call sites.
- Gauges are derived at scrape time from the registry; only counters accumulate.

## Constraints worth knowing before editing

- **The HTTP surface is unauthenticated by design** — the operator's perimeter
  decides who reaches it. That is why the state store is capped, why the metrics
  endpoint carries no token values, and why the status registry keeps no error
  strings. Adding anything that reveals more than metadata needs the auth
  question reopened first.
- The agent is single-replica. In-flight flows live in memory.
- `go 1.27` in go.mod is the single source of truth for the Go version; CI reads
  it with `go-version-file`, so bumping one place is enough.
- Nothing logs a token, an authorization code or a client secret. When adding a
  log line near any of them, name the entry, not the value.

## Testing conventions

Table-driven subtests with `t.Run`; failure messages read `got = X, want Y`.
Everything external is a `httptest.Server` or an in-memory fake — a fake Vault
with real check-and-set semantics, a stub token endpoint — so no test needs a
real Vault, a real provider or a fixture on disk. Time is injected through
`WithClock` wherever a decision depends on it; no test sleeps to advance time.

Concurrency is covered by tests, not just review: the token store's locking and
the metric counters each have a concurrent test. Run `-race` when touching them.
