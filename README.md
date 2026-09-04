# vault-oauth2-credentials-agent

[![CI](https://github.com/edspc/vault-oauth2-credentials-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/edspc/vault-oauth2-credentials-agent/actions/workflows/ci.yml)

An agent that owns the lifecycle of OAuth2 credentials. A person authorizes each
integration once through a browser; from then on the agent keeps the access
token fresh in HashiCorp Vault KV v2 and nobody has to think about it again.

Consumers read the secret straight from Vault with their own policies. The agent
is not on their runtime path: if it stops, they keep working on the last valid
token until it expires. It has no user interface and no database — the
configuration file says what to manage, Vault holds the result.

## Quick start

```sh
make build

# Secrets referenced as ${VAR} in the config come from the environment.
export VAULT_TOKEN=s.your-token
export GITHUB_CLIENT_SECRET=your-client-secret

./bin/vault-oauth2-agent -config config.yaml
```

Open the authorization URL for one entry, sign in at the provider, and it is
done:

```sh
open 'http://localhost:8080/authorize?entry=github-ci'
```

The credential is now in Vault, and stays valid without further attention:

```sh
vault kv get secret/oauth2/github/ci-bot
```

Start from [`configs/config.example.yaml`](configs/config.example.yaml); it
covers every option with comments.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-config` | `config.yaml` | path to the configuration file (`CONFIG_PATH`) |
| `-log-level` | `info` | `debug`, `info`, `warn` or `error` (`LOG_LEVEL`) |
| `-version` | | print the version and exit |

Logs are JSON on stderr. Token values, authorization codes and client secrets
never appear in them.

## Configuration

One file, one entry per credential. An entry names its own Vault path, so two
integrations never collide and moving one is a config change rather than a
migration.

```yaml
server:
  listen: ":8080"
  base_url: "https://oauth-agent.internal"   # used to derive redirect_url
  callback_path: "/callback"

vault:
  address: "https://vault.internal:8200"
  auth:
    method: approle                          # token | approle | kubernetes
    approle:
      role_id: "${VAULT_ROLE_ID}"
      secret_id: "${VAULT_SECRET_ID}"

metrics:
  path: "/metrics"                           # omit to disable entirely

refresh:
  interval: 1m                               # how often credentials are inspected
  before_expiry: 10m                         # refresh once expiry is nearer than this
  max_backoff: 30m

entries:
  - id: github-ci
    auth_url: "https://github.com/login/oauth/authorize"
    token_url: "https://github.com/login/oauth/access_token"
    client_id: "Iv1.0123456789abcdef"
    client_secret: "${GITHUB_CLIENT_SECRET}"
    redirect_url: "https://oauth-agent.internal/callback"
    scopes: [repo, "read:org"]
    vault:
      mount: secret
      path: oauth2/github/ci-bot
```

`${VAR}` is resolved from the environment at startup. An unset variable aborts
the start rather than producing an empty credential. Only the fields of the
selected Vault auth method are expanded, so a config that documents all three
methods does not demand the variables of the two it does not use.

Everything is validated before the agent listens: unknown keys, duplicate entry
ids, two entries pointing at one Vault path, a `before_expiry` smaller than the
tick interval — all of them fail the start with the field named.

### Per-entry options

| Key | Default | Meaning |
| --- | --- | --- |
| `id` | | name used in the authorize URL, the logs and the metric labels |
| `auth_url`, `token_url` | | the provider's endpoints; `https` unless the host is loopback |
| `client_id`, `client_secret` | | the client registration; the secret may be omitted for a public client |
| `redirect_url` | `base_url` + `callback_path` | must match what is registered with the provider |
| `scopes` | none | requested scopes |
| `pkce` | `true` | S256 code challenge; disable only for a provider that rejects it |
| `auth_style` | `auto` | how client credentials reach the token endpoint: `auto`, `header` or `params` |
| `extra_auth_params` | none | provider-specific additions, e.g. Google's `access_type: offline` |
| `vault.mount`, `vault.path` | `secret` | where this entry's tokens are stored |

`auto` tries HTTP Basic first and falls back to request-body parameters if the
provider rejects it, remembering whichever worked.

## HTTP endpoints

| Route | Purpose |
| --- | --- |
| `GET /authorize?entry=ID` | starts a flow; redirects to the provider |
| `GET <callback_path>` | completes it and stores the credential |
| `GET <metrics.path>` | Prometheus exposition, only when `metrics.path` is set |
| `GET /healthz` | 200 while the process is alive |
| `GET /readyz` | 200 once a valid Vault token is held, 503 otherwise |

Every response is plain text; there is no console. Anything else answers 404.

**None of this is authenticated.** Anyone who can reach `/authorize` can start a
flow — they still have to authenticate at the provider to finish one, but the
agent belongs behind an ingress or a network policy that decides who may reach
it, not on a public address.

The callback is a single path shared by every entry; the flow it belongs to is
resolved from the `state` parameter, which is single-use and expires after ten
minutes. In-flight flows are held in memory, so the agent runs as one replica
and a restart mid-flow means starting over.

## What lands in Vault

One KV v2 secret per entry, at the path the entry names:

| Field | Meaning |
| --- | --- |
| `access_token` | what consumers use |
| `refresh_token` | absent when the provider issues none |
| `token_type` | usually `Bearer` |
| `expiry` | RFC 3339; empty when the provider reported no expiry |
| `scope` | what was actually granted, which can differ from the request |
| `obtained_at` | when a person last authorized it; survives refreshes |
| `updated_at` | when the secret was last written |
| `entry_id` | the config entry it came from |
| `extra` | JSON with any remaining fields of the token response, e.g. `id_token` |

Writes use check-and-set, so the background refresher and an interactive
authorization cannot overwrite each other. A provider that does not rotate
refresh tokens omits the field, and the previous one is carried over.

Give consumers read access to the paths they need and nothing else — the agent
itself needs create and update on the same paths.

## Refreshing

A background loop inspects every entry each `refresh.interval` and renews the
ones expiring within `refresh.before_expiry`. A credential whose provider
reported no expiry is left alone; there is nothing to act on and refreshing on
every tick would hammer the provider.

A refresh token the provider rejects with `invalid_grant` is not retried until a
person authorizes the entry again — retrying a revoked token only produces
noise. Anything else backs off exponentially up to `max_backoff`.

## Metrics

Set `metrics.path` to serve them; leave it out and nothing is measured or
exposed. The two the endpoint exists for:

```
oauth2_agent_credential_state{entry="github-ci",state="authorized"} 1
oauth2_agent_credential_expires_at_timestamp_seconds{entry="github-ci"} 1788513169
```

`credential_state` carries the state as a label and a row exists for every
state, so an alert can be written before that state is ever reached:

| State | Meaning |
| --- | --- |
| `unknown` | not inspected yet |
| `needs_auth` | nothing stored, or stored without a refresh token |
| `authorized` | a valid credential is in Vault |
| `needs_reauth` | the refresh token was rejected; only a person can fix it |
| `refresh_failed` | the last attempt failed and will be retried |

`credential_expires_at_timestamp_seconds` is absolute Unix time, and the series
is **omitted** rather than zeroed when no expiry is known — a zero would read as
1970 and fire every expiry alert.

Alongside them: `refresh_attempts_total` and `authorizations_total` by outcome,
`vault_authenticated`, `vault_token_expires_at_timestamp_seconds`, `build_info`
with the version, and `go_goroutines`, `go_memstats_heap_alloc_bytes` and
`process_start_time_seconds`.

## Development

```sh
make test          # go test ./...
make lint          # go vet + a gofmt check that fails rather than rewrites
make cover         # coverage summary
make dist          # the release binaries, exactly as a tag would build them
```

Run `go test ./... -race -count=1` before any change to the refresher, the
status registry, the in-flight state store or the metric counters — that is what
CI runs.

The only third-party dependency is `gopkg.in/yaml.v3`, for the config file.
Everything else, the OAuth2 flow and the Vault client included, is the standard
library.

## Releases

Pushing a `v*` tag builds the binaries and publishes a GitHub release:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

Lint and the test suite run first, so a tag cannot publish a build that does not
pass CI. Binaries are published for `linux/amd64`, `linux/arm64` and
`darwin/arm64` with a `SHA256SUMS` file. There is no cgo, so every target is a
plain cross-compile with no runtime dependencies.

The workflow builds them by running `make dist`, so the same binaries can be
produced locally — static, path-stripped and reproducible:

```sh
make dist                                   # all three targets, into dist/
make dist VERSION=v0.1.0                    # stamp a version
make dist TARGETS=linux/amd64               # just the one you need
```

`vault-oauth2-agent -version` reports the tag it was built from.

## License

MIT — see [LICENSE](LICENSE).
