# Airlance API

A Go foundation for Airlance: passkey authentication, sessions, short-lived
JWT access to the external HTTP API, Redis-backed rate limiting, multi-instance
Pub/Sub event bus, and an encrypted WebSocket channel. Content domains (titles,
people, reviews, and chat) have not been implemented yet.

## Current capabilities

- PostgreSQL migrations for users, identities, passkeys, sessions, devices,
  audit events, API clients, and rate-limit tiers.
- Passwordless WebAuthn/passkey signup, discoverable login, and adding or
  removing additional credentials. Sessions retain only a SHA-256 hash of an
  opaque token; the plaintext token is issued to the client once.
- Session authentication through `Authorization: Bearer …` or the
  `session_token` cookie. Cookie-authenticated state-changing requests use
  Origin/Sec-Fetch-Site checks or a double-submit CSRF token.
- Optional device binding for sessions. The service stores an HMAC of a
  device identifier rather than the identifier itself.
- Append-only audit events for authentication, session, and API-client
  operations.
- API clients with a one-time secret and Ed25519 JWTs containing `kid`,
  `client_id`, `sub`, `jti`, expiry, and RPM/RPD limits. The `default` tier
  permits 60 requests per minute and 5,000 per day.
- Atomic multi-window Redis rate limiting via Lua. Authentication ceremonies,
  credential mutations, and WS ticket issuance fail closed; external API
  traffic fails open if Redis is unavailable.
- WebSocket tickets stored in Redis and consumed before upgrade, wireauth v2
  over WS, FlatBuffers envelopes, strict AEAD sequence validation, a bounded
  send queue, ping/pong, idle timeout, per-IP and per-user connection limits,
  and cross-instance connection closure upon session or device revocation.
- Distributed `RedisEventBus` for cross-instance revocation broadcasting.
- Prometheus text metrics exported at `/metrics`.
- `/livez`, `/readyz`, and backwards-compatible `/healthz`, with request IDs
  in HTTP responses, structured logging with masked subject identifiers, and
  `airlance-api cleanup` CLI for purging expired records.

## Architecture

```text
cmd/main                 CLI entry point
internal/domain          entities and ports (tx, crypto, eventbus, passkey)
internal/usecase         application workflows (auth, session, apiauth)
internal/data            PostgreSQL and Redis repository adapters
internal/infrastructure  database, WebAuthn, crypto, logger, EventBus, metrics, limiter
internal/transport       HTTP and WebSocket adapters
migrations               golang-migrate SQL migrations
tests                    e2e, integration, and wireauth contract checks
```

Dependencies are wired explicitly in `internal/bootstrap`; there is no DI
framework, reflection container, or mutable global application state.

## Local development

You need Go (declared in `go.mod`), Docker Compose, PostgreSQL, and Redis.
The shortest local setup is:

```bash
cp .env.example .env
docker compose up -d postgres redis
set -a && source .env && set +a
go run ./cmd/main migrate up
go run ./cmd/main serve
```

The application reads process environment variables. `.env` is therefore a
local shell convenience file, not an application configuration source: load it
as shown above (or configure your IDE to do so). It is ignored by Git; copy
`.env.example` when you need a fresh local configuration. Do not use `.env` or
its development values in production.

The service listens on `http://localhost:8080` by default. Check readiness:

```bash
curl http://localhost:8080/readyz
```

The CLI provides `serve`, `version`, `cleanup`, and `migrate {up,down,reset,version,create}`:

```bash
go run ./cmd/main migrate create add_something
go run ./cmd/main migrate down --steps 1
go run ./cmd/main cleanup --max-age 24h
```

For production, TLS is mandatory by default. Use one of these mutually
exclusive configurations:

- local TLS: `TLS_LISTENER_ENABLED=true`, `TLS_CERT_FILE`, and `TLS_KEY_FILE`;
- TLS termination at a trusted ingress: `TLS_TERMINATION_INGRESS=true` and an
  explicit `TRUSTED_PROXIES` CIDR list.

`/metrics` is restricted in-process to `METRICS_ALLOWED_CIDRS` (loopback by
default). Set it to the CIDRs used by the production monitoring network.

## HTTP API

All responses and errors are JSON. Errors use the following shape:
`{"error":{"code":"…","message":"…"}}`.

Access levels: **public** (no auth), **session** (`session_token` cookie or
session `Authorization: Bearer`, subject to CSRF checks on cookie-mode
mutating requests), **jwt** (external API `Authorization: Bearer`, Ed25519,
`iss`/`aud`-checked), **internal** (gated by `METRICS_ALLOWED_CIDRS` or
equivalent allowlist, not meant to be reachable from the public internet).

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/livez` | public | Process liveness; does not call dependencies. |
| `GET` | `/readyz`, `/healthz` | public | Checks PostgreSQL, Redis, and the supported schema-version range. |
| `GET` | `/metrics` | internal | Prometheus metrics scrape endpoint; CIDR-gated. |
| `POST` | `/api/v1/auth/passkey/signup/options` | public | Start passkey signup. |
| `POST` | `/api/v1/auth/passkey/signup/verify?challenge_id=` | public | Verify signup and create a session. |
| `POST` | `/api/v1/auth/passkey/login/options` | public | Start discoverable passkey login. |
| `POST` | `/api/v1/auth/passkey/login/verify?challenge_id=` | public | Verify an assertion and create a session. |
| `POST` | `/api/v1/auth/passkey/register/options` | session | Start adding a credential. |
| `POST` | `/api/v1/auth/passkey/register/verify?challenge_id=` | session | Verify the credential. |
| `DELETE` | `/api/v1/auth/passkey/{credentialID}` | session | Remove an owned credential; the last one cannot be removed. |
| `POST` | `/api/v1/auth/session/revoke` | session | Revoke current authenticated session. |
| `POST` | `/api/v1/auth/sessions/revoke-all` | session | Revoke all active sessions for current user. |
| `GET` | `/api/v1/devices` | session | List registered devices for current user. |
| `DELETE` | `/api/v1/devices/{id}` | session | Revoke an owned device. |
| `POST` | `/api/v1/ws/ticket` | session | Issue a single-use WS ticket. |
| `POST`, `GET` | `/api/v1/clients` | session | Create or list API clients. |
| `DELETE` | `/api/v1/clients/{id}` | session | Revoke an owned API client. |
| `POST` | `/api/v1/auth/token` | public | Obtain a JWT from a `client_id` and one-time secret (IP rate-limited). |
| `GET` | `/api/v1/getMe` | jwt | User/client identity and current rate-limit usage. |

## Security

This section documents trust boundaries so changes don't silently weaken
them. See `AGENTS.md` for the enforceable rules and PR checklist.

- **Trusted proxies.** `X-Forwarded-For` and `X-Forwarded-Proto` are only
  honored when the immediate peer address is in `TRUSTED_PROXIES`; otherwise
  the socket's remote address is used as-is. Misconfiguring
  `TRUSTED_PROXIES` (too broad) lets clients spoof their own IP and defeats
  IP-keyed rate limiting; misconfiguring it (too narrow, e.g. missing the
  real ingress) breaks IP-based rate limiting and TLS-termination detection.
- **CSRF.** Cookie-authenticated, state-mutating requests are checked via
  `Sec-Fetch-Site`, then `Origin` against `WEBAUTHN_RP_ORIGINS`, then a
  double-submit `X-CSRF-Token`/`csrf_token` cookie pair. All three paths deny
  by default; a request with no usable signal is rejected, not allowed. This
  check does not run for `Authorization: Bearer` session auth, since that
  mode isn't cookie-driven and browsers can't attach it cross-site.
- **`/metrics` and other internal routes.** Gated by `METRICS_ALLOWED_CIDRS`
  (default: loopback only). Treat this as defense in depth, not a
  replacement for keeping such routes off the public listener/ingress.
- **JWT (external API).** Ed25519, `kid`-selected from `JWT_ED25519_KEYS`,
  and validated for `iss` (`ServiceName`) and `aud` (`"api"`) in addition to
  signature and expiry. A token that only satisfies the signature check is
  rejected.
- **Origins.** `WEBAUTHN_RP_ORIGINS` and `ALLOWED_WS_ORIGINS` reject the
  wildcard `*` outside `development`/`test` at config-load time.
- **Vulnerability reports.** If you find a security issue in this codebase,
  do not open a public issue; contact the maintainers directly first.

## Verification

```bash
GOCACHE=/private/tmp/airlance-go-build-cache go test ./...
GOCACHE=/private/tmp/airlance-go-build-cache go vet ./...
```

The repository includes unit tests for configuration, cryptography,
middleware, EventBus, router, and use cases; `tests/contract/wireauth` checks
wireauth protocol vectors; `tests/integration` validates TLS enforcement,
Redis Pub/Sub event bus, fail-closed rate limiting, and graceful draining;
`tests/e2e` executes full end-to-end user journeys.