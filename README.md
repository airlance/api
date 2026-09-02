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

## HTTP API

All responses and errors are JSON. Errors use the following shape:
`{"error":{"code":"…","message":"…"}}`.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/livez` | Process liveness; does not call dependencies. |
| `GET` | `/readyz`, `/healthz` | Checks PostgreSQL, Redis, and the supported schema-version range. |
| `GET` | `/metrics` | Prometheus metrics scrape endpoint. |
| `POST` | `/api/v1/auth/passkey/signup/options` | Start passkey signup. |
| `POST` | `/api/v1/auth/passkey/signup/verify?challenge_id=` | Verify signup and create a session. |
| `POST` | `/api/v1/auth/passkey/login/options` | Start discoverable passkey login. |
| `POST` | `/api/v1/auth/passkey/login/verify?challenge_id=` | Verify an assertion and create a session. |
| `POST` | `/api/v1/auth/passkey/register/options` | Start adding a credential; requires a session. |
| `POST` | `/api/v1/auth/passkey/register/verify?challenge_id=` | Verify the credential; requires a session. |
| `DELETE` | `/api/v1/auth/passkey/{credentialID}` | Remove an owned credential; the last one cannot be removed. |
| `POST` | `/api/v1/auth/session/revoke` | Revoke current authenticated session. |
| `POST` | `/api/v1/auth/sessions/revoke-all` | Revoke all active sessions for current user. |
| `GET` | `/api/v1/devices` | List registered devices for current user. |
| `DELETE` | `/api/v1/devices/{id}` | Revoke an owned device. |
| `POST` | `/api/v1/ws/ticket` | Issue a single-use WS ticket; requires a session. |
| `POST`, `GET` | `/api/v1/clients` | Create or list API clients; requires a session. |
| `DELETE` | `/api/v1/clients/{id}` | Revoke an owned API client; requires a session. |
| `POST` | `/api/v1/auth/token` | Obtain a JWT from a `client_id` and one-time secret. |
| `GET` | `/api/v1/getMe` | JWT-protected user/client identity and current rate-limit usage. |

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
