# Implementation Plan — Connections, Auth & API Access Foundation

## Scope

Build the foundation layer of a Go service before any content domain (titles,
people, reviews, etc.) is implemented:

- Service bootstrap, config, CLI, DB migrations
- User identity and authentication (WebAuthn/passkey now, extensible to other
  providers later, e.g. email + one-time password)
- Session handling for the primary product surface
- A separate short-lived JWT API-access layer for registered external
  clients/developers, carrying per-client rate-limit entitlements, with
  rotatable signing keys
- A `GET /getMe` endpoint exposing profile + current rate-limit usage
- Rate limiting, designed to support future per-user/tier limit overrides
  (e.g. subscription tiers) and multiple simultaneous limit windows
- Structured, categorized logging (info, debug, error, etc.)
- WS connection security using an existing in-house protocol library
  (Noise-style RSA+ECDH+AES-GCM handshake) layered on top of standard TLS
- A FlatBuffers-based application protocol (envelope, versioning, router)
  running inside the encrypted WS channel, plus WS connection lifecycle
  concerns (backpressure, heartbeats, graceful shutdown) and an `EventBus`
  abstraction for future cross-instance message delivery
- An append-only audit log for security-relevant events

Out of scope for this plan: Title/Person/Company/Genre/Review domain, chat
message domain (DMs/threads) — these build on top of this foundation later.

## Stack

- Go, clean architecture (domain / usecase / infrastructure / transport)
- PostgreSQL, migrations via `golang-migrate`
- Redis — rate limiting, session/ticket caching
- `pgx/v5` for Postgres access
- `go-webauthn/webauthn` for passkey support
- In-house WS transport security library (RSA+ECDH+AES-GCM handshake) —
  `wireauth`. Purely a transport-layer encryptor: `EncryptAESGCM`/
  `DecryptAESGCM` operate on raw `[]byte`, with no opinion on message
  format. FlatBuffers is used as the payload framing format inside the
  encrypted channel (same pattern as the Airlance project) — FlatBuffers
  encode/decode happens in the WS session layer, immediately outside the
  wireauth encrypt/decrypt calls, never inside the wireauth package itself.
- HTTP for request/response API, WS for realtime/core service traffic
- JWT library (e.g. `golang-jwt/jwt`) for external API access tokens

---

## Test strategy and layout

Keep unit tests with the package they exercise, following normal Go
conventions: `internal/<layer>/<package>/*_test.go`. They may test
package-private behavior and must not require a running Postgres, Redis, or
network service. Examples: token generation, session/audit usecases, client-IP
parsing, JWT validation, limiter key construction, and WS sequence handling.

Reserve the top-level `tests/` directory for tests that cross package or
process boundaries:

```
tests/
  integration/  # real Postgres + Redis; repository, migration, and middleware wiring
  e2e/          # booted service; public HTTP/WS workflows
  contract/     # stable cross-client protocol vectors and compatibility checks
  fixtures/     # non-secret WebAuthn, FlatBuffers, and wireauth inputs/outputs
```

- `tests/integration/` runs against isolated Postgres and Redis instances
  supplied by CI/local Compose. Each test owns a unique schema/key prefix and
  cleans up after itself; no test may depend on execution order or shared
  persistent data.
- `tests/e2e/` starts the actual application with test configuration and
  covers the important vertical flows: health/ready checks, signup/login,
  session revocation, WS ticket rejection before upgrade, valid WS handshake,
  rate-limit responses, API-client JWT issuance, and `/getMe` usage.
- `tests/contract/wireauth/` holds versioned binary vectors for protocol v2:
  exact handshake packets, valid and invalid transcript signatures, HKDF
  inputs and direction-separated outputs, encrypted frames, replayed frames,
  and malformed/oversized packets. The Go, TypeScript, and Swift wireauth
  implementations must all consume the same vectors successfully or reject
  the same invalid vectors.
- `tests/fixtures/` contains only synthetic, non-secret data. Never commit
  production credentials, session tokens, private RSA keys, passkeys, or real
  personal identifiers.

CI runs unit tests on every change, then integration and contract tests, then
the slower e2e suite. A bug fix must include a regression test at the lowest
level that reproduces it; security or protocol changes also require an
integration/e2e or contract test when they cross a process boundary.

---

## Phase 0 — Repo skeleton & bootstrap

Use an explicit, staged dependency-wiring style: each stage of application
startup is its own file/function, wired together in one place — no DI
framework, no reflection-based container.

1. `go.mod` init. Base deps: `pgx/v5`, `golang-migrate/migrate/v4`,
   `redis/go-redis/v9`, `spf13/cobra`, `go-webauthn/webauthn`, a JWT library,
   the `wireauth` module.
2. `internal/config` — env-based config struct: app port, database DSN, Redis
   URL, WebAuthn RPID/RPOrigins/RPDisplayName, JWT signing key + TTL, session
   TTL, log level/format, and a `trusted_proxies` list (CIDR ranges or IPs of
   load balancers/reverse proxies this service sits behind). Include separate,
   versioned HMAC key rings for device identifiers and audit subjects; neither
   key may be reused for JWT signing or any other purpose. Configure the
   `wireauth` RSA private-key path separately; its public-key fingerprints are
   client configuration, never a server secret.
3. `internal/infrastructure/logger` — structured logger with explicit level
   support (debug/info/warn/error) and named categories/subsystems (e.g.
   `auth`, `ws`, `ratelimit`, `api`) so log volume per subsystem can be tuned
   independently. Prefer a library with native leveled + structured output
   (e.g. `zerolog` or `zap`) over hand-rolled formatting.
4. `internal/infrastructure/database` — Postgres connection pool +
   transaction helper (`tx.go`) usable by any repository that needs
   multi-statement atomicity.
5. `internal/bootstrap/infrastructures.go` — connect Postgres pool + Redis
   client; ping both at startup, fail fast on error.
6. `internal/bootstrap/repositories.go` — `Repositories` struct (starts with
   just a transaction manager; extended in later phases).
7. `internal/bootstrap/services.go`, `http_handlers.go`, `handlers.go`,
   `server.go`, `app.go` — staged construction ending in a `*http.Server`
   with graceful shutdown (signal handling, bounded shutdown timeout). Start
   with just a health-check route.
8. `internal/cli/cli.go` — cobra root command with subcommands:
   `serve`, `version`, and a `migrate` command group: `up`, `down --steps=N`,
   `reset --force`, `version`, `create <name>`.
9. `internal/cli/migrations.go` — implements the migrate subcommands using
   `golang-migrate`, reading DSN from config, operating on a `file://migrations`
   source directory. `create` auto-numbers new migration file pairs.
10. `cmd/main/main.go` — entrypoint invoking `cli.Execute`.
11. `Dockerfile` + `docker-compose.yml` with Postgres and Redis services for
    local development.
11. `internal/middleware/clientip.go` — resolves the client IP used for
    every IP-keyed decision later in this plan (rate limiting in Phase 3,
    audit logging in Phase 2). In production this service sits behind a
    load balancer/reverse proxy, so the raw TCP peer address is the proxy's
    own IP, not the client's — the real IP must come from a forwarding
    header (`X-Forwarded-For`, `X-Real-IP`, or `Forwarded`), and that
    header must only be trusted when the immediate peer is in the
    configured `trusted_proxies` list. Without this check, any client can
    forge `X-Forwarded-For` and bypass IP-based rate limiting entirely,
    since IP directly drives security decisions elsewhere in this plan.
    Resolve this once at the edge and put the result in request context —
    don't re-derive it ad-hoc in each handler/middleware that needs an IP.
    Built in Phase 0 (ahead of both consumers) since it's general HTTP
    infrastructure, not specific to rate limiting.
12. `GET /healthz` — checks DB and Redis connectivity, returns 200/503.

**Done when:** `go run ./cmd/main serve` boots and serves `/healthz`;
`go run ./cmd/main migrate up` runs cleanly against an empty database with
zero migrations present.

---

## Phase 1 — Core schema: users, identities, sessions

1. Migration: `users` table — `id uuid pk, created_at timestamptz`.
2. Migration: `identities` table — `id uuid pk, user_id fk → users,
   kind text check in ('passkey', 'email_otp'), identifier text,
   verified bool, created_at timestamptz`. Unique index on
   `(kind, identifier)`.
   **WebAuthn identity model:** for the `passkey` kind there is exactly
   one `identities` row per user (identifier = the user's UUID — passkeys
   are discoverable, no email/username needed), and multiple device
   credentials hang off `passkey_credentials.identity_id`. The unique
   index `(kind, identifier)` therefore enforces one passkey identity per
   user. For `email_otp`, identifier is the normalized email address and
   one row per address makes sense. This distinction matters for
   `passkey.added`/`passkey.removed` audit events — they record
   `credential_id`, not the identity row.
3. Migration: `sessions` table — `id uuid pk, token_hash bytea unique,
   user_id fk, identity_id fk, created_at, expires_at, revoked_at
   nullable`. Only `token_hash` (SHA-256 of the token) is ever stored — the
   plaintext session token is returned to the client once at creation and
   is not retrievable from the database afterward, same handling as the
   API client secret in Phase 5. Index on `user_id`; index on `expires_at`
   for cleanup queries.
4. `internal/domain/user` — `User` entity, `Repository` port
   (`Create`, `GetByID`).
5. `internal/domain/identity` — `Identity` entity, `IdentityKind` type,
   `Repository` port, and an `AuthProvider` interface with methods to begin
   and verify a login/signup flow, parameterized so each concrete provider
   (passkey, later email+OTP) can define its own request/response shapes.
6. `internal/domain/session` — `Session` entity, `Repository` port
   (`Create`, `GetValid(token)`, `Revoke`, `RevokeAllForUser`).
7. `internal/data/repository/postgres` — pgx implementations of the three
   repositories above, using the shared transaction manager for any write
   spanning more than one table.
8. `internal/infrastructure/identity/generate_token.go` — cryptographically
   random opaque token generator (`crypto/rand`, sufficient byte length,
   base64/base32 encoded) used for session tokens.
9. `internal/usecase/session` — `CreateSession(userID, identityID) (token,
   error)`, `Validate(token) (Session, error)`, `Revoke(token) error`.

**Done when:** a user, an identity, and a session can be created, validated,
and revoked through the usecase layer with unit tests — no HTTP required yet.

---

## Phase 2 — Passkey provider (signup, login, credential management)

1. Migration: `passkey_credentials` table — `id uuid pk, identity_id fk,
   credential_id bytea unique, public_key bytea, sign_count integer,
   transports text[], aaguid uuid, created_at, last_used_at nullable`.
2. Migration: `challenges` table — `id uuid pk, user_id uuid nullable,
   type text check in ('signup', 'registration', 'authentication'),
   session_data jsonb, expires_at timestamptz`. Rows are deleted on
   consumption, not updated.
3. `internal/domain/passkey` — `Credential`, `Challenge` entities;
   `CredentialRepo`, `ChallengeRepo` ports. `ChallengeRepo` must expose an
   atomic consume operation (single `DELETE ... RETURNING` query, not a
   read followed by a delete) to prevent replay races.
4. `internal/infrastructure/webauthn` — wraps `go-webauthn/webauthn`:
   - RP configuration builder from app config
   - adapter implementing the library's user interface over the domain
     `User`/`Credential` types
   - implements the `AuthProvider` port for the `passkey` identity kind,
     supporting three flows: signup (creates a new user), registration
     (adds a credential to an already-authenticated user), and
     authentication (discoverable/passwordless login — resident keys
     required, since the user isn't known until the assertion is verified)
5. `internal/usecase/auth` — provider-agnostic service holding a registry of
   `AuthProvider` implementations keyed by identity kind; exposes begin/verify
   operations for signup, login, and add-credential, and creates a session on
   successful verification.
6. `internal/transport/http/v1/auth_handlers.go`:
   - `POST /api/v1/auth/passkey/signup/options`
   - `POST /api/v1/auth/passkey/signup/verify`
   - `POST /api/v1/auth/passkey/login/options`
   - `POST /api/v1/auth/passkey/login/verify`
   - `POST /api/v1/auth/passkey/register/options` (requires an existing session)
   - `POST /api/v1/auth/passkey/register/verify` (requires an existing session)
   - `DELETE /api/v1/auth/passkey/{credentialID}` (requires an existing
     session; must verify the credential belongs to the caller)
7. `internal/middleware/session.go` — HTTP middleware resolving a `Session`
   from a bearer token, placing the resolved user ID in request context.
   **Session token delivery policy:** the token returned on successful
   login/signup is delivered differently by client type:
   - **Native clients (iOS/Android):** return the plaintext token in the
     JSON response body; client stores it in the platform secure store and
     sends it as `Authorization: Bearer <token>` on subsequent requests.
   - **Browser clients:** set as `HttpOnly; Secure; SameSite=Strict` cookie
     in the `Set-Cookie` response header; the token never touches JS. The
     session middleware must accept both forms. Cookie mode requires CSRF
     protection (double-submit cookie or `Origin` header validation) on
     state-mutating endpoints — document which CSRF strategy is chosen
     before the first browser-facing endpoint goes live.
8. Migration: `audit_events` table — `id uuid pk, occurred_at timestamptz,
   user_id uuid nullable, actor_type text, actor_id uuid nullable,
   subject_type text nullable, subject_hash bytea nullable, event_type
   text, ip text, user_agent text, request_id text, metadata jsonb,
   created_at timestamptz`. `user_id` is nullable because it's genuinely
   unknown for some events (e.g. a failed login attempt against an
   identifier that doesn't resolve to any user). `subject_type` (e.g.
   `"email"`) + `subject_hash` (`HMAC-SHA-256` of the normalized identifier
   with the dedicated audit-subject HMAC key, not the identifier itself) exist
   specifically so repeated-attempt patterns against the same identifier are
   visible in the audit log (`WHERE subject_hash = ?`) without the raw
   identifier (email address, etc.) ever being persisted in the audit table.
   Plain SHA-256 is not acceptable here: unlike random session/API secrets,
   email addresses are enumerable offline after a database leak. Add
   `subject_hash_key_id smallint` to identify the key version used. Audit rows
   remain append-only; during an HMAC-key transition, queries for a known
   identifier compute the HMAC under each accepted key/version.
   Append-only — no update/delete path in application code. Event types
   for this phase: `auth.signup.success`, `auth.signup.failed`,
   `auth.login.success`, `auth.login.failed`, `passkey.added`,
   `passkey.removed`, `session.revoked`. Emit these from inside the `internal/usecase/auth` and
   `internal/usecase/session` operations built in this phase and Phase 2 —
   audit emission is part of the usecase's job, not bolted on afterward, so
   design each usecase method to take/produce what an audit entry needs
   (actor, event type, metadata) from the start rather than retrofitting it
   once the interfaces are already in use elsewhere.
9. `internal/domain/audit` — `Event` entity, `Repository` port (`Record`
    only — no update/delete method should exist on this port).
    **Audit atomicity rule:** security state mutations and their corresponding
    audit event must commit atomically where practical. Since audit lives in
    the same Postgres instance, use a single transaction for the mutation +
    audit INSERT — this eliminates the failure class where a session is
    created (or credential added/removed) but no audit row appears, or vice
    versa. Apply this to: session creation, session revocation, credential
    add/remove, API client create/revoke. Where the mutation already spans
    multiple tables (using the shared transaction manager), include the audit
    INSERT in the same transaction.

 10. Migration: `devices` table — `id uuid pk, user_id fk → users,
    device_identifier_hash bytea, platform text, created_at timestamptz,
    last_seen_at timestamptz, last_app_version text nullable, revoked_at
    timestamptz nullable`. `device_identifier_hash` stores `HMAC-SHA256(deviceID, server_secret)`,
     not the raw identifier and not a plain SHA-256. The client generates a
     cryptographically random 256-bit device ID once and stores it in the
     platform secure store (Keychain on iOS, Keystore on Android); the server
     stores only the HMAC. Using a keyed HMAC rather than plain SHA-256
     prevents offline enumeration of device IDs even if the DB is leaked —
     an attacker cannot brute-force identifiers without the server secret.
     The raw device ID is sent only for registration/validation, is never
     logged or persisted, and is discarded after deriving the HMAC.
     Rotation is an explicit current+previous-key transition, not a database
     migration: on validation, calculate both hashes; a match using the
     previous key is immediately overwritten with the current-key hash. A
     second rotation is forbidden until the transition window closes (or the
     configured key ring is expanded deliberately). After the window, remove
     the previous key; devices that never reconnect must register again. A
     security incident that makes retaining the old key unacceptable instead
     requires forced device re-registration for all devices.
     `last_app_version` is a field that gets overwritten on each connection
    rather than tracking version history — it changes often and isn't
    something audit/history needs to preserve.
11. Add `device_id` (nullable, fk → `devices`) to `sessions` — nullable
    because not every session (e.g. a future email+OTP web login) will
    necessarily originate from a registered device.
12. `internal/domain/device` — `Device` entity, `Repository` port
    (`Create`, `GetByID`, `Touch(id)` updating `last_seen_at`/
    `last_app_version`, `Revoke`, `ListByUserID`).

Given this project's realtime/WS-centric nature and the per-device
connection limits already planned in Phase 4.5, the device model is
included now rather than deferred — retrofitting it after the session and
passkey usecases are written would mean revisiting those interfaces later,
which is more expensive than including the (small) `devices` table and
`sessions.device_id` column from the start. This unlocks, without further
schema changes later: logout-this-device, logout-all-devices, a per-user
device list, and a home for push-notification tokens if those are added.

**Done when:** a full signup→login round trip succeeds against a real or
simulated WebAuthn client, a second credential can be added to an existing
account, and each of the events above produces a corresponding
`audit_events` row.

---

## Phase 3 — Rate limiting (internal + reusable for API tiers)

Rate limiting must work correctly across multiple server instances — no
in-process-only counters. All limit state lives in Redis so every instance
enforces the same limits consistently. Client IP resolution (behind the
`trusted_proxies` config, needed for IP-keyed limits below) is built in
Phase 0 as general HTTP infrastructure — see `internal/middleware/clientip.go`
there.

1. `internal/domain/ratelimit` — types and port:
   ```go
   type Limit struct {
       Name   string        // e.g. "per_minute", "per_day"
       Max    int64
       Window time.Duration
   }

   type Result struct {
       Allowed    bool
       Remaining  int64
       ResetAt    time.Time
       RetryAfter time.Duration
   }

   type Limiter interface {
       Allow(ctx context.Context, key string, limits []Limit) ([]Result, error)
       Usage(ctx context.Context, key string, limits []Limit) ([]Result, error)
   }
   ```
   Both methods return one `Result` per input `Limit`, in the same order.
   `Allow` returns results for **all** windows even when one has already
   denied — the caller uses the most-restrictive result for the HTTP 429
   response (`RetryAfter`, `ResetAt`) and can log which window triggered.
   This also keeps `Allow` and `Usage` symmetric, which simplifies
   `/getMe` in Phase 5: it calls `Usage` and gets per-window detail to
   return to the client without a separate aggregation step.
   Passing `[]Limit` instead of a single limit/window means adding a third
   window later (e.g. per-second burst, monthly cap) is a caller-side
   change, not an interface-breaking change.
2. `internal/infrastructure/ratelimit` — Redis-backed implementation.
   Use a single Redis `EVAL` (Lua script) per `Allow` call that checks and
   increments all of a key's configured `Limit`s atomically, so the
   read-check-increment sequence is race-free across concurrent requests
   and replicas — no partial state where one window incremented and another
   didn't.
3. Redis failure policy — decide and hardcode per call site, not globally:
   when Redis is unreachable, `Allow` must return an error, and each caller
   decides fail-open vs fail-close explicitly:
   - **Auth endpoints (login, signup, add-credential)**: fail-closed — deny
     the request. An unavailable rate limiter must not become a route
     around brute-force protection.
   - **WS ticket issuance**: fail-closed, same reasoning — this guards
     against handshake-flood DoS (see Phase 4).
   - **General authenticated API traffic**: fail-open is acceptable — a
     Redis outage degrading rate limiting on ordinary reads is a lesser
     risk than an outage taking down the entire API.
   Implement this as an explicit parameter or wrapper the caller chooses
   (e.g. `Allow` returning an error the caller maps to allow/deny), not as
   a hidden default inside the Redis implementation.
4. `internal/infrastructure/ratelimit/registry.go` — a registry that hands
   out/caches a configured limiter per subject key (e.g. per user or per API
   client), with idle eviction so the in-memory side doesn't grow unbounded;
   the source of truth for counts remains Redis.
5. `internal/middleware/ratelimit.go` — generic HTTP middleware parameterized
   by a key-extraction function and a `[]Limit` configuration, so it can
   be applied differently per route group.
6. Apply rate limiting at these points, each with independent limits/keys:
   - **Auth endpoints** (`/auth/*/options`, `/auth/*/verify`): keyed by
     client IP, and separately by identifier (e.g. email) when known —
     two independent checks, not one merged key.
   - **Challenge creation**: a tighter limit checked inside the auth usecase
     itself (not just at the HTTP edge) to prevent flooding the challenges
     table with unconsumed rows.
   - **General authenticated API traffic**: keyed by user/client ID, using
     the per-minute/per-day limits described in Phase 5.

**Done when:** exceeding a configured limit returns HTTP 429 with a
`Retry-After` or equivalent header, and this behavior is verified correct
when two server instances share the same Redis backend.

---

## Phase 4 — WS connection: ticket issuance + wireauth handshake

The WS endpoint runs under standard TLS. `wireauth` is layered on top as an
additional application-level encryption step for the WS payload itself.
Authentication does not happen inside the WS handshake — a client must
already hold a valid session (Phase 1/2) before it can obtain a WS ticket.

Use `wireauth` protocol v2 strictly inside standard TLS as an additional
transport layer. v2 authenticates the complete handshake transcript
(`client_nonce`, `server_nonce`, and both P-256 public keys) with an RSA-2048
signature before either peer uses derived traffic keys. It derives separate
HKDF-SHA256 `client→server` and `server→client` AES-256-GCM keys, preventing
cross-direction packet reflection. Pin the server's public key in clients;
configure `wireauth.WithTimeout` from `ws_handshake_timeout`, and ensure the
websocket adapter exposes read deadlines because `Perform(ctx, ...)` relies
on them rather than observing context cancellation itself.

The ticket must be validated **before** the `wireauth` handshake, not after.
The RSA/ECDH handshake is the most expensive step in this whole path — if a
client can trigger it before presenting any credential, ticket-issuance rate
limiting does nothing to stop a handshake-flood: an attacker doesn't need a
valid ticket to make the server spend CPU on `wireauth.Perform()`, only to
open a WS upgrade and immediately disconnect. The ticket is therefore not
sent as the first encrypted WS frame — it travels as a query parameter (or
header) on the HTTP upgrade request itself, checked before the upgrade
completes.

1. `internal/domain/wsticket` — ticket struct:
   ```go
   type Ticket struct {
       ID        string
       UserID    UUID
       SessionID UUID
       DeviceID  *UUID // nil for sessions without a registered device
       ExpiresAt time.Time
   }
   ```
   `Repository` port with atomic `Create` / `ConsumeByID`. Prefer storing
   tickets in Redis with a TTL rather than Postgres, given their short
   lifetime and high churn. On `ConsumeByID`, after the ticket is atomically
   consumed, verify that the referenced `SessionID` (and `DeviceID`, if set)
   are not revoked before allowing the upgrade — this closes the window where
   a ticket is issued just before a session/device revocation and redeemed
   after. The WS `Session` established after a successful consume carries
   `UserID`, `SessionID`, and `DeviceID` for its entire lifetime, enabling
   precise targeted closure by the security lifecycle events described below.
2. `POST /api/v1/ws/ticket` — requires an existing session; rate-limited by
   user ID; issues a single-use ticket.
3. `internal/transport/ws/server.go` — HTTP upgrade handler, in this order:
   - apply a **pre-upgrade, per-IP connection/rate limiter** first — this is
     the only thing standing between an unauthenticated client and the
     upgrade attempt itself, so it must not depend on the ticket check
     below having happened yet
   - read the ticket from the upgrade request and atomically consume it —
     resolve the associated user ID — **before** upgrading the connection;
     reject with a normal HTTP error (not a WS close frame) if the ticket
     is invalid, expired, or already consumed. **Ticket transport by client
     type:**
     - **Native clients:** send ticket as a custom HTTP header (e.g.
       `X-WS-Ticket`) on the upgrade request — headers are not logged by
       most proxies and the native WebSocket API allows setting custom
       headers freely.
     - **Browser clients:** the standard browser `WebSocket` API cannot
       set custom headers on the upgrade request. Acceptable options:
       (a) query parameter (`?ticket=<value>`) — HTTPS-only + single-use
       + short TTL (≤30 s) make this acceptable despite proxy logging risk;
       Use a query parameter (`?ticket=<value>`) only: HTTPS, single-use,
       TTL ≤30 s, and explicit redaction of the query string from proxy,
       access, trace, and application logs are mandatory. Do not overload
       `Sec-WebSocket-Protocol`, which must remain a negotiated protocol
       identifier rather than a bearer secret.
   - only then upgrade the connection (already under TLS)
   - perform the `wireauth` handshake over the upgraded connection to
     establish a per-connection symmetric key; the resolved user ID from
     the ticket is already bound to the session before this step runs
   - apply a handshake timeout (see Phase 4.5 server limits) so a client
     that completes the upgrade but stalls the `wireauth` exchange doesn't
     hold the connection open indefinitely
   - on any failure (invalid/expired ticket, handshake failure, timeout):
     close immediately with no partial state retained
4. `internal/transport/ws/session.go` — wraps the underlying connection and
   `wireauth` session state; exposes `Send`/`Recv` that transparently
   encrypt/decrypt frames. Message payloads are FlatBuffers-encoded before
   encryption and decoded immediately after decryption — `wireauth` itself
   never sees or parses the FlatBuffers schema, it only handles the
   encrypted byte envelope. Maintain independent, strictly increasing inbound
   and outbound AEAD sequence counters per connection and reject any inbound
   sequence other than the expected next value. `wireauth.DecryptAESGCM`
   authenticates the sequence as AAD but does not enforce ordering or replay
   protection itself. Do not expose `wireauth.VerifyResumeProof` in this
   phase: its proof is not bound to the HTTP WS ticket, session revocation
   lifecycle, or a replay store. Add resumptions only as a separately designed
   protocol feature.
5. `internal/transport/ws/registry.go` — in-memory registry of which
   connections are attached to *this* server instance, keyed by user ID:
   ```go
   type ConnectionRegistry interface {
        Add(session *Session)
        Remove(session *Session)

        ForUser(userID UUID) []*Session       // logout everywhere / revoke all sessions
        ForSession(sessionID UUID) []*Session // logout current session
        ForDevice(deviceID UUID) []*Session   // logout / revoke this device
    }
   ```
   This is deliberately narrower than event delivery (see the `EventBus`
   port in Phase 4.6) — the registry only answers "who is connected to this
   instance right now"; it does not know about topics, publish/subscribe,
   or cross-instance delivery. Keeping these separate avoids collapsing two
   different responsibilities (local connection bookkeeping vs. message
   fanout) into one type, which would make the future multi-instance
    implementation harder to introduce cleanly.
6. **WS security lifecycle** — an active WS connection must be forcibly
   closed when the underlying session or device is revoked. Without this,
   a `logout this device` action revokes the DB record but leaves the open
   WS channel alive for its natural lifetime. Define internal security events:
   ```
   session.revoked
   device.revoked
   user.sessions_revoked
   ```
   `RevokeSession`, `RevokeDevice`, and `RevokeAllSessionsForUser` publish
   the corresponding event to the `EventBus` (Phase 4.6) after the DB write.
   A subscriber (in-process, same instance) receives the event, looks up
   connections via `ConnectionRegistry` (`ForSession`, `ForDevice`, `ForUser`
   respectively), and sends a close frame to each.
   **Single-instance limitation (known):** `LocalEventBus` only delivers
   events within the same process. In a multi-instance deployment, a revoke
   processed by instance A does not close connections open on instance B —
   those will remain open until the next idle timeout, reconnect attempt
   (which will fail session validation), or until the `RedisEventBus`
   implementation is introduced. This is an accepted limitation of the
   foundation phase; document it explicitly in Phase 6 scaling invariants.
   **Best-effort publish semantics:** publishing to `EventBus` after a DB
   commit is not atomic. If the process crashes between the `COMMIT` and
   `EventBus.Publish`, the event is lost and the WS connection stays alive
   until its next natural expiry. For the foundation phase this is
   acceptable. The correct long-term fix is a transactional outbox pattern
   (write the event row in the same transaction; a separate poller/relay
   publishes it); defer this to a future hardening item.

**Done when:** a client can authenticate over HTTP, obtain a WS ticket, and
have that ticket rejected (with the WS upgrade never completing, and no
`wireauth` handshake attempted) when it is invalid, expired, or already
used — verified by testing an invalid ticket does *not* cause any RSA/ECDH
computation to run. With a valid ticket: upgrade succeeds, the `wireauth`
handshake completes, and the connection is immediately usable with its user
identity already resolved — no post-upgrade authentication step remains.
The integration test suite includes byte-for-byte test vectors for every
handshake stage and encrypted frame shared by Go, Web, and Swift clients; it
covers wrong byte order, modified server ECDH key/signature, replayed AEAD
frame, oversized frame, and handshake timeout.

---

## Phase 4.5 — WS Transport Layer

Establishes a stable, resource-bounded connection layer inside the encrypted
channel from Phase 4, **before** any application-level message protocol is
added. After this phase the WS transport is fully observable and testable:
heartbeat, backpressure, timeouts, and graceful shutdown all work without
any FlatBuffers schema yet. Getting this done first gives the earliest
testable vertical slice — a client can connect, the connection stays alive
correctly under load and failure conditions, and the server shuts it down
cleanly.

1. Session lifecycle, explicit stages in `internal/transport/ws/session.go`:
   `authenticate ticket (Phase 4) → upgrade → handshake → register
   connection → read loop → write loop → ping/pong heartbeat → idle
   timeout → graceful close`.
2. Bounded send queue and backpressure policy — a slow client must not grow
   server memory unbounded:
   ```go
   type Session struct {
       UserID    uuid.UUID
       SessionID uuid.UUID
       DeviceID  *uuid.UUID
       conn      *websocket.Conn
       send      chan []byte // bounded, e.g. 256
       ctx       context.Context
       cancel    context.CancelFunc
   }
   ```
   Policy when the send queue is full: **disconnect the slow consumer** (do
   not drop-oldest or drop-newest silently) — this is a realtime/core
   protocol where losing messages silently is worse than a client having to
   reconnect. Log the disconnect with the queue-full reason.
3. Server-side limits — define as explicit config, not implicit library
   defaults:
   ```
   max_http_body_bytes
   max_ws_frame_bytes
   max_ws_connections            (server-wide)
   max_ws_connections_per_ip
   max_ws_connections_per_user
   max_ws_send_queue
   http_read_timeout
   http_write_timeout
   http_idle_timeout
   ws_pre_upgrade_timeout        (time allowed for ticket validation)
   ws_handshake_timeout          (time allowed for the wireauth exchange)
   ws_idle_timeout
   ```
   The pre-upgrade and handshake timeouts matter because without them a
   client that stalls at any point in the connection sequence (Slowloris
   pattern) holds server resources for an unbounded time.
4. Max frame size (`max_ws_frame_bytes`) — reject/close on any incoming
   frame exceeding the configured limit, applied before any decoding, to
   avoid allocating for oversized/malicious payloads.
5. Idle timeout (`ws_idle_timeout`) — close connections with no traffic
   (including no ping/pong) for the configured duration.
6. Connection limits per user/device (`max_ws_connections_per_ip`,
   `max_ws_connections_per_user`) — cap concurrent WS connections per
   subject to bound resource usage from a single compromised or misbehaving
   client.
7. Graceful WS shutdown, distinct from the HTTP graceful shutdown in
   Phase 0 — on SIGTERM: stop accepting new WS upgrades → mark the
   instance draining → send a close frame to each active session → wait a
   bounded grace period for in-flight sends to complete → force-close any
   remaining connections → only then proceed to closing Redis/Postgres
   connections. Without this, a deploy looks to connected clients like a
   random network failure instead of an intentional, recoverable close.

**Done when:** a client can open a WS connection through the Phase 4
upgrade + wireauth handshake; raw encrypted frames can be sent and received;
a ping/pong heartbeat keeps the connection alive past the idle timeout;
a simulated slow consumer gets disconnected rather than growing the send
queue unbounded; a SIGTERM during an active connection results in a clean
close frame at the client rather than an abrupt socket drop.

---

## Phase 4.6 — Application Protocol & Event Delivery

Establishes the FlatBuffers-based message protocol on top of the transport
layer from Phase 4.5, and the `EventBus` abstraction that decouples
cross-component notification from connection bookkeeping. Separating this
from Phase 4.5 means the transport is independently testable before the
protocol layer adds complexity, and gives a natural checkpoint: if the
transport works correctly, any issues in Phase 4.6 are protocol-level, not
transport-level.

1. Define a FlatBuffers `Envelope` schema wrapping every WS message, using a
   FlatBuffers `union` for the payload rather than a raw `[]byte` +
   separate type enum — this gets a compile-time-checked discriminated
   payload instead of hand-rolled dispatch on an integer/string type field:
   ```
   union Payload {
       Ping,
       Pong,
       Error,
       GetTitleRequest,
       GetTitleResponse,
       // one variant per concrete message type, added as they're built
   }

   table Envelope {
       protocol_version: uint;
       message_id: ulong;
       correlation_id: ulong; // 0 / absent when the message isn't a response
       payload: Payload;
   }
   ```
   FlatBuffers generates the `payload_type` discriminator automatically
   from the union, so a separate hand-maintained `REQUEST`/`RESPONSE`/
   `EVENT`/`ERROR`/`PING`/`PONG` type field is unnecessary — `Ping`/`Pong`/
   `Error` are just additional union variants alongside the request/response
   message types. New message types are added by extending the union, not
   by touching dispatch code elsewhere.
2. `message_id`/`correlation_id` semantics — decide and document these
   explicitly rather than leaving them implicit:
   - `message_id`: a `uint64`, generated by whichever side sends the
     message (client generates for requests, server generates for
     server-initiated events), unique **within the connection's lifetime**
     only — not globally unique, not required to survive a reconnect. A
     `uint64` counter is sufficient and far cheaper than a UUID for this
     purpose.
   - `correlation_id`: set by the server on a `RESPONSE`/`ERROR`-variant
     message to the `message_id` of the request it answers; absent/zero on
     requests and on server-initiated events.
   - IDs may be reused after a reconnect (they're not globally unique), so
     any request the client cares about surviving a reconnect needs its own
     idempotency handling (see below) — `message_id` alone does not provide
     that.
   - The server does not need to detect or reject duplicate `message_id`s
     within a connection for this phase; that concern is separate from
     idempotency of the underlying operation (see below).
3. Protocol versioning: add `protocol_version` (already in the envelope
   above) and a `client_version` field to the envelope (or to a
   connection-level handshake message sent once after the ticket/handshake
   complete). Server config carries `min_supported_protocol` and
   `current_protocol`. On a client below the minimum, the server responds
   with an `Error` envelope (`UNSUPPORTED_PROTOCOL`, including the minimum
   and current values — see the error model below) and closes the
   connection, rather than proceeding and failing unpredictably on
   unrecognized message types.
4. Error model — define a fixed taxonomy up front so error handling isn't
   ad-hoc per message type:
   ```
   enum ErrorCode: ubyte {
       INVALID_REQUEST,
       UNAUTHENTICATED,
       PERMISSION_DENIED,
       NOT_FOUND,
       CONFLICT,
       RATE_LIMITED,
       UNSUPPORTED_PROTOCOL,
       INTERNAL,
       SERVICE_UNAVAILABLE,
   }

   table Error {
       code: ErrorCode;
       message: string;    // human-readable, for logs/debugging only
       retryable: bool;
       retry_after_ms: uint;
   }
   ```
   Clients must branch on `code`/`retryable`, never on the `message` string
   — `message` is for logs and developer-facing debugging only and is not
   a stable contract. This mirrors the HTTP-side error handling and should
   stay consistent with it (the HTTP API's error codes and this WS error
   taxonomy should use the same names for the same failure categories).
5. `internal/transport/ws/router.go` — central dispatcher. After the
   FlatBuffers `Envelope` is decoded in the WS session layer, the router
   receives the already-parsed payload — `[]byte` ends at the transport/
   protocol boundary and must not propagate into domain handlers:
   ```go
   // Conceptual shape — concrete types come from FlatBuffers codegen.
   // Each handler is registered for one union variant.
   type Handler[T any] interface {
       Handle(ctx context.Context, session *Session, msg T) error
   }

   type Router struct {
       // handlers keyed by the FlatBuffers-generated payload type enum
       handlers map[PayloadType]untypedHandler
   }
   ```
   Decoded flow: `wireauth` decrypt → FlatBuffers `Envelope` decode → payload
   union discriminant → `Router` → typed `Handler`. Handlers for concrete
   message types (`GetTitle`, `SendMessage`, etc.) are registered here in
   later work — this phase only builds the router and registration mechanism,
   with a handler for `Ping`/`Pong` as the first real registrant.

   **WS → Usecase boundary rule:** a WS handler's only job is decode/adapt;
   business logic lives in a usecase that knows nothing about the wire
   format:
   ```
   WS Handler  (FlatBuffers decode + adapt)
       ↓
   Usecase     (business logic, transport-agnostic)
       ↓
   Repository / Domain
   ```
   The same usecase must be callable from HTTP, WS, or CLI without
   modification — transport concerns must never leak into domain code.
6. `internal/domain/eventbus` — port for event delivery **between**
    components and, later, between server instances — distinct from the
    `ConnectionRegistry` introduced in Phase 4, which only tracks
    connections local to this instance. The separation matters: a handler
    that wants to notify a user of something publishes an `Event` to the
    `EventBus`; something subscribed to that topic (initially, in-process,
    the same instance's WS delivery code) looks up the target user's local
    sessions via `ConnectionRegistry` and sends to them. Neither type
    should grow to cover the other's responsibility.
    ```go
    // Subscription decouples the event channel from unsubscribe semantics.
    // Context cancellation alone is insufficient for broker-backed
    // implementations (Kafka, NATS, Redis Streams) that need an explicit
    // lifecycle call to release server-side resources.
    type Subscription interface {
        Events() <-chan Event
        Close() error
    }

    type EventBus interface {
        Publish(ctx context.Context, topic string, event Event) error
        Subscribe(ctx context.Context, topic string) (Subscription, error)
    }
    ```
    Implement only `LocalEventBus` (in-process, single-instance) now — a
    `RedisEventBus`/`NATSEventBus`/`KafkaEventBus` implementation is the
    cross-instance fanout work explicitly deferred (see Phase 6, item 9,
    and "Deferred by design" below), but the port must exist before any
    handler code is written against it.
7. Idempotency/replay — not implemented in this phase, but the protocol
    must leave room for it: mutation-style requests (as opposed to reads)
    will need an `idempotency_key` field so a client that loses its
    connection after sending a mutating request but before receiving the
    response can safely retry without double-applying the operation (e.g.
    sending a chat message twice, creating a duplicate review). Reserve the
    field in the relevant FlatBuffers request tables now (even if unused
    until the mutation-handling usecases exist) rather than adding it
    later, since adding a field to an existing FlatBuffers table is
    backward-compatible but retrofitting the *handling* of it into
    already-shipped client versions is not something you want to do twice.

**Done when:** a round-trip request/response through the router works
end-to-end: client sends a FlatBuffers `Envelope`, server decodes it,
dispatches to the correct typed handler, and the response `Envelope` with
matching `correlation_id` arrives back at the client. Ping/pong works via
the router (not raw bytes). `EventBus.Publish` + subscriber delivers an
in-process event and triggers a close frame on the target session. An
unsupported protocol version is rejected with an `UNSUPPORTED_PROTOCOL`
error envelope and the connection is closed cleanly.

---

## Phase 5 — External API access: JWT issuance, /getMe, tiered limits

This layer is for registered clients/developers consuming the HTTP API
directly (distinct from the WS-based core service session), authenticated
via short-lived JWTs. Rate limits are per `api_client`, not per `user` — a
single user may hold multiple API clients, each with its own tier and usage.

1. Migration `rate_limit_tiers` (auto-numbered by the generator):
   `rate_limit_tiers` table — `id uuid pk, name text unique,
   requests_per_minute integer check > 0, requests_per_day integer check > 0,
   created_at`. Seed one row via the migration itself:
   `('default', 60, 5000)`. New tiers are added as new rows, not new code.
   Migration file numbers are assigned by the `migrate create` command at
   the time of writing — do not hard-code them in this plan, as the real
   sequence depends on how many migrations Phase 0–4.6 produce.
2. Migration `api_clients` (auto-numbered): `api_clients` table —
   `id uuid pk, user_id fk → users (on delete cascade), tier_id fk →
   rate_limit_tiers, name text, secret_hash bytea, created_at,
   revoked_at nullable`. Index on `user_id`; unique index on
   `(user_id, name) WHERE revoked_at IS NULL` (a user can reuse a client
   name only after revoking the previous one). No DB-level default for
   `tier_id` — Postgres column defaults can't be subqueries, so the
   `default` tier is resolved and set explicitly by the usecase on create.
3. `internal/domain/apiclient` — `APIClient` entity (with an `IsRevoked()`
   helper), `RateLimitTier` entity, and two ports: `Repository` (Create,
   GetByID, ListByUserID, Revoke) and `TierRepository` (GetByID, GetByName).
   Keep tier lookups on a separate port from client CRUD so tier data can be
   cached independently later.
4. `internal/usecase/apiauth` — two operations:
   - `CreateClient(userID, name)`: resolves the `default` tier, generates a
     random client secret (`crypto/rand`, 32 bytes, base64url-encoded),
     stores only its SHA-256 hash, and returns the plaintext secret exactly
     once in the response — it is never retrievable again after this call.
   - `IssueToken(clientID, secret)`: looks up the client, rejects if
     revoked, verifies the secret against the stored hash using a
     constant-time comparison, resolves the client's current tier, and
     mints a short-lived JWT (minutes, not hours) with claims: `iss`, `aud`,
     `sub` (user ID), `jti` (unique per token, random — enables future
     per-token revocation/dedup even though the token itself is stateless),
     `iat`, `exp`, `client_id`, and the resolved `rpm`/`rpd` values at
     issuance time — this lets downstream middleware rate-limit from the
     token alone, without a DB round trip per request.
5. Signing key management: support multiple named keys (`current` +
   `previous`) rather than a single static key, with the key identifier
   (`kid`) written into the JWT header. This allows rotating the signing
   key without invalidating every already-issued token still within its
   TTL — validation checks `kid` against the set of currently-accepted
   keys, signing always uses the `current` one. Config should express this
   as an ordered/keyed set of keys, not a single value.

   **Signing algorithm — decide before implementing:** HS256 (symmetric)
   is simpler and sufficient if only this service ever validates its own
   tokens. **Recommendation: Ed25519 (EdDSA).** This project is likely to
   grow additional services (content domain, notifications, etc.) that will
   need to validate these JWTs independently without holding the HMAC
   secret. Ed25519 allows publishing the public key and letting any service
   verify tokens locally with no network call. It is also faster than
   RS256/ES256 and has a compact key representation. If the decision is
   HS256, revisit before any second service needs to validate tokens.
6. `internal/middleware/jwtauth.go` — validates JWT signature (against the
   key identified by `kid`) and expiry, extracts `user_id`/`client_id`/
   `rpm`/`rpd` into request context. Protects all external API routes.
   Because limits are embedded in the token at issuance, a tier change
   takes effect on the client's *next* token issuance, not retroactively on
   already-issued tokens — acceptable given short TTLs; call this out
   explicitly if a tier change must apply immediately (would require a
   revocation check per request instead).
7. Wire the Phase 3 rate-limit middleware to build its `[]Limit` from the
   `rpm`/`rpd` values in the JWT claims in context.
8. `GET /api/v1/getMe` — authenticated via the JWT middleware; returns
   `user_id`, `client_id`, and current rate-limit info: the limit values
   from the claims plus live usage read via the `Limiter.Usage` call from
   Phase 3, using the same `[]Limit` construction and the same key as the
   rate-limit middleware — don't duplicate that derivation in two places.
9. `POST /api/v1/clients` (requires an existing session, not a client JWT) —
   calls `CreateClient`, returns the client ID and the one-time plaintext
   secret.
10. `POST /api/v1/auth/token` — calls `IssueToken`, given a client ID +
    secret in the request body.
11. `DELETE /api/v1/clients/{id}` (requires an existing session; caller must
    own the client) — calls `Revoke`. Since JWTs are stateless, a revoked
    client's outstanding tokens remain valid until natural expiry — this is
    the reason token TTLs must stay short (minutes).

**Open question, not yet decided:** how a client moves to a different tier
(e.g. a paid subscription upgrade) — no endpoint for this exists yet.
`CreateClient` always assigns the `default` tier. Decide whether this is an
admin-only operation, a self-service endpoint tied to a future billing
system, or something else, before subscription tiers are actually needed.

**Done when:** a registered client can obtain a JWT, call `/getMe` and see
correct profile + live rate-limit usage, get rate-limited according to their
tier once they exceed it, and lose access promptly after revocation (within
one token TTL window).

---

## Phase 6 — Hardening pass

1. Scheduled or CLI-triggered cleanup for expired sessions and challenges
   (`DELETE ... WHERE expires_at < now()`), since these tables accumulate
   dead rows.
2. Apply the categorized/leveled logging from Phase 0 consistently across
   auth, WS, and rate-limit code paths — every auth failure, rate-limit
   rejection, and WS handshake failure should be logged at an appropriate
   level with enough context to debug without being noisy at `info` level.
3. Request-ID propagation: generate a request ID at the HTTP edge, attach it
   to the logger context, and include it in error responses for support/
   debugging correlation.
4. Split the single health endpoint into two, matching standard container/
   orchestration conventions:
   - `GET /livez` — process-alive check only, no dependency calls; used to
     detect a hung process.
   - `GET /readyz` — checks Postgres, Redis, and that the current DB schema
     version falls within this binary's supported range (see migration
     compatibility policy below — a plain equality check between schema
     version and binary version breaks during any rolling deploy, since the
     old and new instances briefly run against the same, single DB schema
     version); used to gate traffic routing to this instance.
5. Metrics: expose Prometheus/OpenTelemetry metrics covering at minimum —
   `http_requests_total`, `http_request_duration_seconds`,
   `ws_connections_active`, `ws_connections_total`,
   `ws_handshake_failures_total`, `ws_messages_received_total`,
   `ws_messages_sent_total`, `auth_attempts_total`, `auth_failures_total`,
   `rate_limit_rejections_total`, `postgres_pool_connections`,
   `redis_errors_total`. Propagate `request_id`/`trace_id` through the
   HTTP → usecase → Postgres/Redis/EventBus call chain for tracing. This is
   additive instrumentation and can be introduced incrementally without
   further architectural changes — unlike the audit log (Phase 2) and rate
   limiter interface (Phase 3), it doesn't affect existing signatures.
6. Migration compatibility policy: document and follow an expand/contract
   discipline for every future migration, since multiple server instances
   (old and new code versions) can run simultaneously during a rolling
   deploy — expand (add new column/table, deploy code that writes both
   old+new) → migrate/backfill data → contract (drop the old column/table)
   as separate deploys. A single migration that does something like
   `DROP COLUMN` on a column the previous instance version still reads is
   not safe once running more than one instance. Express supported schema
   versions as a **range**, not a single expected value: each binary
   version declares `min_schema_version`/`max_schema_version` it can run
   against, and `/readyz` (above) checks
   `min_schema_version <= current_db_version <= max_schema_version`. During
   a rolling deploy the DB is at one schema version while old and new
   binaries are both serving traffic — a strict equality check would make
   one of the two report unready for the entire rollout window; a range
   check is what makes the expand/contract sequence above actually safe to
   roll out.
7. Load-test the WS handshake specifically — the RSA/ECDH step of the
   `wireauth` handshake is the most CPU-expensive part of the stack.
   Protection against a handshake-flood is now a layered combination;
   verify all four controls work together and cannot be bypassed in
   isolation:
   - **pre-upgrade, per-IP rate limiter** — rejects unauthenticated clients
     before the HTTP upgrade even begins
   - **single-use ticket validation before upgrade** — a missing/invalid/
     already-consumed ticket causes a normal HTTP rejection; no WS upgrade
     completes, no `wireauth` handshake is attempted
   - **`ws_handshake_timeout`** — a client that completes the HTTP upgrade
     but stalls the `wireauth` exchange is forcibly closed before spending
     meaningful CPU on a full RSA/ECDH exchange
   - **`max_ws_connections` (server-wide)** — caps total concurrent
     connections regardless of IP diversity
   Synthetic attack scenarios to verify: forged `X-Forwarded-For` headers
   (blocked by `trusted_proxies`), replayed tickets (blocked by single-use
   consume), and clients that stall mid-handshake (blocked by
   `ws_handshake_timeout`).
8. Auth abuse testing: verify the fail-closed Redis policy from Phase 3
   actually blocks auth/WS-ticket requests during a simulated Redis outage,
   and that general API traffic in fail-open mode behaves as intended
   during the same outage.
9. Document the horizontal-scaling invariants relied on so far, so they
   aren't silently violated by future changes:
   - no in-memory session, rate-limit, or ticket state that isn't also
     backed by Redis or Postgres
   - the `ConnectionRegistry` (Phase 4) is per-instance by design — it only
     ever tracks connections local to that instance. The `EventBus` port
     from Phase 4.6 is the abstraction any cross-instance delivery must go
     through — only `LocalEventBus` is implemented so far, so users
     connected to different server instances still cannot reach each other
     over WS yet. A `RedisEventBus` or broker-backed implementation is
     required before the chat domain (DMs/threads) is built on top of this
     foundation, but no code elsewhere needs to change to add it, since
     callers already depend on the `EventBus` interface, not on
     `ConnectionRegistry` or any concrete transport code directly.

---

## Deferred by design

- Additional identity providers (e.g. email + one-time password) — should
  slot into the existing `AuthProvider` registry from Phase 2 without
  changes elsewhere, if that abstraction was implemented correctly.
- Cross-instance WS fanout — a `RedisEventBus`/broker-backed `EventBus`
  implementation (the port is defined in Phase 4.6; only `LocalEventBus`
  exists initially) — required once running more than one server instance
  with chat features.
- Title/Person/Company/Genre/Review content domain, and the chat/DM/thread
  domain — separate plans, built on top of this foundation.
