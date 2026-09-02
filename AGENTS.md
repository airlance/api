## General principles

- Keep clean-architecture boundaries explicit: domain and usecases must not
  import transport, database, Redis, or framework packages.
- Domain packages under `internal/domain/<name>` must separate data structures
  from interface contracts:
  - `entity.go`: domain entities, structs, value objects, invariant methods,
    and typed domain sentinel errors (`Err*`).
  - `interfaces.go`: repository interfaces, port definitions, and service contracts.
  Pure utility packages (such as `crypto`) or interface-only packages (such as `tx`)
  use focused files like `crypto.go` or `interfaces.go`.
- Prefer small, named functions and explicit dependency wiring. Do not add a
  DI framework, reflection-based container, or hidden global state.
- Protocol, database, and public API changes must update their specification,
  fixtures, and tests in the same change.
- Do not edit generated code by hand. Change its schema/source and regenerate.
- Never commit secrets, private keys, production tokens, or real personal
  identifiers.

## Go style

- Format with `gofmt`; use standard Go naming and error-wrapping conventions.
- Keep exported identifiers documented. Prefer typed/sentinel errors and
  `errors.Is`/`errors.As` over matching error strings.
- Do not add package comments that merely restate the package name or an
  obvious implementation detail (for example, `// Package config defines the
  application configuration ...`). Add a package comment only when it conveys
  non-obvious package-level purpose, constraints, or usage; document exported
  identifiers where that documentation is useful to callers.
- Pass `context.Context` as the first parameter for I/O and usecase methods;
  propagate cancellation and deadlines to Postgres, Redis, and EventBus calls.
- Make transaction boundaries explicit. Security mutations and their audit
  records must use the same transaction where practical.
- Avoid package-level mutable state. Inject dependencies through structs or
  constructor arguments.
- Unit tests live beside the package in `*_test.go`.
- Never leave a return value that includes an `error` unhandled. If the error
  is genuinely safe to ignore (e.g. writing to an already-failed connection
  during cleanup), discard it explicitly with `_ = expr` so the omission is
  visibly intentional, not an oversight caught later by `errcheck`/`go vet`.
- Do not write diagnostic/error output with `fmt.Fprintf(os.Stderr, ...)`,
  `fmt.Println`, or `log.Printf` in request-handling or usecase code — use
  the shared `internal/infrastructure/logger` so output is structured,
  leveled, and goes through the same subject-masking as the rest of the
  service. Bare `fmt`/standard-library `log` output to stdout/stderr is only
  acceptable in `cmd/` entrypoints before the logger is constructed, or in
  `_test.go` files.

## Security and protocol code

- TLS is mandatory for the WebSocket endpoint. Use wireauth v2 only; legacy
  v1 is not permitted in the application.
- Never log session tokens, API secrets, device IDs, passkeys, private keys,
  raw identifiers, or decrypted payloads. Use keyed hashes for low-entropy
  audit subjects and device identifiers.
- Do not change protocol constants, HKDF labels, transcript field order,
  sequence byte order, or frame lengths without updating all clients and the
  shared contract fixtures.
- Verify transcript signatures before deriving or using traffic keys. Maintain
  independent directional keys and reject out-of-order or replayed frames.
- Treat malformed input as a protocol error and close/reject promptly; do not
  silently ignore attacker-controlled frames indefinitely.

## Fail-secure defaults

- Any function that returns a security decision (CSRF validation, origin
  checks, authn/authz, signature verification) must have an explicit deny at
  the end of its control flow. Never let an unhandled branch fall through to
  an implicit allow. Write the function as "prove it's safe, then allow" —
  the default should already be deny before any check runs.
- Every branch of such a function requires a table-driven test, including the
  "no signal present" case (missing header, missing cookie, empty origin,
  absent claim). A security predicate with an untested branch is treated as
  unreviewed, regardless of how the rest of the change looks.
- When adding a new trust signal (header, claim, cookie) to an existing
  security check, add the corresponding negative test in the same change.

## Error responses

- Never write `err.Error()`, `fmt.Sprintf("%v", err)`, or any other wrapped
  internal error directly into an HTTP response body. Use
  `writeOperationError` (logs the full error server-side with request
  context, returns a fixed client-safe message) for every handler-level
  error path — this includes `/readyz`/`/healthz` dependency checks, not just
  authentication and business-logic handlers.
- Client-facing error messages are static, enumerable strings defined at the
  call site. When reviewing, grep for `err.Error()` near `writeError` /
  `http.Error` / `checks[...] =`; any hit outside logging or
  `writeOperationError` is a defect, not a style nit.

## New endpoints and tokens

- Every new HTTP route added in `server.go` must be classified in the route
  table in `README.md` by access level: public, session-protected,
  jwt-protected, or internal-only.
- Internal-only routes (metrics, debug, admin, pprof) must be gated by an
  IP/CIDR allowlist by default (see `MetricsAllowedCIDRs`), never left open
  on the assumption that the ingress layer will restrict them.
- Any new token type (JWT, opaque, ticket) must validate signature, expiry,
  issuer, and audience/purpose before its claims are trusted — signature
  validity alone is not sufficient. Add a rejection test for a token that is
  valid except for one mismatched claim (wrong `aud`, wrong `iss`, expired).
- Any new environment variable with a security implication (origins, CIDRs,
  timeouts that gate auth, key sizes) must default to the most restrictive
  safe value and must reject unsafe values (for example a wildcard origin)
  outside `development`/`test`, following the pattern already used for
  `TRUSTED_PROXIES`, `METRICS_ALLOWED_CIDRS`, and the origin wildcard check
  in `LoadFromEnv`.
- Any new secret/key-ring format needs a matching subcommand under
  `internal/cli/keys.go` (mirroring `hmac`/`jwt`/`wireauth`) so operators
  generate it in the exact shape its parser expects, instead of hand-rolling
  values with `openssl`/shell one-liners that silently produce the wrong
  length or encoding. Update `.env.example` and the README "Generating
  secrets" section in the same change.

## Tests and fixtures

- Keep unit tests next to implementation code.
- Put cross-package/process tests under `tests/integration`, `tests/e2e`, and
  `tests/contract`; shared synthetic inputs belong in `tests/fixtures`.
- Wireauth Go, TypeScript, and Swift implementations must consume the same
  versioned protocol vectors. Fixtures must be deterministic and non-secret.
- A bug fix requires a regression test at the lowest reproducing level;
  security/protocol changes also require the relevant integration or contract
  test.
- Run `go test ./...` and `go vet ./...` for Go changes. `golangci-lint run`
  (with `errcheck` and `gosec` enabled) is required before handoff if the
  repository has a `.golangci.yml`; `errcheck` is what catches unhandled
  errors such as an ignored `fmt.Fprintf`/`file.Close`/`rows.Err()` return.
- In the Codex filesystem sandbox, the default Go build cache under the user
  library may be inaccessible. Run checks with a writable temporary cache
  instead of treating that permission error as a code failure or requesting
  broader system-cache access:
  ```bash
  GOCACHE=/private/tmp/airlance-go-build-cache go test ./...
  GOCACHE=/private/tmp/airlance-go-build-cache go vet ./...
  ```
- For a single read-only agent/CI quality gate, run `./scripts/agent-check.sh`
  or `make agent-check`; it verifies formatting, vet, lint, and tests using a
  writable project-local cache and never rewrites source files.
- If an e2e test using `httptest` is then blocked from opening a local
  loopback listener, rerun the same command with the narrowly scoped
  escalation required for local test networking. Do not mistake either
  sandbox restriction for a test failure in the application code.

## Database and migrations

- Migration files are append-only and numbered by the migration tool.
- Use expand/contract for changes that overlap rolling deployments. Do not
  drop or rename fields still read by an older supported binary.
- Repository SQL must use parameterized queries; never concatenate user input.

## Change checklist

Before handoff, run the relevant formatter, tests, and static checks; update
protocol/schema documentation when applicable; and report any checks that
could not run and why.

## Security-sensitive change checklist

Applies in addition to the checklist above whenever a change touches auth,
session, CSRF, rate limiting, WS upgrade, JWT/token issuance or validation,
or config parsing:

- [ ] Every new/changed security predicate has an explicit deny-by-default
  and a test for each branch, including the "no signal" case.
- [ ] No `err.Error()` (or equivalent) reaches an HTTP response body;
  `writeOperationError` (or explicit logging + static message) is used.
- [ ] New env vars with security implications default to the most
  restrictive value and reject unsafe values (e.g. `*`) outside dev/test.
- [ ] New tokens/claims are validated for `iss`/`aud`/`exp`, not just
  signature, with a negative test per claim.
- [ ] New internal-only endpoints are IP/CIDR-gated and documented as such in
  `README.md`.
- [ ] The route table in `README.md` is updated with the correct access
  level for any added/changed route.
