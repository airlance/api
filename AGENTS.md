## General principles

- Keep clean-architecture boundaries explicit: domain and usecases must not
  import transport, database, Redis, or framework packages.
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

## Tests and fixtures

- Keep unit tests next to implementation code.
- Put cross-package/process tests under `tests/integration`, `tests/e2e`, and
  `tests/contract`; shared synthetic inputs belong in `tests/fixtures`.
- Wireauth Go, TypeScript, and Swift implementations must consume the same
  versioned protocol vectors. Fixtures must be deterministic and non-secret.
- A bug fix requires a regression test at the lowest reproducing level;
  security/protocol changes also require the relevant integration or contract
  test.
- Run `go test ./...` and `go vet ./...` for Go changes.
- In the Codex filesystem sandbox, the default Go build cache under the user
  library may be inaccessible. Run checks with a writable temporary cache
  instead of treating that permission error as a code failure or requesting
  broader system-cache access:
  ```bash
  GOCACHE=/private/tmp/airlance-go-build-cache go test ./...
  GOCACHE=/private/tmp/airlance-go-build-cache go vet ./...
  ```
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
