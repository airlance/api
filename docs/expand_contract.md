# Expand/Contract Deployments, Schema Versioning, and API Lifecycle

This document describes the operational rules for zero-downtime database migrations, API client tier changes, and future FlatBuffers message mutations.

---

## 1. Zero-Downtime Expand/Contract Migrations

When releasing schema changes that overlap rolling deployments between binary versions $V_N$ and $V_{N+1}$:

### Phase 1: Expand
1. Add new columns or tables as nullable or with safe defaults.
2. Update application code to write to both old and new locations, but read from the old location (or fall back gracefully).
3. Deploy $V_{N+1}$ binary across the fleet. Both $V_N$ and $V_{N+1}$ remain healthy because the schema range configured in `MIN_SCHEMA_VERSION` and `MAX_SCHEMA_VERSION` accommodates both versions.

### Phase 2: Backfill & Switch
1. Backfill historical data from old columns to new columns asynchronously.
2. Deploy a patch release where application reads from the new columns.

### Phase 3: Contract
1. Once all nodes run the new binary and no active code reads the deprecated fields, execute a contract migration dropping or renaming old columns.
2. Increment `MIN_SCHEMA_VERSION` to ensure older binaries that depend on the dropped fields cannot start.

---

## 2. API Client Tier Change Workflow

API Clients are assigned a rate-limit tier (e.g., `default`, `enterprise`) that controls allowed requests per minute (`RPM`) and requests per day (`RPD`).

### Tier Modification Procedures:
1. **Tier Assignment (Admin/Billing)**:
   - Modifications to client tiers are performed through direct administrative or billing subscription event webhooks.
   - When an account upgrades or downgrades, the client record's `tier_id` is updated in PostgreSQL.
2. **Token Invalidation on Tier Change**:
   - Short-lived JWTs encode `rpm` and `rpd` claims with a 15-minute TTL (`API_TOKEN_TTL`).
   - Tier modifications take effect immediately upon the next client token renewal via `POST /api/v1/auth/token`.
   - For immediate revocation of elevated privileges, execute client revocation (`DELETE /api/v1/clients/{id}`).

---

## 3. FlatBuffers Mutating Request Idempotency

All future state-mutating FlatBuffers request tables must include a client-supplied 16-byte UUID `idempotency_key`:
1. The server checks the key in Redis with a 24-hour TTL before executing mutations.
2. If a duplicated key is observed within the TTL, the cached response is returned without re-executing side effects or audit records.
3. Once completed, the final response is cached atomically with the idempotency key.
