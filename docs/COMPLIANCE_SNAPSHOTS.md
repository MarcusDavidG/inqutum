# Compliance snapshots

The audit trail answers **what happened**. A compliance snapshot answers **what
the record and the rules looked like at that exact moment** — with enough
evidence to prove later that nothing was edited.

Implementation: [`backend/src/audit/compliance-snapshot.ts`](../backend/src/audit/compliance-snapshot.ts).
Write path: [`backend/src/audit/record-event.ts`](../backend/src/audit/record-event.ts).

## Critical lifecycle events

Snapshots are captured automatically for the events that change a settlement,
a dispute outcome, or the operational rules under which an action was taken:

`INVOICE_CREATED`, `INVOICE_CANCELLED`, `INVOICE_EXPIRED`, `PAYMENT_VERIFIED`,
`PAYMENT_SIMULATED`, `DISPUTE_OPENED`, `DISPUTE_RESOLVED`, `DISPUTE_REJECTED`,
`DISPUTE_REOPENED`, `FREEZE_WINDOW_CREATED`, `FREEZE_WINDOW_REVOKED`,
`FREEZE_BYPASS_ISSUED`, `FREEZE_BYPASS_USED`.

Everything else stays in the audit trail without a snapshot. The list lives in
`CRITICAL_LIFECYCLE_EVENTS`; add an event there when a new irreversible
lifecycle transition is introduced.

## Snapshot shape

```json
{
  "id": "snap_6f2c…",
  "eventId": "6f2c…",
  "eventType": "INVOICE_CANCELLED",
  "schemaVersion": 1,
  "entityType": "invoice",
  "entityId": "inv-42",
  "capturedAt": "2026-10-19T12:00:00.000Z",
  "payload": {
    "action": "INVOICE_CANCELLED",
    "actor": { "type": "seller", "id": "G…" },
    "scope": { "entityType": "invoice", "entityId": "inv-42" },
    "reason": "Customer requested cancellation",
    "beforeState": { "status": "PENDING" },
    "afterState": { "status": "CANCELLED" },
    "metadata": null,
    "correlationId": "corr-1"
  },
  "payloadHash": "…",
  "previousHash": "…",
  "integrityHash": "…"
}
```

- `payloadHash` is SHA-256 over the canonical JSON payload.
- `previousHash` is the previous snapshot's `integrityHash`, forming a chain.
- `integrityHash` covers the envelope **and** `payloadHash`, so changing either
  the payload or any envelope field is detectable.
- `schemaVersion` is currently `1`. Unsupported versions are rejected at capture
  time and reported by verification.
- `id` is derived from the audit event id. The event id is the idempotency key:
  retrying the same event returns the original snapshot, while reusing the id
  with different content fails with `SNAPSHOT_CONFLICT` (409).

## Verification

`GET /api/ops/compliance-snapshots/:id/verify` recomputes the payload and
integrity hashes for one snapshot. `GET /api/ops/compliance-snapshots/verify-chain`
walks the retained chain and stops at the first failure:

```json
{
  "valid": false,
  "checked": 12,
  "failure": { "index": 11, "id": "snap_…", "reason": "previous_hash" }
}
```

Reasons: `payload_hash`, `integrity_hash`, `previous_hash`,
`schema_version`, `duplicate_event`.

## Read API

All routes require the admin bearer (`JOBS_ADMIN_TOKEN`). See
[API_CONTRACTS.md](API_CONTRACTS.md).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/ops/compliance-snapshots` | List newest first. Filters: `eventType`, `entityId`, `entityType`, `limit`, `offset`. |
| `GET` | `/api/ops/compliance-snapshots/:id` | Read one snapshot. |
| `GET` | `/api/ops/compliance-snapshots/:id/verify` | Verify one snapshot. |
| `GET` | `/api/ops/compliance-snapshots/verify-chain` | Verify the retained chain (and report `size`). |
| `GET` | `/api/ops/compliance-snapshots/by-event/:eventId` | Fetch by audit event id. |

## Retention and deployment

- The store is in memory and bounded to 10,000 snapshots by default. Eviction
  keeps the retained chain verifiable by remembering the last evicted hash.
- A restart clears snapshots, just like the in-memory audit store. Snapshot
  storage is a projection of the audit stream; wire a persistent store before
  relying on snapshots across restarts.
- Snapshot failures are logged and never roll back the audit event or the
  business action. The trail remains authoritative even if the derived snapshot
  could not be written.
- No database migration is required for the shipped in-memory implementation.

## Tests

```bash
cd backend
node --import tsx --test tests/compliance-snapshot.test.ts
```

Covers capture-once idempotency, non-critical events, schema versioning,
payload/envelope tamper detection, chain reordering, duplicate event ids and
eviction.
