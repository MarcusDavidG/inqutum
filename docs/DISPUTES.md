# Settlement disputes

Disputes give payers and maintainers one structured place for evidence, state
changes and the final decision, instead of off-platform notes.

Implementation: [`backend/src/domain/dispute-workflow.ts`](../backend/src/domain/dispute-workflow.ts).
Audited service: [`backend/src/services/dispute.service.ts`](../backend/src/services/dispute.service.ts).

## States and transitions

```
OPEN ──► INVESTIGATING ──► RESOLVED ──► REOPENED ──► INVESTIGATING
  │             │                              ▲
  └─────────────┴──► REJECTED ─────────────────┘
```

| From | Allowed next states | Who |
| --- | --- | --- |
| `OPEN` | `INVESTIGATING`, `REJECTED` | Maintainer |
| `INVESTIGATING` | `RESOLVED`, `REJECTED` | Maintainer |
| `RESOLVED` | `REOPENED` | Opener or maintainer |
| `REJECTED` | `REOPENED` | Opener or maintainer |
| `REOPENED` | `INVESTIGATING`, `REJECTED` | Maintainer |

Every transition requires a reason (3–2,000 characters). `resolve` and `reject`
also require a resolution summary (10–2,000 characters), which is stored with
its visibility. An invalid transition returns `409 INVALID_DISPUTE_TRANSITION`;
a role violation returns `403 DISPUTE_FORBIDDEN`.

## One dispute per settlement

A settlement may have only one dispute record, ever. Opening a second one
returns `409 DUPLICATE_DISPUTE` with the existing `disputeId`. A closed dispute
is **reopened** instead, so evidence and history stay together.

## Evidence and notes

- Evidence is a labelled reference, not a file body: `label`, `kind`
  (`transaction`, `document`, `reference`, `other`), `reference` (tx hash, URL,
  document id) and `visibility`.
- A SHA-256 `contentHash` over the canonical evidence tuple is stored for later
  integrity checks.
- Notes are plain text with `public` or `private` visibility.
- Evidence and notes can be added while the dispute is `OPEN`, `INVESTIGATING`
  or `REOPENED`. A closed dispute returns `409 DISPUTE_CLOSED`.
- Limits: 100 evidence items and 200 notes per dispute by default.

### Private visibility

Maintainers see everything. Everyone else sees:

- public evidence, notes and transitions,
- private entries they authored themselves,
- a private resolution summary only if they authored it.

A private resolution is hidden entirely from participants who did not write it.
The route also refuses to return a dispute at all unless the caller is a
maintainer, the opener or the named subject (`403`).

## API

All routes are mounted on both the MVP and Postgres surfaces and require a
wallet session or a maintainer bearer. Path ids are dispute ids.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/disputes` | Open. Optional `evidence[]` and `notes[]`. |
| `GET` | `/api/disputes` | List. Maintainers may filter by `status`, `settlementId`, `openedBy`, `participant`, `limit`, `offset`; other callers are limited to their own disputes. |
| `GET` | `/api/disputes/:id` | Read with visibility filtering. |
| `POST` | `/api/disputes/:id/evidence` | Add an evidence reference. |
| `POST` | `/api/disputes/:id/notes` | Add a public/private note. |
| `POST` | `/api/disputes/:id/investigate` | Maintainer. |
| `POST` | `/api/disputes/:id/resolve` | Maintainer; requires `summary`. |
| `POST` | `/api/disputes/:id/reject` | Maintainer; requires `summary`. |
| `POST` | `/api/disputes/:id/reopen` | Opener or maintainer. |

The opener is always derived from the authenticated actor, never from the
request body. See [API_CONTRACTS.md](API_CONTRACTS.md) for full status sets.

## Audit

Every open, transition, evidence item and note is written through the shared
audit trail with `scope.entityType = "dispute"` and the settlement id in
metadata. Events: `DISPUTE_OPENED`, `DISPUTE_INVESTIGATING`,
`DISPUTE_RESOLVED`, `DISPUTE_REJECTED`, `DISPUTE_REOPENED`,
`DISPUTE_EVIDENCE_ADDED`, `DISPUTE_NOTE_ADDED`.

The audit trail is queried by operators and is not filtered by dispute viewer.
Evidence labels, note bodies and private resolution summaries are therefore
never copied into it. A transition marked `private` records its state change,
actor and timestamp but replaces the free-text reason with a withheld marker;
the full reason stays on the dispute record.

`DISPUTE_OPENED`, `DISPUTE_RESOLVED`, `DISPUTE_REJECTED` and
`DISPUTE_REOPENED` are critical lifecycle events and also produce compliance
snapshots. See [COMPLIANCE_SNAPSHOTS.md](COMPLIANCE_SNAPSHOTS.md).

## Operational notes

- Disputes are in memory. A restart clears them; persist them before relying on
  the workflow across deployments.
- The idempotency boundary is the settlement id: retries of the same open
  request return `DUPLICATE_DISPUTE` rather than creating a second record.
- No database migration is required for the shipped in-memory implementation.

## Tests

```bash
cd backend
node --import tsx --test tests/dispute-workflow.test.ts
```

Covers normal resolution, rejected claims, duplicate disputes, reopening,
role enforcement, private evidence visibility and audit output.
