# API Contracts

Integration-facing HTTP contract for the Quittance/Inqutum backend.

- **Contract version:** `1.1.0` (tracked in `CONTRACT_VERSION`, `backend/src/api/contract.ts`)
- **Enforced by:** `backend/tests/api-contract.test.ts`, which runs in CI
- **Base path:** `/api`

Every server response — success or failure — uses the envelope defined in
`backend/src/types/api.ts`. Both `server-mvp.ts` (in-memory) and `server.ts`
(Postgres) return the same shapes, so an integration written against one works
against the other; only the storage adapter differs.

## Why this document is checked

Prose goes stale silently. The route table below is generated from the
`API_CONTRACT` array, and `tests/api-contract.test.ts` fails the build when:

- a route is mounted that the contract does not declare,
- the contract declares a route that is not mounted on the surface it claims,
- the success or failure envelope changes shape,
- a handler emits an error code that is missing from `DOMAIN_ERROR_TAXONOMY`,
- a documented status is no longer the status the server returns,
- an unauthenticated call to the admin surface is accepted, or
- a route in the contract is missing from this document.

Route discovery is done by introspecting the live Express app, not by reading
this file, so adding a route without updating the contract fails even if nobody
re-reads the documentation.

## Envelopes

### Success

```json
{
  "success": true,
  "data": { "id": "0f1c…", "status": "PENDING", "memo": "INV-1042" },
  "message": "Invoice created",
  "pagination": { "limit": 50, "offset": 0, "total": 128, "nextCursor": null, "hasMore": false },
  "correlationId": "3f8c1a20-…"
}
```

`data` is always present. `message`, `pagination`, `correlationId` and
`apiVersion` are added when the endpoint has something to say.

### Endpoints that are not enveloped

Six endpoints return a raw body on success, because their consumer is not a
JSON client. They are marked in `API_CONTRACT` with `responseKind: 'raw'` and
the drift test pins that list, so it cannot grow by accident:

| Endpoint | Body | Read by |
| --- | --- | --- |
| `GET /` | JSON banner | humans / uptime scripts |
| `GET /api/health` | JSON probe payload | Kubernetes liveness |
| `GET /api/ready` | JSON probe payload | Kubernetes readiness |
| `GET /api/metrics` | Prometheus text | scraper |
| `GET /api/audit/export` | streamed document | browser download |
| `GET /api/exports/:id` | artifact body | browser download |

Do not wrap these in the envelope: it would break the platform tooling that
reads them. Everything else on the API returns the envelope.

### Failure

```json
{
  "success": false,
  "error": "Asset code is required for credit assets",
  "code": "INVALID_ASSET",
  "category": "VALIDATION",
  "retryable": false,
  "recoveryAction": "Supply both assetCode and assetIssuer, or omit both to use native XLM.",
  "correlationId": "3f8c1a20-…",
  "timestamp": "2026-09-27T09:14:02.118Z"
}
```

`error` is always a human-readable string. When the failure maps to a domain
error, `code`, `category`, `retryable` and `recoveryAction` come from
`DOMAIN_ERROR_TAXONOMY` in `backend/src/errors/error-taxonomy.ts` and are
guaranteed to agree with that table. Every failure carries a `correlationId`,
which is also logged — quote it in a bug report.

## Authentication

| Mode | Requirement |
| --- | --- |
| `none` | No credential. The invoice API is scoped by wallet key, not by login. |
| `public` | Any authenticated caller: a wallet session (`end_user`) or a `MAINTAINER_API_TOKENS` bearer. Anonymous → 401. Used by disputes and safe risk summaries. |
| `admin` | `Authorization: Bearer <JOBS_ADMIN_TOKEN>`. Compared with `timingSafeEqual`. Absent token → 401, disabled route → 403. |
| `maintainer` | `Authorization: Bearer <token>` from `MAINTAINER_API_TOKENS` or `SERVICE_API_TOKENS`, with the route's permission (for example `monitor:sync`). Absent or wallet-session token → 401; a role without the permission → 403. |
| `hmac` | Signed request body plus a timestamp header, verified against `WEBHOOK_SIGNING_SECRET` with a 5-minute tolerance and a replay window. Missing headers → 400 `MALFORMED_WEBHOOK`; stale timestamp → 408 `STALE_TIMESTAMP`; bad signature → 401 `INVALID_SIGNATURE`; replayed event id → 409 `DUPLICATE_EVENT`. |

Sensitive admin actions (`PUT /api/ops/config/feature-flags/:flag`) need the
`admin` bearer **and** an `X-Capability-Token` from `POST /api/ops/capabilities`:
short-lived, single-use, scoped to one action and target. Missing, malformed,
forged or expired → 401; wrong scope → 403; already used or in flight → 409.
Without `CAPABILITY_TOKEN_SECRET` these routes return 403
`CAPABILITIES_DISABLED`. See [CAPABILITY_TOKENS.md](CAPABILITY_TOKENS.md).

> **Known gap.** The public invoice surface authenticates by wallet key rather
> than by a session, and the `/api/email/*` routes have no auth middleware. Both
> are recorded here as contract facts rather than hidden; they need a decision
> from the maintainers before this surface is exposed beyond a trusted network.
> Anything that mutates state (`verify`, `cancel`, `simulate-payment`) is
> reachable by anyone who can reach the server, so the Postgres deployment
> should sit behind an authenticating proxy until that changes.

## Pagination

`GET /api/invoices` accepts `limit` and `offset`, and prefers keyset pagination
via `cursor` (see `docs/PAGINATION.md`). `offset` is retained for older clients
and is unstable while invoices are being inserted. `limit` defaults to 50 and is
clamped to 1–200; the effective value is echoed in `pagination.limit`.

The response carries a `pagination` block:

```json
{ "limit": 50, "offset": 0, "total": 50, "nextCursor": "MjAyNi0wOS0yN1QwOTowMDowMC4wMDBafDBmMWM…", "hasMore": true }
```

`nextCursor` is an opaque base64url string, `null` on the last page, and
`hasMore` is always `nextCursor !== null`. On the invoice list `total` is the
number of rows on **this page**. On `GET /api/audit/events` `total` is the count
of events matching the filter, `limit` is clamped to 1–500 and there is no
cursor. These semantics are pinned by
`backend/tests/pagination-authorization-contract.test.ts`.

## Endpoints

### Public client surface

| Method | Path | Auth | Statuses | Purpose |
| --- | --- | --- | --- | --- |
| `GET` | `/` | none | 200 | Server banner: name, version and storage mode. |
| `GET` | `/api/health` | none | 200 | Liveness plus the storage mode the server is running in. |
| `GET` | `/api/ready` | none | 200, 503 | Readiness probe. 503 when a dependency is unavailable. |
| `POST` | `/api/invoices` | none | 201, 400 | Create an invoice. 201 returns the stored invoice. |
| `GET` | `/api/invoices` | none | 200, 400, 500 | List invoices for a seller. Keyset pagination via `cursor`; `limit` clamped to 1-200. |
| `GET` | `/api/invoices/stats` | none | 200, 400, 500 | Aggregated counts and revenue per asset for a seller. |
| `GET` | `/api/invoices/:id` | none | 200, 404, 500 | Fetch one invoice by id. |
| `GET` | `/api/invoices/:id/payment-info` | none | 200, 404, 500 | Payment details needed to settle an invoice (asset, memo, destination). |
| `GET` | `/api/invoices/:id/email-preview` | none | 200, 404, 500 | Rendered invoice email, as HTML and text, without sending. |
| `POST` | `/api/invoices/:id/cancel` | none | 200, 400, 404, 409 | Cancel a PENDING invoice. 409 once it is settled. |
| `POST` | `/api/invoices/:id/verify` | none | 200, 400, 404, 500 | Verify a submitted payment and settle the invoice. |
| `POST` | `/api/invoices/:id/simulate-payment` | none | 200, 404, 500 | Mark an invoice paid without contacting the network (sandbox only). |
| `POST` | `/api/invoices/:id/send-email` | none | 200, 400, 404, 409, 422, 500 | Email an invoice to its customer. |
| `GET` | `/api/invoices/:id/audit-trail` | none | 200, 404, 500 | Activity timeline for a single invoice. |
| `GET` | `/api/audit/events` | none | 200, 500 | Query audit events across invoices, filtered by type and time. |
| `GET` | `/api/audit/export` | none | 200, 500 | Stream a full audit export as a downloadable document. |
| `GET` | `/api/metrics` | none | 200 | Prometheus exposition format. |
| `GET` | `/api/observability/metrics` | none | 200 | JSON metrics: counters, latencies and error rates. |
| `GET` | `/api/notifications` | none | 200, 400 | Notifications for a recipient wallet, paginated. |
| `GET` | `/api/notifications/unread-count` | none | 200 | Unread notification count for a recipient wallet. |
| `POST` | `/api/notifications/:id/read` | none | 200, 404 | Mark one notification read. |
| `POST` | `/api/notifications/read-all` | none | 200 | Mark every notification for a recipient read. |
| `GET` | `/api/notifications/preferences` | none | 200, 400 | Retrieve durable notification routing preferences for a recipient. |
| `PUT` | `/api/notifications/preferences` | none | 200, 400 | Update durable notification routing preferences for a recipient. |
| `GET` | `/api/notifications/routing-audit` | none | 200, 400 | Retrieve routing and override audit trail for a recipient. |
| `POST` | `/api/exports` | none | 201, 400, 403, 500, 503 | Generate an export artifact. Returns an expiring download handle. |
| `GET` | `/api/exports/:id` | none | 200, 400, 404, 410 | Download an export artifact. 410 once it has expired. |
| `GET` | `/api/imports/invoices/template` | none | 200 | Download the canonical invoice import CSV template. |
| `POST` | `/api/imports/invoices` | none | 200, 400, 429, 500 | Bulk-import invoices from JSON or CSV. Dry run by default; `dryRun: false` writes. |
| `GET` | `/api/stellar/account` | none | 200 | Account balances from Horizon. |
| `GET` | `/api/stellar/payments` | none | 200 | Recent payments for an account from Horizon. |
| `GET` | `/api/stellar/transaction/:hash` | none | 200, 404 | Fetch one transaction by hash. |
| `POST` | `/api/stellar/verify-payment` | none | 200, 400 | Verify a transaction hash against an expected asset and amount. |
| `POST` | `/api/disputes` | public | 201, 400, 401, 403, 409 | Open a settlement dispute with optional evidence and notes. The opener is the authenticated actor. |
| `GET` | `/api/disputes` | public | 200, 400, 401, 403 | List disputes. Maintainers see all; other callers see only their own. |
| `GET` | `/api/disputes/:id` | public | 200, 401, 403, 404 | Read one dispute; private entries are filtered by role and authorship. |
| `POST` | `/api/disputes/:id/evidence` | public | 201, 400, 401, 403, 404, 409 | Attach an evidence reference. File bodies are never accepted. |
| `POST` | `/api/disputes/:id/notes` | public | 201, 400, 401, 403, 404, 409 | Add a public or private note. |
| `POST` | `/api/disputes/:id/investigate` | public | 200, 400, 401, 403, 404, 409 | Maintainer moves an open or reopened dispute into investigation. |
| `POST` | `/api/disputes/:id/resolve` | public | 200, 400, 401, 403, 404, 409 | Maintainer records the resolution summary. |
| `POST` | `/api/disputes/:id/reject` | public | 200, 400, 401, 403, 404, 409 | Maintainer rejects the claim. |
| `POST` | `/api/disputes/:id/reopen` | public | 200, 400, 401, 403, 404, 409 | Opener or maintainer reopens a closed dispute. |
| `GET` | `/api/risk/counterparty/:subjectId` | public | 200, 401 | Safe risk summary, without scores, factors, signals or thresholds. |

### Admin / maintainer surface

| Method | Path | Auth | Statuses | Purpose |
| --- | --- | --- | --- | --- |
| `POST` | `/api/payment/sync` | `maintainer` | 200, 401, 403, 500 | Run a manual payment-monitor sync sweep (maintainer or service). |
| `GET` | `/api/payment/monitor/status` | `maintainer` | 200, 401, 403 | Payment monitor checkpoint and last sweep status. |
| `POST` | `/api/email/send` | none | 200, 400, 409, 422, 429, 502 | Send an email through the configured provider. |
| `GET` | `/api/email/deliveries` | none | 200 | Recent delivery attempts with provider status. |
| `GET` | `/api/email/problems` | none | 200 | Bounced and complained deliveries that need follow-up. |
| `POST` | `/api/email/webhook` | none | 200, 400, 404 | Provider delivery callback (bounce / complaint / delivered). |
| `GET` | `/api/jobs` | `admin` | 200, 400, 401, 403 | List background jobs with status counts. |
| `GET` | `/api/jobs/:id` | `admin` | 200, 401, 403, 404 | Inspect one job, including its full retry history. |
| `POST` | `/api/jobs/:id/retry` | `admin` | 200, 401, 403, 404, 409 | Requeue a dead-lettered job. 409 if it is not dead. |
| `GET` | `/api/ops/health` | `admin` | 200, 401, 403 | Operational health report for maintainers. |
| `GET` | `/api/ops/impersonation` | `admin` | 200, 401, 403 | List active support impersonation sessions. |
| `POST` | `/api/ops/impersonation` | `admin` | 201, 400, 401, 403 | Open a support impersonation session. Fully audited. |
| `POST` | `/api/ops/impersonation/end` | `admin` | 200, 401, 403, 404 | Close a support impersonation session. |
| `POST` | `/api/ops/policy/simulate` | `admin` | 200, 400, 401, 403 | Simulate policy changes against current dataset before committing. |
| `GET` | `/api/ops/stale-projections/detect` | `admin` | 200, 401, 403 | Detect projection drift, stale statuses, and orphaned records. |
| `POST` | `/api/ops/stale-projections/repair` | `admin` | 200, 401, 403 | Automate repair recommendations for detected projection drift. |
| `POST` | `/api/ops/projections/search-index/replay` | `admin` | 200, 400, 401, 403, 409 | Rebuild the search index by replaying the audit trail through a versioned projector. Dry run by default. |
| `POST` | `/api/ops/projections/search-index/rollback` | `admin` | 200, 401, 403, 409 | Restore the search index that the last applied replay replaced. |
| `POST` | `/api/ops/synthetic-journey/run` | `admin` | 200, 401, 403, 503 | Run synthetic journey monitor across critical workflow with latency and dependency blame. |
| `POST` | `/api/ops/snapshot-restore/verify` | `admin` | 200, 401, 403, 422 | Verify snapshot restore package against data invariants and rebuild derived indexes. |
| `POST` | `/api/ops/policy/dry-run` | `admin` | 200, 400, 401, 403, 503 | Dry-run a validated policy proposal: totals plus a paginated preview of affected records. |
| `POST` | `/api/ops/capabilities` | `admin` | 201, 400, 401, 403 | Issue an expiring, single-use capability token for one sensitive action on one target. |
| `GET` | `/api/ops/config` | `admin` | 200, 401, 403 | Effective runtime configuration, its version and the source of each value. |
| `PUT` | `/api/ops/config/feature-flags/:flag` | `admin` + capability | 200, 400, 401, 403, 404, 409, 503 | Set or clear a feature-flag override. Writes audit evidence first. |
| `GET` | `/api/ops/dependencies/matrix` | `admin` | 200, 401, 403 | External dependency degradation matrix and its validation problems. |
| `GET` | `/api/ops/dependencies` | `admin` | 200, 401, 403, 503 | Probe every external dependency. 503 when the overall state is down. |
| `GET` | `/api/ops/partial-failures` | `admin` | 200, 400, 401, 403 | Partial-failure dashboard over background jobs, filterable. |
| `GET` | `/api/ops/partial-failures/:id` | `admin` | 200, 401, 403, 404 | Inspect one partially failed operation. |
| `POST` | `/api/ops/partial-failures/:id/retry` | `admin` | 200, 401, 403, 404, 409, 422, 503 | Idempotently retry a partially failed operation. |
| `POST` | `/api/ops/intents` | `admin` | 201, 400, 401, 403 | Declare a signed, risk-scored intent for a high-impact maintainer action. |
| `GET` | `/api/ops/intents` | `admin` | 200, 401, 403 | List maintainer intents, optionally by status. |
| `POST` | `/api/ops/intents/:id/approve` | `admin` | 200, 400, 401, 403, 404, 409, 410 | Second-maintainer approval of a pending intent. |
| `POST` | `/api/ops/intents/:id/reject` | `admin` | 200, 401, 403, 404, 409, 410 | Reject an intent and issue a signed receipt. |
| `POST` | `/api/ops/intents/:id/execute` | `admin` | 200, 400, 401, 403, 404, 409, 410, 501, 502 | Execute an intent with its confirmation phrase. 502 when the action itself failed. |
| `GET` | `/api/ops/receipts` | `admin` | 200, 401, 403 | Signed intent receipts plus the first broken chain index. |
| `GET` | `/api/ops/receipts/:id` | `admin` | 200, 401, 403, 404 | One intent receipt with its signature check. |
| `POST` | `/api/ops/freeze-windows` | `admin` | 201, 400, 401, 403 | Schedule a scoped freeze window. |
| `GET` | `/api/ops/freeze-windows` | `admin` | 200, 400, 401, 403 | List freeze windows by state, action and target. |
| `GET` | `/api/ops/freeze-windows/status` | `admin` | 200, 400, 401, 403 | Whether one action/target pair is currently frozen. |
| `GET` | `/api/ops/freeze-windows/:id` | `admin` | 200, 401, 403, 404 | Read one freeze window. |
| `POST` | `/api/ops/freeze-windows/:id/revoke` | `admin` | 200, 400, 401, 403, 404, 409 | Revoke a freeze window early. |
| `POST` | `/api/ops/freeze-windows/:id/bypasses` | `admin` | 201, 400, 401, 403, 404, 409 | Issue a short-lived, single-use emergency bypass. |
| `GET` | `/api/ops/freeze-windows/:id/bypasses` | `admin` | 200, 401, 403, 404 | List bypasses issued for a window. |
| `GET` | `/api/ops/compliance-snapshots` | `admin` | 200, 400, 401, 403 | List captured compliance snapshots. |
| `GET` | `/api/ops/compliance-snapshots/verify-chain` | `admin` | 200, 401, 403 | Verify the retained snapshot hash chain. |
| `GET` | `/api/ops/compliance-snapshots/by-event/:eventId` | `admin` | 200, 401, 403, 404 | Find the snapshot for one audit event id. |
| `GET` | `/api/ops/compliance-snapshots/:id` | `admin` | 200, 401, 403, 404 | Read one immutable snapshot. |
| `GET` | `/api/ops/compliance-snapshots/:id/verify` | `admin` | 200, 401, 403, 404 | Recompute one snapshot's hashes. |
| `GET` | `/api/ops/risk/counterparty/overrides` | `admin` | 200, 401, 403 | List manual counterparty risk overrides. |
| `POST` | `/api/ops/risk/counterparty/:subjectId/evaluate` | `admin` | 200, 400, 401, 403 | Score a counterparty and return the factor breakdown. |
| `GET` | `/api/ops/risk/counterparty/:subjectId` | `admin` | 200, 401, 403, 404 | Full counterparty risk detail for maintainers. |
| `PUT` | `/api/ops/risk/counterparty/:subjectId/override` | `admin` | 200, 400, 401, 403 | Set a reasoned, audited manual risk override. |
| `DELETE` | `/api/ops/risk/counterparty/:subjectId/override` | `admin` | 200, 400, 401, 403, 404 | Clear a manual risk override. |
| `POST` | `/api/webhooks/incoming` | `hmac` (conditional) | 200, 400, 401, 408, 409 | Signed inbound webhook receiver. Rejects unsigned, stale and replayed events. |

`/api/webhooks/incoming` is mounted only when `WEBHOOK_SIGNING_SECRET` is set.

### Disputes and counterparty risk

Dispute routes need a wallet session or a maintainer bearer. The path id is the
dispute id, not the settlement id:

```bash
# Open (the caller is the opener)
curl -sX POST localhost:3001/api/disputes \
  -H 'authorization: Bearer '"$SESSION_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"settlementId":"settle_123","reason":"Payment amount did not match the invoice","evidence":[{"label":"Horizon tx","kind":"transaction","reference":"abc…"}]}'
# → 201 {"success":true,"data":{"id":"…","status":"OPEN",…}}

# Maintainer resolution
curl -sX POST localhost:3001/api/disputes/<id>/resolve \
  -H 'authorization: Bearer '"$MAINTAINER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"reason":"Verified against Horizon","summary":"The transfer matches the invoice amount."}'
```

The safe risk summary is intentionally thin. Thresholds, factor weights and raw
signals are available only through the admin detail route:

```bash
curl -s localhost:3001/api/risk/counterparty/GBR… \
  -H 'authorization: Bearer '"$SESSION_TOKEN"
# → 200 {"success":true,"data":{"level":"medium","label":"Review recommended",…}}
```

See [DISPUTES.md](DISPUTES.md) and [COUNTERPARTY_RISK.md](COUNTERPARTY_RISK.md).

### Freeze windows and compliance snapshots

Freeze windows are checked when a high-impact intent is declared and again when
it executes. A frozen action returns `423 ACTION_FROZEN`; a scoped emergency
bypass (`bypassId`) is validated at declaration and consumed at execution.

```bash
curl -sX POST localhost:3001/api/ops/freeze-windows \
  -H 'authorization: Bearer '"$JOBS_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"Month-end close","reason":"No cancellations during reconciliation","actions":["invoice.cancel"],"startsAt":"2026-10-19T00:00:00Z","endsAt":"2026-10-20T00:00:00Z"}'

curl -s localhost:3001/api/ops/compliance-snapshots/verify-chain \
  -H 'authorization: Bearer '"$JOBS_ADMIN_TOKEN"
# → 200 {"success":true,"data":{"valid":true,"checked":42,"size":42}}
```

Critical lifecycle events are snapshotted automatically by the audit write
path. See [FREEZE_WINDOWS.md](FREEZE_WINDOWS.md) and
[COMPLIANCE_SNAPSHOTS.md](COMPLIANCE_SNAPSHOTS.md).

## Integration flows

### 1. Issue an invoice and settle it

```bash
# Create
curl -sX POST localhost:3001/api/invoices \
  -H 'content-type: application/json' \
  -d '{"sellerPublicKey":"GA5Z…","amount":"25.0000000","assetCode":"XLM","memo":"INV-1042"}'
# → 201 {"success":true,"data":{"id":"0f1c…","status":"PENDING",…}}

# Read the settlement instructions
curl -s localhost:3001/api/invoices/0f1c…/payment-info
# → 200 {"success":true,"data":{"amount":"25.0000000","assetCode":"XLM","memo":"INV-1042",…}}

# After the payer submits the payment, verify with the 64-char tx hash
curl -sX POST localhost:3001/api/invoices/0f1c…/verify \
  -H 'content-type: application/json' \
  -d '{"txHash":"'$(printf 'a%.0s' {1..64})'","payerPublicKey":"GBR…"}'
# → 200 {"success":true,"data":{"status":"PAID","paidAt":"2026-09-27T09:15:44.902Z",…}}
```

### 2. Handle a validation failure

```bash
curl -sX POST localhost:3001/api/invoices \
  -H 'content-type: application/json' \
  -d '{"sellerPublicKey":"GA5Z…","amount":"25.0000000","assetCode":"USDC"}'
```
```json
{
  "success": false,
  "error": "Credit assets require both assetCode and assetIssuer",
  "code": "ASSET_ISSUER_REQUIRED",
  "category": "VALIDATION",
  "retryable": false,
  "recoveryAction": "Add the asset issuer, or drop assetCode to use native XLM.",
  "correlationId": "3f8c1a20-…",
  "timestamp": "2026-09-27T09:14:02.118Z"
}
```

Branch on `code`, not on the `error` string — messages are for people and may
be reworded. Use `retryable` to decide whether to back off and retry, and
`recoveryAction` to tell the user what to change.

### 3. Inspect the background job queue

```bash
curl -s localhost:3001/api/jobs?status=dead -H 'authorization: Bearer '"$JOBS_ADMIN_TOKEN"
# → 200 {"success":true,"data":{"jobs":[…]},"pagination":{…}}

curl -sX POST localhost:3001/api/jobs/<id>/retry -H 'authorization: Bearer '"$JOBS_ADMIN_TOKEN"
# → 200 {"success":true,"data":{"status":"queued","attempts":0,…}}
```

See `docs/JOBS.md` for the lifecycle and `docs/RUNBOOK.md` for what to do with
a dead-lettered job.

## Changing the contract

1. Add or update the entry in `API_CONTRACT` (`backend/src/api/contract.ts`),
   including every status the handler can return.
2. Update the table in this document.
3. Run `npm test` in `backend/`. The drift test fails until both agree.
4. If a change is **breaking** (a removed field, a changed status, a new
   required auth), bump `CONTRACT_VERSION` and note it in the PR.

Related: [PAGINATION.md](PAGINATION.md), [SCHEMA_VERSIONING.md](SCHEMA_VERSIONING.md),
[RUNBOOK.md](RUNBOOK.md), [JOBS.md](JOBS.md), [DISPUTES.md](DISPUTES.md),
[COUNTERPARTY_RISK.md](COUNTERPARTY_RISK.md), [FREEZE_WINDOWS.md](FREEZE_WINDOWS.md),
[COMPLIANCE_SNAPSHOTS.md](COMPLIANCE_SNAPSHOTS.md)
