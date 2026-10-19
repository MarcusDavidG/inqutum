# Operational freeze windows

Freeze windows stop selected high-impact actions during an audit, an event,
a settlement window or an active incident. They complement maintainer
approvals: approval answers **who may do this**, a freeze answers **may this be
done now**.

Implementation: [`backend/src/ops/freeze-window.ts`](../backend/src/ops/freeze-window.ts).
Enforcement point: [`backend/src/ops/maintainer-approval.ts`](../backend/src/ops/maintainer-approval.ts),
which checks the freeze both when an intent is declared and when it executes.

## Scope

```json
{
  "name": "Month-end close",
  "reason": "No cancellations while balances are reconciled",
  "actions": ["invoice.cancel", "job.*"],
  "targets": ["inv-42"],
  "startsAt": "2026-10-19T00:00:00.000Z",
  "endsAt": "2026-10-20T00:00:00.000Z",
  "createdBy": "maintainer-alice"
}
```

- `actions` is required and accepts exact names (`invoice.cancel`), a trailing
  wildcard (`invoice.*`) or `*`.
- `targets` is optional. When present, only those targets of a matching action
  are frozen; every other target keeps working. Wildcards are allowed.
- `startsAt` defaults to now. `endsAt` is required, must be after `startsAt`,
  and a window may not exceed 365 days.
- A window is `scheduled`, `active`, `expired` or `revoked`.

Unrelated actions are never blocked: matching is done per action **and** per
optional target.

## Rejection

A frozen action fails with HTTP `423` and a machine-readable code:

```json
{
  "success": false,
  "code": "ACTION_FROZEN",
  "error": "Action invoice.cancel is frozen until 2026-10-20T00:00:00.000Z by \"Month-end close\": No cancellations while balances are reconciled"
}
```

Other codes: `FREEZE_WINDOW_NOT_FOUND` (404), `FREEZE_WINDOW_ALREADY_REVOKED`
(409), `FREEZE_WINDOW_NOT_ACTIVE` (409), `BYPASS_OUT_OF_SCOPE` (400/403),
`BYPASS_ACTOR_MISMATCH` (403), `BYPASS_ALREADY_USED` (409), `BYPASS_EXPIRED`
(410), `BYPASS_NOT_FOUND` (404), `INVALID_FREEZE_WINDOW` (400).

## Emergency bypasses

A bypass is scoped to one window, one action, one optional target and one
maintainer. It is short-lived (15 minutes by default, never beyond the window)
and single-use:

1. **Issue** during an active window: `POST /api/ops/freeze-windows/:id/bypasses`.
2. **Declare** the intent with `bypassId`. The bypass is validated but **not**
   consumed, so a rejected declaration does not waste it.
3. **Execute** with the same `bypassId`. This consumes it. A second execution
   fails with `BYPASS_ALREADY_USED`. The bypass is consumed even if the
   executor itself fails, which prevents a retry storm around the freeze.

Bypasses cannot be issued for a future or expired window, and cannot cover an
action or target outside the window scope.

One bypass covers exactly one window. When several active windows match the
same action and target, a bypass for one of them does **not** lift the others:
the action stays frozen until every matching window has ended or been revoked.
A blocked attempt does not consume the bypass, so it is still available once
the overlap clears. If an emergency must run during overlapping freezes,
revoke the redundant window first or wait for it to expire.

## API

Admin bearer (`JOBS_ADMIN_TOKEN`) is required for every route. See
[API_CONTRACTS.md](API_CONTRACTS.md).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/ops/freeze-windows` | Schedule a window. |
| `GET` | `/api/ops/freeze-windows` | List, filter by `state`, `action`, `target`, `includeExpired`. |
| `GET` | `/api/ops/freeze-windows/status?action=…&target=…` | Is this pair frozen right now? |
| `GET` | `/api/ops/freeze-windows/:id` | Read one window. |
| `POST` | `/api/ops/freeze-windows/:id/revoke` | Revoke early. |
| `POST` | `/api/ops/freeze-windows/:id/bypasses` | Issue a bypass. |
| `GET` | `/api/ops/freeze-windows/:id/bypasses` | List bypasses (add `includeUsed=true`). |

`POST /api/ops/intents` and `POST /api/ops/intents/:id/execute` accept
`bypassId` for this flow.

## Audit

Every schedule, revoke, issue and use writes an audit event:
`FREEZE_WINDOW_CREATED`, `FREEZE_WINDOW_REVOKED`, `FREEZE_BYPASS_ISSUED`,
`FREEZE_BYPASS_USED`. All four are critical lifecycle events, so they also
produce a compliance snapshot (see [COMPLIANCE_SNAPSHOTS.md](COMPLIANCE_SNAPSHOTS.md)).

## Operational limits

- Window and bypass stores are in memory and bounded (1,000 windows and 10,000
  bypasses by default), like the existing intent and receipt stores. Eviction
  prefers closed bypasses. A restart clears both; schedule a window again after
  a restart if the risk is still present.
- Each API instance enforces its own windows. Run high-impact actions against a
  single instance, or provide a shared `FreezeWindowService` through the
  `freeze` option on `createOpsRouter`.
- Bypasses are for named maintainers, not shared service identities. The actor
  executing the intent must equal `issuedTo`.

## Tests

```bash
cd backend
node --import tsx --test tests/freeze-window.test.ts
```

The suite covers active, future and expired windows, target scoping, revoke,
bypass validation/consumption/expiry, overlapping windows, audit output and the
approval integration.
