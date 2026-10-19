# Counterparty risk scoring

`backend/src/risk/counterparty-risk.ts` scores an actor, issuer, organizer or
workflow participant from documented, bounded signals. It is separate from
`ops/risk-scoring.ts`, which scores maintainer *actions*.

The same normalized input always produces the same score and `inputHash`.
Public output never exposes the score, factor weights, raw signals or
thresholds; maintainers get the full breakdown on the admin surface.

## Inputs

| Signal | Type | Meaning |
| --- | --- | --- |
| `accountAgeDays` | non-negative number | Days since the counterparty first appeared. |
| `completedSettlements` | non-negative number | Settlements completed without a dispute. |
| `failedSettlements` | non-negative number | Failed verification or reversed settlements. |
| `openDisputes` | non-negative number | Disputes currently open against the counterparty. |
| `resolvedDisputesAgainst` | non-negative number | Resolved disputes where the counterparty was at fault. |
| `sanctionsMatch` | boolean | An explicit external sanctions/list match. |
| `manualFlags` | string[] | Named internal flags, e.g. `MANUAL_REVIEW_REQUIRED`. |

Unknown/missing signals are `null`. `manualFlags` are deduplicated.

## Factors and score

| Factor | Observed | Weight |
| --- | --- | --- |
| `ACCOUNT_AGE` | <7 days / <30 / <180 / ≥180 | 30 / 18 / 8 / 0 |
| `COMPLETED_SETTLEMENTS` | 0 / ≥1 / ≥5 / ≥20 | 5 / 0 / −10 / −20 |
| `FAILED_SETTLEMENTS` | 0 / 1–2 / 3–5 / >5 | 0 / 10 / 25 / 40 |
| `OPEN_DISPUTES` | 0 / 1 / 2 / ≥3 | 0 / 10 / 20 / 30 |
| `RESOLVED_DISPUTES_AGAINST` | 0 / ≥1 | 0 / 20 |
| `SANCTIONS_MATCH` | true | 60 |
| `MANUAL_FLAGS` | each flag, capped | 15 each, max 30 |

The score is the sum of matching factors, clamped to `0–100`.

| Level | Score | Effect |
| --- | --- | --- |
| `low` | 0–20 | Normal flow. |
| `medium` | 21–49 | Review before increasing exposure. |
| `high` | ≥50 | Manual review required. |
| `unknown` | — | Fewer than two documented signals were supplied. |

A `sanctionsMatch: true` is decisive: the score is at least 50 and the level is
`high`, even when it is the only signal. `unknown` and `high` set
`requiresManualReview`.

## Manual overrides

Overrides are explicit, reasoned and audited. They win over the computed level
until they expire or are cleared; the computed score and factors are still
returned to maintainers for context.

```bash
curl -sX PUT localhost:3001/api/ops/risk/counterparty/GBR…/override \
  -H 'authorization: Bearer '"$JOBS_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"level":"high","reason":"Open compliance investigation 2026-10-18","actorId":"maintainer-alice","expiresAt":"2026-11-18T00:00:00Z"}'
```

Clear it with `DELETE …/override` and a reason. Both operations emit
`COUNTERPARTY_RISK_OVERRIDDEN` / `COUNTERPARTY_RISK_OVERRIDE_CLEARED` audit
events.

## Visibility

| Surface | Auth | Returns |
| --- | --- | --- |
| `GET /api/risk/counterparty/:subjectId` | any authenticated caller | `level`, `label`, `guidance`, `requiresManualReview`, `overridden`, `assessedAt`. |
| `GET /api/ops/risk/counterparty/:subjectId` | admin bearer | Score, factors, normalized signals, input hash, unknown reason and override. |
| `POST /api/ops/risk/counterparty/:subjectId/evaluate` | admin bearer | Re-score from supplied signals. |
| `GET /api/ops/risk/counterparty/overrides` | admin bearer | Overrides, optionally including expired. |

The public summary deliberately contains no threshold values. Tests assert the
serialized body contains no `score`, `factor`, `weight` or threshold number.

## Operational notes

- Latest assessments and overrides are in memory. A restart clears them;
  re-evaluate after a restart. Supply a shared service if multiple instances
  must agree on overrides.
- An evaluation replaces the latest assessment for that subject. Overrides are
  keyed by subject and do not depend on an assessment existing first.
- `inputHash` uses the same canonical serialization as the audit trail, so two
  callers that normalize to the same signals get the same hash.
- No database migration is required for the shipped in-memory implementation.

## Tests

```bash
cd backend
node --import tsx --test tests/counterparty-risk.test.ts
```

Covers low, medium, high, unknown and manually overridden states, plus
reproducibility and public-summary leakage checks.
