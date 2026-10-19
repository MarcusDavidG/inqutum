/**
 * Counterparty risk scoring and visibility controls (#191).
 *
 * The score must be reproducible from documented inputs, the public summary
 * must not leak thresholds or weights, and manual overrides must be explicit,
 * reasoned and audited.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  COUNTERPARTY_RISK_POLICY_VERSION,
  COUNTERPARTY_RISK_THRESHOLDS,
  CounterpartyRiskError,
  CounterpartyRiskService,
  buildCounterpartyRiskAssessment,
  normalizeCounterpartyRiskSignals,
  publicCounterpartyRiskSummary,
  type CounterpartyRiskAuditRecord,
} from '../src/risk/counterparty-risk';

const NOW = new Date('2026-10-19T12:00:00.000Z');

function rejects(fn: () => unknown, code: string, status: number) {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof CounterpartyRiskError, `expected CounterpartyRiskError, got ${String(err)}`);
    assert.equal(err.code, code);
    assert.equal(err.httpStatus, status);
    return true;
  });
}

describe('counterparty risk — reproducible score buckets', () => {
  it('scores a long, clean history as low risk', () => {
    const assessment = buildCounterpartyRiskAssessment(
      'counterparty-low',
      normalizeCounterpartyRiskSignals({
        accountAgeDays: 400,
        completedSettlements: 25,
        failedSettlements: 0,
        openDisputes: 0,
        resolvedDisputesAgainst: 0,
      }),
      { now: () => NOW }
    );

    assert.equal(assessment.policyVersion, COUNTERPARTY_RISK_POLICY_VERSION);
    assert.equal(assessment.level, 'low');
    assert.equal(assessment.score, 0);
    assert.equal(assessment.unknownReason, null);
    assert.equal(assessment.requiresManualReview, false);
    assert.ok(assessment.factors.some((factor) => factor.code === 'COMPLETED_SETTLEMENTS' && factor.weight < 0));
  });

  it('scores mixed history as medium risk', () => {
    const assessment = buildCounterpartyRiskAssessment(
      'counterparty-medium',
      normalizeCounterpartyRiskSignals({
        accountAgeDays: 2,
        completedSettlements: 0,
        failedSettlements: 1,
        openDisputes: 0,
        resolvedDisputesAgainst: 0,
      }),
      { now: () => NOW }
    );

    assert.equal(assessment.score, 45);
    assert.equal(assessment.level, 'medium');
    assert.ok(assessment.score! >= COUNTERPARTY_RISK_THRESHOLDS.medium);
    assert.ok(assessment.score! < COUNTERPARTY_RISK_THRESHOLDS.high);
  });

  it('scores repeated failures and disputes as high risk and caps the score at 100', () => {
    const assessment = buildCounterpartyRiskAssessment(
      'counterparty-high',
      normalizeCounterpartyRiskSignals({
        accountAgeDays: 2,
        completedSettlements: 0,
        failedSettlements: 6,
        openDisputes: 3,
        resolvedDisputesAgainst: 2,
      }),
      { now: () => NOW }
    );

    assert.equal(assessment.score, 100);
    assert.equal(assessment.level, 'high');
    assert.equal(assessment.requiresManualReview, true);
    assert.ok(assessment.factors.some((factor) => factor.code === 'FAILED_SETTLEMENTS'));
    assert.ok(assessment.factors.some((factor) => factor.code === 'OPEN_DISPUTES'));
  });

  it('returns unknown when fewer than two documented signals are available', () => {
    const assessment = buildCounterpartyRiskAssessment(
      'counterparty-unknown',
      normalizeCounterpartyRiskSignals({ accountAgeDays: 3 }),
      { now: () => NOW }
    );

    assert.equal(assessment.level, 'unknown');
    assert.equal(assessment.score, null);
    assert.deepEqual(assessment.factors, []);
    assert.match(assessment.unknownReason ?? '', /At least 2 documented signals/);
    assert.equal(assessment.requiresManualReview, true);
  });

  it('is reproducible: the same normalized input yields the same hash and score', () => {
    const signals = normalizeCounterpartyRiskSignals({
      accountAgeDays: 12,
      completedSettlements: 6,
      failedSettlements: 1,
      openDisputes: 1,
      resolvedDisputesAgainst: 0,
    });
    const first = buildCounterpartyRiskAssessment('counterparty-x', signals, { now: () => NOW });
    const second = buildCounterpartyRiskAssessment('counterparty-x', signals, { now: () => NOW });

    assert.equal(first.score, second.score);
    assert.equal(first.inputHash, second.inputHash);
    assert.deepEqual(first.factors, second.factors);
  });

  it('treats a sanctions match as decisive progress even with one signal', () => {
    const assessment = buildCounterpartyRiskAssessment(
      'counterparty-sanctioned',
      normalizeCounterpartyRiskSignals({ sanctionsMatch: true }),
      { now: () => NOW }
    );

    assert.equal(assessment.unknownReason, null);
    assert.equal(assessment.level, 'high');
    assert.ok(assessment.score! >= COUNTERPARTY_RISK_THRESHOLDS.high);
  });

  it('rejects invalid signal values', () => {
    rejects(() => normalizeCounterpartyRiskSignals({ failedSettlements: -1 }), 'INVALID_COUNTERPARTY_SIGNAL', 400);
    rejects(() => normalizeCounterpartyRiskSignals({ accountAgeDays: Number.NaN as unknown as number }), 'INVALID_COUNTERPARTY_SIGNAL', 400);
    rejects(
      () => normalizeCounterpartyRiskSignals({ manualFlags: 'NOT_AN_ARRAY' as unknown as string[] }),
      'INVALID_COUNTERPARTY_SIGNAL',
      400
    );
  });
});

describe('counterparty risk — safe public summaries', () => {
  it('omits the score, factors, signals and thresholds from user-facing output', () => {
    const assessment = buildCounterpartyRiskAssessment(
      'counterparty-public',
      normalizeCounterpartyRiskSignals({
        accountAgeDays: 2,
        completedSettlements: 0,
        failedSettlements: 1,
        openDisputes: 0,
        resolvedDisputesAgainst: 0,
      }),
      { now: () => NOW }
    );
    const summary = publicCounterpartyRiskSummary(assessment);
    const serialized = JSON.stringify(summary);

    assert.deepEqual(Object.keys(summary).sort(), [
      'assessedAt',
      'guidance',
      'label',
      'level',
      'overridden',
      'requiresManualReview',
      'subjectId',
    ]);
    assert.equal(summary.level, 'medium');
    assert.equal(summary.label, 'Review recommended');
    assert.equal(serialized.includes('score'), false);
    assert.equal(serialized.includes('factor'), false);
    assert.equal(serialized.includes('threshold'), false);
    assert.equal(serialized.includes('weight'), false);
    assert.equal(serialized.includes(String(COUNTERPARTY_RISK_THRESHOLDS.medium)), false);
  });
});

describe('counterparty risk — manual overrides are explicit and audited', () => {
  function setup() {
    const audit: CounterpartyRiskAuditRecord[] = [];
    const service = new CounterpartyRiskService({
      now: () => NOW,
      onAudit: (record) => audit.push(record),
    });
    return { service, audit };
  }

  it('applies an override until it is cleared, then returns the computed level', () => {
    const { service, audit } = setup();
    const input = {
      accountAgeDays: 400,
      completedSettlements: 25,
      failedSettlements: 0,
      openDisputes: 0,
      resolvedDisputesAgainst: 0,
    };

    assert.equal(service.evaluate('cp-1', input).level, 'low');
    const override = service.setOverride({
      subjectId: 'cp-1',
      level: 'high',
      reason: 'Open compliance investigation from 2026-10-18',
      actorId: 'maintainer-alice',
    });
    assert.equal(override.expiresAt, null);

    // The override applies to the already-stored assessment without a re-evaluation.
    const overridden = service.getLatest('cp-1');
    assert.equal(overridden?.level, 'high');
    assert.equal(overridden?.override?.id, override.id);
    assert.equal(overridden?.requiresManualReview, true);

    const cleared = service.clearOverride('cp-1', 'maintainer-bob', 'Investigation closed with no findings');
    assert.equal(cleared?.id, override.id);
    // Clearing reverts to the computed level, again without re-evaluating.
    assert.equal(service.getLatest('cp-1')?.level, 'low');
    assert.equal(service.evaluate('cp-1', input).level, 'low');
    assert.equal(service.clearOverride('cp-1', 'maintainer-bob', 'Nothing left to clear'), null);

    assert.deepEqual(audit.map((record) => record.action), [
      'COUNTERPARTY_RISK_OVERRIDDEN',
      'COUNTERPARTY_RISK_OVERRIDE_CLEARED',
    ]);
    assert.equal(audit[0]!.level, 'high');
    assert.equal(audit[1]!.actorId, 'maintainer-bob');
  });

  it('lets an override expire without manual cleanup', () => {
    let nowMs = NOW.getTime();
    const service = new CounterpartyRiskService({ now: () => new Date(nowMs) });
    service.evaluate('cp-expiring', {
      accountAgeDays: 400,
      completedSettlements: 25,
      failedSettlements: 0,
      openDisputes: 0,
      resolvedDisputesAgainst: 0,
    });
    service.setOverride({
      subjectId: 'cp-expiring',
      level: 'medium',
      reason: 'Temporary review while documents are collected',
      actorId: 'maintainer-alice',
      expiresAt: new Date(nowMs + 60 * 60_000),
    });
    assert.equal(service.getOverride('cp-expiring')?.level, 'medium');

    nowMs += 61 * 60_000;
    assert.equal(service.getOverride('cp-expiring'), null);
    assert.equal(service.listOverrides().length, 0);
    assert.equal(service.listOverrides(true).length, 1);
  });

  it('applies an override to a public summary even before an assessment exists', () => {
    const { service } = setup();
    service.setOverride({
      subjectId: 'cp-unassessed',
      level: 'high',
      reason: 'Blocked pending an external compliance check',
      actorId: 'maintainer-alice',
    });

    const summary = service.publicSummary('cp-unassessed');
    assert.equal(summary.level, 'high');
    assert.equal(summary.overridden, true);
    assert.equal(summary.requiresManualReview, true);
  });

  it('validates override level, reason and expiry', () => {
    const { service } = setup();
    rejects(() => service.setOverride({
      subjectId: 'cp-1',
      level: 'critical' as any,
      reason: 'A sufficiently long reason',
      actorId: 'maintainer-alice',
    }), 'INVALID_COUNTERPARTY_RISK', 400);
    rejects(() => service.setOverride({
      subjectId: 'cp-1',
      level: 'high',
      reason: 'short',
      actorId: 'maintainer-alice',
    }), 'INVALID_COUNTERPARTY_RISK', 400);
    rejects(() => service.setOverride({
      subjectId: 'cp-1',
      level: 'high',
      reason: 'A sufficiently long reason',
      actorId: 'maintainer-alice',
      expiresAt: '2020-01-01T00:00:00.000Z',
    }), 'INVALID_COUNTERPARTY_RISK', 400);
  });
});
