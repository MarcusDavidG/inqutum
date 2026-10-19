/**
 * Operational freeze windows (#194).
 *
 * Covers the acceptance criteria directly: active/future/expired freezes,
 * scoped unrelated actions, revocation, emergency bypasses and the audit
 * records every state change emits. The final block wires the freeze service
 * into the maintainer approval flow, which is the production enforcement point.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  FreezeWindowError,
  FreezeWindowService,
  matchesFreezePattern,
  type FreezeAuditRecord,
} from '../src/ops/freeze-window';
import { MaintainerApprovalService } from '../src/ops/maintainer-approval';

const START = new Date('2026-10-19T00:00:00.000Z');
const REASON = 'Month-end reconciliation: no cancellations while balances are checked';

function setup(start = START) {
  let nowMs = start.getTime();
  const audit: FreezeAuditRecord[] = [];
  const service = new FreezeWindowService({
    now: () => new Date(nowMs),
    onAudit: (record) => audit.push(record),
  });
  return {
    service,
    audit,
    advance: (ms: number) => {
      nowMs += ms;
    },
  };
}

function rejects(fn: () => unknown, code: string, status: number) {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof FreezeWindowError, `expected FreezeWindowError, got ${String(err)}`);
    assert.equal(err.code, code);
    assert.equal(err.httpStatus, status);
    return true;
  });
}

const schedule = (service: FreezeWindowService, overrides: Record<string, unknown> = {}) =>
  service.schedule({
    name: 'Month-end close',
    reason: REASON,
    actions: ['invoice.cancel'],
    startsAt: new Date('2026-10-19T00:00:00.000Z'),
    endsAt: new Date('2026-10-20T00:00:00.000Z'),
    createdBy: 'maintainer-alice',
    ...overrides,
  });

describe('freeze windows — matching and schedule validation', () => {
  it('supports exact, global and trailing-wildcard action patterns', () => {
    assert.equal(matchesFreezePattern('invoice.cancel', 'invoice.cancel'), true);
    assert.equal(matchesFreezePattern('invoice.cancel', 'invoice.create'), false);
    assert.equal(matchesFreezePattern('invoice.*', 'invoice.cancel'), true);
    assert.equal(matchesFreezePattern('invoice.*', 'payment.cancel'), false);
    assert.equal(matchesFreezePattern('*', 'anything.at.all'), true);
  });

  it('rejects empty scopes, invalid dates and inverted windows', () => {
    const { service } = setup();
    assert.throws(() => schedule(service, { actions: [] }), /at least one entry/);
    rejects(
      () => schedule(service, { endsAt: new Date('2026-10-18T00:00:00.000Z') }),
      'INVALID_FREEZE_WINDOW',
      400
    );
    rejects(
      () => schedule(service, { startsAt: new Date('2026-10-19T00:00:00.000Z'), endsAt: 'not-a-date' }),
      'INVALID_FREEZE_WINDOW',
      400
    );
    rejects(() => schedule(service, { actions: ['invoice.cancel', 'bad pattern!'] }), 'INVALID_FREEZE_WINDOW', 400);
  });
});

describe('freeze windows — active, future and expired windows', () => {
  it('rejects a frozen action with a clear 423 while unrelated actions continue', () => {
    const { service } = setup();
    schedule(service);

    rejects(() => service.assertAllowed({ action: 'invoice.cancel', target: 'inv-1', actor: 'alice' }), 'ACTION_FROZEN', 423);
    // Different action, same actor: untouched.
    assert.equal(service.assertAllowed({ action: 'invoice.create', target: 'inv-1', actor: 'alice' }), null);
  });

  it('only freezes the configured targets when a target scope is present', () => {
    const { service } = setup();
    schedule(service, { targets: ['inv-42'] });

    rejects(() => service.assertAllowed({ action: 'invoice.cancel', target: 'inv-42', actor: 'alice' }), 'ACTION_FROZEN', 423);
    assert.equal(service.assertAllowed({ action: 'invoice.cancel', target: 'inv-43', actor: 'alice' }), null);

    // An action-only list filter must still surface target-scoped windows.
    assert.equal(service.listWindows({ action: 'invoice.cancel' }).length, 1);
    assert.equal(service.listWindows({ action: 'invoice.cancel', target: 'inv-42' }).length, 1);
    assert.equal(service.listWindows({ action: 'invoice.cancel', target: 'inv-43' }).length, 0);
  });

  it('does not block before the window starts or after it ends', () => {
    const { service, advance } = setup(new Date('2026-10-18T23:59:00.000Z'));
    schedule(service);

    assert.equal(service.status('invoice.cancel').frozen, false, 'future window must not be active yet');
    assert.equal(service.assertAllowed({ action: 'invoice.cancel', target: 'inv-1', actor: 'alice' }), null);

    advance(60_000); // 2026-10-19T00:00:00Z
    assert.equal(service.status('invoice.cancel').frozen, true);

    advance(24 * 60 * 60_000); // 2026-10-20T00:00:00Z
    assert.equal(service.status('invoice.cancel').frozen, false, 'expired window must stop blocking');
    assert.equal(service.assertAllowed({ action: 'invoice.cancel', target: 'inv-1', actor: 'alice' }), null);
  });

  it('reports window state and filters expired windows from the default list', () => {
    const { service, advance } = setup();
    const window = schedule(service);
    assert.equal(service.stateOf(window), 'active');
    assert.equal(service.listWindows().length, 1);

    advance(24 * 60 * 60_000);
    assert.equal(service.stateOf(window), 'expired');
    assert.equal(service.listWindows().length, 0);
    assert.equal(service.listWindows({ state: 'expired' }).length, 1);
    assert.equal(service.listWindows({ includeExpired: true }).length, 1);
  });

  it('revocation stops blocking immediately and is audited', () => {
    const { service, audit } = setup();
    const window = schedule(service);
    rejects(() => service.assertAllowed({ action: 'invoice.cancel', target: 'inv-1', actor: 'alice' }), 'ACTION_FROZEN', 423);

    service.revoke(window.id, 'maintainer-bob', 'Incident resolved');
    assert.equal(service.assertAllowed({ action: 'invoice.cancel', target: 'inv-1', actor: 'alice' }), null);
    rejects(() => service.revoke(window.id, 'maintainer-bob', 'again'), 'FREEZE_WINDOW_ALREADY_REVOKED', 409);

    assert.deepEqual(audit.map((entry) => entry.action), ['FREEZE_WINDOW_CREATED', 'FREEZE_WINDOW_REVOKED']);
    assert.equal(audit[1]!.reason, 'Incident resolved');
  });
});

describe('freeze windows — emergency bypasses', () => {
  it('validates a bypass at declaration, consumes it once and audits both steps', () => {
    const { service, audit } = setup();
    const window = schedule(service);
    const bypass = service.issueBypass(window.id, {
      action: 'invoice.cancel',
      target: 'inv-1',
      issuedTo: 'maintainer-alice',
      reason: 'Court-ordered cancellation during the freeze',
    });

    // Declaration check: no consumption, so it can still be presented later.
    service.assertAllowed({
      action: 'invoice.cancel',
      target: 'inv-1',
      actor: 'maintainer-alice',
      bypassId: bypass.id,
      consume: false,
    });
    assert.equal(service.getBypass(bypass.id)?.usedAt, null);

    service.assertAllowed({
      action: 'invoice.cancel',
      target: 'inv-1',
      actor: 'maintainer-alice',
      bypassId: bypass.id,
      consume: true,
    });
    assert.ok(service.getBypass(bypass.id)?.usedAt);

    rejects(
      () =>
        service.assertAllowed({
          action: 'invoice.cancel',
          target: 'inv-1',
          actor: 'maintainer-alice',
          bypassId: bypass.id,
          consume: true,
        }),
      'BYPASS_ALREADY_USED',
      409
    );

    assert.deepEqual(audit.map((entry) => entry.action), [
      'FREEZE_WINDOW_CREATED',
      'FREEZE_BYPASS_ISSUED',
      'FREEZE_BYPASS_USED',
    ]);
  });

  it('does not let a bypass for one window cover an overlapping window', () => {
    const { service } = setup();
    const first = schedule(service, {
      name: 'First overlap',
      actions: ['invoice.cancel'],
      endsAt: new Date('2026-10-19T02:00:00.000Z'),
    });
    const second = schedule(service, {
      name: 'Second overlap',
      actions: ['invoice.*'],
      startsAt: new Date('2026-10-18T23:00:00.000Z'),
      endsAt: new Date('2026-10-19T03:00:00.000Z'),
    });
    const bypass = service.issueBypass(first.id, {
      action: 'invoice.cancel',
      target: 'inv-1',
      issuedTo: 'maintainer-alice',
      reason: 'Emergency cancellation during overlapping freezes',
    });

    rejects(
      () =>
        service.assertAllowed({
          action: 'invoice.cancel',
          target: 'inv-1',
          actor: 'maintainer-alice',
          bypassId: bypass.id,
          consume: true,
        }),
      'ACTION_FROZEN',
      423
    );
    assert.equal(
      service.getBypass(bypass.id)?.usedAt,
      null,
      'a blocked attempt must not consume the bypass'
    );

    service.revoke(second.id, 'maintainer-bob', 'Overlapping incident freeze lifted');
    service.assertAllowed({
      action: 'invoice.cancel',
      target: 'inv-1',
      actor: 'maintainer-alice',
      bypassId: bypass.id,
      consume: true,
    });
    assert.ok(service.getBypass(bypass.id)?.usedAt, 'the bypass remains usable once it covers every window');
  });

  it('rejects an expired bypass, a different actor and an out-of-scope issue', () => {
    const { service, advance } = setup();
    const window = schedule(service, { endsAt: new Date('2026-10-19T01:00:00.000Z') });
    const bypass = service.issueBypass(window.id, {
      action: 'invoice.cancel',
      target: 'inv-1',
      issuedTo: 'maintainer-alice',
      reason: 'Emergency settlement correction',
    });

    rejects(
      () =>
        service.assertAllowed({
          action: 'invoice.cancel',
          target: 'inv-1',
          actor: 'maintainer-bob',
          bypassId: bypass.id,
          consume: false,
        }),
      'BYPASS_ACTOR_MISMATCH',
      403
    );

    advance(16 * 60_000); // default TTL is 15 minutes
    rejects(
      () =>
        service.assertAllowed({
          action: 'invoice.cancel',
          target: 'inv-1',
          actor: 'maintainer-alice',
          bypassId: bypass.id,
          consume: false,
        }),
      'BYPASS_EXPIRED',
      410
    );

    rejects(
      () => service.issueBypass(window.id, {
        action: 'payment.verify',
        target: 'inv-1',
        issuedTo: 'maintainer-alice',
        reason: 'Out of scope request',
      }),
      'BYPASS_OUT_OF_SCOPE',
      400
    );
  });

  it('only issues bypasses while the window is active and returns the same unused bypass on retry', () => {
    const { service, advance } = setup(new Date('2026-10-18T23:00:00.000Z'));
    const window = schedule(service);
    rejects(
      () => service.issueBypass(window.id, {
        action: 'invoice.cancel',
        target: 'inv-1',
        issuedTo: 'alice',
        reason: 'Too early to need a bypass',
      }),
      'FREEZE_WINDOW_NOT_ACTIVE',
      409
    );

    advance(2 * 60 * 60_000);
    const first = service.issueBypass(window.id, {
      action: 'invoice.cancel',
      target: 'inv-1',
      issuedTo: 'alice',
      reason: 'Emergency correction during the freeze',
    });
    const second = service.issueBypass(window.id, {
      action: 'invoice.cancel',
      target: 'inv-1',
      issuedTo: 'alice',
      reason: 'Retry after a timeout',
    });
    assert.equal(second.id, first.id);
  });
});

describe('freeze windows — maintainer approval integration', () => {
  const SECRET = 'freeze-approval-secret-0123456789';

  it('blocks intent declaration during a freeze and allows it with a bypass', async () => {
    const { service } = setup();
    const window = schedule(service);
    let runs = 0;
    const approvals = new MaintainerApprovalService({
      secret: SECRET,
      now: () => new Date(START),
      freeze: service,
    });
    approvals.registerExecutor('invoice.cancel', async () => {
      runs += 1;
      return { cancelled: true };
    });

    assert.throws(
      () =>
        approvals.requestIntent({
          action: 'invoice.cancel',
          target: 'inv-1',
          reason: REASON,
          requestedBy: 'maintainer-alice',
        }),
      (err: unknown) => err instanceof FreezeWindowError && err.code === 'ACTION_FROZEN'
    );

    const bypass = service.issueBypass(window.id, {
      action: 'invoice.cancel',
      target: 'inv-1',
      issuedTo: 'maintainer-alice',
      reason: 'Emergency cancellation approved by incident lead',
    });
    const intent = approvals.requestIntent({
      action: 'invoice.cancel',
      target: 'inv-1',
      reason: REASON,
      requestedBy: 'maintainer-alice',
      bypassId: bypass.id,
    });
    approvals.approve(intent.id, 'maintainer-bob');
    const receipt = await approvals.execute(intent.id, {
      executedBy: 'maintainer-alice',
      confirmation: intent.confirmationPhrase,
      bypassId: bypass.id,
    });

    assert.equal(receipt.outcome, 'succeeded');
    assert.equal(runs, 1);
    assert.ok(service.getBypass(bypass.id)?.usedAt, 'execution must consume the bypass');
  });

  it('leaves unfrozen actions on the normal approval path', () => {
    const { service } = setup();
    schedule(service, { actions: ['payment.verify'] });
    const approvals = new MaintainerApprovalService({
      secret: SECRET,
      now: () => new Date(START),
      freeze: service,
    });

    const intent = approvals.requestIntent({
      action: 'invoice.cancel',
      target: 'inv-99',
      reason: REASON,
      requestedBy: 'maintainer-alice',
    });
    assert.equal(intent.target, 'inv-99');
  });
});
