/**
 * Deterministic settlement dispute workflow (#190).
 *
 * Covers normal resolution, rejected claims, duplicate disputes, private
 * evidence visibility, reopening and the audit records each transition emits.
 */
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  DISPUTE_TRANSITIONS,
  DisputeWorkflowError,
  DisputeWorkflowService,
  type DisputeAuditRecord,
} from '../src/domain/dispute-workflow';
import { auditStore } from '../src/audit/audit-service';
import { createAuditedDisputeService } from '../src/services/dispute.service';

const START = new Date('2026-10-19T12:00:00.000Z');
const REASON = 'The settled amount does not match the invoice total';

function setup() {
  let nowMs = START.getTime();
  const audit: DisputeAuditRecord[] = [];
  const service = new DisputeWorkflowService({
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
    assert.ok(err instanceof DisputeWorkflowError, `expected DisputeWorkflowError, got ${String(err)}`);
    assert.equal(err.code, code);
    assert.equal(err.httpStatus, status);
    return true;
  });
}

const OPEN = {
  settlementId: 'settlement-1',
  openedBy: 'buyer-alice',
  subject: 'seller-bob',
  invoiceId: 'invoice-1',
  reason: REASON,
};

describe('disputes — normal resolution', () => {
  it('opens, investigates and resolves with evidence and a public summary', () => {
    const { service, audit } = setup();
    const opened = service.open({
      ...OPEN,
      evidence: [
        { label: 'Horizon payment', kind: 'transaction', reference: 'abc123' },
        { label: 'Internal memo', kind: 'document', reference: 'doc-9', visibility: 'private' },
      ],
      notes: [{ body: 'Paid on time' }],
    });

    assert.equal(opened.status, 'OPEN');
    assert.equal(opened.version, 4); // open + 2 evidence + 1 note
    assert.equal(opened.evidence.length, 2);
    assert.equal(opened.notes.length, 1);
    assert.equal(opened.transitions[0]?.action, 'open');

    const investigating = service.transition(opened.id, {
      action: 'investigate',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'Checking Horizon and the invoice record',
      visibility: 'private',
    });
    assert.equal(investigating.status, 'INVESTIGATING');
    assert.equal(investigating.version, 5);

    const resolved = service.transition(opened.id, {
      action: 'resolve',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'Verified the transfer against the invoice',
      summary: 'The transfer matches the invoice amount; the dispute is resolved.',
    });
    assert.equal(resolved.status, 'RESOLVED');
    assert.equal(resolved.resolution?.outcome, 'RESOLVED');
    assert.equal(resolved.resolution?.summary, 'The transfer matches the invoice amount; the dispute is resolved.');

    assert.deepEqual(audit.map((record) => record.action), [
      'DISPUTE_OPENED',
      'DISPUTE_EVIDENCE_ADDED',
      'DISPUTE_EVIDENCE_ADDED',
      'DISPUTE_NOTE_ADDED',
      'DISPUTE_INVESTIGATING',
      'DISPUTE_RESOLVED',
    ]);
    assert.equal(audit[4]!.from, 'OPEN');
    assert.equal(audit[4]!.to, 'INVESTIGATING');
    assert.equal(audit[4]!.visibility, 'private');
  });

  it('rejects a claim with a summary and keeps it closed to new evidence', () => {
    const { service, audit } = setup();
    const opened = service.open(OPEN);
    const rejected = service.transition(opened.id, {
      action: 'reject',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'No matching on-chain payment exists',
      summary: 'No payment to the invoice destination was found on Horizon.',
    });

    assert.equal(rejected.status, 'REJECTED');
    assert.equal(rejected.resolution?.outcome, 'REJECTED');
    assert.deepEqual(audit.map((record) => record.action), ['DISPUTE_OPENED', 'DISPUTE_REJECTED']);

    rejects(
      () => service.addEvidence(opened.id, { label: 'Late', reference: 'x' }, 'buyer-alice'),
      'DISPUTE_CLOSED',
      409
    );
  });
});

describe('disputes — duplicate disputes and transitions', () => {
  it('refuses a second dispute for the same settlement and points at the existing one', () => {
    const { service } = setup();
    const first = service.open(OPEN);

    assert.throws(
      () => service.open(OPEN),
      (err: unknown) =>
        err instanceof DisputeWorkflowError &&
        err.code === 'DUPLICATE_DISPUTE' &&
        err.httpStatus === 409 &&
        err.details?.disputeId === first.id
    );
  });

  it('does not leave a half-open dispute when the initial bundle is invalid', () => {
    const { service } = setup();
    rejects(
      () => service.open({ ...OPEN, evidence: [{ label: '', reference: 'x' }] }),
      'INVALID_DISPUTE',
      400
    );
    assert.equal(service.open(OPEN).status, 'OPEN');
  });

  it('enforces the declared transition table', () => {
    assert.deepEqual(DISPUTE_TRANSITIONS.OPEN, ['INVESTIGATING', 'REJECTED']);
    assert.deepEqual(DISPUTE_TRANSITIONS.RESOLVED, ['REOPENED']);

    const { service } = setup();
    const opened = service.open(OPEN);
    rejects(
      () => service.transition(opened.id, {
        action: 'resolve',
        actorId: 'maintainer-carol',
        actorRole: 'maintainer',
        reason: 'Skipping investigation',
        summary: 'Resolved without investigating at all.',
      }),
      'INVALID_DISPUTE_TRANSITION',
      409
    );
  });

  it('only maintainers may investigate, resolve or reject', () => {
    const { service } = setup();
    const opened = service.open(OPEN);

    rejects(
      () => service.transition(opened.id, {
        action: 'investigate',
        actorId: 'buyer-alice',
        actorRole: 'user',
        reason: 'I want to investigate this myself',
      }),
      'DISPUTE_FORBIDDEN',
      403
    );
  });
});

describe('disputes — reopening', () => {
  it('lets the opener reopen a resolved dispute and a maintainer reopen a rejected one', () => {
    const { service, audit } = setup();
    const opened = service.open(OPEN);
    service.transition(opened.id, {
      action: 'reject',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'No on-chain payment found',
      summary: 'No matching payment was found on Horizon.',
    });

    const reopened = service.transition(opened.id, {
      action: 'reopen',
      actorId: 'buyer-alice',
      actorRole: 'user',
      reason: 'A second transaction was submitted late',
    });
    assert.equal(reopened.status, 'REOPENED');
    assert.equal(reopened.version, 3);

    const investigated = service.transition(opened.id, {
      action: 'investigate',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'Checking the late transaction',
    });
    const resolved = service.transition(opened.id, {
      action: 'resolve',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'Late transaction matches',
      summary: 'The late transaction matches the invoice.',
    });

    const maintainerReopened = service.transition(opened.id, {
      action: 'reopen',
      actorId: 'maintainer-dave',
      actorRole: 'maintainer',
      reason: 'New evidence from the payer',
    });

    assert.equal(investigated.status, 'INVESTIGATING');
    assert.equal(resolved.status, 'RESOLVED');
    assert.equal(maintainerReopened.status, 'REOPENED');
    assert.deepEqual(
      audit.filter((record) => record.action === 'DISPUTE_REOPENED').map((record) => record.actorId),
      ['buyer-alice', 'maintainer-dave']
    );
  });

  it('refuses a reopen by someone other than the opener or a maintainer', () => {
    const { service } = setup();
    const opened = service.open(OPEN);
    service.transition(opened.id, {
      action: 'reject',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'No matching payment found at all',
      summary: 'No matching payment was found on Horizon.',
    });

    rejects(
      () => service.transition(opened.id, {
        action: 'reopen',
        actorId: 'unrelated-user',
        actorRole: 'user',
        reason: 'I want to reopen this dispute',
      }),
      'DISPUTE_FORBIDDEN',
      403
    );
  });
});

describe('disputes — private visibility', () => {
  it('shows private evidence only to its author and maintainers', () => {
    const { service } = setup();
    const opened = service.open({
      ...OPEN,
      evidence: [{ label: 'Bank statement', kind: 'document', reference: 'doc-9', visibility: 'private' }],
      notes: [{ body: 'Internal context for maintainers', visibility: 'private' }],
    });

    const authorView = service.get(opened.id, { role: 'user', subject: 'buyer-alice', wallet: 'buyer-alice' });
    assert.equal(authorView?.evidence.length, 1);
    assert.equal(authorView?.notes.length, 1);

    const counterpartyView = service.get(opened.id, { role: 'user', subject: 'seller-bob', wallet: 'seller-bob' });
    assert.equal(counterpartyView?.evidence.length, 0);
    assert.equal(counterpartyView?.notes.length, 0);

    const strangerView = service.get(opened.id, { role: 'user', subject: 'stranger' });
    assert.equal(strangerView?.evidence.length, 0);
    assert.equal(strangerView?.notes.length, 0);

    const maintainerView = service.get(opened.id, { role: 'maintainer', subject: 'maintainer-carol' });
    assert.equal(maintainerView?.evidence.length, 1);
    assert.equal(maintainerView?.notes.length, 1);
  });

  it('hides a private resolution summary from non-maintainers', () => {
    const { service } = setup();
    const opened = service.open(OPEN);
    service.transition(opened.id, {
      action: 'investigate',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'Reviewing the internal fraud report',
    });
    service.transition(opened.id, {
      action: 'resolve',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'Internal fraud review completed',
      summary: 'Resolved under the internal fraud procedure.',
      visibility: 'private',
    });

    assert.equal(service.get(opened.id, { role: 'user', subject: 'buyer-alice' })?.resolution, null);
    assert.equal(
      service.get(opened.id, { role: 'maintainer', subject: 'maintainer-carol' })?.resolution?.summary,
      'Resolved under the internal fraud procedure.'
    );
  });
});

describe('disputes — audit integration', () => {
  afterEach(() => {
    auditStore.clear();
  });

  it('writes dispute events through the shared audit trail with dispute scope', () => {
    auditStore.clear();
    const service = createAuditedDisputeService({ now: () => START });
    const opened = service.open({
      ...OPEN,
      evidence: [{ label: 'Horizon lookup', kind: 'transaction', reference: 'abc123' }],
    });
    service.addNote(opened.id, { body: 'Payer contacted support' }, 'buyer-alice', 'user');
    service.transition(opened.id, {
      action: 'reject',
      actorId: 'maintainer-carol',
      actorRole: 'maintainer',
      reason: 'No matching payment found',
      summary: 'The referenced transaction does not exist on Horizon.',
    });

    const events = auditStore.getEventsByEntity(opened.id).reverse();
    // Opening is recorded first, then its initial bundle, the later note and
    // finally the rejection.
    assert.deepEqual(events.map((event) => event.action), [
      'DISPUTE_OPENED',
      'DISPUTE_EVIDENCE_ADDED',
      'DISPUTE_NOTE_ADDED',
      'DISPUTE_REJECTED',
    ]);
    for (const event of events) {
      assert.equal(event.scope.entityType, 'dispute');
      assert.equal(event.metadata?.settlementId, 'settlement-1');
    }
    assert.equal(events[0]!.actor.id, 'buyer-alice');
    assert.equal(events[3]!.actor.type, 'maintainer');
    assert.equal(events[3]!.afterState?.status, 'REJECTED');
  });
});
