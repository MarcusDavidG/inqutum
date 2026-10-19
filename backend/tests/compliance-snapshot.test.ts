/**
 * Immutable compliance snapshots (#192).
 *
 * Exercises creation once per critical event, schema versioning, idempotency,
 * tamper detection, chain verification and bounded retention.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { MemoryAuditStore } from '../src/audit/audit-service';
import {
  COMPLIANCE_SNAPSHOT_SCHEMA_VERSION,
  ComplianceSnapshotStore,
  SnapshotError,
  type ComplianceSnapshotPayload,
} from '../src/audit/compliance-snapshot';

const START = new Date('2026-10-19T12:00:00.000Z');

function payload(overrides: Partial<ComplianceSnapshotPayload> = {}): ComplianceSnapshotPayload {
  return {
    action: 'INVOICE_CANCELLED',
    actor: { type: 'seller', id: 'seller-alice' },
    scope: { entityType: 'invoice', entityId: 'inv-1' },
    reason: 'Customer requested cancellation',
    beforeState: { status: 'PENDING' },
    afterState: { status: 'CANCELLED' },
    metadata: { memo: 'INV-1' },
    correlationId: 'corr-1',
    ...overrides,
  };
}

function setup(maxSnapshots?: number) {
  let eventCounter = 0;
  const store = new ComplianceSnapshotStore({ now: () => START, maxSnapshots });
  const capture = (eventId = `evt-${++eventCounter}`, body = payload()) =>
    store.capture({
      eventId,
      eventType: body.action,
      entityType: body.scope.entityType,
      entityId: body.scope.entityId,
      payload: body,
    });
  return { store, capture };
}

describe('compliance snapshots — capture once per critical event', () => {
  it('captures a critical audit event with schema version and both hashes', () => {
    const audit = new MemoryAuditStore();
    audit.clear();
    const event = audit.recordEvent({
      action: 'INVOICE_CANCELLED',
      actor: { type: 'seller', id: 'seller-alice' },
      scope: { entityType: 'invoice', entityId: 'inv-1' },
      reason: 'Customer requested cancellation',
      beforeState: { status: 'PENDING' },
      afterState: { status: 'CANCELLED' },
    });
    const store = new ComplianceSnapshotStore({ now: () => START });

    const snapshot = store.captureFromAuditEvent(event);
    assert.ok(snapshot);
    assert.equal(snapshot.eventId, event.id);
    assert.equal(snapshot.eventType, 'INVOICE_CANCELLED');
    assert.equal(snapshot.schemaVersion, COMPLIANCE_SNAPSHOT_SCHEMA_VERSION);
    assert.equal(snapshot.entityType, 'invoice');
    assert.equal(snapshot.entityId, 'inv-1');
    assert.equal(snapshot.payload.afterState?.status, 'CANCELLED');
    assert.equal(snapshot.payloadHash.length, 64);
    assert.equal(snapshot.integrityHash.length, 64);
    assert.equal(store.size(), 1);
  });

  it('ignores non-critical audit events', () => {
    const audit = new MemoryAuditStore();
    audit.clear();
    const event = audit.recordEvent({
      action: 'CONFIG_CHANGED',
      actor: { type: 'maintainer', id: 'ops' },
      scope: { entityType: 'config', entityId: 'feature:demo' },
      reason: 'Enabled a flag',
    });
    const store = new ComplianceSnapshotStore({ now: () => START });

    assert.equal(store.captureFromAuditEvent(event), null);
    assert.equal(store.size(), 0);
  });

  it('is idempotent per audit event id and refuses reused ids with new content', () => {
    const { store, capture } = setup();
    const first = capture('evt-fixed');
    const retry = capture('evt-fixed');

    assert.equal(retry.id, first.id);
    assert.equal(retry.integrityHash, first.integrityHash);
    assert.equal(store.size(), 1);

    assert.throws(
      () => capture('evt-fixed', payload({ afterState: { status: 'PAID' } })),
      (err: unknown) => err instanceof SnapshotError && err.code === 'SNAPSHOT_CONFLICT' && err.httpStatus === 409
    );
  });
});

describe('compliance snapshots — schema versioning', () => {
  it('records the schema version and refuses an unsupported one', () => {
    const { store } = setup();
    const snapshot = store.capture({
      eventId: 'evt-v1',
      eventType: 'PAYMENT_VERIFIED',
      entityType: 'invoice',
      entityId: 'inv-1',
      schemaVersion: 1,
      payload: payload({ action: 'PAYMENT_VERIFIED' }),
    });
    assert.equal(snapshot.schemaVersion, 1);

    assert.throws(
      () =>
        store.capture({
          eventId: 'evt-v2',
          eventType: 'PAYMENT_VERIFIED',
          entityType: 'invoice',
          entityId: 'inv-1',
          schemaVersion: 99,
          payload: payload({ action: 'PAYMENT_VERIFIED' }),
        }),
      (err: unknown) => err instanceof SnapshotError && err.code === 'UNSUPPORTED_SNAPSHOT_SCHEMA' && err.httpStatus === 400
    );

    const tampered = { ...snapshot, schemaVersion: 99 };
    const verification = store.verify(tampered);
    assert.equal(verification.valid, false);
    assert.ok(verification.reasons.includes('unsupported_schema_version'));
  });
});

describe('compliance snapshots — integrity and tamper detection', () => {
  it('verifies an untouched snapshot and detects a changed payload', () => {
    const { store, capture } = setup();
    const snapshot = capture();

    assert.deepEqual(store.verify(snapshot), { valid: true, reasons: [] });

    const tampered = {
      ...snapshot,
      payload: { ...snapshot.payload, afterState: { status: 'PAID' } },
    };
    const verification = store.verify(tampered);
    assert.equal(verification.valid, false);
    assert.ok(verification.reasons.includes('payload_hash_mismatch'));
    assert.ok(verification.reasons.includes('integrity_hash_mismatch'));
  });

  it('detects a changed envelope field and a self-consistent forged payload without the key', () => {
    const { store, capture } = setup();
    const snapshot = capture();

    const renamedEntity = { ...snapshot, entityId: 'inv-other' };
    assert.ok(store.verify(renamedEntity).reasons.includes('integrity_hash_mismatch'));

    // Recomputing payloadHash from the tampered payload is not enough: the
    // integrity envelope binds the payload hash as well.
    const forged = {
      ...snapshot,
      payload: { ...snapshot.payload, reason: 'forged' },
      payloadHash: '0'.repeat(64),
    };
    assert.equal(store.verify(forged).valid, false);
  });

  it('verifies the previousHash chain and reports the first broken link', () => {
    const { store, capture } = setup();
    const first = capture();
    const second = capture();
    const third = capture();

    assert.deepEqual(store.verifyChain(), { valid: true, checked: 3 });
    assert.equal(second.previousHash, first.integrityHash);
    assert.equal(third.previousHash, second.integrityHash);

    const tamperedMiddle = {
      ...second,
      payload: { ...second.payload, reason: 'edited later' },
    };
    const failure = store.verifyChain([first, tamperedMiddle, third]);
    assert.equal(failure.valid, false);
    assert.equal(failure.failure?.reason, 'payload_hash');
    assert.equal(failure.failure?.index, 1);

    const reordered = store.verifyChain([second, first, third]);
    assert.equal(reordered.valid, false);
    assert.equal(reordered.failure?.reason, 'previous_hash');
    assert.equal(reordered.failure?.index, 1);
  });

  it('flags a duplicate event id inside a supplied chain', () => {
    const { store, capture } = setup();
    const first = capture();
    const second = capture();
    const result = store.verifyChain([first, second, { ...second }]);
    assert.equal(result.valid, false);
    assert.equal(result.failure?.reason, 'duplicate_event');
  });
});

describe('compliance snapshots — bounded retention', () => {
  it('keeps the retained chain verifiable after eviction', () => {
    const { store, capture } = setup(2);
    capture();
    capture();
    capture();

    assert.equal(store.size(), 2);
    assert.equal(store.verifyChain().valid, true, 'eviction must not look like a broken chain');

    store.clear();
    assert.equal(store.size(), 0);
    assert.deepEqual(store.verifyChain(), { valid: true, checked: 0 });
  });
});
