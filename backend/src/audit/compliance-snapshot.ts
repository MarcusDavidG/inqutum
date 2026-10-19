/**
 * Immutable compliance snapshots for critical lifecycle events (issue #192).
 *
 * The audit trail answers "what happened?". A compliance snapshot answers
 * "what did the record and the rules look like at that exact moment?".
 *
 * Each snapshot stores the canonical event payload, the schema version used to
 * interpret it, a hash of the payload and an integrity hash over the snapshot
 * envelope. Snapshots are hash-chained, so an edit is detectable from the
 * snapshot itself and a deleted or reordered snapshot is detectable from the
 * chain.
 *
 * Capture is idempotent per audit event id: retries return the original
 * snapshot instead of creating a second one. Reusing an event id with different
 * content is refused (`SNAPSHOT_CONFLICT`).
 *
 * Retention is in-memory and bounded, matching the rest of the operational
 * audit surface. The read API is mounted on the admin-only ops router.
 */
import { createHash } from 'node:crypto';
import { canonicalize } from '../security/canonical-serialization';
import type { AuditAction, AuditEvent, AuditScope } from './audit-service';

export const COMPLIANCE_SNAPSHOT_SCHEMA_VERSION = 1;
export const SUPPORTED_COMPLIANCE_SNAPSHOT_SCHEMA_VERSIONS: readonly number[] = [1];

/**
 * Lifecycle events that change a settlement, a dispute outcome, or the
 * operational rules under which an action was taken.
 */
export const CRITICAL_LIFECYCLE_EVENTS: ReadonlySet<AuditAction> = new Set<AuditAction>([
  'INVOICE_CREATED',
  'INVOICE_CANCELLED',
  'INVOICE_EXPIRED',
  'PAYMENT_VERIFIED',
  'PAYMENT_SIMULATED',
  'DISPUTE_OPENED',
  'DISPUTE_RESOLVED',
  'DISPUTE_REJECTED',
  'DISPUTE_REOPENED',
  'FREEZE_WINDOW_CREATED',
  'FREEZE_WINDOW_REVOKED',
  'FREEZE_BYPASS_ISSUED',
  'FREEZE_BYPASS_USED',
]);

export interface ComplianceSnapshotPayload {
  action: AuditAction;
  actor: AuditEvent['actor'];
  scope: AuditScope;
  reason: string | null;
  beforeState: Record<string, unknown> | null;
  afterState: Record<string, unknown> | null;
  metadata: Record<string, unknown> | null;
  correlationId: string | null;
}

export interface ComplianceSnapshot {
  id: string;
  /** Audit event id. Also the idempotency key for snapshot creation. */
  eventId: string;
  eventType: AuditAction;
  schemaVersion: number;
  entityType: AuditScope['entityType'];
  entityId: string;
  capturedAt: string;
  payload: ComplianceSnapshotPayload;
  payloadHash: string;
  previousHash: string | null;
  integrityHash: string;
}

export interface CaptureComplianceSnapshotInput {
  eventId: string;
  eventType: AuditAction;
  entityType: AuditScope['entityType'];
  entityId: string;
  capturedAt?: string | Date;
  payload: ComplianceSnapshotPayload;
  schemaVersion?: number;
}

export interface SnapshotVerification {
  valid: boolean;
  reasons: string[];
}

export interface SnapshotChainVerification {
  valid: boolean;
  checked: number;
  failure?: {
    index: number;
    id: string;
    reason: 'payload_hash' | 'integrity_hash' | 'previous_hash' | 'schema_version' | 'duplicate_event';
  };
}

export class SnapshotError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly httpStatus = 409,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'SnapshotError';
  }
}

const sha256 = (value: unknown): string => createHash('sha256').update(canonicalize(value)).digest('hex');

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

function payloadHashOf(payload: ComplianceSnapshotPayload): string {
  return sha256(payload);
}

function integrityHashOf(snapshot: Omit<ComplianceSnapshot, 'integrityHash'>): string {
  return sha256({
    id: snapshot.id,
    eventId: snapshot.eventId,
    eventType: snapshot.eventType,
    schemaVersion: snapshot.schemaVersion,
    entityType: snapshot.entityType,
    entityId: snapshot.entityId,
    capturedAt: snapshot.capturedAt,
    payload: snapshot.payload,
    payloadHash: snapshot.payloadHash,
    previousHash: snapshot.previousHash,
  });
}

export class ComplianceSnapshotStore {
  private readonly snapshots: ComplianceSnapshot[] = [];
  private readonly byId = new Map<string, ComplianceSnapshot>();
  private readonly byEventId = new Map<string, ComplianceSnapshot>();
  private readonly now: () => Date;
  private readonly maxSnapshots: number;
  /** Integrity hash of the most recently evicted snapshot, so the retained chain still verifies. */
  private chainBaseHash: string | null = null;

  constructor(options: { now?: () => Date; maxSnapshots?: number } = {}) {
    this.now = options.now ?? (() => new Date());
    this.maxSnapshots = Math.max(1, options.maxSnapshots ?? 10_000);
  }

  /**
   * Captures a critical audit event. Non-critical events return null and are
   * not stored; they remain available through the audit trail.
   */
  captureFromAuditEvent(event: AuditEvent): ComplianceSnapshot | null {
    if (!CRITICAL_LIFECYCLE_EVENTS.has(event.action)) return null;
    return this.capture({
      eventId: event.id,
      eventType: event.action,
      entityType: event.scope.entityType,
      entityId: event.scope.entityId,
      capturedAt: event.timestamp,
      payload: {
        action: event.action,
        actor: clone(event.actor),
        scope: clone(event.scope),
        reason: event.reason ?? null,
        beforeState: event.beforeState ? clone(event.beforeState) : null,
        afterState: event.afterState ? clone(event.afterState) : null,
        metadata: event.metadata ? clone(event.metadata) : null,
        correlationId: event.correlationId ?? null,
      },
    });
  }

  capture(input: CaptureComplianceSnapshotInput): ComplianceSnapshot {
    const eventId = String(input.eventId ?? '').trim();
    if (!eventId) throw new SnapshotError('INVALID_SNAPSHOT', 'eventId is required', 400);
    const entityId = String(input.entityId ?? '').trim();
    if (!entityId) throw new SnapshotError('INVALID_SNAPSHOT', 'entityId is required', 400);

    const schemaVersion = input.schemaVersion ?? COMPLIANCE_SNAPSHOT_SCHEMA_VERSION;
    if (!SUPPORTED_COMPLIANCE_SNAPSHOT_SCHEMA_VERSIONS.includes(schemaVersion)) {
      throw new SnapshotError(
        'UNSUPPORTED_SNAPSHOT_SCHEMA',
        `Snapshot schema version ${schemaVersion} is not supported`,
        400,
        { supported: [...SUPPORTED_COMPLIANCE_SNAPSHOT_SCHEMA_VERSIONS] }
      );
    }

    const payload = clone(input.payload);
    const payloadHash = payloadHashOf(payload);
    const existing = this.byEventId.get(eventId);
    if (existing) {
      if (
        existing.payloadHash !== payloadHash ||
        existing.eventType !== input.eventType ||
        existing.entityType !== input.entityType ||
        existing.entityId !== entityId ||
        existing.schemaVersion !== schemaVersion
      ) {
        throw new SnapshotError(
          'SNAPSHOT_CONFLICT',
          `Snapshot for event ${eventId} already exists with different content`,
          409,
          { snapshotId: existing.id }
        );
      }
      return clone(existing);
    }

    const capturedAt = input.capturedAt instanceof Date
      ? input.capturedAt.toISOString()
      : input.capturedAt ?? this.now().toISOString();
    const previousHash = this.snapshots.at(-1)?.integrityHash ?? null;
    const withoutHash: Omit<ComplianceSnapshot, 'integrityHash'> = {
      // The snapshot has its own id; the audit event id stays the idempotency key.
      id: `snap_${eventId}`,
      eventId,
      eventType: input.eventType,
      schemaVersion,
      entityType: input.entityType,
      entityId,
      capturedAt,
      payload,
      payloadHash,
      previousHash,
    };
    const snapshot: ComplianceSnapshot = {
      ...withoutHash,
      integrityHash: integrityHashOf(withoutHash),
    };

    this.snapshots.push(snapshot);
    this.byId.set(snapshot.id, snapshot);
    this.byEventId.set(snapshot.eventId, snapshot);
    if (this.snapshots.length > this.maxSnapshots) {
      const evicted = this.snapshots.shift();
      if (evicted) {
        this.byId.delete(evicted.id);
        this.byEventId.delete(evicted.eventId);
        this.chainBaseHash = evicted.integrityHash;
      }
    }
    return clone(snapshot);
  }

  get(id: string): ComplianceSnapshot | null {
    const snapshot = this.byId.get(id);
    return snapshot ? clone(snapshot) : null;
  }

  getByEventId(eventId: string): ComplianceSnapshot | null {
    const snapshot = this.byEventId.get(eventId);
    return snapshot ? clone(snapshot) : null;
  }

  list(filter: {
    eventType?: string;
    entityId?: string;
    entityType?: string;
    limit?: number;
    offset?: number;
  } = {}): { snapshots: ComplianceSnapshot[]; total: number; limit: number; offset: number } {
    let result = [...this.snapshots].reverse();
    if (filter.eventType) result = result.filter((snapshot) => snapshot.eventType === filter.eventType);
    if (filter.entityId) result = result.filter((snapshot) => snapshot.entityId === filter.entityId);
    if (filter.entityType) result = result.filter((snapshot) => snapshot.entityType === filter.entityType);
    const total = result.length;
    const requestedLimit = Number.isFinite(filter.limit) ? filter.limit! : 50;
    const requestedOffset = Number.isFinite(filter.offset) ? filter.offset! : 0;
    const limit = Math.min(Math.max(1, Math.floor(requestedLimit)), 500);
    const offset = Math.max(0, Math.floor(requestedOffset));
    return { snapshots: result.slice(offset, offset + limit).map(clone), total, limit, offset };
  }

  size(): number {
    return this.snapshots.length;
  }

  clear(): void {
    this.snapshots.length = 0;
    this.byId.clear();
    this.byEventId.clear();
    this.chainBaseHash = null;
  }

  /** Recomputes the payload and envelope hashes for one snapshot. */
  verify(snapshot: ComplianceSnapshot): SnapshotVerification {
    const reasons: string[] = [];
    if (!SUPPORTED_COMPLIANCE_SNAPSHOT_SCHEMA_VERSIONS.includes(snapshot.schemaVersion)) {
      reasons.push('unsupported_schema_version');
    }
    if (payloadHashOf(snapshot.payload) !== snapshot.payloadHash) reasons.push('payload_hash_mismatch');
    const { integrityHash: _ignored, ...withoutHash } = snapshot;
    if (integrityHashOf(withoutHash) !== snapshot.integrityHash) reasons.push('integrity_hash_mismatch');
    return { valid: reasons.length === 0, reasons };
  }

  /** Verifies every hash and the previousHash link between adjacent snapshots. */
  verifyChain(snapshots: ComplianceSnapshot[] = this.snapshots): SnapshotChainVerification {
    // For the full store, continue from the last evicted hash so bounded
    // retention does not look like tampering. A caller-supplied slice uses its
    // own first link as the baseline.
    let previous: string | null =
      snapshots === this.snapshots ? this.chainBaseHash : snapshots[0]?.previousHash ?? null;
    const seenEvents = new Set<string>();
    for (let index = 0; index < snapshots.length; index += 1) {
      const snapshot = snapshots[index]!;
      if (seenEvents.has(snapshot.eventId)) {
        return { valid: false, checked: index + 1, failure: { index, id: snapshot.id, reason: 'duplicate_event' } };
      }
      seenEvents.add(snapshot.eventId);

      if (!SUPPORTED_COMPLIANCE_SNAPSHOT_SCHEMA_VERSIONS.includes(snapshot.schemaVersion)) {
        return { valid: false, checked: index + 1, failure: { index, id: snapshot.id, reason: 'schema_version' } };
      }
      if (payloadHashOf(snapshot.payload) !== snapshot.payloadHash) {
        return { valid: false, checked: index + 1, failure: { index, id: snapshot.id, reason: 'payload_hash' } };
      }
      const { integrityHash: _ignored, ...withoutHash } = snapshot;
      if (integrityHashOf(withoutHash) !== snapshot.integrityHash) {
        return { valid: false, checked: index + 1, failure: { index, id: snapshot.id, reason: 'integrity_hash' } };
      }
      if ((snapshot.previousHash ?? null) !== previous) {
        return { valid: false, checked: index + 1, failure: { index, id: snapshot.id, reason: 'previous_hash' } };
      }
      previous = snapshot.integrityHash;
    }
    return { valid: true, checked: snapshots.length };
  }
}

/** Process-wide snapshot store used by the audit write path and read API. */
export const complianceSnapshotStore = new ComplianceSnapshotStore();
