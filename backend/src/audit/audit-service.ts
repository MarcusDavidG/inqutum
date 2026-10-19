/**
 * Audit-grade Event Trail for Quittance.
 *
 * Provides durable, structured, tamper-evident audit logging for sensitive user
 * and maintainer operations (invoice creation, settlement verification, cancellation,
 * proof export, simulation, maintainer actions) with actor attribution, state transitions,
 * and automated secret sanitization.
 */

import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'node:crypto';
import { sanitizeForLogging } from '../observability/telemetry';

export type AuditAction =
  | 'INVOICE_CREATED'
  | 'INVOICE_CANCELLED'
  | 'PAYMENT_VERIFIED'
  | 'PAYMENT_SIMULATED'
  | 'INVOICE_EXPIRED'
  | 'PROOF_EXPORTED'
  | 'MAINTAINER_ACTION'
  | 'IMPERSONATION_STARTED'
  | 'IMPERSONATION_ENDED'
  | 'IMPERSONATION_EXPIRED'
  | 'IMPERSONATION_ACTION_ALLOWED'
  | 'IMPERSONATION_ACTION_BLOCKED'
  | 'CAPABILITY_ISSUED'
  | 'CONFIG_CHANGED'
  // Operational freeze windows and emergency bypasses (#194)
  | 'FREEZE_WINDOW_CREATED'
  | 'FREEZE_WINDOW_REVOKED'
  | 'FREEZE_BYPASS_ISSUED'
  | 'FREEZE_BYPASS_USED'
  // Settlement disputes (#190)
  | 'DISPUTE_OPENED'
  | 'DISPUTE_INVESTIGATING'
  | 'DISPUTE_RESOLVED'
  | 'DISPUTE_REJECTED'
  | 'DISPUTE_REOPENED'
  | 'DISPUTE_EVIDENCE_ADDED'
  | 'DISPUTE_NOTE_ADDED'
  // Counterparty risk controls (#191)
  | 'COUNTERPARTY_RISK_OVERRIDDEN'
  | 'COUNTERPARTY_RISK_OVERRIDE_CLEARED';

export type AuditActorType = 'seller' | 'payer' | 'system' | 'maintainer';

export interface AuditActor {
  type: AuditActorType;
  id: string; // Stellar public key or 'system'
  ip?: string;
  userAgent?: string;
}

export interface AuditScope {
  entityType: 'invoice' | 'system' | 'stellar' | 'config' | 'dispute' | 'counterparty';
  entityId: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  action: AuditAction;
  actor: AuditActor;
  scope: AuditScope;
  reason?: string;
  beforeState?: Record<string, any> | null;
  afterState?: Record<string, any> | null;
  metadata?: Record<string, any>;
  correlationId?: string;
  previousHash?: string | null;
  hash?: string;
}

export interface AuditFilter {
  action?: AuditAction;
  entityId?: string;
  actorId?: string;
  actorType?: AuditActorType;
  fromTimestamp?: string;
  toTimestamp?: string;
  limit?: number;
  offset?: number;
}

export interface AuditQueryResult {
  events: AuditEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditChainVerification {
  valid: boolean;
  checked: number;
  failure?: { index: number; eventId: string; reason: 'previous_hash' | 'event_hash' };
}

import { canonicalize } from '../security/canonical-serialization';

function stableJson(value: unknown): string {
  return canonicalize(value);
}

export function hashEvent(event: Omit<AuditEvent, 'hash'>): string {
  return createHash('sha256').update(stableJson(event)).digest('hex');
}

/**
 * In-memory bounded audit event repository with O(1) insertion and indexed lookups.
 */
export class MemoryAuditStore {
  private events: AuditEvent[] = [];
  private readonly maxCapacity: number;
  // Secondary indexes for O(1) / O(K) lookups by entity and actor
  private eventsByEntity: Map<string, string[]> = new Map(); // entityId -> eventIds
  private eventsByActor: Map<string, string[]> = new Map(); // actorId -> eventIds
  private eventsById: Map<string, AuditEvent> = new Map();

  constructor(maxCapacity = 5000) {
    this.maxCapacity = maxCapacity;
  }

  recordEvent(input: Omit<AuditEvent, 'id' | 'timestamp'> & { timestamp?: string }): AuditEvent {
    const previousHash = this.events.at(-1)?.hash ?? null;
    const eventWithoutHash: Omit<AuditEvent, 'hash'> = {
      id: uuidv4(),
      timestamp: input.timestamp || new Date().toISOString(),
      action: input.action,
      actor: {
        type: input.actor.type,
        id: input.actor.id,
        ip: input.actor.ip,
        userAgent: input.actor.userAgent,
      },
      scope: {
        entityType: input.scope.entityType,
        entityId: input.scope.entityId,
      },
      reason: input.reason,
      beforeState: input.beforeState ? sanitizeForLogging(input.beforeState) : null,
      afterState: input.afterState ? sanitizeForLogging(input.afterState) : null,
      metadata: input.metadata ? sanitizeForLogging(input.metadata) : undefined,
      correlationId: input.correlationId,
      previousHash,
    };
    const event: AuditEvent = { ...eventWithoutHash, hash: hashEvent(eventWithoutHash) };

    // If buffer capacity exceeded, evict oldest entry from collections and indexes
    if (this.events.length >= this.maxCapacity) {
      const oldest = this.events.shift();
      if (oldest) {
        this.eventsById.delete(oldest.id);
        const entityList = this.eventsByEntity.get(oldest.scope.entityId);
        if (entityList) {
          const idx = entityList.indexOf(oldest.id);
          if (idx !== -1) entityList.splice(idx, 1);
        }
        const actorList = this.eventsByActor.get(oldest.actor.id);
        if (actorList) {
          const idx = actorList.indexOf(oldest.id);
          if (idx !== -1) actorList.splice(idx, 1);
        }
      }
    }

    this.events.push(event);
    this.eventsById.set(event.id, event);

    // Update entity index
    if (!this.eventsByEntity.has(event.scope.entityId)) {
      this.eventsByEntity.set(event.scope.entityId, []);
    }
    this.eventsByEntity.get(event.scope.entityId)!.push(event.id);

    // Update actor index
    if (!this.eventsByActor.has(event.actor.id)) {
      this.eventsByActor.set(event.actor.id, []);
    }
    this.eventsByActor.get(event.actor.id)!.push(event.id);

    return event;
  }

  getEventsByEntity(entityId: string): AuditEvent[] {
    const ids = this.eventsByEntity.get(entityId) || [];
    const list = ids
      .map((id) => this.eventsById.get(id))
      .filter((e): e is AuditEvent => Boolean(e));
    return list.reverse();
  }

  queryEvents(filter: AuditFilter = {}): AuditQueryResult {
    // Reverse events copy so most recent comes first by default
    // Timestamp ties are common when several state transitions are committed
    // in one request. Use the immutable event id as a deterministic tie-breaker
    // so pagination never reshuffles between calls.
    let result = [...this.events].sort((a, b) =>
      b.timestamp.localeCompare(a.timestamp) || a.id.localeCompare(b.id)
    );

    if (filter.action) {
      result = result.filter((e) => e.action === filter.action);
    }
    if (filter.entityId) {
      result = result.filter((e) => e.scope.entityId === filter.entityId);
    }
    if (filter.actorId) {
      result = result.filter((e) => e.actor.id === filter.actorId);
    }
    if (filter.actorType) {
      result = result.filter((e) => e.actor.type === filter.actorType);
    }
    if (filter.fromTimestamp) {
      const fromTime = new Date(filter.fromTimestamp).getTime();
      result = result.filter((e) => new Date(e.timestamp).getTime() >= fromTime);
    }
    if (filter.toTimestamp) {
      const toTime = new Date(filter.toTimestamp).getTime();
      result = result.filter((e) => new Date(e.timestamp).getTime() <= toTime);
    }

    const total = result.length;
    const limit = Math.max(1, Math.min(filter.limit || 50, 500));
    const offset = Math.max(0, filter.offset || 0);
    const paginated = result.slice(offset, offset + limit);

    return {
      events: paginated,
      total,
      limit,
      offset,
    };
  }

  /** Every retained event, oldest first: the input to projection replay (#290). O(E). */
  listChronological(): AuditEvent[] {
    return [...this.events];
  }

  clear(): void {
    this.events = [];
    this.eventsById.clear();
    this.eventsByEntity.clear();
    this.eventsByActor.clear();
  }

  size(): number {
    return this.events.length;
  }

  verifyChain(): AuditChainVerification {
    let previousHash: string | null = null;
    for (let index = 0; index < this.events.length; index++) {
      const event = this.events[index];
      if ((event.previousHash ?? null) !== previousHash) {
        return { valid: false, checked: index + 1, failure: { index, eventId: event.id, reason: 'previous_hash' } };
      }
      const { hash, ...eventWithoutHash } = event;
      if (hash !== hashEvent(eventWithoutHash)) {
        return { valid: false, checked: index + 1, failure: { index, eventId: event.id, reason: 'event_hash' } };
      }
      previousHash = hash ?? null;
    }
    return { valid: true, checked: this.events.length };
  }
}

export const auditStore = new MemoryAuditStore();

/**
 * Format audit events for maintainer export in JSON, NDJSON, or CSV format.
 */
export function exportAuditEvents(events: AuditEvent[], format: 'json' | 'ndjson' | 'csv' = 'json'): string {
  if (format === 'ndjson') {
    return events.map((e) => JSON.stringify(e)).join('\n');
  }

  if (format === 'csv') {
    const headers = [
      'Event ID',
      'Timestamp',
      'Action',
      'Actor Type',
      'Actor ID',
      'Entity Type',
      'Entity ID',
      'Reason',
      'Correlation ID',
    ];
    const escapeCsv = (val: any) => `"${String(val ?? '').replace(/"/g, '""')}"`;

    const rows = events.map((e) => [
      escapeCsv(e.id),
      escapeCsv(e.timestamp),
      escapeCsv(e.action),
      escapeCsv(e.actor.type),
      escapeCsv(e.actor.id),
      escapeCsv(e.scope.entityType),
      escapeCsv(e.scope.entityId),
      escapeCsv(e.reason || ''),
      escapeCsv(e.correlationId || ''),
    ]);

    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  }

  return JSON.stringify(events, null, 2);
}
