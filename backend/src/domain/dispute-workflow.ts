/**
 * Deterministic settlement dispute workflow (issue #190).
 *
 * Disputes move through a small, explicit state machine:
 *
 *   OPEN ──► INVESTIGATING ──► RESOLVED ──► REOPENED ──► INVESTIGATING
 *     │             │                              ▲
 *     └─────────────┴──► REJECTED ─────────────────┘
 *
 * Only a maintainer may investigate, resolve or reject. The original opener may
 * reopen a resolved/rejected dispute, and a maintainer may reopen it too.
 *
 * Evidence and notes carry a `public` or `private` visibility. The safe read
 * path filters private entries and private resolution notes; only the
 * maintainer view returns them. Opening the same settlement twice is refused:
 * a closed dispute must be reopened instead, so its evidence stays in one place.
 */
import { createHash, randomUUID } from 'node:crypto';
import { canonicalize } from '../security/canonical-serialization';

export const DISPUTE_STATES = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'REJECTED', 'REOPENED'] as const;
export type DisputeState = (typeof DISPUTE_STATES)[number];

export type DisputeAction = 'investigate' | 'resolve' | 'reject' | 'reopen';

export const DISPUTE_TRANSITIONS: Readonly<Record<DisputeState, readonly DisputeState[]>> = Object.freeze({
  OPEN: Object.freeze(['INVESTIGATING', 'REJECTED']),
  INVESTIGATING: Object.freeze(['RESOLVED', 'REJECTED']),
  RESOLVED: Object.freeze(['REOPENED']),
  REJECTED: Object.freeze(['REOPENED']),
  REOPENED: Object.freeze(['INVESTIGATING', 'REJECTED']),
});

const ACTION_TARGET: Record<DisputeAction, DisputeState> = {
  investigate: 'INVESTIGATING',
  resolve: 'RESOLVED',
  reject: 'REJECTED',
  reopen: 'REOPENED',
};

const AUDIT_ACTION: Record<DisputeAction, DisputeAuditAction> = {
  investigate: 'DISPUTE_INVESTIGATING',
  resolve: 'DISPUTE_RESOLVED',
  reject: 'DISPUTE_REJECTED',
  reopen: 'DISPUTE_REOPENED',
};

export type DisputeVisibility = 'public' | 'private';
export type DisputeEvidenceKind = 'transaction' | 'document' | 'reference' | 'other';

export interface DisputeEvidence {
  id: string;
  label: string;
  kind: DisputeEvidenceKind;
  /** A tx hash, URL, document id or other stable reference. Never the file body. */
  reference: string;
  visibility: DisputeVisibility;
  contentHash: string;
  addedBy: string;
  addedAt: string;
}

export interface DisputeNote {
  id: string;
  body: string;
  visibility: DisputeVisibility;
  author: string;
  createdAt: string;
}

export interface DisputeTransition {
  id: string;
  action: 'open' | DisputeAction;
  from: DisputeState | null;
  to: DisputeState;
  actorId: string;
  actorRole: string;
  reason: string;
  visibility: DisputeVisibility;
  occurredAt: string;
}

export interface DisputeResolution {
  outcome: 'RESOLVED' | 'REJECTED';
  summary: string;
  actorId: string;
  decidedAt: string;
  visibility: DisputeVisibility;
}

export interface DisputeRecord {
  id: string;
  settlementId: string;
  invoiceId: string | null;
  openedBy: string;
  subject: string | null;
  reason: string;
  status: DisputeState;
  evidence: DisputeEvidence[];
  notes: DisputeNote[];
  transitions: DisputeTransition[];
  resolution: DisputeResolution | null;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface DisputeViewer {
  role?: string;
  subject?: string;
  wallet?: string;
}

export interface OpenDisputeInput {
  settlementId: string;
  openedBy: string;
  openedByRole?: string;
  subject?: string;
  invoiceId?: string;
  reason: string;
  evidence?: NewDisputeEvidence[];
  notes?: NewDisputeNote[];
}

export interface NewDisputeEvidence {
  label: string;
  kind?: DisputeEvidenceKind;
  reference: string;
  visibility?: DisputeVisibility;
}

export interface NewDisputeNote {
  body: string;
  visibility?: DisputeVisibility;
}

export interface TransitionDisputeInput {
  action: DisputeAction;
  actorId: string;
  actorRole: string;
  reason: string;
  /** Required for resolve/reject; made available to the appropriate viewer. */
  summary?: string;
  visibility?: DisputeVisibility;
}

export type DisputeAuditAction =
  | 'DISPUTE_OPENED'
  | 'DISPUTE_INVESTIGATING'
  | 'DISPUTE_RESOLVED'
  | 'DISPUTE_REJECTED'
  | 'DISPUTE_REOPENED'
  | 'DISPUTE_EVIDENCE_ADDED'
  | 'DISPUTE_NOTE_ADDED';

export interface DisputeAuditRecord {
  action: DisputeAuditAction;
  disputeId: string;
  settlementId: string;
  actorId: string;
  actorRole: string;
  reason: string;
  from: DisputeState | null;
  to: DisputeState;
  visibility: DisputeVisibility;
  metadata?: Record<string, unknown>;
}

export class DisputeWorkflowError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly httpStatus = 409,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'DisputeWorkflowError';
  }
}

const requireText = (value: unknown, field: string, min: number, max: number): string => {
  const text = typeof value === 'string' ? value.trim() : '';
  if (text.length < min || text.length > max) {
    throw new DisputeWorkflowError(
      'INVALID_DISPUTE',
      `${field} must be between ${min} and ${max} characters`,
      400,
      { field }
    );
  }
  return text;
};

const visibilityOf = (value: unknown): DisputeVisibility => {
  if (value === undefined) return 'public';
  if (value === 'public' || value === 'private') return value;
  throw new DisputeWorkflowError('INVALID_DISPUTE', 'visibility must be public or private', 400);
};

const evidenceKindOf = (value: unknown): DisputeEvidenceKind => {
  if (value === undefined) return 'reference';
  if (value === 'transaction' || value === 'document' || value === 'reference' || value === 'other') return value;
  throw new DisputeWorkflowError('INVALID_DISPUTE', 'kind must be transaction, document, reference or other', 400);
};

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

export interface DisputeWorkflowOptions {
  now?: () => Date;
  onAudit?: (record: DisputeAuditRecord) => void;
  maxEvidencePerDispute?: number;
  maxNotesPerDispute?: number;
}

export class DisputeWorkflowService {
  private readonly disputes = new Map<string, DisputeRecord>();
  private readonly bySettlement = new Map<string, string>();
  private readonly now: () => Date;
  private readonly onAudit?: (record: DisputeAuditRecord) => void;
  private readonly maxEvidence: number;
  private readonly maxNotes: number;

  constructor(options: DisputeWorkflowOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.onAudit = options.onAudit;
    this.maxEvidence = Math.max(1, options.maxEvidencePerDispute ?? 100);
    this.maxNotes = Math.max(1, options.maxNotesPerDispute ?? 200);
  }

  open(input: OpenDisputeInput): DisputeRecord {
    const settlementId = requireText(input.settlementId, 'settlementId', 1, 200);
    const openedBy = requireText(input.openedBy, 'openedBy', 1, 200);
    const reason = requireText(input.reason, 'reason', 10, 2_000);
    const existingId = this.bySettlement.get(settlementId);
    if (existingId) {
      throw new DisputeWorkflowError(
        'DUPLICATE_DISPUTE',
        `Settlement ${settlementId} already has dispute ${existingId}; reopen it instead of opening a duplicate`,
        409,
        { disputeId: existingId }
      );
    }

    const now = this.now().toISOString();
    const id = randomUUID();
    const record: DisputeRecord = {
      id,
      settlementId,
      invoiceId: input.invoiceId ? requireText(input.invoiceId, 'invoiceId', 1, 200) : null,
      openedBy,
      subject: input.subject ? requireText(input.subject, 'subject', 1, 200) : null,
      reason,
      status: 'OPEN',
      evidence: [],
      notes: [],
      transitions: [
        {
          id: randomUUID(),
          action: 'open',
          from: null,
          to: 'OPEN',
          actorId: openedBy,
          actorRole: input.openedByRole ?? 'user',
          reason,
          visibility: 'public',
          occurredAt: now,
        },
      ],
      resolution: null,
      createdAt: now,
      updatedAt: now,
      version: 1,
    };

    // Validate the initial evidence/notes before publishing the dispute. A
    // rejected bundle therefore leaves neither a half-open record nor a
    // settlement mapping that blocks the corrected retry.
    for (const evidence of input.evidence ?? []) this.addEvidenceInternal(record, evidence, openedBy);
    for (const note of input.notes ?? []) this.addNoteInternal(record, note, openedBy);

    this.disputes.set(id, record);
    this.bySettlement.set(settlementId, id);

    const actorRole = record.transitions[0]!.actorRole;
    this.emit({
      action: 'DISPUTE_OPENED',
      disputeId: id,
      settlementId,
      actorId: openedBy,
      actorRole,
      reason,
      from: null,
      to: 'OPEN',
      visibility: 'public',
    });
    // Initial entries are part of the opening submission, so they are emitted
    // after the OPENED record rather than before the dispute exists.
    for (const evidence of record.evidence) {
      this.emit({
        action: 'DISPUTE_EVIDENCE_ADDED',
        disputeId: id,
        settlementId,
        actorId: openedBy,
        actorRole,
        // Do not copy the label into the audit trail: it may belong to private evidence.
        reason: 'Dispute evidence added',
        from: 'OPEN',
        to: 'OPEN',
        visibility: evidence.visibility,
        metadata: { evidenceId: evidence.id, kind: evidence.kind, contentHash: evidence.contentHash },
      });
    }
    for (const note of record.notes) {
      this.emit({
        action: 'DISPUTE_NOTE_ADDED',
        disputeId: id,
        settlementId,
        actorId: openedBy,
        actorRole,
        reason: 'Dispute note added',
        from: 'OPEN',
        to: 'OPEN',
        visibility: note.visibility,
        metadata: { noteId: note.id },
      });
    }
    return clone(record);
  }

  get(id: string, viewer: DisputeViewer = {}): DisputeRecord | null {
    const record = this.disputes.get(id);
    return record ? this.project(record, viewer) : null;
  }

  list(
    filter: {
      status?: string;
      settlementId?: string;
      openedBy?: string;
      /** Matches either the opener or the named subject. */
      participant?: string;
      limit?: number;
      offset?: number;
    } = {},
    viewer: DisputeViewer = {}
  ): { disputes: DisputeRecord[]; total: number; limit: number; offset: number } {
    let result = [...this.disputes.values()];
    if (filter.status) {
      const status = String(filter.status).toUpperCase();
      if (!(DISPUTE_STATES as readonly string[]).includes(status)) {
        throw new DisputeWorkflowError('INVALID_DISPUTE_FILTER', `status must be one of ${DISPUTE_STATES.join(', ')}`, 400);
      }
      result = result.filter((record) => record.status === status);
    }
    if (filter.settlementId) result = result.filter((record) => record.settlementId === filter.settlementId);
    if (filter.openedBy) result = result.filter((record) => record.openedBy === filter.openedBy);
    if (filter.participant) {
      result = result.filter(
        (record) => record.openedBy === filter.participant || record.subject === filter.participant
      );
    }
    result.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.id.localeCompare(b.id));
    const total = result.length;
    const requestedLimit = Number.isFinite(filter.limit) ? filter.limit! : 50;
    const requestedOffset = Number.isFinite(filter.offset) ? filter.offset! : 0;
    const limit = Math.min(Math.max(1, Math.floor(requestedLimit)), 200);
    const offset = Math.max(0, Math.floor(requestedOffset));
    return {
      disputes: result.slice(offset, offset + limit).map((record) => this.project(record, viewer)),
      total,
      limit,
      offset,
    };
  }

  addEvidence(id: string, input: NewDisputeEvidence, actorId: string, actorRole = 'user'): DisputeEvidence {
    const record = this.requireOpenForEdits(id);
    const author = requireText(actorId, 'actorId', 1, 200);
    const evidence = this.addEvidenceInternal(record, input, author);
    this.emit({
      action: 'DISPUTE_EVIDENCE_ADDED',
      disputeId: record.id,
      settlementId: record.settlementId,
      actorId: author,
      actorRole,
      // Labels are kept out of audit metadata for the same reason as above.
      reason: 'Dispute evidence added',
      from: record.status,
      to: record.status,
      visibility: evidence.visibility,
      metadata: { evidenceId: evidence.id, kind: evidence.kind, contentHash: evidence.contentHash },
    });
    return clone(evidence);
  }

  addNote(id: string, input: NewDisputeNote, actorId: string, actorRole = 'user'): DisputeNote {
    const record = this.requireOpenForEdits(id);
    const author = requireText(actorId, 'actorId', 1, 200);
    const note = this.addNoteInternal(record, input, author);
    this.emit({
      action: 'DISPUTE_NOTE_ADDED',
      disputeId: record.id,
      settlementId: record.settlementId,
      actorId: author,
      actorRole,
      reason: 'Dispute note added',
      from: record.status,
      to: record.status,
      visibility: note.visibility,
      metadata: { noteId: note.id },
    });
    return clone(note);
  }

  transition(id: string, input: TransitionDisputeInput): DisputeRecord {
    const record = this.disputes.get(id);
    if (!record) throw new DisputeWorkflowError('DISPUTE_NOT_FOUND', 'Dispute not found', 404);

    const target = ACTION_TARGET[input.action];
    if (!target) {
      throw new DisputeWorkflowError(
        'INVALID_DISPUTE_ACTION',
        `action must be one of ${Object.keys(ACTION_TARGET).join(', ')}`,
        400
      );
    }

    const actorId = requireText(input.actorId, 'actorId', 1, 200);
    const actorRole = String(input.actorRole ?? 'user');
    if (['investigate', 'resolve', 'reject'].includes(input.action) && actorRole !== 'maintainer') {
      throw new DisputeWorkflowError('DISPUTE_FORBIDDEN', 'Only a maintainer may investigate, resolve or reject a dispute', 403);
    }
    if (input.action === 'reopen' && actorRole !== 'maintainer' && actorId !== record.openedBy) {
      throw new DisputeWorkflowError('DISPUTE_FORBIDDEN', 'Only the opener or a maintainer may reopen this dispute', 403);
    }

    const allowed = DISPUTE_TRANSITIONS[record.status];
    if (!allowed.includes(target)) {
      throw new DisputeWorkflowError(
        'INVALID_DISPUTE_TRANSITION',
        `Cannot move dispute from ${record.status} to ${target}`,
        409,
        { from: record.status, to: target, allowed: [...allowed] }
      );
    }

    const reason = requireText(input.reason, 'reason', 3, 2_000);
    const visibility = visibilityOf(input.visibility);
    const summary = input.action === 'resolve' || input.action === 'reject'
      ? requireText(input.summary, 'summary', 10, 2_000)
      : undefined;
    const now = this.now().toISOString();
    const from = record.status;
    record.status = target;
    record.updatedAt = now;
    record.version += 1;
    record.transitions.push({
      id: randomUUID(),
      action: input.action,
      from,
      to: target,
      actorId,
      actorRole,
      reason,
      visibility,
      occurredAt: now,
    });
    if (summary !== undefined) {
      record.resolution = {
        outcome: target as 'RESOLVED' | 'REJECTED',
        summary,
        actorId,
        decidedAt: now,
        visibility,
      };
    }

    this.emit({
      action: AUDIT_ACTION[input.action],
      disputeId: record.id,
      settlementId: record.settlementId,
      actorId,
      actorRole,
      reason,
      from,
      to: target,
      visibility,
      metadata: summary === undefined ? undefined : { summaryVisibility: visibility },
    });
    return clone(record);
  }

  private requireOpenForEdits(id: string): DisputeRecord {
    const record = this.disputes.get(id);
    if (!record) throw new DisputeWorkflowError('DISPUTE_NOT_FOUND', 'Dispute not found', 404);
    if (record.status === 'RESOLVED' || record.status === 'REJECTED') {
      throw new DisputeWorkflowError('DISPUTE_CLOSED', 'Reopen the dispute before adding evidence or notes', 409);
    }
    return record;
  }

  private addEvidenceInternal(record: DisputeRecord, input: NewDisputeEvidence, actorId: string): DisputeEvidence {
    if (record.evidence.length >= this.maxEvidence) {
      throw new DisputeWorkflowError('DISPUTE_EVIDENCE_LIMIT', 'This dispute has reached its evidence limit', 409);
    }
    const label = requireText(input.label, 'label', 1, 200);
    const reference = requireText(input.reference, 'reference', 1, 2_000);
    const kind = evidenceKindOf(input.kind);
    const visibility = visibilityOf(input.visibility);
    const evidence: DisputeEvidence = {
      id: randomUUID(),
      label,
      kind,
      reference,
      visibility,
      contentHash: createHash('sha256').update(canonicalize({ label, kind, reference })).digest('hex'),
      addedBy: actorId,
      addedAt: this.now().toISOString(),
    };
    record.evidence.push(evidence);
    record.updatedAt = evidence.addedAt;
    record.version += 1;
    return evidence;
  }

  private addNoteInternal(record: DisputeRecord, input: NewDisputeNote, actorId: string): DisputeNote {
    if (record.notes.length >= this.maxNotes) {
      throw new DisputeWorkflowError('DISPUTE_NOTE_LIMIT', 'This dispute has reached its note limit', 409);
    }
    const body = requireText(input.body, 'body', 1, 5_000);
    const note: DisputeNote = {
      id: randomUUID(),
      body,
      visibility: visibilityOf(input.visibility),
      author: actorId,
      createdAt: this.now().toISOString(),
    };
    record.notes.push(note);
    record.updatedAt = note.createdAt;
    record.version += 1;
    return note;
  }

  /**
   * Filters private evidence, notes, transitions and resolution summaries.
   * Private entries stay visible to their author and to maintainers; everyone
   * else sees only the public record.
   */
  private project(record: DisputeRecord, viewer: DisputeViewer): DisputeRecord {
    if (viewer.role === 'maintainer') return clone(record);
    const viewerIds = new Set(
      [viewer.subject, viewer.wallet].filter((value): value is string => Boolean(value))
    );
    const mine = (actorId: string) => viewerIds.has(actorId);
    const projected = clone(record);
    projected.evidence = projected.evidence.filter(
      (evidence) => evidence.visibility === 'public' || mine(evidence.addedBy)
    );
    projected.notes = projected.notes.filter((note) => note.visibility === 'public' || mine(note.author));
    projected.transitions = projected.transitions.filter(
      (transition) => transition.visibility !== 'private' || mine(transition.actorId)
    );
    if (projected.resolution && projected.resolution.visibility !== 'public' && !mine(projected.resolution.actorId)) {
      projected.resolution = null;
    }
    return projected;
  }

  private emit(record: DisputeAuditRecord): void {
    try {
      this.onAudit?.(record);
    } catch {
      // Audit sinks must not undo a state change that already happened.
    }
  }
}
