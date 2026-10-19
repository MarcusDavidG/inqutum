/**
 * Audited dispute workflow used by the public dispute routes (#190).
 *
 * The state machine lives in `domain/dispute-workflow.ts`; this module owns the
 * side effects: every transition, evidence item and note is written through
 * `recordAuditEvent`, so critical outcomes (opened/resolved/rejected/reopened)
 * also produce the compliance snapshot required by #192.
 */
import {
  DisputeWorkflowService,
  type DisputeAuditRecord,
  type DisputeWorkflowOptions,
} from '../domain/dispute-workflow';
import { recordAuditEvent } from '../audit/record-event';

/** End users are the sellers/participants of a settlement in this domain. */
function auditActorType(actorRole: string): 'maintainer' | 'seller' {
  return actorRole === 'maintainer' ? 'maintainer' : 'seller';
}

export function auditDisputeRecord(record: DisputeAuditRecord): void {
  recordAuditEvent({
    action: record.action,
    actor: {
      type: auditActorType(record.actorRole),
      id: record.actorId,
    },
    scope: {
      entityType: 'dispute',
      entityId: record.disputeId,
    },
    // The shared audit trail is queryable beyond the dispute participants, so
    // free-text detail marked private stays in the dispute record only.
    reason: record.visibility === 'private' ? 'Dispute detail withheld (private)' : record.reason,
    beforeState: record.from ? { status: record.from } : null,
    afterState: { status: record.to },
    metadata: {
      settlementId: record.settlementId,
      actorRole: record.actorRole,
      visibility: record.visibility,
      ...(record.metadata ?? {}),
    },
  });
}

/**
 * Builds a workflow whose audit sink writes to the shared audit trail and
 * snapshot store. A caller-supplied `onAudit` still runs first, so tests and
 * embeddings can observe records without replacing the durable trail.
 */
export function createAuditedDisputeService(options: DisputeWorkflowOptions = {}): DisputeWorkflowService {
  return new DisputeWorkflowService({
    ...options,
    onAudit: (record) => {
      options.onAudit?.(record);
      try {
        auditDisputeRecord(record);
      } catch (error) {
        // The workflow state change already happened. Losing the derived audit
        // record must not roll it back, but it must be visible to operators.
        console.error('Dispute audit write failed:', error);
      }
    },
  });
}

/** Process-wide service shared by both HTTP surfaces. */
export const disputeService = createAuditedDisputeService();
