/**
 * Single write path for audit events that also captures the compliance
 * snapshot for critical lifecycle events (#192).
 *
 * Snapshot failures are logged and do not roll back the audit event: the trail
 * remains usable even if the derived snapshot projection is unavailable.
 */
import { auditStore, type AuditEvent } from './audit-service';
import { complianceSnapshotStore } from './compliance-snapshot';

export function recordAuditEvent(
  input: Omit<AuditEvent, 'id' | 'timestamp'> & { timestamp?: string }
): AuditEvent {
  const event = auditStore.recordEvent(input);
  try {
    complianceSnapshotStore.captureFromAuditEvent(event);
  } catch (error) {
    console.error('Compliance snapshot capture failed:', error);
  }
  return event;
}
