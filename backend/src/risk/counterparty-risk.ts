/**
 * Configurable counterparty risk scoring (issue #191).
 *
 * This is deliberately separate from `ops/risk-scoring.ts`, which scores
 * maintainer *actions*. This module scores an actor, issuer, organizer or
 * workflow participant from documented, bounded signals.
 *
 * Public output never exposes the score, thresholds, raw signals or factor
 * weights. Maintainers get the full detail through the admin read path.
 * Manual overrides are explicit, reasoned and audited; they win over the
 * computed score until they expire or are cleared.
 */
import { createHash, randomUUID } from 'node:crypto';
import { canonicalize } from '../security/canonical-serialization';
import { recordAuditEvent } from '../audit/record-event';

export const COUNTERPARTY_RISK_POLICY_VERSION = 'counterparty-risk-v1';
export const COUNTERPARTY_RISK_MIN_SIGNALS = 2;

/** Score bands are inclusive lower bounds. Exported for maintainer docs/tests. */
export const COUNTERPARTY_RISK_THRESHOLDS = Object.freeze({
  medium: 21,
  high: 50,
});

export type CounterpartyRiskLevel = 'low' | 'medium' | 'high' | 'unknown';

export interface CounterpartyRiskSignals {
  /** Days since the counterparty first appeared on the platform. */
  accountAgeDays?: number | null;
  /** Settlements completed without a dispute. */
  completedSettlements?: number | null;
  /** Settlements that failed verification or were reversed. */
  failedSettlements?: number | null;
  /** Disputes currently open against the counterparty. */
  openDisputes?: number | null;
  /** Resolved disputes where the counterparty was found at fault. */
  resolvedDisputesAgainst?: number | null;
  /** An explicit external sanctions/list match. */
  sanctionsMatch?: boolean | null;
  /** Named internal flags, e.g. `MANUAL_REVIEW_REQUIRED`. */
  manualFlags?: string[] | null;
}

export interface NormalizedCounterpartyRiskSignals {
  accountAgeDays: number | null;
  completedSettlements: number | null;
  failedSettlements: number | null;
  openDisputes: number | null;
  resolvedDisputesAgainst: number | null;
  sanctionsMatch: boolean | null;
  manualFlags: string[];
}

export interface CounterpartyRiskFactor {
  code:
    | 'ACCOUNT_AGE'
    | 'COMPLETED_SETTLEMENTS'
    | 'FAILED_SETTLEMENTS'
    | 'OPEN_DISPUTES'
    | 'RESOLVED_DISPUTES_AGAINST'
    | 'SANCTIONS_MATCH'
    | 'MANUAL_FLAGS';
  weight: number;
  observed: number | boolean;
  detail: string;
}

export interface CounterpartyRiskOverride {
  id: string;
  subjectId: string;
  level: Exclude<CounterpartyRiskLevel, 'unknown'>;
  reason: string;
  actorId: string;
  createdAt: string;
  expiresAt: string | null;
}

export interface CounterpartyRiskAssessment {
  subjectId: string;
  policyVersion: string;
  /** Null when the available signals are insufficient (level `unknown`). */
  score: number | null;
  level: CounterpartyRiskLevel;
  factors: CounterpartyRiskFactor[];
  signals: NormalizedCounterpartyRiskSignals;
  inputHash: string;
  unknownReason: string | null;
  override: CounterpartyRiskOverride | null;
  requiresManualReview: boolean;
  assessedAt: string;
}

/** Safe, non-threshold-bearing output for user-facing surfaces. */
export interface CounterpartyRiskSummary {
  subjectId: string;
  level: CounterpartyRiskLevel;
  label: string;
  guidance: string;
  requiresManualReview: boolean;
  overridden: boolean;
  assessedAt: string;
}

export class CounterpartyRiskError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly httpStatus = 400,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'CounterpartyRiskError';
  }
}

const LABELS: Record<CounterpartyRiskLevel, string> = {
  low: 'Low risk',
  medium: 'Review recommended',
  high: 'High risk',
  unknown: 'Not enough information',
};

const GUIDANCE: Record<CounterpartyRiskLevel, string> = {
  low: 'Continue with the normal settlement flow.',
  medium: 'Review the counterparty before increasing exposure.',
  high: 'A maintainer must review this counterparty before settlement.',
  unknown: 'Collect more settlement history before relying on this summary.',
};

const REQUIRE_TEXT = (value: unknown, field: string, min: number, max: number): string => {
  const text = typeof value === 'string' ? value.trim() : '';
  if (text.length < min || text.length > max) {
    throw new CounterpartyRiskError(
      'INVALID_COUNTERPARTY_RISK',
      `${field} must be between ${min} and ${max} characters`,
      400,
      { field }
    );
  }
  return text;
};

const normalizeNumber = (value: unknown, field: string): number | null => {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new CounterpartyRiskError(
      'INVALID_COUNTERPARTY_SIGNAL',
      `${field} must be a non-negative number`,
      400,
      { field }
    );
  }
  return Math.floor(value);
};

const normalizeBoolean = (value: unknown, field: string): boolean | null => {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'boolean') {
    throw new CounterpartyRiskError(
      'INVALID_COUNTERPARTY_SIGNAL',
      `${field} must be a boolean`,
      400,
      { field }
    );
  }
  return value;
};

export function normalizeCounterpartyRiskSignals(
  input: CounterpartyRiskSignals
): NormalizedCounterpartyRiskSignals {
  const rawFlags: unknown = input.manualFlags;
  if (rawFlags !== undefined && rawFlags !== null && !Array.isArray(rawFlags)) {
    throw new CounterpartyRiskError(
      'INVALID_COUNTERPARTY_SIGNAL',
      'manualFlags must be an array of strings',
      400,
      { field: 'manualFlags' }
    );
  }
  const manualFlags = rawFlags === undefined || rawFlags === null
    ? []
    : (rawFlags as unknown[]).map((flag) => REQUIRE_TEXT(flag, 'manualFlags', 1, 80));
  return {
    accountAgeDays: normalizeNumber(input.accountAgeDays, 'accountAgeDays'),
    completedSettlements: normalizeNumber(input.completedSettlements, 'completedSettlements'),
    failedSettlements: normalizeNumber(input.failedSettlements, 'failedSettlements'),
    openDisputes: normalizeNumber(input.openDisputes, 'openDisputes'),
    resolvedDisputesAgainst: normalizeNumber(input.resolvedDisputesAgainst, 'resolvedDisputesAgainst'),
    sanctionsMatch: normalizeBoolean(input.sanctionsMatch, 'sanctionsMatch'),
    manualFlags: [...new Set(manualFlags)],
  };
}

function ageFactor(days: number | null): CounterpartyRiskFactor | null {
  if (days === null) return null;
  if (days < 7) {
    return { code: 'ACCOUNT_AGE', weight: 30, observed: days, detail: 'Counterparty is less than 7 days old' };
  }
  if (days < 30) {
    return { code: 'ACCOUNT_AGE', weight: 18, observed: days, detail: 'Counterparty is less than 30 days old' };
  }
  if (days < 180) {
    return { code: 'ACCOUNT_AGE', weight: 8, observed: days, detail: 'Counterparty is less than 180 days old' };
  }
  return { code: 'ACCOUNT_AGE', weight: 0, observed: days, detail: 'Counterparty account is at least 180 days old' };
}

function completedFactor(count: number | null): CounterpartyRiskFactor | null {
  if (count === null) return null;
  if (count >= 20) {
    return { code: 'COMPLETED_SETTLEMENTS', weight: -20, observed: count, detail: 'At least 20 completed settlements' };
  }
  if (count >= 5) {
    return { code: 'COMPLETED_SETTLEMENTS', weight: -10, observed: count, detail: 'At least 5 completed settlements' };
  }
  if (count >= 1) {
    return { code: 'COMPLETED_SETTLEMENTS', weight: 0, observed: count, detail: 'Some completed settlement history' };
  }
  return { code: 'COMPLETED_SETTLEMENTS', weight: 5, observed: count, detail: 'No completed settlements yet' };
}

function failedFactor(count: number | null): CounterpartyRiskFactor | null {
  if (count === null) return null;
  if (count === 0) {
    return { code: 'FAILED_SETTLEMENTS', weight: 0, observed: count, detail: 'No failed settlements' };
  }
  if (count <= 2) {
    return { code: 'FAILED_SETTLEMENTS', weight: 10, observed: count, detail: 'One or two failed settlements' };
  }
  if (count <= 5) {
    return { code: 'FAILED_SETTLEMENTS', weight: 25, observed: count, detail: 'Three to five failed settlements' };
  }
  return { code: 'FAILED_SETTLEMENTS', weight: 40, observed: count, detail: 'More than five failed settlements' };
}

function openDisputeFactor(count: number | null): CounterpartyRiskFactor | null {
  if (count === null) return null;
  if (count === 0) {
    return { code: 'OPEN_DISPUTES', weight: 0, observed: count, detail: 'No open disputes' };
  }
  if (count === 1) {
    return { code: 'OPEN_DISPUTES', weight: 10, observed: count, detail: 'One open dispute' };
  }
  if (count === 2) {
    return { code: 'OPEN_DISPUTES', weight: 20, observed: count, detail: 'Two open disputes' };
  }
  return { code: 'OPEN_DISPUTES', weight: 30, observed: count, detail: 'Three or more open disputes' };
}

function resolvedAgainstFactor(count: number | null): CounterpartyRiskFactor | null {
  if (count === null) return null;
  return {
    code: 'RESOLVED_DISPUTES_AGAINST',
    weight: count === 0 ? 0 : 20,
    observed: count,
    detail: count === 0 ? 'No resolved disputes against the counterparty' : 'At least one dispute was resolved against the counterparty',
  };
}

function factorSignature(level: CounterpartyRiskLevel, score: number): CounterpartyRiskLevel {
  if (score >= COUNTERPARTY_RISK_THRESHOLDS.high) return 'high';
  if (score >= COUNTERPARTY_RISK_THRESHOLDS.medium) return 'medium';
  return level;
}

export function buildCounterpartyRiskAssessment(
  subjectId: string,
  signals: NormalizedCounterpartyRiskSignals,
  options: { now?: () => Date; override?: CounterpartyRiskOverride | null } = {}
): CounterpartyRiskAssessment {
  const inputHash = createHash('sha256').update(canonicalize(signals)).digest('hex');
  const provided = [
    signals.accountAgeDays,
    signals.completedSettlements,
    signals.failedSettlements,
    signals.openDisputes,
    signals.resolvedDisputesAgainst,
  ].filter((value) => value !== null).length
    + (signals.sanctionsMatch === null ? 0 : 1)
    + (signals.manualFlags.length > 0 ? 1 : 0);

  const factors = [
    ageFactor(signals.accountAgeDays),
    completedFactor(signals.completedSettlements),
    failedFactor(signals.failedSettlements),
    openDisputeFactor(signals.openDisputes),
    resolvedAgainstFactor(signals.resolvedDisputesAgainst),
  ].filter((factor): factor is CounterpartyRiskFactor => factor !== null);

  if (signals.sanctionsMatch === true) {
    factors.push({
      code: 'SANCTIONS_MATCH',
      weight: 60,
      observed: true,
      detail: 'The counterparty matched an explicit sanctions signal',
    });
  }
  if (signals.manualFlags.length > 0) {
    factors.push({
      code: 'MANUAL_FLAGS',
      weight: Math.min(30, signals.manualFlags.length * 15),
      observed: signals.manualFlags.length,
      detail: `${signals.manualFlags.length} internal manual flag(s) are set`,
    });
  }

  const now = options.now ?? (() => new Date());
  const assessedAt = now().toISOString();
  const unknownReason = signals.sanctionsMatch !== true && provided < COUNTERPARTY_RISK_MIN_SIGNALS
    ? `At least ${COUNTERPARTY_RISK_MIN_SIGNALS} documented signals are required for a score`
    : null;

  let score: number | null = null;
  let level: CounterpartyRiskLevel = 'unknown';
  if (!unknownReason) {
    score = Math.max(0, Math.min(100, factors.reduce((sum, factor) => sum + factor.weight, 0)));
    level = factorSignature('low', score);
  }
  if (signals.sanctionsMatch === true) {
    // A sanctions match is decisive and always at least high risk.
    score = Math.max(score ?? 0, COUNTERPARTY_RISK_THRESHOLDS.high);
    level = signals.manualFlags.length > 0 ? factorSignature(level, score) : 'high';
  }

  const activeOverride = options.override ?? null;
  if (activeOverride) {
    level = activeOverride.level;
  }

  return {
    subjectId,
    policyVersion: COUNTERPARTY_RISK_POLICY_VERSION,
    score,
    level,
    factors: unknownReason ? [] : factors,
    signals,
    inputHash,
    unknownReason,
    override: activeOverride,
    requiresManualReview: level === 'high' || level === 'unknown',
    assessedAt,
  };
}

export function publicCounterpartyRiskSummary(
  assessment: CounterpartyRiskAssessment
): CounterpartyRiskSummary {
  return {
    subjectId: assessment.subjectId,
    level: assessment.level,
    label: LABELS[assessment.level],
    guidance: GUIDANCE[assessment.level],
    requiresManualReview: assessment.requiresManualReview,
    overridden: assessment.override !== null,
    assessedAt: assessment.assessedAt,
  };
}

export interface CounterpartyRiskAuditRecord {
  action: 'COUNTERPARTY_RISK_OVERRIDDEN' | 'COUNTERPARTY_RISK_OVERRIDE_CLEARED';
  subjectId: string;
  actorId: string;
  reason: string;
  level?: CounterpartyRiskLevel;
  metadata?: Record<string, unknown>;
}

export interface CounterpartyRiskServiceOptions {
  now?: () => Date;
  onAudit?: (record: CounterpartyRiskAuditRecord) => void;
  maxSubjects?: number;
}

export class CounterpartyRiskService {
  private readonly now: () => Date;
  private readonly onAudit?: (record: CounterpartyRiskAuditRecord) => void;
  private readonly maxSubjects: number;
  private readonly assessments = new Map<string, CounterpartyRiskAssessment>();
  private readonly overrides = new Map<string, CounterpartyRiskOverride>();

  constructor(options: CounterpartyRiskServiceOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.onAudit = options.onAudit;
    this.maxSubjects = Math.max(1, options.maxSubjects ?? 10_000);
  }

  evaluate(subjectId: string, input: CounterpartyRiskSignals = {}): CounterpartyRiskAssessment {
    const id = REQUIRE_TEXT(subjectId, 'subjectId', 1, 200);
    const normalized = normalizeCounterpartyRiskSignals(input);
    // Store the computed assessment, not the overridden view: an override set
    // later (or cleared) must take effect without re-evaluating.
    const assessment = buildCounterpartyRiskAssessment(id, normalized, { now: this.now });
    this.assessments.set(id, assessment);
    if (this.assessments.size > this.maxSubjects) {
      const oldest = this.assessments.keys().next().value as string | undefined;
      if (oldest) this.assessments.delete(oldest);
    }
    return this.withOverride(assessment);
  }

  getLatest(subjectId: string): CounterpartyRiskAssessment | null {
    const id = String(subjectId ?? '').trim();
    const assessment = this.assessments.get(id);
    return assessment ? this.withOverride(assessment) : null;
  }

  publicSummary(subjectId: string): CounterpartyRiskSummary {
    const latest = this.getLatest(subjectId);
    if (latest) return publicCounterpartyRiskSummary(latest);
    const unknown = buildCounterpartyRiskAssessment(
      String(subjectId ?? '').trim(),
      normalizeCounterpartyRiskSignals({}),
      { now: this.now }
    );
    // Overrides are keyed by subject and do not require an assessment first,
    // so apply one here too rather than exposing a contradictory `unknown`.
    return publicCounterpartyRiskSummary(this.withOverride(unknown));
  }

  setOverride(input: {
    subjectId: string;
    level: Exclude<CounterpartyRiskLevel, 'unknown'>;
    reason: string;
    actorId: string;
    expiresAt?: string | Date | null;
  }): CounterpartyRiskOverride {
    const subjectId = REQUIRE_TEXT(input.subjectId, 'subjectId', 1, 200);
    if (!['low', 'medium', 'high'].includes(input.level)) {
      throw new CounterpartyRiskError('INVALID_COUNTERPARTY_RISK', 'override level must be low, medium or high', 400);
    }
    const reason = REQUIRE_TEXT(input.reason, 'reason', 10, 1_000);
    const actorId = REQUIRE_TEXT(input.actorId, 'actorId', 1, 200);
    const now = this.now();
    let expiresAt: string | null = null;
    if (input.expiresAt !== undefined && input.expiresAt !== null) {
      const date = input.expiresAt instanceof Date ? new Date(input.expiresAt.getTime()) : new Date(input.expiresAt);
      if (!Number.isFinite(date.getTime()) || date.getTime() <= now.getTime()) {
        throw new CounterpartyRiskError('INVALID_COUNTERPARTY_RISK', 'expiresAt must be in the future', 400);
      }
      expiresAt = date.toISOString();
    }
    const override: CounterpartyRiskOverride = {
      id: randomUUID(),
      subjectId,
      level: input.level,
      reason,
      actorId,
      createdAt: now.toISOString(),
      expiresAt,
    };
    this.overrides.set(subjectId, override);
    this.emit({
      action: 'COUNTERPARTY_RISK_OVERRIDDEN',
      subjectId,
      actorId,
      reason,
      level: override.level,
      metadata: { overrideId: override.id, expiresAt },
    });
    return { ...override };
  }

  clearOverride(subjectId: string, actorId: string, reason: string): CounterpartyRiskOverride | null {
    const id = String(subjectId ?? '').trim();
    const existing = this.overrides.get(id) ?? null;
    if (!existing) return null;
    const actor = REQUIRE_TEXT(actorId, 'actorId', 1, 200);
    const why = REQUIRE_TEXT(reason, 'reason', 3, 500);
    this.overrides.delete(id);
    this.emit({
      action: 'COUNTERPARTY_RISK_OVERRIDE_CLEARED',
      subjectId: id,
      actorId: actor,
      reason: why,
      metadata: { overrideId: existing.id },
    });
    return { ...existing };
  }

  getOverride(subjectId: string): CounterpartyRiskOverride | null {
    const override = this.activeOverride(String(subjectId ?? '').trim());
    return override ? { ...override } : null;
  }

  listOverrides(includeExpired = false): CounterpartyRiskOverride[] {
    const now = this.now();
    return [...this.overrides.values()]
      .filter((override) => includeExpired || !override.expiresAt || new Date(override.expiresAt).getTime() > now.getTime())
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .map((override) => ({ ...override }));
  }

  /** Applies the current manual override to a stored computed assessment. */
  private withOverride(assessment: CounterpartyRiskAssessment): CounterpartyRiskAssessment {
    const override = this.activeOverride(assessment.subjectId);
    if (!override) {
      return clone({ ...assessment, override: null, requiresManualReview: assessment.level === 'high' || assessment.level === 'unknown' });
    }
    return clone({
      ...assessment,
      level: override.level,
      override,
      // An override can only be low, medium or high; unknown is not reachable.
      requiresManualReview: override.level === 'high',
    });
  }

  private activeOverride(subjectId: string): CounterpartyRiskOverride | null {
    const override = this.overrides.get(subjectId);
    if (!override) return null;
    // Expired overrides stay in the map so `listOverrides(true)` can still show
    // them for audit; they simply no longer affect scoring.
    if (override.expiresAt && new Date(override.expiresAt).getTime() <= this.now().getTime()) {
      return null;
    }
    return { ...override };
  }

  private emit(record: CounterpartyRiskAuditRecord): void {
    try {
      this.onAudit?.(record);
    } catch {
      // Audit sinks must not undo an explicit override that already happened.
    }
  }
}

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/**
 * Process-wide scorer shared by the public summary and admin detail routes.
 * Overrides are audited because they deliberately override a computed score.
 */
export const counterpartyRiskService = new CounterpartyRiskService({
  onAudit: (record) => {
    try {
      recordAuditEvent({
        action: record.action,
        actor: { type: 'maintainer', id: record.actorId },
        scope: { entityType: 'counterparty', entityId: record.subjectId },
        reason: record.reason,
        metadata: {
          ...(record.metadata ?? {}),
          ...(record.level ? { level: record.level } : {}),
        },
      });
    } catch (error) {
      console.error('Counterparty risk audit write failed:', error);
    }
  },
});
