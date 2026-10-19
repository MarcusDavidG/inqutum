/**
 * Maintainer action approval flow with signed intent receipts.
 *
 * High-impact maintainer actions go through three explicit steps:
 *
 *   1. declare intent  -> what, on which target, why, with which params.
 *                         The intent is HMAC-signed and binds a hash of params.
 *   2. approve         -> required for actions marked `requiresSecondApprover`;
 *                         the approver must be a different maintainer.
 *   3. execute         -> caller must echo the confirmation phrase. The intent
 *                         is single use (pending/approved -> executing is atomic
 *                         in-process), and must not be expired.
 *
 * Every terminal outcome (succeeded, failed, rejected, expired) produces a signed
 * receipt. Receipts are hash-chained (each carries the previous receipt hash) so
 * deletion or edits are detectable with `verifyReceiptChain`. Receipts can be
 * reviewed after completion or failure; a failed action keeps the redacted error.
 *
 * Every intent is risk-scored at declaration (see risk-scoring.ts). The signed
 * assessment travels on the intent and its receipts: a `high` score demands a
 * second approver, a `critical` score refuses the intent with a signed receipt.
 *
 * See docs/MAINTAINER-APPROVALS.md.
 */
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'crypto';
import { redactSecrets } from '../domain/partial-failures';
import { RiskScorer, type RiskAssessment } from './risk-scoring';

export interface HighImpactActionSpec {
  action: string;
  description: string;
  requiresSecondApprover: boolean;
  /** How long an intent stays executable. */
  ttlMs: number;
}

export const HIGH_IMPACT_ACTIONS: Record<string, HighImpactActionSpec> = {
  'job.requeue_dead': {
    action: 'job.requeue_dead',
    description: 'Requeue a dead-lettered job (may resend notifications / re-run verification)',
    requiresSecondApprover: false,
    ttlMs: 15 * 60_000,
  },
  'invoice.cancel': {
    action: 'invoice.cancel',
    description: 'Cancel a seller invoice on their behalf',
    requiresSecondApprover: true,
    ttlMs: 30 * 60_000,
  },
};

export type IntentStatus = 'pending' | 'approved' | 'executing' | 'succeeded' | 'failed' | 'rejected' | 'expired';

export interface MaintainerIntent {
  id: string;
  action: string;
  target: string;
  reason: string;
  requestedBy: string;
  approvedBy: string | null;
  paramsHash: string;
  params: Record<string, unknown>;
  confirmationPhrase: string;
  createdAt: string;
  expiresAt: string;
  status: IntentStatus;
  /** Declaration-time assessment, bound into the signature. Null when scoring is disabled. */
  risk: RiskAssessment | null;
  signature: string;
}

export type ReceiptOutcome = 'succeeded' | 'failed' | 'rejected' | 'expired';

export interface IntentReceipt {
  id: string;
  intentId: string;
  action: string;
  target: string;
  reason: string;
  requestedBy: string;
  approvedBy: string | null;
  executedBy: string | null;
  paramsHash: string;
  outcome: ReceiptOutcome;
  /** Redacted, JSON-safe summary of the result; never full payloads. */
  result: unknown;
  error: string | null;
  intentSignature: string;
  risk: RiskAssessment | null;
  issuedAt: string;
  prevReceiptHash: string | null;
  signature: string;
}

export class ApprovalError extends Error {
  constructor(public readonly code: string, message: string, public readonly httpStatus = 409) {
    super(message);
    this.name = 'ApprovalError';
  }
}

import { canonicalize } from '../security/canonical-serialization';

/** Deterministic RFC 8785 JSON so the same params always hash the same. */
export function canonicalJson(value: unknown): string {
  return canonicalize(value);
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

export type ActionExecutor = (intent: MaintainerIntent) => Promise<unknown>;

/**
 * The part of a freeze-window service the approval flow needs. Kept structural
 * so the approval service does not depend on the freeze implementation.
 */
export interface ActionFreezeGuard {
  assertAllowed(input: {
    action: string;
    target: string;
    actor: string;
    bypassId?: string;
    consume?: boolean;
  }): unknown;
}

export interface ApprovalServiceOptions {
  secret: string;
  now?: () => Date;
  actions?: Record<string, HighImpactActionSpec>;
  /** Called with every receipt (wire to the audit store). Failures are swallowed. */
  onReceipt?: (receipt: IntentReceipt) => void;
  /** Risk scorer for declared intents. Defaults to one on the same clock; `null` disables scoring. */
  risk?: RiskScorer | null;
  /**
   * Optional operational freeze guard (#194). When an action is frozen, intent
   * declaration and execution throw the guard's error unless a valid emergency
   * bypass is supplied.
   */
  freeze?: ActionFreezeGuard | null;
}

export class MaintainerApprovalService {
  private readonly intents = new Map<string, MaintainerIntent>();
  private readonly receipts: IntentReceipt[] = [];
  private readonly executors = new Map<string, ActionExecutor>();
  private readonly now: () => Date;
  private readonly actions: Record<string, HighImpactActionSpec>;
  private readonly risk: RiskScorer | null;
  private readonly freeze: ActionFreezeGuard | null;

  constructor(private readonly options: ApprovalServiceOptions) {
    if (!options.secret || options.secret.length < 16) {
      throw new Error('MaintainerApprovalService requires a secret of at least 16 characters');
    }
    this.now = options.now ?? (() => new Date());
    this.actions = options.actions ?? HIGH_IMPACT_ACTIONS;
    this.risk = options.risk === undefined ? new RiskScorer({ now: this.now }) : options.risk;
    this.freeze = options.freeze ?? null;
  }

  registerExecutor(action: string, executor: ActionExecutor): void {
    if (!this.actions[action]) throw new Error(`Unknown high-impact action ${action}`);
    this.executors.set(action, executor);
  }

  isHighImpact(action: string): boolean {
    return Boolean(this.actions[action]);
  }

  private sign(payload: string): string {
    return createHmac('sha256', this.options.secret).update(payload).digest('hex');
  }

  private intentPayload(i: MaintainerIntent): string {
    return canonicalJson({
      id: i.id, action: i.action, target: i.target, reason: i.reason,
      requestedBy: i.requestedBy, paramsHash: i.paramsHash, createdAt: i.createdAt, expiresAt: i.expiresAt,
      risk: i.risk,
    });
  }

  private receiptPayload(r: Omit<IntentReceipt, 'signature'>): string {
    return canonicalJson(r);
  }

  private safeEqual(a: string, b: string): boolean {
    const x = Buffer.from(a);
    const y = Buffer.from(b);
    return x.length === y.length && timingSafeEqual(x, y);
  }

  verifyIntent(intent: MaintainerIntent): boolean {
    return (
      this.safeEqual(intent.signature, this.sign(this.intentPayload(intent))) &&
      this.safeEqual(intent.paramsHash, sha256(canonicalJson(intent.params)))
    );
  }

  verifyReceipt(receipt: IntentReceipt): boolean {
    const { signature, ...rest } = receipt;
    return this.safeEqual(signature, this.sign(this.receiptPayload(rest)));
  }

  /** Every receipt valid and each links to its predecessor. Returns the first broken index or -1. */
  verifyReceiptChain(receipts: IntentReceipt[] = this.receipts): number {
    let prev: string | null = null;
    for (let i = 0; i < receipts.length; i++) {
      const r = receipts[i];
      if (!this.verifyReceipt(r) || r.prevReceiptHash !== prev) return i;
      prev = sha256(canonicalJson(r));
    }
    return -1;
  }

  requestIntent(input: {
    action: string;
    target: string;
    reason: string;
    requestedBy: string;
    params?: Record<string, unknown>;
    /** Emergency freeze bypass (#194). Validated here, consumed on execution. */
    bypassId?: string;
  }): MaintainerIntent {
    const spec = this.actions[input.action];
    if (!spec) throw new ApprovalError('UNKNOWN_ACTION', `Unknown high-impact action ${input.action}`, 400);
    const requestedBy = String(input.requestedBy ?? '').trim();
    const target = String(input.target ?? '').trim();
    const reason = String(input.reason ?? '').trim();
    if (!requestedBy) throw new ApprovalError('REQUESTER_REQUIRED', 'requestedBy is required', 400);
    if (!target) throw new ApprovalError('TARGET_REQUIRED', 'target is required', 400);
    if (reason.length < 10) throw new ApprovalError('REASON_REQUIRED', 'reason must explain the action (min 10 chars)', 400);

    this.freeze?.assertAllowed({
      action: spec.action,
      target,
      actor: requestedBy,
      bypassId: input.bypassId,
      consume: false,
    });

    const params = input.params ?? {};
    const created = this.now();
    // Score against prior history, then record this attempt so a refused retry still counts.
    const risk = this.risk?.assess({ action: spec.action, requiresSecondApprover: spec.requiresSecondApprover, requestedBy, target }) ?? null;
    this.risk?.recordIntent(requestedBy, target);
    const intent: MaintainerIntent = {
      id: randomUUID(),
      action: spec.action,
      target,
      reason,
      requestedBy,
      approvedBy: null,
      params,
      paramsHash: sha256(canonicalJson(params)),
      confirmationPhrase: `${spec.action} ${target}`,
      createdAt: created.toISOString(),
      expiresAt: new Date(created.getTime() + spec.ttlMs).toISOString(),
      status: 'pending',
      risk,
      signature: '',
    };
    intent.signature = this.sign(this.intentPayload(intent));
    this.intents.set(intent.id, intent);

    if (risk?.blocked) {
      intent.status = 'rejected';
      const codes = risk.factors.map((f) => f.code).join(', ');
      const receipt = this.issueReceipt(intent, 'rejected', null, null, `Refused by risk policy ${risk.policyVersion}: score ${risk.score} (${codes})`);
      throw new ApprovalError(
        'RISK_BLOCKED',
        `Risk score ${risk.score} (${risk.level}) exceeds policy: ${codes}. Wait ${Math.round(risk.windowMs / 60_000)} min without new attempts and declare again. Receipt ${receipt.id}`,
        403
      );
    }
    return { ...intent };
  }

  private load(id: string): MaintainerIntent {
    const intent = this.intents.get(id);
    if (!intent) throw new ApprovalError('INTENT_NOT_FOUND', 'Intent not found', 404);
    if (!this.verifyIntent(intent)) throw new ApprovalError('INTENT_TAMPERED', 'Intent signature does not verify', 409);
    if ((intent.status === 'pending' || intent.status === 'approved') && this.now() >= new Date(intent.expiresAt)) {
      intent.status = 'expired';
      this.issueReceipt(intent, 'expired', null, null, 'Intent expired before execution');
      throw new ApprovalError('INTENT_EXPIRED', 'Intent expired; declare a new one', 410);
    }
    return intent;
  }

  approve(id: string, approverId: string): MaintainerIntent {
    const intent = this.load(id);
    if (intent.status !== 'pending') throw new ApprovalError('INVALID_STATE', `Intent is ${intent.status}`);
    const approver = String(approverId ?? '').trim();
    if (!approver) throw new ApprovalError('APPROVER_REQUIRED', 'approverId is required', 400);
    if (approver === intent.requestedBy) {
      throw new ApprovalError('SELF_APPROVAL', 'A different maintainer must approve this action', 403);
    }
    intent.approvedBy = approver;
    intent.status = 'approved';
    return { ...intent };
  }

  reject(id: string, maintainerId: string, why: string): IntentReceipt {
    const intent = this.load(id);
    if (intent.status !== 'pending' && intent.status !== 'approved') {
      throw new ApprovalError('INVALID_STATE', `Intent is ${intent.status}`);
    }
    intent.status = 'rejected';
    return this.issueReceipt(intent, 'rejected', maintainerId, null, redactSecrets(String(why || 'rejected')));
  }

  async execute(id: string, input: {
    executedBy: string;
    confirmation: string;
    params?: Record<string, unknown>;
    /** Emergency freeze bypass (#194), consumed when the action executes. */
    bypassId?: string;
  }): Promise<IntentReceipt> {
    const intent = this.load(id);
    const spec = this.actions[intent.action];
    const needsSecondApprover = spec.requiresSecondApprover || intent.risk?.requiresSecondApprover === true;
    const ready = needsSecondApprover ? intent.status === 'approved' : intent.status === 'pending' || intent.status === 'approved';
    if (!ready) {
      throw new ApprovalError(
        intent.status === 'pending' ? 'APPROVAL_REQUIRED' : 'INVALID_STATE',
        intent.status === 'pending' ? 'This action needs a second maintainer approval' : `Intent is ${intent.status}`
      );
    }
    if (String(input.confirmation ?? '') !== intent.confirmationPhrase) {
      throw new ApprovalError('CONFIRMATION_MISMATCH', `Type "${intent.confirmationPhrase}" to confirm`, 400);
    }
    if (input.params !== undefined && sha256(canonicalJson(input.params)) !== intent.paramsHash) {
      throw new ApprovalError('PARAMS_CHANGED', 'Params differ from the declared intent; declare a new intent', 409);
    }
    this.freeze?.assertAllowed({
      action: intent.action,
      target: intent.target,
      actor: String(input.executedBy ?? '').trim(),
      bypassId: input.bypassId,
      consume: true,
    });
    const executor = this.executors.get(intent.action);
    if (!executor) throw new ApprovalError('NO_EXECUTOR', `No executor registered for ${intent.action}`, 501);

    // Single use: flip before awaiting so a concurrent execute sees 'executing'.
    intent.status = 'executing';
    try {
      const result = await executor({ ...intent });
      intent.status = 'succeeded';
      return this.issueReceipt(intent, 'succeeded', input.executedBy, result ?? null, null);
    } catch (err) {
      intent.status = 'failed';
      const message = err instanceof Error ? err.message : String(err);
      return this.issueReceipt(intent, 'failed', input.executedBy, null, redactSecrets(message).slice(0, 500));
    }
  }

  private issueReceipt(
    intent: MaintainerIntent,
    outcome: ReceiptOutcome,
    executedBy: string | null,
    result: unknown,
    error: string | null
  ): IntentReceipt {
    const last = this.receipts.at(-1);
    const body: Omit<IntentReceipt, 'signature'> = {
      id: randomUUID(),
      intentId: intent.id,
      action: intent.action,
      target: intent.target,
      reason: intent.reason,
      requestedBy: intent.requestedBy,
      approvedBy: intent.approvedBy,
      executedBy,
      paramsHash: intent.paramsHash,
      outcome,
      result: JSON.parse(JSON.stringify(result ?? null)),
      error,
      intentSignature: intent.signature,
      risk: intent.risk,
      issuedAt: this.now().toISOString(),
      prevReceiptHash: last ? sha256(canonicalJson(last)) : null,
    };
    const receipt: IntentReceipt = { ...body, signature: this.sign(this.receiptPayload(body)) };
    this.receipts.push(receipt);
    if (outcome === 'failed' || outcome === 'rejected') this.risk?.recordFailure(intent.requestedBy);
    try {
      this.options.onReceipt?.(receipt);
    } catch {
      // Audit sink failures must not undo an action that already happened.
    }
    return receipt;
  }

  getIntent(id: string): MaintainerIntent | null {
    const i = this.intents.get(id);
    return i ? { ...i } : null;
  }

  listIntents(filter: { status?: IntentStatus } = {}): MaintainerIntent[] {
    return [...this.intents.values()].filter((i) => !filter.status || i.status === filter.status).map((i) => ({ ...i }));
  }

  listReceipts(filter: { outcome?: ReceiptOutcome; intentId?: string; target?: string } = {}): IntentReceipt[] {
    return this.receipts.filter(
      (r) =>
        (!filter.outcome || r.outcome === filter.outcome) &&
        (!filter.intentId || r.intentId === filter.intentId) &&
        (!filter.target || r.target === filter.target)
    );
  }

  getReceipt(id: string): IntentReceipt | null {
    return this.receipts.find((r) => r.id === id) ?? null;
  }
}
