import { Router } from 'express';
import type { JobStore } from '../jobs/job-types';
import type { InvoiceStorage } from '../storage/invoice-storage';
import { metrics } from '../observability/telemetry';
import { buildOpsHealthReport } from '../ops/ops-health';
import { requireAdmin } from './jobs.routes';
import {
  ImpersonationService,
  impersonationService,
  IMPERSONATION_PERMISSIONS,
  type ImpersonationPermission,
} from '../audit/impersonation';
import { stellarPublicKeySchema } from '../utils/validation';
import { simulatePolicyChange } from '../domain/policy-simulation';
import { evaluatePolicyDryRun, parsePolicyDryRunRequest, PolicyDryRunError } from '../domain/policy-dry-run';
import { loadPolicy } from '../domain/policy';
import { CapabilityError, CapabilityTokenService, capabilityServiceFromEnv } from '../security/capability-tokens';
import { AdminConfigError, AdminConfigService, adminConfig } from '../config/admin-config';
import { staleProjectionService } from '../ops/stale-projections.service';
import { defaultSearchIndex } from '../services/search-index.service';
import { SyntheticJourneyMonitor } from '../ops/synthetic-journey-monitor';
import { verifySnapshotRestore } from '../db/snapshot-restore-verification';
import {
  DEPENDENCY_MATRIX,
  runDependencyChecks,
  validateMatrix,
  type DependencyId,
  type DependencyProbe,
} from '../ops/dependency-degradation';
import {
  PartialFailureRetryCoordinator,
  buildDashboard,
  inspectJobFailure,
  parseDashboardFilter,
} from '../ops/partial-failure-dashboard';
import { jobsToOperations } from '../domain/partial-failures';
import { ApprovalError, MaintainerApprovalService, type IntentStatus, type ReceiptOutcome } from '../ops/maintainer-approval';
import { auditStore } from '../audit/audit-service';
import { recordAuditEvent } from '../audit/record-event';
import {
  FreezeWindowError,
  FreezeWindowService,
  type FreezeWindowState,
} from '../ops/freeze-window';
import {
  ComplianceSnapshotStore,
  SnapshotError,
  complianceSnapshotStore,
} from '../audit/compliance-snapshot';
import {
  CounterpartyRiskError,
  CounterpartyRiskService,
  counterpartyRiskService,
} from '../risk/counterparty-risk';
import {
  NothingToRollBackError,
  ProjectionReplayService,
  ReplayInProgressError,
  UnknownProjectorVersionError,
} from '../ops/projection-replay';
import {
  ResumableRepairService,
  RepairJobNotFoundError,
  type RepairPhase,
} from '../ops/resumable-repair.service';
import { pool } from '../config/database';

export interface OpsRouterOptions {
  storage: InvoiceStorage;
  jobs?: JobStore;
  /** Same bearer token as /jobs (JOBS_ADMIN_TOKEN). When empty, the route is disabled (403). */
  adminToken?: string;
  /** Overridable for tests. */
  impersonation?: ImpersonationService;
  /** Health probes per external dependency. Missing probes report `unknown`. */
  dependencyProbes?: Partial<Record<DependencyId, DependencyProbe>>;
  /**
   * Approval service for high-impact actions. Defaults to one keyed by
   * MAINTAINER_INTENT_SECRET; when that is unset the intent routes return 403.
   */
  approvals?: MaintainerApprovalService | null;
  /**
   * Capability tokens for sensitive actions. Defaults to one keyed by
   * CAPABILITY_TOKEN_SECRET; when that is unset the capability routes return 403.
   */
  capabilities?: CapabilityTokenService | null;
  /** Audited runtime configuration. Defaults to the process instance. */
  adminConfig?: AdminConfigService;
  /** Search-index event replay (#290). Defaults to the live index and audit trail. */
  replay?: ProjectionReplayService;
  /** Resumable record repair service for orphaned and inconsistent records. */
  repairService?: ResumableRepairService;
  /** Operational freeze windows (#194). Defaults to the process-wide service. */
  freeze?: FreezeWindowService;
  /** Counterparty risk service (#191). Defaults to the process-wide scorer. */
  risk?: CounterpartyRiskService;
  /** Compliance snapshot store (#192). Defaults to the process-wide store. */
  snapshots?: ComplianceSnapshotStore;
}

const defaultFreezeService = new FreezeWindowService({
  onAudit: (record) => {
    try {
      recordAuditEvent({
        action: record.action,
        actor: { type: 'maintainer', id: record.actorId },
        scope: { entityType: 'system', entityId: record.windowId },
        reason: record.reason,
        metadata: {
          ...(record.metadata ?? {}),
          windowId: record.windowId,
          ...(record.bypassId ? { bypassId: record.bypassId } : {}),
        },
      });
    } catch (error) {
      console.error('Freeze audit write failed:', error);
    }
  },
});

function defaultApprovals(freeze: FreezeWindowService): MaintainerApprovalService | null {
  const secret = process.env.MAINTAINER_INTENT_SECRET;
  if (!secret || secret.length < 16) return null;
  return new MaintainerApprovalService({
    secret,
    freeze,
    onReceipt: (r) =>
      auditStore.recordEvent({
        action: 'MAINTAINER_ACTION',
        actor: { type: 'maintainer', id: r.executedBy ?? r.requestedBy },
        scope: { entityType: 'system', entityId: r.target },
        reason: `${r.action}: ${r.outcome}`,
        metadata: {
          receiptId: r.id,
          intentId: r.intentId,
          outcome: r.outcome,
          approvedBy: r.approvedBy,
          riskScore: r.risk?.score ?? null,
          riskLevel: r.risk?.level ?? null,
          riskFactors: r.risk?.factors.map((f) => f.code) ?? [],
        },
      }),
  });
}

const durationOf = (v: unknown): number | undefined => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : undefined;
};

/**
 * Mount under `/api`.
 *   GET  /ops/health  maintainer summary of unresolved failures and drift
 *
 *   POST /ops/impersonation           start a scoped, time-limited session
 *   POST /ops/impersonation/end       close a session
 *   GET  /ops/impersonation           list sessions / read the banner state
 */
export function createOpsRouter(options: OpsRouterOptions): Router {
  const router = Router();
  const impersonation = options.impersonation ?? impersonationService;
  const admin = requireAdmin(options.adminToken);
  const freeze = options.freeze ?? defaultFreezeService;
  const approvals = options.approvals === undefined ? defaultApprovals(freeze) : options.approvals;
  const retries = options.jobs ? new PartialFailureRetryCoordinator(options.jobs) : null;
  const capabilities = options.capabilities === undefined ? capabilityServiceFromEnv() : options.capabilities;
  const config = options.adminConfig ?? adminConfig;
  const risk = options.risk ?? counterpartyRiskService;
  const snapshots = options.snapshots ?? complianceSnapshotStore;
  const replay =
    options.replay ??
    new ProjectionReplayService({
      storage: options.storage,
      index: defaultSearchIndex,
      events: () => auditStore.listChronological(),
    });
  const repairService = options.repairService ?? new ResumableRepairService({ db: pool });

  if (approvals && options.jobs) {
    const jobs = options.jobs;
    approvals.registerExecutor('job.requeue_dead', async (intent) => {
      const job = await jobs.requeueDead(intent.target, new Date());
      if (!job) throw new Error('Job is not dead-lettered (state changed since intent was declared)');
      return { jobId: job.id, status: job.status };
    });
  }
  if (approvals) {
    approvals.registerExecutor('invoice.cancel', async (intent) => {
      const expected = typeof intent.params.expectedVersion === 'number' ? intent.params.expectedVersion : undefined;
      const invoice = await options.storage.cancelInvoice(intent.target, expected);
      return { invoiceId: invoice.id, status: invoice.status, version: invoice.version ?? null };
    });
  }

  const fail = (res: any, req: any, status: number, code: string, error: string) =>
    res.status(status).json({ success: false, code, error, correlationId: req.correlationId });

  // -- External dependency degradation matrix --------------------------------

  router.get('/ops/dependencies/matrix', admin, (req, res) => {
    res.json({
      success: true,
      data: { matrix: DEPENDENCY_MATRIX.map((d) => ({ ...d, failureModes: d.failureModes.map((f) => ({ code: f.code, description: f.description })) })), problems: validateMatrix() },
      correlationId: req.correlationId,
    });
  });

  router.get('/ops/dependencies', admin, async (req, res, next) => {
    try {
      const report = await runDependencyChecks(options.dependencyProbes ?? {});
      res.status(report.overall === 'down' ? 503 : 200).json({ success: report.overall !== 'down', data: report, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  // -- Partial-failure dashboard ---------------------------------------------

  router.get('/ops/partial-failures', admin, async (req, res, next) => {
    try {
      const { filter, error } = parseDashboardFilter(req.query as Record<string, unknown>);
      if (error) return fail(res, req, 400, 'INVALID_FILTER', error);
      const jobs = options.jobs ? (await options.jobs.list({ limit: 1000 })).jobs : [];
      res.json({ success: true, data: buildDashboard(jobsToOperations(jobs), filter), correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  router.get('/ops/partial-failures/:id', admin, async (req, res, next) => {
    try {
      const job = options.jobs ? await options.jobs.get(req.params.id) : null;
      if (!job) return fail(res, req, 404, 'NOT_FOUND', 'Operation not found');
      res.json({ success: true, data: inspectJobFailure(job), correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  router.post('/ops/partial-failures/:id/retry', admin, async (req, res, next) => {
    try {
      if (!retries) return fail(res, req, 503, 'JOBS_UNAVAILABLE', 'Job store not configured');
      const key = req.header('idempotency-key') ?? (typeof req.body?.idempotencyKey === 'string' ? req.body.idempotencyKey : undefined);
      const outcome = await retries.retry(req.params.id, key);
      if (outcome.status === 'rejected') {
        const status = outcome.code === 'NOT_FOUND' ? 404 : outcome.code === 'USER_ACTION_REQUIRED' ? 422 : 409;
        return fail(res, req, status, outcome.code, outcome.message);
      }
      if (outcome.status === 'requeued') {
        auditStore.recordEvent({
          action: 'MAINTAINER_ACTION',
          actor: { type: 'maintainer', id: 'ops-admin' },
          scope: { entityType: 'system', entityId: outcome.job.id },
          reason: 'Partial failure retried from dashboard',
          metadata: { jobType: outcome.job.type, idempotencyKey: key ?? null },
          correlationId: req.correlationId,
        });
      }
      res.json({ success: true, data: { status: outcome.status, job: outcome.job }, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  // -- Maintainer action approvals with signed intent receipts ---------------

  const needApprovals = (req: any, res: any, next: any) =>
    approvals ? next() : fail(res, req, 403, 'APPROVALS_DISABLED', 'Set MAINTAINER_INTENT_SECRET to enable high-impact actions');
  /** Typed domain errors carry their own status and code; anything else is a 500. */
  const knownError = (req: any, res: any, err: unknown, next: any) =>
    err instanceof ApprovalError ||
    err instanceof CapabilityError ||
    err instanceof AdminConfigError ||
    err instanceof PolicyDryRunError ||
    err instanceof FreezeWindowError ||
    err instanceof CounterpartyRiskError ||
    err instanceof SnapshotError
      ? fail(res, req, err.httpStatus, err.code, err.message)
      : next(err);

  router.post('/ops/intents', admin, needApprovals, (req, res, next) => {
    try {
      const intent = approvals!.requestIntent({
        action: String(req.body?.action ?? ''),
        target: String(req.body?.target ?? ''),
        reason: String(req.body?.reason ?? ''),
        requestedBy: String(req.body?.requestedBy ?? ''),
        params: req.body?.params && typeof req.body.params === 'object' ? req.body.params : {},
        bypassId: typeof req.body?.bypassId === 'string' ? req.body.bypassId : undefined,
      });
      res.status(201).json({ success: true, data: intent, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.get('/ops/intents', admin, needApprovals, (req, res) => {
    const status = typeof req.query.status === 'string' ? (req.query.status as IntentStatus) : undefined;
    res.json({ success: true, data: approvals!.listIntents({ status }), correlationId: req.correlationId });
  });

  router.post('/ops/intents/:id/approve', admin, needApprovals, (req, res, next) => {
    try {
      res.json({ success: true, data: approvals!.approve(req.params.id, String(req.body?.approverId ?? '')), correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.post('/ops/intents/:id/reject', admin, needApprovals, (req, res, next) => {
    try {
      res.json({ success: true, data: approvals!.reject(req.params.id, String(req.body?.maintainerId ?? ''), String(req.body?.reason ?? '')), correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.post('/ops/intents/:id/execute', admin, needApprovals, async (req, res, next) => {
    try {
      const receipt = await approvals!.execute(req.params.id, {
        executedBy: String(req.body?.executedBy ?? ''),
        confirmation: String(req.body?.confirmation ?? ''),
        params: req.body?.params,
        bypassId: typeof req.body?.bypassId === 'string' ? req.body.bypassId : undefined,
      });
      res.status(receipt.outcome === 'succeeded' ? 200 : 502).json({ success: receipt.outcome === 'succeeded', data: receipt, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.get('/ops/receipts', admin, needApprovals, (req, res) => {
    const outcome = typeof req.query.outcome === 'string' ? (req.query.outcome as ReceiptOutcome) : undefined;
    const target = typeof req.query.target === 'string' ? req.query.target : undefined;
    res.json({
      success: true,
      data: { receipts: approvals!.listReceipts({ outcome, target }), chainBrokenAt: approvals!.verifyReceiptChain() },
      correlationId: req.correlationId,
    });
  });

  router.get('/ops/receipts/:id', admin, needApprovals, (req, res) => {
    const receipt = approvals!.getReceipt(req.params.id);
    if (!receipt) return fail(res, req, 404, 'RECEIPT_NOT_FOUND', 'Receipt not found');
    res.json({ success: true, data: { receipt, signatureValid: approvals!.verifyReceipt(receipt) }, correlationId: req.correlationId });
  });

  // -- Operational freeze windows (#194) -------------------------------------

  router.post('/ops/freeze-windows', admin, (req, res, next) => {
    try {
      const window = freeze.schedule({
        name: String(req.body?.name ?? ''),
        reason: String(req.body?.reason ?? ''),
        actions: Array.isArray(req.body?.actions) ? req.body.actions.map(String) : [],
        targets: Array.isArray(req.body?.targets) ? req.body.targets.map(String) : undefined,
        startsAt: req.body?.startsAt ?? new Date().toISOString(),
        endsAt: String(req.body?.endsAt ?? ''),
        createdBy: String(req.body?.createdBy ?? 'ops-admin'),
      });
      res.status(201).json({ success: true, data: window, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.get('/ops/freeze-windows/status', admin, (req, res) => {
    const action = typeof req.query.action === 'string' ? req.query.action.trim() : '';
    if (!action) {
      return fail(res, req, 400, 'INVALID_FREEZE_WINDOW', 'action is required');
    }
    const target = typeof req.query.target === 'string' && req.query.target.trim()
      ? req.query.target.trim()
      : null;
    res.json({ success: true, data: freeze.status(action, target), correlationId: req.correlationId });
  });

  router.get('/ops/freeze-windows', admin, (req, res) => {
    const state = typeof req.query.state === 'string' ? (req.query.state as FreezeWindowState) : undefined;
    if (state && !['scheduled', 'active', 'expired', 'revoked'].includes(state)) {
      return fail(res, req, 400, 'INVALID_FREEZE_WINDOW', 'state must be scheduled, active, expired or revoked');
    }
    const action = typeof req.query.action === 'string' ? req.query.action.trim() : '';
    const windows = freeze.listWindows({
      state,
      action: action || undefined,
      target: typeof req.query.target === 'string' && req.query.target.trim()
        ? req.query.target.trim()
        : null,
      includeExpired: req.query.includeExpired === 'true',
    });
    res.json({ success: true, data: { windows }, correlationId: req.correlationId });
  });

  router.get('/ops/freeze-windows/:id', admin, (req, res) => {
    const window = freeze.getWindow(req.params.id);
    if (!window) return fail(res, req, 404, 'FREEZE_WINDOW_NOT_FOUND', 'Freeze window not found');
    res.json({ success: true, data: window, correlationId: req.correlationId });
  });

  router.post('/ops/freeze-windows/:id/revoke', admin, (req, res, next) => {
    try {
      const window = freeze.revoke(
        req.params.id,
        String(req.body?.actorId ?? 'ops-admin'),
        String(req.body?.reason ?? '')
      );
      res.json({ success: true, data: window, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.post('/ops/freeze-windows/:id/bypasses', admin, (req, res, next) => {
    try {
      const bypass = freeze.issueBypass(req.params.id, {
        action: String(req.body?.action ?? ''),
        target: req.body?.target === undefined || req.body?.target === null ? null : String(req.body.target),
        issuedTo: String(req.body?.issuedTo ?? ''),
        reason: String(req.body?.reason ?? ''),
      });
      res.status(201).json({ success: true, data: bypass, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.get('/ops/freeze-windows/:id/bypasses', admin, (req, res) => {
    if (!freeze.getWindow(req.params.id)) {
      return fail(res, req, 404, 'FREEZE_WINDOW_NOT_FOUND', 'Freeze window not found');
    }
    const bypasses = freeze.listBypasses({
      windowId: req.params.id,
      includeUsed: req.query.includeUsed === 'true',
    });
    res.json({ success: true, data: { bypasses }, correlationId: req.correlationId });
  });

  // -- Compliance snapshots (#192) -------------------------------------------

  router.get('/ops/compliance-snapshots/verify-chain', admin, (req, res) => {
    res.json({
      success: true,
      data: { ...snapshots.verifyChain(), size: snapshots.size() },
      correlationId: req.correlationId,
    });
  });

  router.get('/ops/compliance-snapshots/by-event/:eventId', admin, (req, res) => {
    const snapshot = snapshots.getByEventId(req.params.eventId);
    if (!snapshot) return fail(res, req, 404, 'SNAPSHOT_NOT_FOUND', 'No snapshot for that audit event');
    res.json({ success: true, data: snapshot, correlationId: req.correlationId });
  });

  router.get('/ops/compliance-snapshots', admin, (req, res) => {
    const limit = req.query.limit === undefined ? undefined : Number(req.query.limit);
    const offset = req.query.offset === undefined ? undefined : Number(req.query.offset);
    const result = snapshots.list({
      eventType: typeof req.query.eventType === 'string' ? req.query.eventType : undefined,
      entityId: typeof req.query.entityId === 'string' ? req.query.entityId : undefined,
      entityType: typeof req.query.entityType === 'string' ? req.query.entityType : undefined,
      limit,
      offset,
    });
    res.json({
      success: true,
      data: { snapshots: result.snapshots, total: result.total },
      pagination: { limit: result.limit, offset: result.offset, total: result.total },
      correlationId: req.correlationId,
    });
  });

  router.get('/ops/compliance-snapshots/:id', admin, (req, res) => {
    const snapshot = snapshots.get(req.params.id);
    if (!snapshot) return fail(res, req, 404, 'SNAPSHOT_NOT_FOUND', 'Compliance snapshot not found');
    res.json({ success: true, data: snapshot, correlationId: req.correlationId });
  });

  router.get('/ops/compliance-snapshots/:id/verify', admin, (req, res) => {
    const snapshot = snapshots.get(req.params.id);
    if (!snapshot) return fail(res, req, 404, 'SNAPSHOT_NOT_FOUND', 'Compliance snapshot not found');
    res.json({
      success: true,
      data: { snapshotId: snapshot.id, eventId: snapshot.eventId, ...snapshots.verify(snapshot) },
      correlationId: req.correlationId,
    });
  });

  // -- Counterparty risk (#191) ----------------------------------------------

  router.get('/ops/risk/counterparty/overrides', admin, (req, res) => {
    const overrides = risk.listOverrides(req.query.includeExpired === 'true');
    res.json({ success: true, data: { overrides }, correlationId: req.correlationId });
  });

  router.post('/ops/risk/counterparty/:subjectId/evaluate', admin, (req, res, next) => {
    try {
      const input =
        req.body?.signals && typeof req.body.signals === 'object' ? req.body.signals : req.body ?? {};
      const assessment = risk.evaluate(req.params.subjectId, input);
      res.json({ success: true, data: assessment, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.get('/ops/risk/counterparty/:subjectId', admin, (req, res) => {
    const assessment = risk.getLatest(req.params.subjectId);
    if (!assessment) {
      return fail(res, req, 404, 'RISK_ASSESSMENT_NOT_FOUND', 'No assessment for that counterparty');
    }
    res.json({ success: true, data: assessment, correlationId: req.correlationId });
  });

  router.put('/ops/risk/counterparty/:subjectId/override', admin, (req, res, next) => {
    try {
      const override = risk.setOverride({
        subjectId: req.params.subjectId,
        level: req.body?.level,
        reason: String(req.body?.reason ?? ''),
        actorId: String(req.body?.actorId ?? 'ops-admin'),
        expiresAt: req.body?.expiresAt,
      });
      res.json({ success: true, data: override, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.delete('/ops/risk/counterparty/:subjectId/override', admin, (req, res, next) => {
    try {
      const cleared = risk.clearOverride(
        req.params.subjectId,
        String(req.body?.actorId ?? 'ops-admin'),
        String(req.body?.reason ?? '')
      );
      if (!cleared) {
        return fail(res, req, 404, 'RISK_ASSESSMENT_NOT_FOUND', 'No override for that counterparty');
      }
      res.json({ success: true, data: { cleared }, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  router.get('/ops/health', admin, async (req, res, next) => {
    try {
      const report = await buildOpsHealthReport({
        storage: options.storage,
        jobs: options.jobs,
        recentLogs: () => metrics.getRecentLogs(200),
      });
      res.json({ success: true, data: report, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  // Policy simulation preview before committing changes (Issue #267)
  router.post('/ops/policy/simulate', admin, async (req, res, next) => {
    try {
      const invoices = options.storage.getAllInvoices ? await options.storage.getAllInvoices() : [];
      const current = loadPolicy();
      const simulation = simulatePolicyChange(invoices, req.body?.proposedPolicy || {}, current);
      res.json({ success: true, data: simulation, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  // Dry-run policy evaluation with paginated affected-record previews (#296).
  // Validation runs before any record is read; a storage that cannot enumerate
  // invoices fails closed rather than reporting an empty impact.
  router.post('/ops/policy/dry-run', admin, async (req, res, next) => {
    try {
      const request = parsePolicyDryRunRequest(req.body, loadPolicy());
      if (!options.storage.getAllInvoices) {
        return fail(res, req, 503, 'DRY_RUN_UNAVAILABLE', 'Storage cannot enumerate invoices, so impact cannot be evaluated');
      }
      const invoices = await options.storage.getAllInvoices();
      res.json({ success: true, data: evaluatePolicyDryRun(invoices, request), correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  // -- Capability tokens for sensitive actions (#285) ------------------------

  const needCapabilities = (req: any, res: any, next: any) =>
    capabilities
      ? next()
      : fail(res, req, 403, 'CAPABILITIES_DISABLED', 'Set CAPABILITY_TOKEN_SECRET (32+ characters) to enable sensitive admin actions');

  router.post('/ops/capabilities', admin, needCapabilities, (req, res, next) => {
    try {
      const ttlSeconds = req.body?.ttlSeconds;
      const { token, claims } = capabilities!.issue({
        action: String(req.body?.action ?? ''),
        target: String(req.body?.target ?? ''),
        subject: String(req.body?.subject ?? ''),
        ttlMs: ttlSeconds === undefined ? undefined : Number(ttlSeconds) * 1000,
      });
      // Recorded before the token is returned: no capability exists without evidence.
      auditStore.recordEvent({
        action: 'CAPABILITY_ISSUED',
        actor: { type: 'maintainer', id: claims.subject, ip: req.ip, userAgent: req.get('user-agent') },
        scope: { entityType: 'system', entityId: claims.target },
        reason: `Capability issued for ${claims.action}`,
        metadata: { capabilityId: claims.id, action: claims.action, expiresAt: new Date(claims.exp).toISOString() },
        correlationId: req.correlationId,
      });
      res.status(201).json({
        success: true,
        data: {
          token,
          capabilityId: claims.id,
          action: claims.action,
          target: claims.target,
          subject: claims.subject,
          issuedAt: new Date(claims.iat).toISOString(),
          expiresAt: new Date(claims.exp).toISOString(),
        },
        correlationId: req.correlationId,
      });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  // -- Audited runtime configuration (#292) ----------------------------------

  router.get('/ops/config', admin, (req, res) => {
    res.json({ success: true, data: config.snapshot(), correlationId: req.correlationId });
  });

  router.put('/ops/config/feature-flags/:flag', admin, needCapabilities, async (req, res, next) => {
    try {
      const result = await capabilities!.use(
        req.header('x-capability-token'),
        { action: 'config.feature_flag.set', target: req.params.flag },
        (claims) =>
          config.setFeatureFlag({
            flag: req.params.flag,
            enabled: req.body?.enabled,
            reason: req.body?.reason,
            expectedVersion: req.body?.expectedVersion,
            actorId: claims.subject,
            capabilityId: claims.id,
            correlationId: req.correlationId,
            ip: req.ip,
            userAgent: req.get('user-agent'),
          })
      );
      res.json({ success: true, data: result, correlationId: req.correlationId });
    } catch (err) {
      knownError(req, res, err, next);
    }
  });

  // Stale projection detection and repair recommendations (Issue #269)
  router.get('/ops/stale-projections/detect', admin, async (req, res, next) => {
    try {
      const report = await staleProjectionService.detect(options.storage);
      res.json({ success: true, data: report, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  router.post('/ops/stale-projections/repair', admin, async (req, res, next) => {
    try {
      const mode = req.body?.mode === 'queued' ? 'queued' : 'immediate';
      const evidence = await staleProjectionService.repair(options.storage, defaultSearchIndex, { mode });
      res.json({ success: true, data: evidence, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  // Versioned event replay for the search-index projection (#290). Dry run by default.
  router.post('/ops/projections/search-index/replay', admin, async (req, res, next) => {
    const dryRun = req.body?.dryRun !== false;
    const version = req.body?.projectorVersion;
    if (version !== undefined && !Number.isSafeInteger(version)) {
      return fail(res, req, 400, 'INVALID_PROJECTOR_VERSION', 'projectorVersion must be an integer');
    }
    try {
      const report = await replay.replay({ dryRun, projectorVersion: version });
      if (report.outcome === 'refused') {
        return res.status(409).json({
          success: false,
          code: 'REPLAY_REFUSED',
          error: `Replay not applied: ${report.reasons.join('; ')}`,
          data: report,
          correlationId: req.correlationId,
        });
      }
      if (report.outcome === 'applied') {
        auditStore.recordEvent({
          action: 'MAINTAINER_ACTION',
          actor: { type: 'maintainer', id: 'ops-admin' },
          scope: { entityType: 'system', entityId: 'search_index' },
          reason: 'Search index rebuilt by event replay',
          metadata: { projectorVersion: report.projectorVersion, events: report.events.total, diff: report.diff },
          correlationId: req.correlationId,
        });
      }
      res.json({ success: true, data: report, correlationId: req.correlationId });
    } catch (err) {
      if (err instanceof UnknownProjectorVersionError) return fail(res, req, 400, 'INVALID_PROJECTOR_VERSION', err.message);
      if (err instanceof ReplayInProgressError) return fail(res, req, 409, 'REPLAY_IN_PROGRESS', err.message);
      next(err);
    }
  });

  router.post('/ops/projections/search-index/rollback', admin, (req, res) => {
    try {
      const result = replay.rollback();
      auditStore.recordEvent({
        action: 'MAINTAINER_ACTION',
        actor: { type: 'maintainer', id: 'ops-admin' },
        scope: { entityType: 'system', entityId: 'search_index' },
        reason: 'Search index replay rolled back',
        metadata: result,
        correlationId: req.correlationId,
      });
      res.json({ success: true, data: result, correlationId: req.correlationId });
    } catch (err) {
      if (err instanceof NothingToRollBackError) return fail(res, req, 409, 'NOTHING_TO_ROLL_BACK', err.message);
      throw err;
    }
  });

  // Synthetic journey monitor for critical workflow (Issue #264)
  router.post('/ops/synthetic-journey/run', admin, async (req, res, next) => {
    try {
      const monitor = new SyntheticJourneyMonitor({ storage: options.storage });
      const report = await monitor.runJourney();
      res.status(report.success ? 200 : 503).json({ success: report.success, data: report, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  // Snapshot restore verification for critical data and derived indexes (Issue #263)
  router.post('/ops/snapshot-restore/verify', admin, async (req, res, next) => {
    try {
      const snapshotPkg = req.body?.snapshotPackage || {
        invoices: options.storage.getAllInvoices ? await options.storage.getAllInvoices() : [],
        metadata: { exportedAt: new Date().toISOString(), source: 'api' },
      };
      const report = verifySnapshotRestore(snapshotPkg);
      res.status(report.ok ? 200 : 422).json({ success: report.ok, data: report, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  // -- Resumable record repair jobs -----------------------------------------

  router.post('/ops/repair-records/jobs', admin, async (req, res, next) => {
    try {
      const { dryRun, batchSize, phases, maxBatches } = req.body ?? {};
      const report = await repairService.startRepairJob({
        dryRun: dryRun !== undefined ? Boolean(dryRun) : undefined,
        batchSize: typeof batchSize === 'number' ? batchSize : undefined,
        phases: Array.isArray(phases) ? (phases as RepairPhase[]) : undefined,
        maxBatches: typeof maxBatches === 'number' ? maxBatches : undefined,
      });

      auditStore.recordEvent({
        action: 'MAINTAINER_ACTION',
        actor: { type: 'maintainer', id: 'ops-admin' },
        scope: { entityType: 'system', entityId: report.jobId },
        reason: `Record repair job started (${report.status})`,
        metadata: {
          jobId: report.jobId,
          status: report.status,
          dryRun: report.dryRun,
          repaired: report.counts.repaired,
          scanned: report.counts.scanned,
          failed: report.counts.failed,
        },
        correlationId: req.correlationId,
      });

      res.status(201).json({ success: true, data: report, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  router.post('/ops/repair-records/jobs/:id/resume', admin, async (req, res, next) => {
    try {
      const { batchSize, maxBatches } = req.body ?? {};
      const report = await repairService.resumeRepairJob(req.params.id, {
        batchSize: typeof batchSize === 'number' ? batchSize : undefined,
        maxBatches: typeof maxBatches === 'number' ? maxBatches : undefined,
      });

      auditStore.recordEvent({
        action: 'MAINTAINER_ACTION',
        actor: { type: 'maintainer', id: 'ops-admin' },
        scope: { entityType: 'system', entityId: report.jobId },
        reason: `Record repair job resumed (${report.status})`,
        metadata: {
          jobId: report.jobId,
          status: report.status,
          dryRun: report.dryRun,
          repaired: report.counts.repaired,
          scanned: report.counts.scanned,
          failed: report.counts.failed,
        },
        correlationId: req.correlationId,
      });

      res.json({ success: true, data: report, correlationId: req.correlationId });
    } catch (err) {
      if (err instanceof RepairJobNotFoundError) {
        return fail(res, req, 404, 'REPAIR_JOB_NOT_FOUND', err.message);
      }
      next(err);
    }
  });

  router.get('/ops/repair-records/jobs/:id', admin, async (req, res, next) => {
    try {
      const report = await repairService.getJob(req.params.id);
      if (!report) {
        return fail(res, req, 404, 'REPAIR_JOB_NOT_FOUND', `Repair job ${req.params.id} not found`);
      }
      res.json({ success: true, data: report, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  router.get('/ops/repair-records/jobs', admin, async (req, res, next) => {
    try {
      const status = typeof req.query.status === 'string' ? (req.query.status as any) : undefined;
      const limit = typeof req.query.limit === 'string' ? parseInt(req.query.limit, 10) : undefined;
      const jobs = await repairService.listJobs({ status, limit });
      res.json({ success: true, data: jobs, correlationId: req.correlationId });
    } catch (err) {
      next(err);
    }
  });

  // -- Scoped maintainer impersonation (#76) --------------------------------

  router.get('/ops/impersonation', admin, (req, res) => {
    const maintainerId = String(req.query.maintainerId ?? '');
    const includeClosed = req.query.includeClosed !== 'false';
    res.json({
      success: true,
      data: {
        indicator: maintainerId
          ? impersonation.indicator(maintainerId)
          : { active: false },
        sessions: impersonation.listSessions(includeClosed),
        permissions: IMPERSONATION_PERMISSIONS,
      },
      correlationId: req.correlationId,
    });
  });

  router.post('/ops/impersonation', admin, (req, res) => {
    const target = stellarPublicKeySchema.safeParse(req.body?.targetId);
    if (!target.success) {
      return res.status(400).json({
        success: false,
        code: 'TARGET_INVALID',
        error: 'targetId must be a valid Stellar public key',
        correlationId: req.correlationId,
      });
    }

    const permissions = (req.body?.permissions ?? ['read']) as ImpersonationPermission[];

    try {
      const session = impersonation.startSession({
        maintainerId: String(req.body?.maintainerId ?? ''),
        targetId: target.data,
        permissions,
        reason: String(req.body?.reason ?? ''),
        durationMs: durationOf(req.body?.durationMs),
        ip: req.ip,
        userAgent: req.get('user-agent'),
      });
      return res.status(201).json({
        success: true,
        data: { session, indicator: impersonation.indicator(session.maintainerId) },
        correlationId: req.correlationId,
      });
    } catch (err) {
      return res.status(400).json({
        success: false,
        code: 'IMPERSONATION_REJECTED',
        error: err instanceof Error ? err.message : 'Impersonation session rejected',
        correlationId: req.correlationId,
      });
    }
  });

  router.post('/ops/impersonation/end', admin, (req, res) => {
    const sessionId = String(req.body?.sessionId ?? '');
    const closed = impersonation.endSession(
      sessionId,
      req.body?.maintainerId ? String(req.body.maintainerId) : undefined,
    );
    if (!closed) {
      return res.status(404).json({
        success: false,
        code: 'SESSION_NOT_FOUND',
        error: 'No active session with that id for this maintainer',
        correlationId: req.correlationId,
      });
    }
    return res.json({ success: true, data: { sessionId, closed: true }, correlationId: req.correlationId });
  });

  return router;
}

export default createOpsRouter;
