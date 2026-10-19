/**
 * Settlement dispute routes (#190). Mount under `/api`.
 *
 *   POST /disputes                     open a dispute with optional evidence/notes
 *   GET  /disputes                     list disputes visible to the caller
 *   GET  /disputes/:id                 read one dispute, private entries filtered
 *   POST /disputes/:id/evidence        attach a reference (not a file body)
 *   POST /disputes/:id/notes           add a public or private note
 *   POST /disputes/:id/investigate     maintainer starts the investigation
 *   POST /disputes/:id/resolve         maintainer records a resolution
 *   POST /disputes/:id/reject          maintainer rejects the claim
 *   POST /disputes/:id/reopen          opener or maintainer reopens a closed dispute
 *
 * The opener is always taken from the authenticated actor, never from the body.
 * Anonymous callers may not open or read disputes; private evidence is hidden
 * from anyone who is neither a maintainer nor its author.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { authenticate } from '../middleware/access-control';
import { ANONYMOUS_ACTOR, type Actor } from '../auth/actor';
import {
  DisputeWorkflowError,
  type DisputeRecord,
  type DisputeWorkflowService,
  type NewDisputeEvidence,
  type NewDisputeNote,
} from '../domain/dispute-workflow';
import { disputeService } from '../services/dispute.service';
import { sendFailure, sendSuccess } from '../types/api';

export interface DisputeRouterOptions {
  /** Overridable for tests; defaults to the audited process-wide service. */
  service?: DisputeWorkflowService;
}

const actorOf = (req: Request): Actor => req.actor ?? ANONYMOUS_ACTOR;
const actorIdOf = (actor: Actor): string => actor.wallet ?? actor.subject;
const actorRoleOf = (actor: Actor): string => (actor.role === 'maintainer' ? 'maintainer' : 'user');

function requireActor(req: Request, res: Response, next: NextFunction): void {
  if (actorOf(req).role === 'anonymous') {
    res.setHeader('WWW-Authenticate', 'Bearer');
    sendFailure(res, 401, 'Authentication required', { code: 'UNAUTHENTICATED' });
    return;
  }
  next();
}

function requireMaintainer(req: Request, res: Response, next: NextFunction): void {
  if (actorOf(req).role !== 'maintainer') {
    sendFailure(res, 403, 'Only a maintainer may perform this action', { code: 'FORBIDDEN' });
    return;
  }
  next();
}

function canRead(record: DisputeRecord, actor: Actor): boolean {
  if (actor.role === 'maintainer') return true;
  const id = actorIdOf(actor);
  return record.openedBy === id || record.subject === id;
}

function evidenceOf(body: any): NewDisputeEvidence[] | undefined {
  if (!Array.isArray(body?.evidence)) return undefined;
  return body.evidence.map((item: any) => ({
    label: String(item?.label ?? ''),
    kind: item?.kind,
    reference: String(item?.reference ?? ''),
    visibility: item?.visibility,
  }));
}

function notesOf(body: any): NewDisputeNote[] | undefined {
  if (!Array.isArray(body?.notes)) return undefined;
  return body.notes.map((item: any) => ({
    body: String(item?.body ?? ''),
    visibility: item?.visibility,
  }));
}

export function createDisputeRouter(options: DisputeRouterOptions = {}): Router {
  const router = Router();
  const service = options.service ?? disputeService;

  const fail = (req: Request, res: Response, err: unknown, next: NextFunction) => {
    if (err instanceof DisputeWorkflowError) {
      return sendFailure(res, err.httpStatus, err.message, { code: err.code });
    }
    return next(err);
  };

  router.use('/disputes', authenticate());

  router.post('/disputes', requireActor, (req, res, next) => {
    const actor = actorOf(req);
    try {
      const record = service.open({
        settlementId: String(req.body?.settlementId ?? ''),
        openedBy: actorIdOf(actor),
        openedByRole: actorRoleOf(actor),
        subject: typeof req.body?.subject === 'string' ? req.body.subject : undefined,
        invoiceId: typeof req.body?.invoiceId === 'string' ? req.body.invoiceId : undefined,
        reason: String(req.body?.reason ?? ''),
        evidence: evidenceOf(req.body),
        notes: notesOf(req.body),
      });
      sendSuccess(res, 201, record);
    } catch (err) {
      fail(req, res, err, next);
    }
  });

  router.get('/disputes', requireActor, (req, res, next) => {
    const actor = actorOf(req);
    try {
      const isMaintainer = actor.role === 'maintainer';
      const result = service.list(
        {
          status: typeof req.query.status === 'string' ? req.query.status : undefined,
          settlementId:
            typeof req.query.settlementId === 'string' ? req.query.settlementId : undefined,
          openedBy: isMaintainer && typeof req.query.openedBy === 'string' ? req.query.openedBy : undefined,
          participant: isMaintainer
            ? typeof req.query.participant === 'string'
              ? req.query.participant
              : undefined
            : actorIdOf(actor),
          limit: req.query.limit === undefined ? undefined : Number(req.query.limit),
          offset: req.query.offset === undefined ? undefined : Number(req.query.offset),
        },
        { role: actorRoleOf(actor), subject: actor.subject, wallet: actor.wallet }
      );
      sendSuccess(res, 200, { disputes: result.disputes, total: result.total }, {
        pagination: { limit: result.limit, offset: result.offset, total: result.total },
      });
    } catch (err) {
      fail(req, res, err, next);
    }
  });

  router.get('/disputes/:id', requireActor, (req, res, next) => {
    const actor = actorOf(req);
    try {
      const record = service.get(req.params.id, {
        role: actorRoleOf(actor),
        subject: actor.subject,
        wallet: actor.wallet,
      });
      if (!record) {
        return sendFailure(res, 404, 'Dispute not found', { code: 'DISPUTE_NOT_FOUND' });
      }
      if (!canRead(record, actor)) {
        return sendFailure(res, 403, 'You can only read disputes you participate in', { code: 'FORBIDDEN' });
      }
      sendSuccess(res, 200, record);
    } catch (err) {
      fail(req, res, err, next);
    }
  });

  router.post('/disputes/:id/evidence', requireActor, (req, res, next) => {
    const actor = actorOf(req);
    try {
      const current = service.get(req.params.id);
      if (!current) {
        return sendFailure(res, 404, 'Dispute not found', { code: 'DISPUTE_NOT_FOUND' });
      }
      if (!canRead(current, actor)) {
        return sendFailure(res, 403, 'You can only add evidence to disputes you participate in', { code: 'FORBIDDEN' });
      }
      const evidence = service.addEvidence(
        req.params.id,
        {
          label: String(req.body?.label ?? ''),
          kind: req.body?.kind,
          reference: String(req.body?.reference ?? ''),
          visibility: req.body?.visibility,
        },
        actorIdOf(actor),
        actorRoleOf(actor)
      );
      sendSuccess(res, 201, evidence);
    } catch (err) {
      fail(req, res, err, next);
    }
  });

  router.post('/disputes/:id/notes', requireActor, (req, res, next) => {
    const actor = actorOf(req);
    try {
      const current = service.get(req.params.id);
      if (!current) {
        return sendFailure(res, 404, 'Dispute not found', { code: 'DISPUTE_NOT_FOUND' });
      }
      if (!canRead(current, actor)) {
        return sendFailure(res, 403, 'You can only add notes to disputes you participate in', { code: 'FORBIDDEN' });
      }
      const note = service.addNote(
        req.params.id,
        {
          body: String(req.body?.body ?? ''),
          visibility: req.body?.visibility,
        },
        actorIdOf(actor),
        actorRoleOf(actor)
      );
      sendSuccess(res, 201, note);
    } catch (err) {
      fail(req, res, err, next);
    }
  });

  const transition = (action: 'investigate' | 'resolve' | 'reject' | 'reopen') =>
    (req: Request, res: Response, next: NextFunction) => {
      const actor = actorOf(req);
      try {
        const record = service.transition(req.params.id, {
          action,
          actorId: actorIdOf(actor),
          actorRole: actorRoleOf(actor),
          reason: String(req.body?.reason ?? ''),
          summary: typeof req.body?.summary === 'string' ? req.body.summary : undefined,
          visibility: req.body?.visibility,
        });
        sendSuccess(res, 200, record);
      } catch (err) {
        fail(req, res, err, next);
      }
    };

  router.post('/disputes/:id/investigate', requireActor, requireMaintainer, transition('investigate'));
  router.post('/disputes/:id/resolve', requireActor, requireMaintainer, transition('resolve'));
  router.post('/disputes/:id/reject', requireActor, requireMaintainer, transition('reject'));
  router.post('/disputes/:id/reopen', requireActor, transition('reopen'));

  return router;
}

export default createDisputeRouter;
