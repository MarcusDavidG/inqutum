/**
 * Safe counterparty risk summaries (#191). Mount under `/api`.
 *
 *   GET /risk/counterparty/:subjectId
 *
 * Only the non-threshold-bearing summary is returned: level, label, guidance
 * and whether manual review is required. Scores, factor weights, raw signals
 * and the override reason stay on the maintainer-only ops surface.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { authenticate } from '../middleware/access-control';
import { ANONYMOUS_ACTOR } from '../auth/actor';
import {
  CounterpartyRiskError,
  counterpartyRiskService,
  type CounterpartyRiskService,
} from '../risk/counterparty-risk';
import { sendFailure, sendSuccess } from '../types/api';

export interface RiskRouterOptions {
  /** Overridable for tests; defaults to the process-wide scorer. */
  service?: CounterpartyRiskService;
}

export function createRiskRouter(options: RiskRouterOptions = {}): Router {
  const router = Router();
  const service = options.service ?? counterpartyRiskService;

  router.use('/risk', authenticate());

  router.get('/risk/counterparty/:subjectId', (req: Request, res: Response, next: NextFunction) => {
    const actor = req.actor ?? ANONYMOUS_ACTOR;
    if (actor.role === 'anonymous') {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return sendFailure(res, 401, 'Authentication required', { code: 'UNAUTHENTICATED' });
    }
    try {
      const summary = service.publicSummary(req.params.subjectId);
      sendSuccess(res, 200, summary);
    } catch (err) {
      if (err instanceof CounterpartyRiskError) {
        return sendFailure(res, err.httpStatus, err.message, { code: err.code });
      }
      next(err);
    }
  });

  return router;
}

export default createRiskRouter;
