/**
 * Public API contract (#55).
 *
 * The HTTP surface grew route by route: invoice, audit, observability,
 * notifications, exports, then jobs/ops/webhooks. Nothing recorded the result,
 * so an integration could not tell whether a change to a status code, a
 * response key or an auth requirement was intentional. `docs/API_CONTRACTS.md`
 * describes the surface, but prose cannot fail a build.
 *
 * This module is the machine-readable half of that contract:
 *
 *  1. `API_CONTRACT` declares every integration-facing endpoint, its auth
 *     requirement and the statuses it may return.
 *  2. `collectRoutes` walks a live Express app and reports what is actually
 *     mounted.
 *  3. `diffContract` compares the two and returns the drift in both
 *     directions, so `tests/api-contract.test.ts` fails CI when a route is
 *     added, removed or re-pathed without updating the contract.
 *
 * Deliberately not enforced here: payload shapes. Those are pinned separately by
 * `schema-versioning` and the envelope tests, which already own field-level
 * compatibility. Keeping this file to method/path/auth/status means the drift
 * check stays cheap enough to trust, and a false negative costs a review
 * comment rather than a broken deploy.
 */

/** How a caller is expected to authenticate. */
export type ContractAuth = 'none' | 'admin' | 'hmac' | 'public' | 'maintainer';

/**
 * Which surface an endpoint belongs to. `public` is the storage-agnostic client
 * surface mounted by both server-mvp.ts and server.ts; `admin` is mounted only
 * by the Postgres server and is never part of the frontend contract.
 */
export type ContractGroup = 'public' | 'admin';

/** Which server actually mounts the route. */
export type ContractSurface = 'mvp' | 'postgres';

/**
 * Shape of a successful response body.
 *
 * `envelope` is the shared `{ success, data }` contract from `types/api.ts` and
 * is what integrations should code against. `raw` is reserved for the few
 * endpoints whose body is consumed by something other than a JSON client:
 * Kubernetes probes, a Prometheus scraper, and document downloads. Those are
 * called out explicitly so the drift test holds them to their real shape
 * instead of quietly exempting them, and so nobody "fixes" a probe endpoint
 * into an envelope and breaks the platform that reads it.
 */
export type ContractResponseKind = 'envelope' | 'raw';

export interface ContractEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Express-style path, including `:param` segments. */
  path: string;
  group: ContractGroup;
  /** Servers that mount this route. Drives the drift check, not the docs. */
  surfaces: ContractSurface[];
  auth: ContractAuth;
  /** One line, mirrored in docs/API_CONTRACTS.md. */
  summary: string;
  /** Statuses the endpoint can return, in ascending order. */
  responses: number[];
  /** Whether success uses the shared envelope or returns a raw body. */
  responseKind?: ContractResponseKind;
  /**
   * True when the route is only mounted under a configuration flag. The drift
   * check tolerates its absence unless the flag is enabled in the test env.
   */
  conditional?: string;
}

export interface RouteDescriptor {
  method: string;
  path: string;
}

export interface ContractDrift {
  /** Mounted in the app but absent from the contract. */
  undocumented: RouteDescriptor[];
  /** Declared in the contract but not mounted. */
  phantom: RouteDescriptor[];
}

/** Bumped when a breaking change to the declared surface is made deliberately. */
export const CONTRACT_VERSION = '1.1.0';

/**
 * Express 4 encodes a mounted path as a regexp source of the shape
 * `^\/api\/?(?=\/|$)`. Unescape it back to `/api`; a mount of `/?` or a bare
 * regex is not a path prefix and returns null so the walker keeps the prefix it
 * already had.
 */
function mountPathToPrefix(regexp: RegExp): string | null {
  const source = regexp?.source;
  if (!source || !source.startsWith('^')) return null;

  const withoutAnchors = source
    .replace(/^\^/, '')
    .replace(/\\\/\?\(\?=\\\/\|\$\)$/, '')
    .split('\\/')
    .join('/');

  if (withoutAnchors === '/?' || withoutAnchors === '') return null;
  return withoutAnchors;
}

/**
 * Express stores its route table in two different places: an `Application`
 * keeps it on `_router.stack`, while a `Router` exposes `stack` directly.
 * Both the servers and the route factories are handed to this module, so read
 * whichever is present.
 */
function routeStack(target: any): any[] | null {
  const fromApp = target?._router?.stack;
  if (Array.isArray(fromApp)) return fromApp;

  const fromRouter = target?.stack;
  if (Array.isArray(fromRouter)) return fromRouter;

  return null;
}

/**
 * Enumerates every method/path actually mounted, including routers attached
 * with `use(prefix, router)`. Mounted sub-routers are followed so a prefix is
 * applied exactly as Express would apply it at request time.
 */
export function collectRoutes(app: any, prefix = ''): RouteDescriptor[] {
  const found: RouteDescriptor[] = [];
  const stack = routeStack(app);

  if (!stack) return found;

  for (const layer of stack) {
    if (layer?.route) {
      const methods = Object.keys(layer.route.methods ?? {}).filter((m) => m !== '_all');
      for (const method of methods) {
        found.push({ method: method.toUpperCase(), path: `${prefix}${layer.route.path}` });
      }
      continue;
    }

    const nested = layer?.handle?.stack;
    if (Array.isArray(nested)) {
      const mountPath = mountPathToPrefix(layer.regexp);
      found.push(...collectRoutes(layer.handle, `${prefix}${mountPath ?? ''}`));
    }
  }

  return found;
}

function routeKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${path}`;
}

export function diffContract(contract: ContractEndpoint[], actual: RouteDescriptor[]): ContractDrift {
  const declared = new Set(contract.map((e) => routeKey(e.method, e.path)));
  const mounted = new Set(actual.map((r) => routeKey(r.method, r.path)));

  return {
    undocumented: actual
      .filter((r) => !declared.has(routeKey(r.method, r.path)))
      .map((r) => ({ method: r.method, path: r.path }))
      .sort((a, b) => routeKey(a.method, a.path).localeCompare(routeKey(b.method, b.path))),
    phantom: contract
      .filter((e) => !mounted.has(routeKey(e.method, e.path)))
      .map((e) => ({ method: e.method, path: e.path }))
      .sort((a, b) => routeKey(a.method, a.path).localeCompare(routeKey(b.method, b.path))),
  };
}

const BOTH: ContractSurface[] = ['mvp', 'postgres'];
const PG_ONLY: ContractSurface[] = ['postgres'];

/**
 * The declared integration surface.
 *
 * `responses` is the set of statuses the handler can actually emit, read off
 * the `sendSuccess` / `sendFailure` / `res.status` calls in the route files —
 * not the set of statuses that would be nice. Where an endpoint has a
 * documented, meaningful error contract (see docs/API_CONTRACTS.md) the drift
 * test also probes it live, so a status change fails rather than going stale.
 */
export const API_CONTRACT: ContractEndpoint[] = [
  // ── Service metadata ────────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/',
    group: 'public',
    surfaces: ['mvp'],
    auth: 'none',
    summary: 'Server banner: name, version and storage mode.',
    responseKind: 'raw',
    responses: [200],
  },
  {
    method: 'GET',
    path: '/api/health',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Liveness plus the storage mode the server is running in.',
    responseKind: 'raw',
    responses: [200],
  },
  {
    method: 'GET',
    path: '/api/ready',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Readiness probe. 503 when a dependency is unavailable.',
    responseKind: 'raw',
    responses: [200, 503],
  },

  // ── Invoices ────────────────────────────────────────────────────────────
  {
    method: 'POST',
    path: '/api/invoices',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Create an invoice. 201 returns the stored invoice.',
    responses: [201, 400],
  },
  {
    method: 'GET',
    path: '/api/invoices',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'List invoices for a seller. Keyset pagination via `cursor`; `limit` clamped to 1-200.',
    responses: [200, 400, 500],
  },
  {
    method: 'GET',
    path: '/api/invoices/stats',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Aggregated counts and revenue per asset for a seller.',
    responses: [200, 400, 500],
  },
  {
    method: 'GET',
    path: '/api/invoices/:id',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Fetch one invoice by id.',
    responses: [200, 404, 500],
  },
  {
    method: 'GET',
    path: '/api/invoices/:id/payment-info',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Payment details needed to settle an invoice (asset, memo, destination).',
    responses: [200, 404, 500],
  },
  {
    method: 'GET',
    path: '/api/invoices/:id/email-preview',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Rendered invoice email, as HTML and text, without sending.',
    responses: [200, 404, 500],
  },
  {
    method: 'POST',
    path: '/api/invoices/:id/cancel',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Cancel a PENDING invoice. 409 once it is settled.',
    responses: [200, 400, 404, 409],
  },
  {
    method: 'POST',
    path: '/api/invoices/:id/verify',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Verify a submitted payment and settle the invoice.',
    responses: [200, 400, 404, 500],
  },
  {
    method: 'POST',
    path: '/api/invoices/:id/simulate-payment',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Mark an invoice paid without contacting the network (sandbox only).',
    responses: [200, 404, 500],
  },
  {
    method: 'POST',
    path: '/api/invoices/:id/send-email',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Email an invoice to its customer.',
    responses: [200, 400, 404, 409, 422, 500],
  },

  // ── Audit ───────────────────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/api/invoices/:id/audit-trail',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Activity timeline for a single invoice.',
    responses: [200, 404, 500],
  },
  {
    method: 'GET',
    path: '/api/audit/events',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Query audit events across invoices, filtered by type and time.',
    responses: [200, 500],
  },
  {
    method: 'GET',
    path: '/api/audit/export',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Stream a full audit export as a downloadable document.',
    responseKind: 'raw',
    responses: [200, 500],
  },

  // ── Observability ───────────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/api/metrics',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Prometheus exposition format.',
    responseKind: 'raw',
    responses: [200],
  },
  {
    method: 'GET',
    path: '/api/observability/metrics',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'JSON metrics: counters, latencies and error rates.',
    responses: [200],
  },

  // ── Notifications ───────────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/api/notifications',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Notifications for a recipient wallet, paginated.',
    responses: [200, 400],
  },
  {
    method: 'GET',
    path: '/api/notifications/unread-count',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Unread notification count for a recipient wallet.',
    responses: [200],
  },
  {
    method: 'POST',
    path: '/api/notifications/:id/read',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Mark one notification read.',
    responses: [200, 404],
  },
  {
    method: 'POST',
    path: '/api/notifications/read-all',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Mark every notification for a recipient read.',
    responses: [200],
  },
  {
    method: 'GET',
    path: '/api/notifications/preferences',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Retrieve durable notification routing preferences for a recipient.',
    responses: [200, 400],
  },
  {
    method: 'PUT',
    path: '/api/notifications/preferences',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Update durable notification routing preferences for a recipient.',
    responses: [200, 400],
  },
  {
    method: 'GET',
    path: '/api/notifications/routing-audit',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Retrieve routing and override audit trail for a recipient.',
    responses: [200, 400],
  },

  // ── Exports ─────────────────────────────────────────────────────────────
  {
    method: 'POST',
    path: '/api/exports',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Generate an export artifact. Returns an expiring download handle.',
    responses: [201, 400, 403, 500, 503],
  },
  {
    method: 'GET',
    path: '/api/exports/:id',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Download an export artifact. 410 once it has expired.',
    responseKind: 'raw',
    responses: [200, 400, 404, 410],
  },

  // ── Bulk import ─────────────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/api/imports/invoices/template',
    group: 'public',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Download the canonical invoice import CSV template.',
    responseKind: 'raw',
    responses: [200],
  },
  {
    method: 'POST',
    path: '/api/imports/invoices',
    group: 'public',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Bulk-import invoices from JSON or CSV. Dry run by default; `dryRun: false` writes.',
    responses: [200, 400, 429, 500],
  },

  // ── Stellar ─────────────────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/api/stellar/account',
    group: 'public',
    surfaces: BOTH,
    auth: 'none',
    summary: 'Account balances from Horizon.',
    responses: [200],
  },
  {
    method: 'GET',
    path: '/api/stellar/payments',
    group: 'public',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Recent payments for an account from Horizon.',
    responses: [200],
  },
  {
    method: 'GET',
    path: '/api/stellar/transaction/:hash',
    group: 'public',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Fetch one transaction by hash.',
    responses: [200, 404],
  },
  {
    method: 'POST',
    path: '/api/stellar/verify-payment',
    group: 'public',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Verify a transaction hash against an expected asset and amount.',
    responses: [200, 400],
  },
  {
    method: 'POST',
    path: '/api/payment/sync',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'maintainer',
    summary: 'Run a manual payment-monitor sync sweep (maintainer or service).',
    responses: [200, 401, 403, 500],
  },
  {
    method: 'GET',
    path: '/api/payment/monitor/status',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'maintainer',
    summary: 'Payment monitor checkpoint and last sweep status (maintainer or service).',
    responses: [200, 401, 403],
  },

  // ── Email (admin surface) ───────────────────────────────────────────────
  {
    method: 'POST',
    path: '/api/email/send',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Send an email through the configured provider.',
    responses: [200, 400, 409, 422, 429, 502],
  },
  {
    method: 'GET',
    path: '/api/email/deliveries',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Recent delivery attempts with provider status.',
    responses: [200],
  },
  {
    method: 'GET',
    path: '/api/email/problems',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Bounced and complained deliveries that need follow-up.',
    responses: [200],
  },
  {
    method: 'POST',
    path: '/api/email/webhook',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'none',
    summary: 'Provider delivery callback (bounce / complaint / delivered).',
    responses: [200, 400, 404],
  },

  // ── Settlement disputes (#190) ──────────────────────────────────────────
  {
    method: 'POST',
    path: '/api/disputes',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'Open a settlement dispute with optional evidence bundles and notes. The opener is the authenticated actor.',
    responses: [201, 400, 401, 403, 409],
  },
  {
    method: 'GET',
    path: '/api/disputes',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'List disputes. Maintainers see all; other callers see only disputes they participate in.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/disputes/:id',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'Read one dispute. Private evidence, notes and resolution detail are filtered by role and authorship.',
    responses: [200, 401, 403, 404],
  },
  {
    method: 'POST',
    path: '/api/disputes/:id/evidence',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'Attach a labelled evidence reference (transaction, document, URL). File bodies are never accepted.',
    responses: [201, 400, 401, 403, 404, 409],
  },
  {
    method: 'POST',
    path: '/api/disputes/:id/notes',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'Add a public or private note. Private notes are visible to their author and maintainers only.',
    responses: [201, 400, 401, 403, 404, 409],
  },
  {
    method: 'POST',
    path: '/api/disputes/:id/investigate',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'Maintainer moves an open or reopened dispute into investigation.',
    responses: [200, 400, 401, 403, 404, 409],
  },
  {
    method: 'POST',
    path: '/api/disputes/:id/resolve',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'Maintainer records the resolution summary and closes the dispute as resolved.',
    responses: [200, 400, 401, 403, 404, 409],
  },
  {
    method: 'POST',
    path: '/api/disputes/:id/reject',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'Maintainer rejects the claim with a summary and closes the dispute.',
    responses: [200, 400, 401, 403, 404, 409],
  },
  {
    method: 'POST',
    path: '/api/disputes/:id/reopen',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'The opener or a maintainer reopens a resolved or rejected dispute.',
    responses: [200, 400, 401, 403, 404, 409],
  },

  // ── Counterparty risk summary (#191) ────────────────────────────────────
  {
    method: 'GET',
    path: '/api/risk/counterparty/:subjectId',
    group: 'public',
    surfaces: BOTH,
    auth: 'public',
    summary: 'Safe risk summary for a counterparty. Omits scores, factor weights, raw signals and thresholds.',
    responses: [200, 401],
  },

  // ── Jobs and ops (bearer admin token) ───────────────────────────────────
  {
    method: 'GET',
    path: '/api/jobs',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'List background jobs with status counts.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/jobs/:id',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Inspect one job, including its full retry history.',
    responses: [200, 401, 403, 404],
  },
  {
    method: 'POST',
    path: '/api/jobs/:id/retry',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Requeue a dead-lettered job. 409 if it is not dead.',
    responses: [200, 401, 403, 404, 409],
  },
  {
    method: 'GET',
    path: '/api/ops/health',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Operational health report for maintainers.',
    responses: [200, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/impersonation',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'List active support impersonation sessions.',
    responses: [200, 401, 403],
  },
  {
    method: 'POST',
    path: '/api/ops/impersonation',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Open a support impersonation session. Fully audited.',
    responses: [201, 400, 401, 403],
  },
  {
    method: 'POST',
    path: '/api/ops/impersonation/end',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Close a support impersonation session.',
    responses: [200, 401, 403, 404],
  },
  {
    method: 'POST',
    path: '/api/ops/policy/simulate',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Simulate policy changes against current dataset before committing.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/stale-projections/detect',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Detect projection drift, stale statuses, and orphaned records.',
    responses: [200, 401, 403],
  },
  {
    method: 'POST',
    path: '/api/ops/stale-projections/repair',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Automate repair recommendations for detected projection drift.',
    responses: [200, 401, 403],
  },
  {
    method: 'POST',
    path: '/api/ops/projections/search-index/replay',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Rebuild the search index by replaying the audit trail through a versioned projector. Dry run by default.',
    responses: [200, 400, 401, 403, 409],
  },
  {
    method: 'POST',
    path: '/api/ops/projections/search-index/rollback',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Restore the search index that the last applied replay replaced.',
    responses: [200, 401, 403, 409],
  },
  {
    method: 'POST',
    path: '/api/ops/synthetic-journey/run',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Run synthetic journey monitor across critical workflow with latency and dependency blame.',
    responses: [200, 401, 403, 503],
  },
  {
    method: 'POST',
    path: '/api/ops/snapshot-restore/verify',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Verify snapshot restore package against data invariants and rebuild derived indexes.',
    responses: [200, 401, 403, 422],
  },
  {
    method: 'POST',
    path: '/api/ops/policy/dry-run',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Dry-run a validated policy proposal: totals plus a paginated preview of affected records.',
    responses: [200, 400, 401, 403, 503],
  },
  {
    method: 'POST',
    path: '/api/ops/capabilities',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Issue an expiring, single-use capability token for one sensitive action on one target.',
    responses: [201, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/config',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Effective runtime configuration, its version and the source of each value.',
    responses: [200, 401, 403],
  },
  {
    method: 'PUT',
    path: '/api/ops/config/feature-flags/:flag',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Set or clear a feature-flag override. Also needs X-Capability-Token; writes audit evidence first.',
    responses: [200, 400, 401, 403, 404, 409, 503],
  },
  {
    method: 'GET',
    path: '/api/ops/dependencies/matrix',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'External dependency degradation matrix and its validation problems.',
    responses: [200, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/dependencies',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Probe every external dependency. 503 when the overall state is down.',
    responses: [200, 401, 403, 503],
  },
  {
    method: 'GET',
    path: '/api/ops/partial-failures',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Partial-failure dashboard over background jobs, filterable.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/partial-failures/:id',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Inspect one partially failed operation.',
    responses: [200, 401, 403, 404],
  },
  {
    method: 'POST',
    path: '/api/ops/partial-failures/:id/retry',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Idempotently retry a partially failed operation.',
    responses: [200, 401, 403, 404, 409, 422, 503],
  },
  {
    method: 'POST',
    path: '/api/ops/intents',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Declare a signed, risk-scored intent for a high-impact maintainer action.',
    responses: [201, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/intents',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'List maintainer intents, optionally by status.',
    responses: [200, 401, 403],
  },
  {
    method: 'POST',
    path: '/api/ops/intents/:id/approve',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Second-maintainer approval of a pending intent.',
    responses: [200, 400, 401, 403, 404, 409, 410],
  },
  {
    method: 'POST',
    path: '/api/ops/intents/:id/reject',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Reject an intent and issue a signed receipt.',
    responses: [200, 401, 403, 404, 409, 410],
  },
  {
    method: 'POST',
    path: '/api/ops/intents/:id/execute',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Execute an intent with its confirmation phrase. 502 when the action itself failed.',
    responses: [200, 400, 401, 403, 404, 409, 410, 501, 502],
  },
  {
    method: 'GET',
    path: '/api/ops/receipts',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Signed intent receipts plus the first broken chain index.',
    responses: [200, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/receipts/:id',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'One intent receipt with its signature check.',
    responses: [200, 401, 403, 404],
  },

  // ── Operational freeze windows (#194) ───────────────────────────────────
  {
    method: 'POST',
    path: '/api/ops/freeze-windows',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Schedule a scoped freeze window. Actions accept exact names or a trailing-* wildcard.',
    responses: [201, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/freeze-windows',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'List freeze windows, filtered by state, action and target.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/freeze-windows/status',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Whether one action/target pair is currently frozen and by which window.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/freeze-windows/:id',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Read one freeze window and its scope.',
    responses: [200, 401, 403, 404],
  },
  {
    method: 'POST',
    path: '/api/ops/freeze-windows/:id/revoke',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Revoke a scheduled or active freeze window before its scheduled end.',
    responses: [200, 400, 401, 403, 404, 409],
  },
  {
    method: 'POST',
    path: '/api/ops/freeze-windows/:id/bypasses',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Issue a short-lived, single-use emergency bypass for one action and target.',
    responses: [201, 400, 401, 403, 404, 409],
  },
  {
    method: 'GET',
    path: '/api/ops/freeze-windows/:id/bypasses',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'List emergency bypasses issued for a freeze window.',
    responses: [200, 401, 403, 404],
  },

  // ── Compliance snapshots (#192) ─────────────────────────────────────────
  {
    method: 'GET',
    path: '/api/ops/compliance-snapshots',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'List captured compliance snapshots, newest first, filtered by event or entity.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/compliance-snapshots/verify-chain',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Verify every hash and previousHash link in the retained snapshot chain.',
    responses: [200, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/compliance-snapshots/by-event/:eventId',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Find the single snapshot captured for an audit event id.',
    responses: [200, 401, 403, 404],
  },
  {
    method: 'GET',
    path: '/api/ops/compliance-snapshots/:id',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Read one immutable compliance snapshot, including its schema version and hashes.',
    responses: [200, 401, 403, 404],
  },
  {
    method: 'GET',
    path: '/api/ops/compliance-snapshots/:id/verify',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Recompute one snapshot payload and integrity hash to detect tampering.',
    responses: [200, 401, 403, 404],
  },

  // ── Counterparty risk (#191) ────────────────────────────────────────────
  {
    method: 'GET',
    path: '/api/ops/risk/counterparty/overrides',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'List manual counterparty risk overrides, optionally including expired ones.',
    responses: [200, 401, 403],
  },
  {
    method: 'POST',
    path: '/api/ops/risk/counterparty/:subjectId/evaluate',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Score a counterparty from documented signals and return the full factor breakdown.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'GET',
    path: '/api/ops/risk/counterparty/:subjectId',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Maintainer detail view: score, factors, normalized signals, override and input hash.',
    responses: [200, 401, 403, 404],
  },
  {
    method: 'PUT',
    path: '/api/ops/risk/counterparty/:subjectId/override',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Set a reasoned, audited manual risk override, optionally with an expiry.',
    responses: [200, 400, 401, 403],
  },
  {
    method: 'DELETE',
    path: '/api/ops/risk/counterparty/:subjectId/override',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'admin',
    summary: 'Clear a manual risk override and record who cleared it and why.',
    responses: [200, 400, 401, 403, 404],
  },

  // ── Webhooks (only mounted when WEBHOOK_SIGNING_SECRET is set) ───────────
  {
    method: 'POST',
    path: '/api/webhooks/incoming',
    group: 'admin',
    surfaces: PG_ONLY,
    auth: 'hmac',
    summary: 'Signed inbound webhook receiver. Rejects unsigned, stale and replayed events.',
    responses: [200, 400, 401, 403, 408, 409],
    conditional: 'WEBHOOK_SIGNING_SECRET',
  },
];

/** Routes a given server is expected to mount. */
export function contractRoutesFor(surface: ContractSurface): ContractEndpoint[] {
  return API_CONTRACT.filter((e) => e.surfaces.includes(surface));
}

