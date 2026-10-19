/**
 * Operational freeze windows for risky maintenance actions (issue #194).
 *
 * A freeze window is a scheduled, scoped block on one or more actions. It is
 * deliberately separate from the maintainer approval flow: approval answers
 * "who may do this?", a freeze answers "may this be done *now*?".
 *
 * Scopes support exact action names and a trailing `*` wildcard:
 *
 *   invoice.cancel          one action
 *   invoice.*               every invoice action
 *   *                       everything
 *
 * Targets are optional. When a window names targets, it only freezes those
 * targets; every other target of the same action keeps working. That is the
 * property the acceptance criteria call "unrelated actions continue outside
 * freeze scope".
 *
 * Emergency work is possible through a scoped, short-lived, single-use bypass.
 * A bypass is validated when an intent is declared and consumed when the action
 * executes, so a bypass issued during a freeze cannot be replayed. Every
 * schedule, revoke, issue and use is emitted to the audit sink configured by the
 * caller.
 */
import { randomUUID } from 'node:crypto';

export type FreezeWindowState = 'scheduled' | 'active' | 'expired' | 'revoked';

export interface FreezeWindowScope {
  /** Action names or trailing-`*` patterns. Never empty. */
  actions: string[];
  /** Optional target ids. An empty/absent list means every target. */
  targets?: string[];
}

export interface FreezeWindow {
  id: string;
  name: string;
  reason: string;
  scope: FreezeWindowScope;
  startsAt: string;
  endsAt: string;
  createdBy: string;
  createdAt: string;
  revokedAt: string | null;
  revokedBy: string | null;
  revocationReason: string | null;
}

export type FreezeBypassState = 'active' | 'used' | 'expired';

export interface FreezeBypass {
  id: string;
  windowId: string;
  action: string;
  target: string | null;
  issuedTo: string;
  reason: string;
  issuedAt: string;
  expiresAt: string;
  usedAt: string | null;
  usedBy: string | null;
}

export type FreezeAuditAction =
  | 'FREEZE_WINDOW_CREATED'
  | 'FREEZE_WINDOW_REVOKED'
  | 'FREEZE_BYPASS_ISSUED'
  | 'FREEZE_BYPASS_USED';

export interface FreezeAuditRecord {
  action: FreezeAuditAction;
  actorId: string;
  windowId: string;
  bypassId?: string;
  reason: string;
  metadata?: Record<string, unknown>;
}

export interface CreateFreezeWindowInput {
  name: string;
  reason: string;
  actions: string[];
  targets?: string[];
  startsAt: string | Date;
  endsAt: string | Date;
  createdBy: string;
}

export interface IssueFreezeBypassInput {
  action: string;
  target?: string | null;
  issuedTo: string;
  reason: string;
}

export interface AssertFreezeInput {
  action: string;
  target?: string | null;
  actor: string;
  bypassId?: string;
  /** Declaration checks should pass `false`; only execution consumes a bypass. */
  consume?: boolean;
}

export class FreezeWindowError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly httpStatus = 409,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'FreezeWindowError';
  }
}

const MAX_WINDOW_MS = 365 * 24 * 60 * 60_000;
const DEFAULT_BYPASS_TTL_MS = 15 * 60_000;

const requireText = (value: unknown, field: string, min = 1, max = 500): string => {
  const text = typeof value === 'string' ? value.trim() : '';
  if (text.length < min || text.length > max) {
    throw new FreezeWindowError(
      'INVALID_FREEZE_WINDOW',
      `${field} must be between ${min} and ${max} characters`,
      400,
      { field }
    );
  }
  return text;
};

const parseDate = (value: string | Date, field: string): Date => {
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new FreezeWindowError('INVALID_FREEZE_WINDOW', `${field} must be a valid date`, 400, { field });
  }
  return date;
};

const normalizePatterns = (values: unknown, field: string): string[] => {
  if (!Array.isArray(values) || values.length === 0) {
    throw new FreezeWindowError('INVALID_FREEZE_WINDOW', `${field} must contain at least one entry`, 400, { field });
  }
  const patterns = values.map((value) => requireText(value, field, 1, 200));
  for (const pattern of patterns) {
    if (!/^[A-Za-z0-9_.:-]+\*?$/.test(pattern)) {
      throw new FreezeWindowError(
        'INVALID_FREEZE_WINDOW',
        `${field} entry "${pattern}" is not an action name or a trailing-wildcard pattern`,
        400,
        { field, pattern }
      );
    }
  }
  return [...new Set(patterns)];
};

/** Exact match, `*`, or a trailing-`*` prefix such as `invoice.*`. */
export function matchesFreezePattern(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return value.startsWith(pattern.slice(0, -1));
  return pattern === value;
}

export class FreezeWindowService {
  private readonly windows = new Map<string, FreezeWindow>();
  private readonly bypasses = new Map<string, FreezeBypass>();
  private readonly now: () => Date;
  private readonly onAudit?: (record: FreezeAuditRecord) => void;
  private readonly maxWindows: number;
  private readonly maxBypasses: number;
  private readonly bypassTtlMs: number;

  constructor(options: {
    now?: () => Date;
    onAudit?: (record: FreezeAuditRecord) => void;
    maxWindows?: number;
    maxBypasses?: number;
    bypassTtlMs?: number;
  } = {}) {
    this.now = options.now ?? (() => new Date());
    this.onAudit = options.onAudit;
    this.maxWindows = Math.max(1, options.maxWindows ?? 1_000);
    this.maxBypasses = Math.max(1, options.maxBypasses ?? 10_000);
    this.bypassTtlMs = Math.max(1_000, options.bypassTtlMs ?? DEFAULT_BYPASS_TTL_MS);
  }

  schedule(input: CreateFreezeWindowInput): FreezeWindow {
    const name = requireText(input.name, 'name', 3, 120);
    const reason = requireText(input.reason, 'reason', 10, 1_000);
    const createdBy = requireText(input.createdBy, 'createdBy', 1, 200);
    const startsAt = parseDate(input.startsAt, 'startsAt');
    const endsAt = parseDate(input.endsAt, 'endsAt');
    if (endsAt.getTime() <= startsAt.getTime()) {
      throw new FreezeWindowError('INVALID_FREEZE_WINDOW', 'endsAt must be after startsAt', 400);
    }
    if (endsAt.getTime() - startsAt.getTime() > MAX_WINDOW_MS) {
      throw new FreezeWindowError('INVALID_FREEZE_WINDOW', 'A freeze window may not exceed 365 days', 400);
    }

    const actions = normalizePatterns(input.actions, 'actions');
    // An empty target list is the same as no target filter: every target of the
    // matching actions is frozen.
    const targets = input.targets === undefined || input.targets.length === 0
      ? undefined
      : normalizePatterns(input.targets, 'targets');
    const now = this.now();
    const window: FreezeWindow = {
      id: randomUUID(),
      name,
      reason,
      scope: { actions, ...(targets ? { targets } : {}) },
      startsAt: startsAt.toISOString(),
      endsAt: endsAt.toISOString(),
      createdBy,
      createdAt: now.toISOString(),
      revokedAt: null,
      revokedBy: null,
      revocationReason: null,
    };

    this.windows.set(window.id, window);
    if (this.windows.size > this.maxWindows) {
      // Retire expired/revoked windows first so scheduled control is not lost.
      const closed = [...this.windows.values()]
        .filter((candidate) => ['expired', 'revoked'].includes(this.stateOf(candidate, now)))
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      const oldest = [...this.windows.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
      const victim = closed[0] ?? oldest;
      if (victim) this.windows.delete(victim.id);
    }

    this.emit({
      action: 'FREEZE_WINDOW_CREATED',
      actorId: createdBy,
      windowId: window.id,
      reason: `Freeze window "${name}" scheduled`,
      metadata: { startsAt: window.startsAt, endsAt: window.endsAt, scope: window.scope },
    });
    return this.cloneWindow(window);
  }

  revoke(id: string, actorId: string, reason: string): FreezeWindow {
    const window = this.windows.get(id);
    if (!window) throw new FreezeWindowError('FREEZE_WINDOW_NOT_FOUND', 'Freeze window not found', 404);
    if (window.revokedAt) {
      throw new FreezeWindowError('FREEZE_WINDOW_ALREADY_REVOKED', 'Freeze window is already revoked', 409);
    }
    const by = requireText(actorId, 'actorId', 1, 200);
    const why = requireText(reason, 'reason', 3, 500);
    const now = this.now();
    window.revokedAt = now.toISOString();
    window.revokedBy = by;
    window.revocationReason = why;
    this.emit({
      action: 'FREEZE_WINDOW_REVOKED',
      actorId: by,
      windowId: id,
      reason: why,
    });
    return this.cloneWindow(window);
  }

  getWindow(id: string): FreezeWindow | null {
    const window = this.windows.get(id);
    return window ? this.cloneWindow(window) : null;
  }

  listWindows(filter: {
    state?: FreezeWindowState;
    action?: string;
    target?: string | null;
    includeExpired?: boolean;
  } = {}): FreezeWindow[] {
    const now = this.now();
    return [...this.windows.values()]
      .filter((window) => {
        const state = this.stateOf(window, now);
        // An explicit state filter is an opt-in to that state. Only the
        // unfiltered list hides closed windows unless includeExpired is set.
        if (!filter.includeExpired && !filter.state && (state === 'expired' || state === 'revoked')) return false;
        if (filter.state && state !== filter.state) return false;
        if (filter.action) {
          const action = filter.action;
          if (!window.scope.actions.some((pattern) => matchesFreezePattern(pattern, action))) return false;
          // A target filter is only applied when the caller supplied one. An
          // action-only query must still show windows that are target-scoped.
          if (filter.target !== undefined && filter.target !== null) {
            const target = filter.target;
            if (
              window.scope.targets?.length &&
              !window.scope.targets.some((pattern) => matchesFreezePattern(pattern, target))
            ) {
              return false;
            }
          }
        }
        return true;
      })
      .sort((a, b) => a.startsAt.localeCompare(b.startsAt) || a.id.localeCompare(b.id))
      .map((window) => this.cloneWindow(window));
  }

  stateOf(window: FreezeWindow, at: Date = this.now()): FreezeWindowState {
    if (window.revokedAt) return 'revoked';
    const nowMs = at.getTime();
    if (nowMs < new Date(window.startsAt).getTime()) return 'scheduled';
    if (nowMs >= new Date(window.endsAt).getTime()) return 'expired';
    return 'active';
  }

  /** Every active window covering this action/target, earliest end first. */
  private activeWindowsFor(action: string, target?: string | null, at: Date = this.now()): FreezeWindow[] {
    return [...this.windows.values()]
      .filter((window) => this.stateOf(window, at) === 'active' && this.scopeMatches(window, action, target))
      .sort((a, b) => a.endsAt.localeCompare(b.endsAt) || a.id.localeCompare(b.id))
      .map((window) => this.cloneWindow(window));
  }

  /** The active window covering this action/target, if any. */
  activeWindowFor(action: string, target?: string | null, at: Date = this.now()): FreezeWindow | null {
    return this.activeWindowsFor(action, target, at)[0] ?? null;
  }

  status(action: string, target?: string | null): { frozen: boolean; window: FreezeWindow | null } {
    const window = this.activeWindowFor(action, target);
    return { frozen: Boolean(window), window };
  }

  issueBypass(windowId: string, input: IssueFreezeBypassInput): FreezeBypass {
    const window = this.windows.get(windowId);
    if (!window) throw new FreezeWindowError('FREEZE_WINDOW_NOT_FOUND', 'Freeze window not found', 404);
    const now = this.now();
    if (this.stateOf(window, now) !== 'active') {
      throw new FreezeWindowError('FREEZE_WINDOW_NOT_ACTIVE', 'Emergency bypasses can only be issued during an active freeze window', 409);
    }

    const action = requireText(input.action, 'action', 1, 200);
    const target = input.target === undefined || input.target === null ? null : requireText(input.target, 'target', 1, 500);
    if (!this.scopeMatches(window, action, target)) {
      throw new FreezeWindowError('BYPASS_OUT_OF_SCOPE', 'The action and target are outside this freeze window', 400);
    }
    const issuedTo = requireText(input.issuedTo, 'issuedTo', 1, 200);
    const reason = requireText(input.reason, 'reason', 10, 500);
    const expiresAt = new Date(Math.min(new Date(window.endsAt).getTime(), now.getTime() + this.bypassTtlMs));
    if (expiresAt.getTime() <= now.getTime()) {
      throw new FreezeWindowError('FREEZE_WINDOW_NOT_ACTIVE', 'The freeze window has already ended', 409);
    }

    const existing = [...this.bypasses.values()].find(
      (bypass) =>
        bypass.windowId === windowId &&
        bypass.action === action &&
        bypass.target === target &&
        bypass.issuedTo === issuedTo &&
        !bypass.usedAt &&
        new Date(bypass.expiresAt).getTime() > now.getTime()
    );
    if (existing) {
      return { ...existing };
    }

    const bypass: FreezeBypass = {
      id: randomUUID(),
      windowId,
      action,
      target,
      issuedTo,
      reason,
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      usedAt: null,
      usedBy: null,
    };
    this.bypasses.set(bypass.id, bypass);
    if (this.bypasses.size > this.maxBypasses) {
      // Prefer evicting closed bypasses so an active emergency grant is not
      // silently lost. A forced eviction still fails closed: the unknown id is
      // rejected with BYPASS_NOT_FOUND.
      const removable = [...this.bypasses.values()]
        .filter((candidate) => this.bypassState(candidate, now) !== 'active')
        .sort((a, b) => a.issuedAt.localeCompare(b.issuedAt));
      const victim =
        removable[0] ??
        [...this.bypasses.values()].sort((a, b) => a.issuedAt.localeCompare(b.issuedAt))[0];
      if (victim) this.bypasses.delete(victim.id);
    }
    this.emit({
      action: 'FREEZE_BYPASS_ISSUED',
      actorId: issuedTo,
      windowId,
      bypassId: bypass.id,
      reason,
      metadata: { action, target, expiresAt: bypass.expiresAt },
    });
    return { ...bypass };
  }

  listBypasses(filter: { windowId?: string; includeUsed?: boolean } = {}): FreezeBypass[] {
    const now = this.now();
    return [...this.bypasses.values()]
      .filter((bypass) => {
        if (filter.windowId && bypass.windowId !== filter.windowId) return false;
        if (!filter.includeUsed && bypass.usedAt) return false;
        return this.bypassState(bypass, now) === 'active' || filter.includeUsed;
      })
      .sort((a, b) => a.issuedAt.localeCompare(b.issuedAt))
      .map((bypass) => ({ ...bypass }));
  }

  getBypass(id: string): FreezeBypass | null {
    const bypass = this.bypasses.get(id);
    return bypass ? { ...bypass } : null;
  }

  /**
   * Checks an action against active freezes.
   *
   * Returns the matching window, or null when the action is not frozen.
   * Throws `ACTION_FROZEN` when a freeze applies and no valid bypass is
   * presented. A valid bypass is consumed when `consume` is not false.
   */
  assertAllowed(input: AssertFreezeInput): FreezeWindow | null {
    const windows = this.activeWindowsFor(input.action, input.target);
    if (windows.length === 0) return null;

    if (!input.bypassId) {
      const window = windows[0]!;
      throw new FreezeWindowError(
        'ACTION_FROZEN',
        `Action ${input.action} is frozen until ${window.endsAt} by "${window.name}": ${window.reason}`,
        423,
        {
          windowId: window.id,
          startsAt: window.startsAt,
          endsAt: window.endsAt,
          windowIds: windows.map((candidate) => candidate.id),
        }
      );
    }

    const bypass = this.bypasses.get(input.bypassId);
    if (!bypass) throw new FreezeWindowError('BYPASS_NOT_FOUND', 'Emergency bypass not found', 404);

    const actor = requireText(input.actor, 'actor', 1, 200);
    const covered = windows.find((window) => window.id === bypass.windowId);
    if (!covered) {
      throw new FreezeWindowError('BYPASS_OUT_OF_SCOPE', 'Emergency bypass belongs to a different freeze window', 403, {
        windowIds: windows.map((candidate) => candidate.id),
      });
    }
    if (bypass.action !== input.action || bypass.target !== (input.target ?? null)) {
      throw new FreezeWindowError('BYPASS_OUT_OF_SCOPE', 'Emergency bypass is scoped to a different action or target', 403);
    }
    if (bypass.issuedTo !== actor) {
      throw new FreezeWindowError('BYPASS_ACTOR_MISMATCH', 'Emergency bypass was issued to a different maintainer', 403);
    }
    const state = this.bypassState(bypass, this.now());
    if (state === 'used') {
      throw new FreezeWindowError('BYPASS_ALREADY_USED', 'Emergency bypass has already been used', 409);
    }
    if (state === 'expired') {
      throw new FreezeWindowError('BYPASS_EXPIRED', 'Emergency bypass has expired', 410);
    }

    // A bypass covers exactly one window. If another active window also
    // matches, keep blocking and leave the single-use grant untouched: it is
    // still valid for its own window once the overlap ends or is revoked.
    const uncovered = windows.filter((window) => window.id !== bypass.windowId);
    if (uncovered.length > 0) {
      const window = uncovered[0]!;
      throw new FreezeWindowError(
        'ACTION_FROZEN',
        `Action ${input.action} is frozen until ${window.endsAt} by "${window.name}": ${window.reason}`,
        423,
        {
          windowId: window.id,
          startsAt: window.startsAt,
          endsAt: window.endsAt,
          windowIds: windows.map((candidate) => candidate.id),
          uncoveredWindowIds: uncovered.map((candidate) => candidate.id),
          bypassId: bypass.id,
        }
      );
    }

    if (input.consume !== false) {
      const now = this.now();
      bypass.usedAt = now.toISOString();
      bypass.usedBy = actor;
      this.emit({
        action: 'FREEZE_BYPASS_USED',
        actorId: actor,
        windowId: covered.id,
        bypassId: bypass.id,
        reason: `Emergency bypass used for ${input.action}`,
        metadata: { action: input.action, target: input.target ?? null },
      });
    }
    return covered;
  }

  bypassState(bypass: FreezeBypass, at: Date = this.now()): FreezeBypassState {
    if (bypass.usedAt) return 'used';
    if (new Date(bypass.expiresAt).getTime() <= at.getTime()) return 'expired';
    return 'active';
  }

  private scopeMatches(window: FreezeWindow, action: string, target?: string | null): boolean {
    if (!window.scope.actions.some((pattern) => matchesFreezePattern(pattern, action))) return false;
    if (!window.scope.targets || window.scope.targets.length === 0) return true;
    if (!target) return false;
    return window.scope.targets.some((pattern) => matchesFreezePattern(pattern, target));
  }

  private emit(record: FreezeAuditRecord): void {
    try {
      this.onAudit?.(record);
    } catch {
      // Audit sinks must not undo a state change that already happened.
    }
  }

  private cloneWindow(window: FreezeWindow): FreezeWindow {
    return {
      ...window,
      scope: {
        actions: [...window.scope.actions],
        ...(window.scope.targets ? { targets: [...window.scope.targets] } : {}),
      },
    };
  }
}
