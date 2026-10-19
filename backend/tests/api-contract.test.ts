/**
 * API contract drift tests (#55).
 *
 * `docs/API_CONTRACTS.md` describes the integration surface in prose, but prose
 * cannot fail a build. These tests bind prose to the running server:
 *
 *  1. Every route the app actually mounts is declared in API_CONTRACT, and
 *     every declared route is mounted on the surfaces it claims.
 *  2. The success and failure envelopes keep their exact key sets.
 *  3. Emitted error codes stay inside DOMAIN_ERROR_TAXONOMY.
 *  4. The admin surface still refuses unauthenticated callers.
 *  5. The documented statuses are the statuses the server returns.
 *  6. Every declared route appears in docs/API_CONTRACTS.md, so the document
 *     cannot fall behind the manifest either.
 *
 * The route-table checks introspect the app instead of hand-listing paths, so a
 * newly mounted route fails here even if nobody remembers to update the docs.
 */

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Application } from 'express';

import {
  API_CONTRACT,
  CONTRACT_VERSION,
  collectRoutes,
  contractRoutesFor,
  diffContract,
  type RouteDescriptor,
} from '../src/api/contract';
import { DOMAIN_ERROR_TAXONOMY } from '../src/errors/error-taxonomy';

const SELLER = 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN';
const DOC_PATH = path.join(__dirname, '../../docs/API_CONTRACTS.md');

const ENV = {
  NODE_ENV: 'test',
  STELLAR_NETWORK: 'TESTNET',
  // The app builds a Horizon client at import time; nothing here reaches it.
  STELLAR_HORIZON_URL: 'http://127.0.0.1:1',
  // Pins the conditional webhook route so the contract is deterministic.
  WEBHOOK_SIGNING_SECRET: 'contract-drift-test-secret',
  JOBS_ADMIN_TOKEN: 'contract-drift-admin-token',
};

let server: http.Server;
let adminServer: http.Server;
let port: number;
let adminPort: number;
let app: Application;

/** Mounted on server-mvp only, so the Postgres router is prefixed with /api. */
function collectPostgresRoutes(router: any): RouteDescriptor[] {
  return collectRoutes(router).map((r) => ({ method: r.method, path: `/api${r.path}` }));
}

function send(
  target: number,
  method: string,
  urlPath: string,
  body?: unknown,
  headers: Record<string, string> = {}
): Promise<{ status: number; body: any; raw: string }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request(
      {
        host: '127.0.0.1',
        port: target,
        method,
        path: urlPath,
        headers: {
          ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
          ...headers,
        },
      },
      (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let parsed: any;
          try {
            parsed = JSON.parse(raw);
          } catch {
            parsed = undefined;
          }
          resolve({ status: res.statusCode ?? 0, body: parsed, raw });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const request = (method: string, urlPath: string, body?: unknown, headers?: Record<string, string>) =>
  send(port, method, urlPath, body, headers);

const adminRequest = (method: string, urlPath: string, body?: unknown, headers?: Record<string, string>) =>
  send(adminPort, method, urlPath, body, headers);

before(async () => {
  // Must be set before the app is imported: config/stellar.ts builds its client
  // at module load and the webhook router is mounted conditionally.
  for (const [key, value] of Object.entries(ENV)) {
    process.env[key] = value;
  }

  const mod = await import('../src/server-mvp');
  app = mod.default;
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  port = (server.address() as AddressInfo).port;

  // The admin and webhook routes exist only on the Postgres server. Mounting the
  // router on a bare app is enough: every probe below is refused by middleware
  // before any handler reaches storage, so no database is contacted.
  const express = (await import('express')).default;
  const { default: pgRouter } = await import('../src/routes/index');
  const adminApp = express();
  adminApp.use(express.json());
  adminApp.use('/api', pgRouter);
  adminServer = adminApp.listen(0);
  await new Promise((resolve) => adminServer.once('listening', resolve));
  adminPort = (adminServer.address() as AddressInfo).port;
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  if (adminServer) await new Promise((resolve) => adminServer.close(resolve));
});

describe('API contract — route table', () => {
  it('mounts only routes the contract declares (server-mvp)', () => {
    const mounted = collectRoutes(app);
    const drift = diffContract(contractRoutesFor('mvp'), mounted);

    assert.deepEqual(
      drift.undocumented.map((r) => `${r.method} ${r.path}`),
      [],
      'Routes are mounted but missing from API_CONTRACT. Add them to backend/src/api/contract.ts and docs/API_CONTRACTS.md.'
    );
    assert.deepEqual(
      drift.phantom.map((r) => `${r.method} ${r.path}`),
      [],
      'API_CONTRACT declares routes the server does not mount. Remove them or set the documented surfaces.'
    );
  });

  it('mounts only routes the contract declares (Postgres router)', async () => {
    const { default: pgRouter } = await import('../src/routes/index');
    const mounted = collectPostgresRoutes(pgRouter);
    const drift = diffContract(contractRoutesFor('postgres'), mounted);

    assert.deepEqual(
      drift.undocumented.map((r) => `${r.method} ${r.path}`),
      [],
      'Routes are mounted on the Postgres server but missing from API_CONTRACT.'
    );
    assert.deepEqual(
      drift.phantom.map((r) => `${r.method} ${r.path}`),
      [],
      'API_CONTRACT declares Postgres routes that are not mounted.'
    );
  });

  it('keeps the client surface identical across both servers', async () => {
    const { default: pgRouter } = await import('../src/routes/index');
    const shared = contractRoutesFor('mvp').filter((e) => e.path.startsWith('/api/'));
    const mvpKeys = new Set(shared.map((e) => `${e.method} ${e.path}`));
    const pgKeys = new Set(collectPostgresRoutes(pgRouter).map((r) => `${r.method} ${r.path}`));

    // A route declared as available on both servers must actually be on both.
    for (const endpoint of contractRoutesFor('postgres').filter((e) => e.group === 'public')) {
      if (endpoint.surfaces.includes('mvp')) {
        assert.ok(mvpKeys.has(`${endpoint.method} ${endpoint.path}`), `missing from mvp contract: ${endpoint.path}`);
        assert.ok(pgKeys.has(`${endpoint.method} ${endpoint.path}`), `not mounted on Postgres: ${endpoint.path}`);
      }
    }
  });

  it('declares the contract version and keeps it a valid semver', () => {
    assert.match(CONTRACT_VERSION, /^\d+\.\d+\.\d+$/);
  });
});

describe('API contract — response envelopes', () => {
  it('wraps success in { success: true, data }', async () => {
    const res = await request('GET', `/api/invoices?sellerPublicKey=${SELLER}`);

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok('data' in res.body);
    assert.equal('error' in res.body, false);
  });

  it('keeps raw endpoints raw', async () => {
    // Probes and scrapes must not be wrapped: the platform reading them expects
    // the bare payload. Asserted so nobody "fixes" these into an envelope.
    const health = await request('GET', '/api/health');
    assert.equal(health.status, 200);
    assert.equal('success' in health.body, false, '/api/health must stay a raw probe payload');

    const metrics = await request('GET', '/api/metrics');
    assert.equal(metrics.status, 200);
    assert.equal(typeof metrics.raw, 'string', '/api/metrics must stay Prometheus text');
  });

  it('resolves a response kind for every endpoint', () => {
    // Undeclared means the shared envelope; only genuine exceptions opt out.
    for (const endpoint of API_CONTRACT) {
      assert.ok(
        endpoint.responseKind === undefined ||
          endpoint.responseKind === 'envelope' ||
          endpoint.responseKind === 'raw',
        `${endpoint.method} ${endpoint.path} has an unknown responseKind`
      );
    }
  });

  it('keeps the raw-body endpoint list explicit and small', () => {
    // Each of these is read by something that is not a JSON client. Adding a
    // new one is a deliberate act and must be justified in review.
    assert.deepEqual(
      API_CONTRACT.filter((e) => e.responseKind === 'raw').map((e) => e.path).sort(),
      [
        '/',
        '/api/audit/export',
        '/api/exports/:id',
        '/api/health',
        '/api/imports/invoices/template',
        '/api/metrics',
        '/api/ready',
      ].sort()
    );
  });

  it('wraps failure in { success: false, error } with a correlationId', async () => {
    const res = await request('GET', `/api/invoices/00000000-0000-0000-0000-000000000000`);

    assert.equal(res.status, 404);
    assert.equal(res.body.success, false);
    assert.equal(typeof res.body.error, 'string');
    assert.ok(res.body.correlationId, 'failures must carry a correlationId for support');
    assert.equal('data' in res.body, false);
  });

  it('keeps 404 envelope for unknown routes', async () => {
    const res = await request('GET', '/api/definitely-not-a-route');

    assert.equal(res.status, 404);
    assert.equal(res.body.success, false);
    assert.equal(res.body.code, 'NOT_FOUND');
  });

  it('emits only error codes present in the domain taxonomy', async () => {
    // A rejected create is the richest failure path: validation, then a
    // settlement-domain error code.
    const res = await request('POST', '/api/invoices', {
      sellerPublicKey: 'not-a-key',
      amount: '1.0000000',
      assetCode: 'XLM',
    });

    assert.equal(res.body.success, false);
    assert.ok(res.body.code, 'a machine-readable code is required');
    assert.ok(
      res.body.code in DOMAIN_ERROR_TAXONOMY,
      `error code "${res.body.code}" is not in DOMAIN_ERROR_TAXONOMY; add it or reuse an existing code`
    );
    assert.equal(res.body.category, DOMAIN_ERROR_TAXONOMY[res.body.code].category);
    assert.equal(res.body.retryable, DOMAIN_ERROR_TAXONOMY[res.body.code].retryable);
  });

  it('paginates list endpoints with limit, offset and total', async () => {
    const res = await request('GET', `/api/invoices?sellerPublicKey=${SELLER}&limit=1`);

    assert.equal(res.status, 200);
    assert.ok(res.body.pagination, 'list endpoints must return a pagination block');
    for (const key of ['limit', 'offset', 'total']) {
      assert.equal(typeof res.body.pagination[key], 'number', `pagination.${key} must be a number`);
    }
  });
});

describe('API contract — documented statuses', () => {
  /** Probes a representative error/success path per endpoint worth pinning. */
  const probes: Array<{
    endpoint: string;
    expected: number;
    run: () => Promise<number>;
  }> = [
    {
      endpoint: 'GET /api/health',
      expected: 200,
      run: async () => (await request('GET', '/api/health')).status,
    },
    {
      endpoint: 'GET /api/invoices',
      expected: 200,
      run: async () => (await request('GET', `/api/invoices?sellerPublicKey=${SELLER}`)).status,
    },
    {
      endpoint: 'GET /api/invoices',
      expected: 400,
      run: async () => (await request('GET', '/api/invoices')).status,
    },
    {
      endpoint: 'POST /api/invoices',
      expected: 400,
      run: async () => (await request('POST', '/api/invoices', { amount: 'not-a-number' })).status,
    },
    {
      endpoint: 'POST /api/invoices',
      expected: 201,
      run: async () =>
        (
          await request('POST', '/api/invoices', {
            sellerPublicKey: SELLER,
            amount: 12.5,
            assetCode: 'XLM',
          })
        ).status,
    },
    {
      endpoint: 'GET /api/invoices/:id',
      expected: 404,
      run: async () => (await request('GET', '/api/invoices/00000000-0000-0000-0000-000000000000')).status,
    },
    {
      endpoint: 'GET /api/exports/:id',
      expected: 400,
      run: async () => (await request('GET', '/api/exports/00000000-0000-0000-0000-000000000000')).status,
    },
    {
      endpoint: 'GET /api/exports/:id',
      expected: 404,
      run: async () =>
        (
          await request(
            'GET',
            `/api/exports/00000000-0000-0000-0000-000000000000?requester=${SELLER}`
          )
        ).status,
    },
    {
      endpoint: 'POST /api/exports',
      expected: 400,
      run: async () => (await request('POST', '/api/exports', {})).status,
    },
  ];

  for (const probe of probes) {
    it(`${probe.endpoint} returns ${probe.expected}`, async () => {
      const [probeMethod, probePath] = probe.endpoint.split(' ');
      const declared = API_CONTRACT.find((e) => e.method === probeMethod && e.path === probePath);

      assert.ok(declared, `${probe.endpoint} is not in API_CONTRACT`);
      assert.ok(
        declared.responses.includes(probe.expected),
        `${probe.endpoint} is documented as [${declared.responses}] but returns ${probe.expected}. ` +
          'Update API_CONTRACT.responses and docs/API_CONTRACTS.md in the same change.'
      );
      assert.equal(await probe.run(), probe.expected);
    });
  }
});

describe('API contract — admin auth', () => {
  it('refuses /api/ops/health without a token', async () => {
    const res = await adminRequest('GET', '/api/ops/health');

    assert.ok(
      res.status === 401 || res.status === 403,
      `unauthenticated admin call should be refused, got ${res.status}`
    );
    assert.equal(res.body.success, false);
  });

  it('refuses a wrong admin token', async () => {
    const res = await adminRequest('GET', '/api/ops/health', undefined, {
      authorization: 'Bearer wrong-token',
    });

    assert.ok(
      res.status === 401 || res.status === 403,
      `a wrong admin token should be refused, got ${res.status}`
    );
  });

  it('refuses /api/jobs inspection without a token', async () => {
    const res = await adminRequest('GET', '/api/jobs');

    assert.ok(
      res.status === 401 || res.status === 403,
      `unauthenticated job inspection should be refused, got ${res.status}`
    );
  });

  it('rejects inbound webhooks with a bad signature', async () => {
    const res = await adminRequest('POST', '/api/webhooks/incoming', { type: 'test' }, {
      'x-webhook-signature': 'sha256=deadbeef',
      'x-webhook-timestamp': String(Math.floor(Date.now() / 1000)),
      'x-webhook-event-id': 'evt-contract-drift',
    });

    assert.equal(res.status, 401, 'a bad signature must be refused');
    assert.equal(res.body.code, 'INVALID_SIGNATURE');
  });

  it('rejects inbound webhooks missing required headers', async () => {
    const res = await adminRequest('POST', '/api/webhooks/incoming', { type: 'test' });

    assert.equal(res.status, 400, 'missing signature headers must be rejected as malformed');
    assert.equal(res.body.code, 'MALFORMED_WEBHOOK');
  });

  it('documents auth for every endpoint', () => {
    for (const endpoint of API_CONTRACT) {
      assert.ok(
        ['none', 'admin', 'hmac', 'public', 'maintainer'].includes(endpoint.auth),
        `${endpoint.method} ${endpoint.path} has an unknown auth mode "${endpoint.auth}"`
      );
    }
  });

  it('marks every hmac endpoint as conditional on a signing secret', () => {
    for (const endpoint of API_CONTRACT.filter((e) => e.auth === 'hmac')) {
      assert.ok(
        endpoint.conditional,
        `${endpoint.path} is HMAC-protected but is not marked conditional, so the drift check would be flaky`
      );
    }
  });
});

describe('API contract — documentation', () => {
  const doc = fs.readFileSync(DOC_PATH, 'utf-8');

  it('documents every declared route', () => {
    const missing = API_CONTRACT.filter((e) => !doc.includes(e.path)).map((e) => `${e.method} ${e.path}`);

    assert.deepEqual(
      missing,
      [],
      'Routes are missing from docs/API_CONTRACTS.md. Every entry in API_CONTRACT must be documented.'
    );
  });

  it('documents the contract version it was generated against', () => {
    assert.ok(doc.includes(CONTRACT_VERSION), 'docs/API_CONTRACTS.md must state the contract version it matches');
  });

  it('includes both success and failure examples', () => {
    assert.ok(/success/i.test(doc), 'the doc must show a success example');
    assert.ok(/"success":\s*false/.test(doc), 'the doc must show a failure example');
  });
});
