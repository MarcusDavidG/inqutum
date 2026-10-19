// MVP in-memory backend. Mirrors server.ts exactly in HTTP surface, route
// order, response envelopes and StoredInvoice shape — the only substantive
// difference is the storage adapter passed to createInvoiceRouter. Both
// servers export startServer(port?) with the same signature so the same
// integration harness (see invoice-payment-loop.test.ts) can drive either.
import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import path from 'path';
import dotenv from 'dotenv';
import { createInvoiceRouter } from './routes/invoice.routes';
import { createAuditRouter } from './routes/audit.routes';
import { createExportRouter } from './routes/export.routes';
import { createNotificationRouter } from './routes/notification.routes';
import { createObservabilityRouter } from './routes/observability.routes';
import memoryInvoiceStorage from './storage/memory-invoice-storage';
import invoiceMemoryService from './services/invoice-memory.service';
import paymentMonitorService from './services/payment-monitor.service';
import { createPaymentMonitorRouter } from './routes/payment-monitor.routes';
import { FilePaymentMonitorCheckpointStore } from './services/payment-monitor-checkpoint';
import { SELLER_PUBLIC_KEY } from './config/stellar';
import { assertSafeEnvironment, configuredFrontendOrigins, corsOptions } from './config/runtime';
import { healthHandler, readinessHandler } from './health';
import { securityHeaders } from './security/content-safety';
import { correlationMiddleware } from './observability/telemetry';
import { buildUserSafeErrorResponse, classifyError } from './errors/error-taxonomy';
import { authenticate, requirePermission } from './middleware/access-control';
import { createDisputeRouter } from './routes/dispute.routes';
import { createRiskRouter } from './routes/risk.routes';

import { validateEnvironment } from './config/env-validator';
import { VERIFICATION_CONTRACT_VERSION } from './services/payment-verification';

dotenv.config();
assertSafeEnvironment();

paymentMonitorService.configure({
  invoices: invoiceMemoryService,
  database: undefined,
  checkpoints: new FilePaymentMonitorCheckpointStore(
    process.env.PAYMENT_MONITOR_CURSOR_FILE
      ? path.resolve(process.env.PAYMENT_MONITOR_CURSOR_FILE)
      : path.resolve('data/payment-monitor-checkpoint.json')
  ),
});

// Validate startup environment and secrets safely
const envCheck = validateEnvironment(process.env, { strict: process.env.NODE_ENV === 'production' });
if (envCheck.issues.length > 0 && process.env.NODE_ENV !== 'test') {
  console.warn(`⚠️ Configuration warnings detected:\n  - ${envCheck.issues.join('\n  - ')}`);
}

const app: Application = express();
const PORT = envCheck.validated.PORT || process.env.PORT || 3001;

// Correlation ID & Latency Tracking
app.use(correlationMiddleware());

// Restrictive security headers on every API response
app.use(securityHeaders());

// Middleware
app.use(cors(corsOptions()));

app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));

// Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`${new Date().toISOString()} [${req.correlationId}] - ${req.method} ${req.path}`);
  next();
});

// Root endpoint
app.get('/', (req: Request, res: Response) => {
  res.json({
    name: 'Quittance API (MVP)',
    version: '1.0.0',
    status: 'running',
    mode: memoryInvoiceStorage.mode,
    documentation: '/api/health',
  });
});

// Health check
app.get('/api/health', healthHandler(memoryInvoiceStorage.mode));
app.get('/api/ready', readinessHandler(memoryInvoiceStorage.mode));

// Invoice, Audit & Observability routes
app.use('/api', createInvoiceRouter({ storage: memoryInvoiceStorage }));
app.use('/api', createAuditRouter({ storage: memoryInvoiceStorage }));
app.use('/api', createObservabilityRouter({ storage: memoryInvoiceStorage }));
app.use('/api', createNotificationRouter());
app.use('/api', createExportRouter({ storage: memoryInvoiceStorage }));

// Settlement disputes and safe counterparty risk summaries (#190, #191)
app.use('/api', createDisputeRouter());
app.use('/api', createRiskRouter());

// Mock Stellar endpoint (MVP only)
app.get('/api/stellar/account', authenticate(), requirePermission('stellar:read'), (req: Request, res: Response) => {
  const { publicKey } = req.query;
  res.json({
    success: true,
    data: {
      publicKey: publicKey || 'EXAMPLE',
      balances: [
        { assetCode: 'XLM', balance: '1000.0000000' },
      ],
      sequence: '12345678',
      subentryCount: 0,
    },
    correlationId: req.correlationId,
  });
});

// User-Safe Error handling middleware with taxonomy and correlation tracking
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  if ((err as any).type === 'entity.too.large' || (err as any).status === 413 || (err as any).statusCode === 413) {
    return res.status(413).json({
      success: false,
      code: 'PAYLOAD_TOO_LARGE',
      error: 'Payload too large: request body exceeds 16 kB limit',
    });
  }
  console.error('Unhandled error:', err);
  const classified = classifyError(err);
  const status = (err as any).code === 'CORS_ORIGIN_DENIED' ? 403 : classified.httpStatus || 500;
  const payload = buildUserSafeErrorResponse(err, req.correlationId);

  res.status(status).json(payload);
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    code: 'NOT_FOUND',
    error: 'Endpoint not found',
    correlationId: req.correlationId,
  });
});

/**
 * Starts the HTTP listener.
 *
 * Exported so integration tests can bind an ephemeral port instead of the
 * configured one, and so importing this module never starts a server.
 */
export function startServer(port: number | string = PORT) {
  if (SELLER_PUBLIC_KEY) {
    try {
      paymentMonitorService.start();
    } catch (error) {
      console.warn('Payment monitor not started:', error);
    }
  }

  return app.listen(port, () => {
    console.log('\n🚀 Quittance Backend (MVP Mode)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`✅ Server running on port ${port}`);
    console.log(`📍 API: http://localhost:${port}/api`);
    console.log(`🏥 Health: http://localhost:${port}/api/health`);
    console.log(`💾 Storage: In-Memory (No Database)`);
    console.log(`💰 Dynamic Seller: Each user uses their own wallet!`);
    console.log(`🌐 Frontends: ${configuredFrontendOrigins().join(', ') || 'not configured'}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  });
}

const entryPoint = process.argv[1] ?? '';
if (/server-mvp(\.[cm]?[jt]s)?$/.test(entryPoint)) {
  startServer();
}

function dumpMemorySnapshot(reason: string) {
  try {
    const snapshot = exportMemorySnapshot(memoryStorage);
    const dest = path.resolve(
      process.env.CUTOVER_DUMP_PATH || `data/cutover-snapshot-${Date.now()}.json`
    );
    mkdirSync(path.dirname(dest), { recursive: true });
    writeFileSync(dest, JSON.stringify(snapshot, null, 2));
    console.log(`[cutover] ${reason}: wrote ${snapshot.count} invoices to ${dest}`);
  } catch (error) {
    console.error('[cutover] snapshot dump failed:', error);
  }
}

process.on('SIGUSR1', () => {
  dumpMemorySnapshot('SIGUSR1');
});

process.on('SIGTERM', () => {
  dumpMemorySnapshot('SIGTERM');
  paymentMonitorService.stop();
  process.exit(0);
});

process.on('SIGINT', () => {
  dumpMemorySnapshot('SIGINT');
  paymentMonitorService.stop();
  process.exit(0);
});

export default app;
