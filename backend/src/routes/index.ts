import { Router } from 'express';
import stellarController from '../controllers/stellar.controller';
import paymentMonitorService from '../services/payment-monitor.service';
import postgresInvoiceStorage from '../storage/postgres-invoice-storage';
import { createInvoiceRouter } from './invoice.routes';
import { createAuditRouter } from './audit.routes';
import { createExportRouter } from './export.routes';
import { createNotificationRouter } from './notification.routes';
import { createEmailRouter } from './email.routes';
import { createObservabilityRouter } from './observability.routes';
import { createJobsRouter } from './jobs.routes';
import { createOpsRouter } from './ops.routes';
import { createWebhookRouter } from './webhook.routes';
import { PostgresJobStore } from '../jobs/postgres-job-store';
import { pool } from '../config/database';
import { EmailDeliveryService } from '../notifications/email-delivery';
import { PostgresCheckpointStore } from '../recovery/side-effect-checkpoint';
import { healthHandler, readinessHandler } from '../health';
import { PostgresIdempotencyStore } from '../idempotency/postgres-store';
import { createAuthRouter } from './auth.routes';
import { createReconciliationRouter } from './reconciliation.routes';
import { authenticate, requirePermission } from '../middleware/access-control';
import { createQuotaRouter } from './quota.routes';
import { createAnalyticsRouter } from './analytics.routes';
import { createDisputeRouter } from './dispute.routes';
import { createRiskRouter } from './risk.routes';
import { createImportRouter } from './import.routes';
import { createPaymentMonitorRouter } from './payment-monitor.routes';

const router: Router = Router();

// Health check
router.get('/health', healthHandler(postgresInvoiceStorage.mode));
router.get('/ready', readinessHandler(postgresInvoiceStorage.mode));

// Invoice routes — same handlers the MVP server uses, backed by PostgreSQL
router.use(createInvoiceRouter({ storage: postgresInvoiceStorage }));
router.use(createAuditRouter({ storage: postgresInvoiceStorage }));
router.use(createObservabilityRouter({ storage: postgresInvoiceStorage }));
router.use(createNotificationRouter());
// Keyed sends are checkpointed in Postgres so a crash mid-send is detected after restart (#289).
router.use(createEmailRouter({ service: new EmailDeliveryService({ checkpoints: new PostgresCheckpointStore(pool) }) }));
router.use(createExportRouter({ storage: postgresInvoiceStorage }));

const jobStore = new PostgresJobStore(pool);
router.use(createJobsRouter({ store: jobStore }));
router.use(createOpsRouter({ storage: postgresInvoiceStorage, jobs: jobStore }));

// Webhook routes (only mounted when WEBHOOK_SIGNING_SECRET is set)
const webhookRouter = createWebhookRouter({});
if (webhookRouter) router.use(webhookRouter);

// Bulk import (issue #53). Dry run by default; opt in with dryRun: false.
router.use(createImportRouter({ storage: postgresInvoiceStorage }));

// Email delivery & queue routes
router.use(createQuotaRouter());
router.use(createAnalyticsRouter());

// Wallet sign-in and role introspection
router.use(createAuthRouter());

// Read-only reconciliation dry run (operators and services only)
router.use(createReconciliationRouter({ storage: postgresInvoiceStorage }));

// Settlement disputes and safe counterparty risk summaries (#190, #191)
router.use(createDisputeRouter());
router.use(createRiskRouter());

// Stellar routes. These proxy Horizon on the server's quota, so they need a
// signed-in caller rather than being an open relay.
router.use('/stellar', authenticate(), requirePermission('stellar:read'));
router.get('/stellar/account', stellarController.getAccountInfo.bind(stellarController));
router.get('/stellar/payments', stellarController.getPayments.bind(stellarController));
router.get('/stellar/transaction/:hash', stellarController.getTransaction.bind(stellarController));
router.post('/stellar/verify-payment', stellarController.verifyPayment.bind(stellarController));
router.use(createPaymentMonitorRouter(paymentMonitorService));

export default router;
