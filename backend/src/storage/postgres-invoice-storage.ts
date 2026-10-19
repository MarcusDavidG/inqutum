import invoiceService, { InvoiceService } from '../services/invoice.service';
import { CreateInvoiceInput } from '../utils/validation';
import type { InvoiceCursor } from './invoice-cursor';
import type { InvoiceStats } from './invoice-stats';
import type { InvoiceStorage, OverduePendingInvoices, PayerInfo, StoredInvoice } from './invoice-storage';
import { auditStore, AuditEvent, AuditFilter, AuditQueryResult } from '../audit/audit-service';
import { recordAuditEvent } from '../audit/record-event';

/**
 * PostgreSQL storage backend. Same contract as the in-memory backend, but the
 * invoices survive restarts. Field parity with the memory backend is enforced
 * through the shared StoredInvoice interface: every column the Postgres path
 * writes (seller_email, asset_issuer, payer_name/email, expires_at, metadata,
 * paid_at) is matched by the same field name in MemoryStorage. Behavioural
 * parity (expires_at > NOW() guard in markAsPaid, seller-scoped list+stats,
 * PENDING-only cancel) is enforced by the SQL WHERE clauses mirroring the
 * branches in memory-storage.ts.
 *
 * This adapter deliberately makes one service call per operation and lets
 * failures propagate unchanged. In particular, it does not retry writes after
 * an ambiguous database failure; callers must use the established idempotency
 * and error-handling paths rather than risk applying a state change twice.
 */
export class PostgresInvoiceStorage implements InvoiceStorage {
  readonly mode = 'postgres';

  constructor(private readonly service: InvoiceService = invoiceService) {}

  async createInvoice(input: CreateInvoiceInput): Promise<StoredInvoice> {
    return this.service.createInvoice(input);
  }

  async getInvoiceById(id: string): Promise<StoredInvoice | null> {
    return this.service.getInvoiceById(id);
  }

  async getInvoiceByExternalId(externalId: string): Promise<StoredInvoice | null> {
    return this.service.getInvoiceByExternalId(externalId);
  }

  async updateInvoiceMutableFields(
    id: string,
    patch: {
      description?: string;
      customerName?: string;
      customerEmail?: string;
      sellerName?: string;
      sellerEmail?: string;
    }
  ): Promise<StoredInvoice | null> {
    return this.service.updateInvoiceMutableFields(id, patch);
  }

  async getInvoicesBySeller(
    sellerPublicKey: string,
    status?: string,
    limit = 50,
    offset = 0,
    after?: InvoiceCursor
  ): Promise<StoredInvoice[]> {
    return this.service.getInvoicesBySeller(sellerPublicKey, status, limit, offset, after);
  }

  async cancelInvoice(id: string, expectedVersion?: number): Promise<StoredInvoice> {
    return this.service.cancelInvoice(id, expectedVersion);
  }

  async markAsPaid(
    id: string,
    txHash: string,
    payerPublicKey: string,
    payerInfo?: PayerInfo,
    expectedVersion?: number
  ): Promise<StoredInvoice> {
    return this.service.markAsPaid(id, txHash, payerPublicKey, payerInfo, expectedVersion);
  }

  async getInvoiceStats(sellerPublicKey: string): Promise<InvoiceStats[]> {
    return this.service.getInvoiceStats(sellerPublicKey);
  }

  async markExpiredInvoices(now?: Date): Promise<number> {
    return this.service.markExpiredInvoices(now);
  }

  async findOverduePendingInvoices(cutoff: Date, limit: number): Promise<OverduePendingInvoices> {
    return this.service.findOverduePendingInvoices(cutoff, limit);
  }

  async getAllInvoices(filter?: { status?: string }): Promise<StoredInvoice[]> {
    return this.service.getAllInvoices(filter);
  }

  async recordAuditEvent(event: Omit<AuditEvent, 'id' | 'timestamp'> & { timestamp?: string }): Promise<AuditEvent> {
    return recordAuditEvent(event);
  }

  async getAuditEvents(filter?: AuditFilter): Promise<AuditQueryResult> {
    return auditStore.queryEvents(filter);
  }

  async getAuditEventsByInvoice(invoiceId: string): Promise<AuditEvent[]> {
    return auditStore.getEventsByEntity(invoiceId);
  }
}

export default new PostgresInvoiceStorage();
