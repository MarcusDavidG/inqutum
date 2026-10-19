import { InvoiceMemoryService } from '../services/invoice-memory.service';
import { CreateInvoiceInput } from '../utils/validation';
import type { InvoiceCursor } from './invoice-cursor';
import type { InvoiceStats } from './invoice-stats';
import type { InvoiceStorage, OverduePendingInvoices, PayerInfo, StoredInvoice } from './invoice-storage';
import { auditStore, AuditEvent, AuditFilter, AuditQueryResult } from '../audit/audit-service';
import { recordAuditEvent } from '../audit/record-event';

export class MemoryInvoiceStorage implements InvoiceStorage {
  readonly mode = 'in-memory';

  constructor(private readonly service: InvoiceMemoryService = new InvoiceMemoryService()) {}

  async createInvoice(input: CreateInvoiceInput): Promise<StoredInvoice> {
    return this.service.createInvoice(input);
  }

  async getInvoiceById(id: string): Promise<StoredInvoice | null> {
    const invoice = await this.service.getInvoiceById(id);
    return invoice ?? null;
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

export default new MemoryInvoiceStorage();
