/**
 * Constrained SafeBox service adapter (SafeBox side of the trust boundary).
 *
 * Two ports, never mixed:
 *  - AiPort: the ONLY object the MCP gateway receives. Four fixed operations (status, check, prepare, payment status),
 *    all scoped to an account resolved from a verified OAuth principal. It can create an immutable approval REQUEST
 *    and read state; it has no reference to any signer, owner device, Root admin socket or Vault control socket.
 *  - OwnerPort: used by the owner's enrolled device app (in V0: the simulated V5 devices in the mock harness). It reads a
 *    pending request for display and forwards the device-signed exact payment capability to the Vault, which verifies it
 *    against its OWN Root replica (epoch, Purpose, credential status, WebAuthn UV, holds, limits). The OwnerPort grants no
 *    authority by itself: without a valid enrolled-device assertion over the exact capability the Vault refuses.
 *
 * Authority, settlement, buffers, holds, Rapid-Use, anomaly delay and post-approval verification all stay in the existing
 * V5 Root/Vault code; this adapter only adds the approval-request handoff (one-use, exact, expiring, idempotent).
 */
import { createHash, randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { loadV5, type V5Modules } from "./loadV5.js";

export const REQUEST_DOMAIN = "DIAPORIA_SAFEBOX_EXTERNAL_INTERACTOR_APPROVAL_REQUEST_V0\n";
export const REQUEST_TTL_MS = 15 * 60_000;
export const MAX_AWAITING_PER_ACCOUNT = 10;
/** Per AI client: one client cannot exhaust the account-wide cap on its own. */
export const MAX_AWAITING_PER_CLIENT = 3;
export const MAX_MEMO = 140;
export const ASSET = "NEAR" as const;

export class InteractorError extends Error {
  constructor(readonly code: string, message: string, readonly details: Record<string, unknown> = {}) { super(message); this.name = "InteractorError"; }
}

/** Envelope returned by the V5 DirectClient wire (`{ok, result}` or `{ok:false, error:{code, detail}}`). */
export type Envelope = { ok: true; result: any } | { ok: false; error: { code: string; detail?: string } };

/**
 * What the adapter may touch for ONE SafeBox account. Built by the host process from the V5 world; contains no owner
 * device, no signer, no Root admin client and no Vault control client.
 */
export interface AccountBinding {
  accountRef: string;
  /** General Zone client of the Vault: PROPOSE / STATUS / HEALTH / ROOT_VIEW only (V3/V5 vaultOps().gz). */
  gz: { request(op: "PROPOSE" | "STATUS" | "HEALTH" | "ROOT_VIEW", args: Record<string, unknown>): Promise<Envelope> };
  /** Read-only Mock Ledger client (TX_STATUS for receipt verification). */
  ledgerRead: { request(op: "TX_STATUS", args: { txId: string }): Promise<Envelope> };
  /** Read-only views of the Vault: its OWN Root replica, spend counters, buffer configuration, cap->payment index. */
  vaultRead: {
    replica(): any;
    spent(): { cumulativeYocto: string; last24hYocto: string };
    bufferMs(): number;
    minBufferMs(): number;
    paymentIdForCap(capId: string): string | null;
  };
  now(): number;
}

export type RequestState = "AWAITING_OWNER_APPROVAL" | "OWNER_SUBMITTING" | "SUBMITTED_TO_VAULT" | "VAULT_REJECTED" | "OWNER_DECLINED" | "EXPIRED";

export interface ApprovalRequest {
  requestId: string; accountRef: string; clientRef: string; recipientId: string; amountYocto: string; asset: "NEAR"; memo: string;
  purposeId: string; purposeVersion: string; epoch: string; chainId: string; vaultAccountId: string;
  createdAt: number; expiresAt: number; requestDigest: string; state: RequestState; capId: string | null; paymentId: string | null; vaultCode: string | null;
}

export interface PaymentArgs { recipientId: string; amountYocto: string; asset: "NEAR" }

export type RequestDigestFields = Omit<ApprovalRequest, "requestDigest" | "state" | "capId" | "paymentId" | "vaultCode" | "clientRef">;
/** Pure: domain-separated SHA-256 over the V3 canonical encoding of the immutable request fields (devices recompute it). */
export function computeRequestDigest(canon: (o: unknown) => string, f: RequestDigestFields): string {
  const fields = { requestId: f.requestId, accountRef: f.accountRef, recipientId: f.recipientId, amountYocto: f.amountYocto, asset: f.asset, memo: f.memo, purposeId: f.purposeId,
    purposeVersion: f.purposeVersion, epoch: f.epoch, chainId: f.chainId, vaultAccountId: f.vaultAccountId, createdAt: new Date(f.createdAt).toISOString(), expiresAt: new Date(f.expiresAt).toISOString() };
  return createHash("sha256").update(REQUEST_DOMAIN + canon(fields)).digest("hex");
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const iso = (t: number) => new Date(t).toISOString();

/** Untrusted text (merchant memo, AI-supplied note): printable ASCII only, bounded, never interpreted. */
export function sanitizeUntrusted(s: string, max = MAX_MEMO): string {
  return s.replace(/[^\x20-\x7e]/g, "?").replace(/["\\|`]/g, "'").slice(0, max);
}

export class SafeBoxService {
  readonly db: DatabaseSync;
  private readonly accounts = new Map<string, AccountBinding>();
  private constructor(private readonly v5: V5Modules, dbPath: string) {
    this.db = new DatabaseSync(dbPath);
    this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS approval_requests (
        request_id TEXT PRIMARY KEY, account_ref TEXT NOT NULL, client_ref TEXT NOT NULL, idem_key TEXT NOT NULL, body_digest TEXT NOT NULL,
        request_digest TEXT NOT NULL UNIQUE, recipient TEXT NOT NULL, amount TEXT NOT NULL, asset TEXT NOT NULL, memo TEXT NOT NULL,
        purpose_id TEXT NOT NULL, purpose_version TEXT NOT NULL, epoch TEXT NOT NULL, chain_id TEXT NOT NULL, vault_account TEXT NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, state TEXT NOT NULL, cap_id TEXT, payment_id TEXT, vault_code TEXT, updated_at INTEGER NOT NULL,
        UNIQUE (account_ref, client_ref, idem_key));
      CREATE UNIQUE INDEX IF NOT EXISTS approval_requests_cap ON approval_requests(cap_id) WHERE cap_id IS NOT NULL;
      CREATE TABLE IF NOT EXISTS request_events (n INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, at INTEGER NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
      CREATE TRIGGER IF NOT EXISTS request_events_append_only BEFORE DELETE ON request_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
      CREATE TRIGGER IF NOT EXISTS request_events_no_update BEFORE UPDATE ON request_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;`);
  }
  static async open(dbPath: string): Promise<SafeBoxService> { return new SafeBoxService(await loadV5(), dbPath); }
  close() { this.db.close(); }

  addAccount(b: AccountBinding) {
    if (!/^[a-z0-9][a-z0-9-]{2,40}$/.test(b.accountRef)) throw new Error("bad accountRef");
    if (this.accounts.has(b.accountRef)) throw new Error("duplicate accountRef");
    this.accounts.set(b.accountRef, b);
  }
  private acct(accountRef: string): AccountBinding {
    const a = this.accounts.get(accountRef);
    if (!a) throw new InteractorError("ACCOUNT_NOT_AVAILABLE", "No SafeBox account is bound to this principal");
    return a;
  }

  // ------------------------------------------------------------------ shared read helpers
  private snapshot(a: AccountBinding) {
    const now = a.now();
    const replica = a.vaultRead.replica();
    const s = this.v5.chain.projectState(replica, now);
    return { now, replica, s };
  }
  private blockers(a: AccountBinding, s: any, now: number, recipientId: string | null): string[] {
    const b: string[] = [];
    if (s.freeze?.active) b.push("FREEZE_ACTIVE");
    if (s.lockdown?.active) b.push("EMERGENCY_LOCKDOWN_ACTIVE");
    if (s.case) b.push("RECOVERY_OR_GOVERNANCE_CASE_OPEN");
    if (recipientId && this.v5.holds.merchantHolds(s, recipientId, now).length) b.push("MERCHANT_HOLD_ACTIVE");
    const payRoles = new Set<string>((s.matrix?.rules?.PAY?.anyOf ?? []).flatMap((alt: Record<string, string>) => Object.keys(alt)));
    const payCreds = Object.values<any>(s.creds ?? {}).filter((c) => c.status === "active" && payRoles.has(c.role));
    if (!payCreds.length) b.push("NO_ACTIVE_PAYMENT_CREDENTIAL");
    else if (payCreds.every((c) => this.v5.holds.credentialHolds(s, c.credId, now).length)) b.push("ALL_PAYMENT_CREDENTIALS_HELD");
    return b;
  }
  private policyViolations(a: AccountBinding, s: any, now: number, p: PaymentArgs, excludeAwaiting = false): string[] {
    const spent = a.vaultRead.spent();
    let reserved = 0n;
    if (!excludeAwaiting) for (const r of this.awaiting(a.accountRef, now)) reserved += BigInt(r.amount);
    const adj = { cumulativeYocto: (BigInt(spent.cumulativeYocto) + reserved).toString(), last24hYocto: (BigInt(spent.last24hYocto) + reserved).toString() };
    return this.v5.capsule.purposeViolations(s.purpose, { operation: "PAY", recipientId: p.recipientId, asset: p.asset, amountYocto: p.amountYocto, sku: null,
      now, capExpiresAt: now + REQUEST_TTL_MS, capIssuedAt: now }, adj);
  }
  private awaiting(accountRef: string, now: number): Array<{ request_id: string; amount: string }> {
    return this.db.prepare("SELECT request_id, amount FROM approval_requests WHERE account_ref=? AND state='AWAITING_OWNER_APPROVAL' AND expires_at>?").all(accountRef, now) as any;
  }
  private event(requestId: string, at: number, event: string, detail: Record<string, unknown> = {}) {
    this.db.prepare("INSERT INTO request_events (request_id, at, event, detail) VALUES (?,?,?,?)").run(requestId, at, event, JSON.stringify(detail));
  }
  private row(accountRef: string, requestId: string): ApprovalRequest | null {
    const r = this.db.prepare("SELECT * FROM approval_requests WHERE request_id=? AND account_ref=?").get(requestId, accountRef) as any;
    return r ? this.toReq(r) : null;
  }
  /** AI-side lookup: a client sees only the requests IT prepared (same account is not enough). */
  private clientRow(accountRef: string, clientRef: string, requestId: string): ApprovalRequest | null {
    const r = this.db.prepare("SELECT * FROM approval_requests WHERE request_id=? AND account_ref=? AND client_ref=?").get(requestId, accountRef, clientRef) as any;
    return r ? this.toReq(r) : null;
  }
  /**
   * Late-acceptance reconciliation: if a request was closed as NOT_RECEIVED_BY_VAULT but the Vault's own cap index
   * shows the capability was accepted, attach the Vault payment (the Vault is authoritative; never the other way round).
   */
  private reconcile(a: AccountBinding, r: ApprovalRequest): ApprovalRequest {
    if (r.state === "VAULT_REJECTED" && r.vaultCode === "NOT_RECEIVED_BY_VAULT" && r.capId) {
      const pid = a.vaultRead.paymentIdForCap(r.capId);
      if (pid) {
        const now = a.now();
        const u = this.db.prepare("UPDATE approval_requests SET state='SUBMITTED_TO_VAULT', payment_id=?, vault_code=NULL, updated_at=? WHERE request_id=? AND state='VAULT_REJECTED' AND vault_code='NOT_RECEIVED_BY_VAULT' AND cap_id=?").run(pid, now, r.requestId, r.capId);
        if (u.changes === 1) this.event(r.requestId, now, "LATE_VAULT_ACCEPTANCE_RECONCILED", { paymentId: pid });
        return this.row(r.accountRef, r.requestId)!;
      }
    }
    return r;
  }
  /** Requests whose PROPOSE is in flight in THIS process; recovery never touches them. */
  private readonly inFlight = new Set<string>();
  private toReq(r: any): ApprovalRequest {
    return { requestId: r.request_id, accountRef: r.account_ref, clientRef: r.client_ref, recipientId: r.recipient, amountYocto: r.amount, asset: r.asset, memo: r.memo,
      purposeId: r.purpose_id, purposeVersion: r.purpose_version, epoch: r.epoch, chainId: r.chain_id, vaultAccountId: r.vault_account, createdAt: Number(r.created_at),
      expiresAt: Number(r.expires_at), requestDigest: r.request_digest, state: r.state, capId: r.cap_id, paymentId: r.payment_id, vaultCode: r.vault_code };
  }
  private expireDue(accountRef: string, now: number) {
    const due = this.db.prepare("SELECT request_id FROM approval_requests WHERE account_ref=? AND state='AWAITING_OWNER_APPROVAL' AND expires_at<=?").all(accountRef, now) as any[];
    for (const d of due) {
      const u = this.db.prepare("UPDATE approval_requests SET state='EXPIRED', updated_at=? WHERE request_id=? AND state='AWAITING_OWNER_APPROVAL'").run(now, d.request_id);
      if (u.changes === 1) this.event(d.request_id, now, "EXPIRED");
    }
  }
  /** The digest a device binds into the payment capability (`taskRef`). */
  static taskRefFor(requestDigest: string): string { return "mcp-" + requestDigest.slice(0, 48); }
  requestDigestOf(fields: RequestDigestFields): string { return computeRequestDigest(this.v5.canon.canon, fields); }

  // ================================================================== AI PORT (the only thing the MCP gateway gets)
  aiPort(): AiPort {
    const self = this;
    // A frozen object of four closures: no prototype access to the service, its database or the bindings.
    return Object.freeze({
      status: (accountRef: string) => self.status(accountRef),
      check: (accountRef: string, p: PaymentArgs) => self.check(accountRef, p),
      prepare: (accountRef: string, clientRef: string, p: PaymentArgs & { memo: string; idempotencyKey: string }) => self.prepare(accountRef, clientRef, p),
      paymentStatus: (accountRef: string, clientRef: string, requestId: string) => self.paymentStatus(accountRef, clientRef, requestId),
    });
  }

  status(accountRef: string) {
    const a = this.acct(accountRef);
    const { now, s } = this.snapshot(a);
    this.expireDue(accountRef, now);
    const holds = this.v5.holds.effectiveHolds(s, now);
    const byKind: Record<string, number> = {};
    for (const h of holds) byKind[h.scope.kind] = (byKind[h.scope.kind] ?? 0) + 1;
    const spent = a.vaultRead.spent();
    const reserved = this.awaiting(accountRef, now).reduce((t, x) => t + BigInt(x.amount), 0n);
    const remaining = BigInt(s.purpose.dailyLimitYocto) - BigInt(spent.last24hYocto) - reserved;
    const rapidActive = Object.values<any>(s.v5?.rapid?.grants ?? {}).some((g) => g.status === "ACTIVE" && now < Number(g.expiresAt));
    return {
      accountRef, environment: "MOCK" as const, observedAt: iso(now),
      protection: { frozen: !!s.freeze?.active, emergencyLockdown: !!s.lockdown?.active, activeHolds: holds.length, activeHoldsByScope: byKind, rapidUseActive: rapidActive,
        blockers: this.blockers(a, s, now, null) },
      purpose: { purposeId: String(s.purpose.purposeId), version: String(s.purpose.version), asset: String(s.purpose.asset), allowedRecipients: [...s.purpose.recipients].map(String),
        perPaymentMaxYocto: String(s.purpose.perPaymentMaxYocto), dailyLimitYocto: String(s.purpose.dailyLimitYocto),
        remainingDailyYocto: (remaining > 0n ? remaining : 0n).toString() },
      epoch: String(s.epoch),
      settlement: { minimumBufferMs: a.vaultRead.minBufferMs(), configuredBufferMs: a.vaultRead.bufferMs(), note: "Every approved payment waits at least the buffer before release; the Vault re-checks Root state at release." },
      pendingApprovalRequests: this.awaiting(accountRef, now).length,
      redaction: "Credential ids, device keys, contacts, guardians and journal contents are never returned.",
    };
  }

  check(accountRef: string, p: PaymentArgs) {
    const a = this.acct(accountRef);
    const { now, s } = this.snapshot(a);
    this.expireDue(accountRef, now);
    const violations = this.policyViolations(a, s, now, p);
    const blockers = this.blockers(a, s, now, p.recipientId);
    return {
      isAuthorization: false as const, environment: "MOCK" as const, observedAt: iso(now),
      wouldBeAcceptedForOwnerApproval: violations.length === 0 && blockers.length === 0,
      policyViolations: violations, blockers,
      payment: { recipientId: p.recipientId, amountYocto: p.amountYocto, asset: p.asset },
      estimate: { feeYocto: "0", feeModel: "MOCK_LEDGER_NO_FEE" as const, minimumBufferMs: a.vaultRead.minBufferMs(), configuredBufferMs: a.vaultRead.bufferMs(),
        anomalyDelay: "POSSIBLE: the Risk Policy Engine may delay a payment of an unusual flow (bounded, at most 24 h); not predictable from this check" },
      statement: "This is a read-only estimate. It authorizes nothing. Payment requires the owner's approval on an enrolled SafeBox device, then Vault verification and the settlement buffer.",
    };
  }

  prepare(accountRef: string, clientRef: string, p: PaymentArgs & { memo: string; idempotencyKey: string }) {
    const a = this.acct(accountRef);
    const { now, replica, s } = this.snapshot(a);
    this.expireDue(accountRef, now);
    const memo = sanitizeUntrusted(p.memo);
    const bodyDigest = sha(JSON.stringify([p.recipientId, p.amountYocto, p.asset, memo]));
    const existing = this.db.prepare("SELECT * FROM approval_requests WHERE account_ref=? AND client_ref=? AND idem_key=?").get(accountRef, clientRef, p.idempotencyKey) as any;
    if (existing) {
      if (existing.body_digest !== bodyDigest) throw new InteractorError("IDEMPOTENCY_CONFLICT", "This idempotencyKey was already used with different payment details");
      return { ...this.preparedView(this.toReq(existing)), idempotentReplay: true };
    }
    const violations = this.policyViolations(a, s, now, p);
    const blockers = this.blockers(a, s, now, p.recipientId);
    if (violations.length || blockers.length)
      throw new InteractorError("NOT_PREPARABLE", "SafeBox policy would refuse this payment; no approval request was created", { policyViolations: violations, blockers });
    const fields = { requestId: "apr_" + randomBytes(16).toString("hex"), accountRef, recipientId: p.recipientId, amountYocto: p.amountYocto, asset: ASSET, memo,
      purposeId: String(s.purpose.purposeId), purposeVersion: String(s.purpose.version), epoch: String(s.epoch), chainId: String(replica.chainId), vaultAccountId: String(replica.accountId),
      createdAt: now, expiresAt: now + REQUEST_TTL_MS };
    const requestDigest = this.requestDigestOf(fields);
    // Atomic: pending cap + idempotency uniqueness (concurrent identical calls collapse to one row).
    try {
      this.db.exec("BEGIN IMMEDIATE");
      const n = (this.db.prepare("SELECT COUNT(*) n FROM approval_requests WHERE account_ref=? AND state='AWAITING_OWNER_APPROVAL' AND expires_at>?").get(accountRef, now) as any).n;
      if (Number(n) >= MAX_AWAITING_PER_ACCOUNT) throw new InteractorError("TOO_MANY_PENDING_REQUESTS", `At most ${MAX_AWAITING_PER_ACCOUNT} approval requests may await the owner at once`);
      const nc = (this.db.prepare("SELECT COUNT(*) n FROM approval_requests WHERE account_ref=? AND client_ref=? AND state='AWAITING_OWNER_APPROVAL' AND expires_at>?").get(accountRef, clientRef, now) as any).n;
      if (Number(nc) >= MAX_AWAITING_PER_CLIENT) throw new InteractorError("TOO_MANY_PENDING_REQUESTS", `At most ${MAX_AWAITING_PER_CLIENT} approval requests from this client may await the owner at once`);
      this.db.prepare(`INSERT INTO approval_requests (request_id, account_ref, client_ref, idem_key, body_digest, request_digest, recipient, amount, asset, memo, purpose_id, purpose_version, epoch, chain_id, vault_account, created_at, expires_at, state, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'AWAITING_OWNER_APPROVAL',?)`).run(fields.requestId, accountRef, clientRef, p.idempotencyKey, bodyDigest, requestDigest, fields.recipientId,
        fields.amountYocto, fields.asset, memo, fields.purposeId, fields.purposeVersion, fields.epoch, fields.chainId, fields.vaultAccountId, fields.createdAt, fields.expiresAt, now);
      this.event(fields.requestId, now, "CREATED", { clientRef });
      this.db.exec("COMMIT");
    } catch (e) {
      try { this.db.exec("ROLLBACK"); } catch { /* not in a transaction */ }
      if (e instanceof InteractorError) throw e;
      const again = this.db.prepare("SELECT * FROM approval_requests WHERE account_ref=? AND client_ref=? AND idem_key=?").get(accountRef, clientRef, p.idempotencyKey) as any;
      if (again && again.body_digest === bodyDigest) return { ...this.preparedView(this.toReq(again)), idempotentReplay: true };
      if (again) throw new InteractorError("IDEMPOTENCY_CONFLICT", "This idempotencyKey was already used with different payment details");
      throw e;
    }
    return { ...this.preparedView(this.row(accountRef, fields.requestId)!), idempotentReplay: false };
  }
  private preparedView(r: ApprovalRequest) {
    return {
      requestId: r.requestId, state: r.state, requestDigest: r.requestDigest, expiresAt: iso(r.expiresAt),
      payment: { recipientId: r.recipientId, amountYocto: r.amountYocto, asset: r.asset },
      boundTo: { purposeId: r.purposeId, purposeVersion: r.purposeVersion, epoch: r.epoch },
      ownerAction: { kind: "APPROVE_ON_ENROLLED_SAFEBOX_DEVICE" as const, deviceIntent: `safebox-device://approval-request/${r.requestId}`,
        instruction: "Ask the owner to open the SafeBox app on an enrolled device and review this exact request. The owner's device shows the details from SafeBox itself, not from this conversation." },
      paymentEffect: "NONE" as const, signed: false as const, settled: false as const,
    };
  }

  async paymentStatus(accountRef: string, clientRef: string, requestId: string) {
    const a = this.acct(accountRef);
    const now = a.now();
    this.expireDue(accountRef, now);
    const r0 = this.clientRow(accountRef, clientRef, requestId);
    if (!r0) throw new InteractorError("NOT_FOUND", "No such approval request for this client");
    const r = this.reconcile(a, r0);
    let payment: null | { paymentId: string; vaultState: string; releaseAt: string | null; reason: string | null } = null;
    let receipt: { txId: string; ledgerStatus: string; matchesRequest: boolean } | null = null;
    if (r.paymentId) {
      const st = await a.gz.request("STATUS", { paymentId: r.paymentId });
      if (st.ok) {
        payment = { paymentId: r.paymentId, vaultState: String(st.result.state), releaseAt: st.result.releaseAt ? iso(Number(st.result.releaseAt)) : null, reason: st.result.reason ?? null };
        if (st.result.txId) {
          const tx = await a.ledgerRead.request("TX_STATUS", { txId: String(st.result.txId) });
          if (tx.ok && tx.result.found) receipt = { txId: String(tx.result.txId), ledgerStatus: String(tx.result.status),
            matchesRequest: tx.result.recipient === r.recipientId && tx.result.amountYocto === r.amountYocto && tx.result.paymentId === r.paymentId };
        }
      }
    }
    const settledVerified = payment?.vaultState === "SETTLED" && receipt?.ledgerStatus === "SETTLED" && receipt.matchesRequest === true;
    return {
      requestId: r.requestId, requestState: r.state, environment: "MOCK" as const, observedAt: iso(now), expiresAt: iso(r.expiresAt),
      payment: { recipientId: r.recipientId, amountYocto: r.amountYocto, asset: r.asset },
      vault: payment, ledgerReceipt: receipt, vaultRejectionCode: r.vaultCode,
      settledVerified, stateIsVerifiedBy: "SAFEBOX_VAULT_AND_MOCK_LEDGER" as const,
      statement: settledVerified ? "Settled on the MOCK ledger; the Vault state and the ledger receipt agree with the approved request. No real NEAR moved."
        : "Not settled. Only report what vault.vaultState says; nothing is paid until settledVerified is true.",
    };
  }

  // ================================================================== OWNER PORT (enrolled device app; never given to the gateway)
  ownerPort(): OwnerPort {
    const self = this;
    return Object.freeze({
      pending: (accountRef: string, requestId: string) => self.ownerPending(accountRef, requestId),
      decline: (accountRef: string, requestId: string) => self.ownerDecline(accountRef, requestId),
      submit: (accountRef: string, requestId: string, signed: { capability: any; approval: any }) => self.ownerSubmit(accountRef, requestId, signed),
      recover: (accountRef: string) => self.recover(accountRef),
    });
  }
  private ownerPending(accountRef: string, requestId: string): ApprovalRequest {
    const a = this.acct(accountRef); this.expireDue(accountRef, a.now());
    const r = this.row(accountRef, requestId);
    if (!r) throw new InteractorError("NOT_FOUND", "No such approval request");
    return this.reconcile(a, r);
  }
  private ownerDecline(accountRef: string, requestId: string) {
    const a = this.acct(accountRef); const now = a.now();
    const u = this.db.prepare("UPDATE approval_requests SET state='OWNER_DECLINED', updated_at=? WHERE request_id=? AND account_ref=? AND state='AWAITING_OWNER_APPROVAL'").run(now, requestId, accountRef);
    if (u.changes !== 1) throw new InteractorError("REQUEST_NOT_AWAITING", "Request is not awaiting approval");
    this.event(requestId, now, "OWNER_DECLINED");
    return { requestId, state: "OWNER_DECLINED" as const };
  }
  private async ownerSubmit(accountRef: string, requestId: string, signed: { capability: any; approval: any }) {
    const a = this.acct(accountRef); const now = a.now();
    this.expireDue(accountRef, now);
    const r = this.row(accountRef, requestId);
    if (!r) throw new InteractorError("NOT_FOUND", "No such approval request");
    if (r.state !== "AWAITING_OWNER_APPROVAL") throw new InteractorError("REQUEST_NOT_AWAITING", `Request is ${r.state}`);
    const cap = signed?.capability;
    if (!cap || typeof cap !== "object" || Array.isArray(cap) || !signed.approval || typeof signed.approval !== "object") throw new InteractorError("BAD_APPROVAL", "capability and approval objects are required");
    // Exactness: the device-signed capability must be for THIS request and nothing else (the Vault re-verifies everything else).
    const mismatch: string[] = [];
    if (cap.recipientId !== r.recipientId) mismatch.push("recipientId");
    if (cap.amountYocto !== r.amountYocto) mismatch.push("amountYocto");
    if (cap.asset !== r.asset) mismatch.push("asset");
    if (cap.operation !== "PAY") mismatch.push("operation");
    if (cap.accountId !== r.vaultAccountId || cap.chainId !== r.chainId) mismatch.push("account");
    if (cap.epoch !== r.epoch) mismatch.push("epoch");
    if (cap.purposeId !== r.purposeId || cap.purposeVersion !== r.purposeVersion) mismatch.push("purpose");
    const v6 = signed.approval.v6;
    if (v6 !== undefined) {
      // V6 per-transaction owner approval: the binding names THIS request (id + digest) and the capability's taskRef is
      // derived from the binding, so one device signature covers request, amount, recipient, asset, Purpose, Epoch,
      // credential, policy version and expiry. The Vault re-verifies the binding, the one-time challenge and the gate.
      const b = v6 && typeof v6 === "object" ? v6.binding : null;
      if (!b || typeof b !== "object" || b.v !== this.v5.v6pa.BINDING_V) mismatch.push("v6.binding");
      else {
        if (b.requestId !== r.requestId) mismatch.push("v6.requestId");
        if (b.requestDigest !== r.requestDigest) mismatch.push("v6.requestDigest");
        if (b.recipientId !== r.recipientId || b.amountYocto !== r.amountYocto || b.asset !== r.asset) mismatch.push("v6.payment");
        if (cap.taskRef !== this.v5.v6pa.taskRefFor(b)) mismatch.push("taskRef(v6.binding)");
      }
    } else if (cap.taskRef !== SafeBoxService.taskRefFor(r.requestDigest)) mismatch.push("taskRef(requestDigest)");
    if (typeof cap.capId !== "string" || !/^[0-9a-f-]{36}$/.test(cap.capId)) mismatch.push("capId");
    if (mismatch.length) { this.event(requestId, now, "OWNER_SUBMIT_MISMATCH", { fields: mismatch }); throw new InteractorError("CAPABILITY_MISMATCH", "The signed capability does not match this approval request", { fields: mismatch }); }
    // One-use: only one submission can move the request out of AWAITING.
    let u;
    try { u = this.db.prepare("UPDATE approval_requests SET state='OWNER_SUBMITTING', cap_id=?, updated_at=? WHERE request_id=? AND account_ref=? AND state='AWAITING_OWNER_APPROVAL'").run(cap.capId, now, requestId, accountRef); }
    catch { throw new InteractorError("CAPABILITY_ALREADY_USED", "This capability was already submitted for another request"); }
    if (u.changes !== 1) throw new InteractorError("REQUEST_NOT_AWAITING", "Request was already submitted");
    this.event(requestId, now, "OWNER_SUBMITTING", { capId: cap.capId });
    this.inFlight.add(requestId);
    try {
      const env = await a.gz.request("PROPOSE", { capability: cap, approval: signed.approval, recipientId: r.recipientId, amountYocto: r.amountYocto, asset: r.asset, memo: `external-interactor ${r.requestId}` });
      return this.finishSubmit(a, { ...r, capId: cap.capId }, env);
    } finally { this.inFlight.delete(requestId); }
  }
  private finishSubmit(a: AccountBinding, r: ApprovalRequest, env: Envelope) {
    const now = a.now();
    if (env.ok) {
      let u = this.db.prepare("UPDATE approval_requests SET state='SUBMITTED_TO_VAULT', payment_id=?, updated_at=? WHERE request_id=? AND state='OWNER_SUBMITTING'").run(String(env.result.paymentId), now, r.requestId);
      // A concurrent recovery (other process) may have closed it as NOT_RECEIVED: the Vault accepted, so the Vault wins.
      if (u.changes !== 1) u = this.db.prepare("UPDATE approval_requests SET state='SUBMITTED_TO_VAULT', payment_id=?, vault_code=NULL, updated_at=? WHERE request_id=? AND state='VAULT_REJECTED' AND vault_code='NOT_RECEIVED_BY_VAULT' AND cap_id=?").run(String(env.result.paymentId), now, r.requestId, r.capId);
      if (u.changes !== 1) throw new InteractorError("STATE_CONFLICT", "Vault accepted the payment but the request record could not be updated; check get_payment_status", { paymentId: env.result.paymentId });
      this.event(r.requestId, now, "SUBMITTED_TO_VAULT", { paymentId: env.result.paymentId, vaultState: env.result.state });
      return { requestId: r.requestId, state: "SUBMITTED_TO_VAULT" as const, paymentId: String(env.result.paymentId), vaultState: String(env.result.state) };
    }
    const code = String(env.error.code).slice(0, 60);
    const u = this.db.prepare("UPDATE approval_requests SET state='VAULT_REJECTED', vault_code=?, updated_at=? WHERE request_id=? AND state='OWNER_SUBMITTING'").run(code, now, r.requestId);
    if (u.changes !== 1) throw new InteractorError("STATE_CONFLICT", "Request record changed while the Vault was deciding");
    this.event(r.requestId, now, "VAULT_REJECTED", { code });
    return { requestId: r.requestId, state: "VAULT_REJECTED" as const, vaultCode: code };
  }
  /** Crash recovery: a request left in OWNER_SUBMITTING is resolved from the Vault's own cap index (never re-signed). */
  private recover(accountRef: string) {
    const a = this.acct(accountRef); const now = a.now(); const out: Array<{ requestId: string; state: RequestState }> = [];
    for (const row of this.db.prepare("SELECT * FROM approval_requests WHERE account_ref=? AND state='OWNER_SUBMITTING'").all(accountRef) as any[]) {
      if (this.inFlight.has(row.request_id)) continue; // a live submit in this process: not a crash
      const pid = row.cap_id ? a.vaultRead.paymentIdForCap(row.cap_id) : null;
      if (pid) {
        this.db.prepare("UPDATE approval_requests SET state='SUBMITTED_TO_VAULT', payment_id=?, updated_at=? WHERE request_id=? AND state='OWNER_SUBMITTING'").run(pid, now, row.request_id);
        this.event(row.request_id, now, "RECOVERED_SUBMITTED", { paymentId: pid }); out.push({ requestId: row.request_id, state: "SUBMITTED_TO_VAULT" });
      } else {
        // The Vault never accepted this capability. Fail closed: the request ends; the owner must start a fresh one.
        this.db.prepare("UPDATE approval_requests SET state='VAULT_REJECTED', vault_code='NOT_RECEIVED_BY_VAULT', updated_at=? WHERE request_id=? AND state='OWNER_SUBMITTING'").run(now, row.request_id);
        this.event(row.request_id, now, "RECOVERED_NOT_RECEIVED"); out.push({ requestId: row.request_id, state: "VAULT_REJECTED" });
      }
    }
    return out;
  }
  events(requestId: string) { return this.db.prepare("SELECT at, event, detail FROM request_events WHERE request_id=? ORDER BY n").all(requestId) as any[]; }
}

export interface AiPort {
  status(accountRef: string): ReturnType<SafeBoxService["status"]>;
  check(accountRef: string, p: PaymentArgs): ReturnType<SafeBoxService["check"]>;
  prepare(accountRef: string, clientRef: string, p: PaymentArgs & { memo: string; idempotencyKey: string }): ReturnType<SafeBoxService["prepare"]>;
  paymentStatus(accountRef: string, clientRef: string, requestId: string): ReturnType<SafeBoxService["paymentStatus"]>;
}
export interface OwnerPort {
  pending(accountRef: string, requestId: string): ApprovalRequest;
  decline(accountRef: string, requestId: string): { requestId: string; state: "OWNER_DECLINED" };
  submit(accountRef: string, requestId: string, signed: { capability: any; approval: any }): Promise<{ requestId: string; state: RequestState; paymentId?: string; vaultState?: string; vaultCode?: string }>;
  recover(accountRef: string): Array<{ requestId: string; state: RequestState }>;
}
