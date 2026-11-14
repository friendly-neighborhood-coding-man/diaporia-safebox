// SafeBox V5 Execution Vault = the V3/V4 vault (own Root replica, exact capabilities, buffered release with a
// release-time re-check, freeze semantics, idempotent ledger submission) plus:
//   * ANOMALY_PAYMENT_DELAY: the Risk Policy Engine's signed decision may push the release time of SPECIFIC unsettled
//     payments of ONE flow, bounded by a vault-enforced hard cap (24 h). Amount, recipient, asset, Purpose and the
//     original authorization are never touched; settled payments are never "stopped" (recorded as such).
//   * targeted holds: MERCHANT / DELEGATION scoped holds block only the affected flow; CREDENTIAL holds act through the
//     replica's derived credential status; GLOBAL holds through the replica's derived freeze.
//   * Rapid-Use: the vault itself verifies an ACTIVE grant on its own Root replica before removing an anomaly delay,
//     and only for payments inside the grant's exact scope; Purpose limits and every other check still apply.
//   * delegated execution: a delegate (AI agent) key may execute payments inside an owner-granted capability scope
//     (recipients, asset, per-op max, cumulative max, max uses, expiry), counted durably here.
//   * every lifecycle step is mirrored into the Footprint Journal (VAULT layer).
import { randomBytes, randomUUID } from 'node:crypto';
import { fail, exactFields, iso, uint, isoMs, canon } from '../../v3/common/canon.mjs';
import { ExecutionVault } from '../../v3/vault/vault.mjs';
import { purposeViolations } from '../../v3/root/capsule.mjs';
import { V5_DOMAINS, d5hex, verifyObj5 } from '../common/v5.mjs';
import { merchantHolds, delegationHolds, credentialHolds } from '../root/holds.mjs';
import { RISK_POLICY_V1 } from '../risk/detector.mjs';
import { bufferFloorMs, MAX_BUFFER_MS, tierToBufferMs } from '../risk/buffer.mjs';

const HOLDING = ['RESERVED', 'BUFFERED', 'RELEASED', 'UNKNOWN', 'FROZEN'];
const V5_SCHEMA = `
CREATE TABLE IF NOT EXISTS v5_pay (payment_id TEXT PRIMARY KEY, flow TEXT NOT NULL, cred_id TEXT NOT NULL, delegation_id TEXT, recipient TEXT NOT NULL, amount TEXT NOT NULL,
  proposed_at INTEGER NOT NULL, anomaly TEXT NOT NULL, delay_ms INTEGER NOT NULL, incident_id TEXT, rapid_grant TEXT, baseline_eligible INTEGER NOT NULL, decision TEXT, settled_before_detection INTEGER NOT NULL DEFAULT 0, cap_expires_orig INTEGER,
  risk_class TEXT NOT NULL DEFAULT 'NONE', auth_issued_at INTEGER, settle_deadline INTEGER, buffer_ms INTEGER, tier INTEGER);
CREATE TABLE IF NOT EXISTS v5_incidents (incident_id TEXT PRIMARY KEY, flow TEXT NOT NULL, cred_id TEXT NOT NULL, opened_at INTEGER NOT NULL, state TEXT NOT NULL,
  last_trigger_at INTEGER NOT NULL, delayed_count INTEGER NOT NULL, reasons TEXT NOT NULL, closed_at INTEGER, settled_before INTEGER NOT NULL, exposure_before TEXT NOT NULL, risk_class TEXT NOT NULL DEFAULT 'LOW', triggers INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS v5_security (n INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, type TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS v5_deleg_use (delegation_id TEXT NOT NULL, op_seq INTEGER NOT NULL, payment_id TEXT NOT NULL, amount TEXT NOT NULL, PRIMARY KEY (delegation_id, op_seq));
CREATE TABLE IF NOT EXISTS v5_rapid_use (grant_id TEXT NOT NULL, payment_id TEXT PRIMARY KEY, amount TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS v5_pay_no_delete BEFORE DELETE ON v5_pay BEGIN SELECT RAISE(ABORT, 'append-only'); END;
`;
const SECURITY_EFFECTS = new Set(['SUSPENDED', 'HOLD_CREATED', 'RECOVERY_OPENED', 'REVOKED', 'FROZEN', 'CONTEST_RESOLVED', 'GOV_CASE_OPENED', 'RAPID_USE_REQUESTED']);
const MAX_DELAY_MS = Number(RISK_POLICY_V1.delay.maxDelayMs); // vault-side hard cap, independent of the engine
const DUE_STATES = ['BUFFERED'];

export class ExecutionVaultV5 extends ExecutionVault {
  constructor(cfg, deps) {
    super(cfg, deps);
    this.engine = deps.engine; this.enginePublicKey = deps.enginePublicKey; this.journal = deps.journal; this.jw = deps.journal?.writer('VAULT');
    this.onIncident = deps.onIncident ?? (() => {}); this.onRapidRule = deps.onRapidRule ?? (() => {});
    this.store.db.exec(V5_SCHEMA);
    this.mirrorSeq = Number(this.store.getControl('v5MirrorSeq') ?? 0);
    this.metrics = { detectionLatencyMs: [], decisionsMs: [] };
    // the vault's own floor must match the owner-signed policy on its replica (never lower than the signed floor)
    if (this.cfg.minBufferMs !== bufferFloorMs(this.bufferPolicy())) fail('BUFFER_POLICY_FLOOR_MISMATCH', `${this.cfg.minBufferMs} vs ${this.bufferPolicy()}`);
    this.#failSafeUnevaluated();
  }
  bufferPolicy() { return this.root.v5.config.bufferPolicy ?? 'FIXED_600'; }
  /**
   * Restart safety (P4): a payment the V3 core reserved but the V5 layer never evaluated (crash between the two steps)
   * would otherwise keep the policy floor (30 s under EXP_30). It gets the maximum buffer instead.
   */
  #failSafeUnevaluated() {
    for (const r of this.store.db.prepare("SELECT p.payment_id, p.proposed_at, p.release_at FROM payments p LEFT JOIN v5_pay v ON v.payment_id=p.payment_id WHERE p.state='BUFFERED' AND v.payment_id IS NULL AND p.cap_id NOT LIKE 'hist-%'").all())
      if (r.release_at < r.proposed_at + MAX_BUFFER_MS) { this.store.db.prepare("UPDATE payments SET release_at=? WHERE payment_id=? AND state='BUFFERED'").run(r.proposed_at + MAX_BUFFER_MS, r.payment_id); this.store.journal(r.payment_id, 'BUFFERED', 'BUFFERED', 'vault', { event: 'UNEVALUATED_AFTER_RESTART', releaseAt: r.proposed_at + MAX_BUFFER_MS }); }
  }
  ref(credId) { return this.journal ? this.journal.ref('cred', credId) : credId; }
  #j(ev) { try { this.jw?.append(ev); } catch (e) { if (e.code === 'JOURNAL_PRIVACY_VIOLATION') throw e; } }
  #attempt(ev) { try { this.jw?.attempt(ev); } catch {} }
  spent() {
    const rows = this.store.db.prepare(`SELECT amount, proposed_at FROM payments WHERE state IN (${[...HOLDING, 'SETTLED'].map(() => '?').join(',')})`).all(...HOLDING, 'SETTLED');
    const now = this.now(); let cum = 0n, day = 0n;
    for (const r of rows) { cum += BigInt(r.amount); if (r.proposed_at > now - 86_400_000) day += BigInt(r.amount); }
    return { cumulativeYocto: cum.toString(), last24hYocto: day.toString() };
  }

  // ------------------------------------------------ payments
  propose(args) {
    const t0 = Date.now();
    try {
      exactFields(args, ['capability', 'approval', 'recipientId', 'amountYocto', 'asset', 'memo'], [], 'PROPOSE_FIELDS');
    } catch (e) { this.store.decision('gz', 'PROPOSE', 'DENY', [e.code ?? 'INVALID']); throw e; } // malformed input: decision log only, never the authoritative journal
    const credId = String(args.approval?.credId ?? '?');
    try {
      if (merchantHolds(this.root, args.recipientId, this.now()).length) fail('MERCHANT_HOLD_ACTIVE');
      if (credentialHolds(this.root, credId, this.now()).length) fail('CREDENTIAL_HOLD_ACTIVE');
    } catch (e) { this.#attempt({ type: 'PAYMENT_REJECTED', principal: this.ref(credId), outcome: e.code, epoch: this.root.epoch, purposeVersion: this.root.purpose.version }); throw e; }
    let r;
    try { r = super.propose(args); }
    catch (e) {
      // recorded only after the trust-boundary validation above, and rate-limited per principal
      this.#attempt({ type: e.code === 'PAYCAP_BAD_SIGNATURE' || e.code === 'WEBAUTHN_BAD_SIGNATURE' ? 'INVALID_SIGNATURE' : 'PAYMENT_REJECTED', principal: this.ref(credId), outcome: `${e.code}:${String(e.detail ?? '').slice(0, 80)}`,
        epoch: this.root.epoch, purposeVersion: this.root.purpose.version, untrusted: { recipient: String(args.recipientId).slice(0, 64) } });
      throw e;
    }
    const out = this.#afterPropose(r.paymentId, { credId, delegationId: null, memo: args.memo });
    this.metrics.decisionsMs.push(Date.now() - t0);
    return out;
  }
  /** Delegated execution: the delegate key signs {delegationId, seq, recipient, asset, amount, opId, issuedAt}. */
  proposeDelegated({ op, sig }) {
    const now = this.now();
    exactFields(op, ['v', 'delegationId', 'seq', 'recipientId', 'asset', 'amountYocto', 'opId', 'issuedAt', 'memo'], [], 'DELEGATED_OP_FIELDS');
    const d = this.root.v5.delegations[op.delegationId];
    const deny = (code, detail) => { this.#attempt({ type: 'DELEGATED_PAYMENT_REJECTED', principal: this.ref('delegation:' + op.delegationId), outcome: code, relatedId: op.delegationId }); fail(code, detail); };
    if (!d || d.status !== 'ACTIVE' || now >= Number(d.expiresAt)) deny('DELEGATION_NOT_ACTIVE');
    if (op.v !== 'safebox.v5.delegated-op') deny('DELEGATED_OP_VERSION');
    if (!verifyObj5(V5_DOMAINS.DELEGATED_OP, op, sig, d.delegateKey)) deny('DELEGATED_OP_BAD_SIGNATURE');
    if (d.epoch !== String(this.root.epoch) || d.purposeVersion !== this.root.purpose.version) deny('DELEGATION_STALE');
    const issuer = this.root.creds[d.issuerCredId];
    if (!issuer || issuer.status !== 'active' || credentialHolds(this.root, d.issuerCredId, now).length) deny('DELEGATION_ISSUER_RESTRICTED');
    if (delegationHolds(this.root, d.delegationId, now).length) deny('DELEGATION_HOLD_ACTIVE');
    if (merchantHolds(this.root, op.recipientId, now).length) deny('MERCHANT_HOLD_ACTIVE');
    if (this.root.freeze.active) deny('FREEZE_ACTIVE');
    if (this.root.lockdown.active) deny('EMERGENCY_LOCKDOWN_ACTIVE');
    if (!d.recipients.includes(op.recipientId)) deny('RECIPIENT_NOT_IN_DELEGATION');
    if (op.asset !== d.asset) deny('ASSET_NOT_IN_DELEGATION');
    const amt = uint(op.amountYocto, 'amountYocto'); if (amt <= 0n || amt > BigInt(d.perOpMaxYocto)) deny('OVER_DELEGATION_PER_OP');
    const ia = isoMs(op.issuedAt, 'issuedAt'); if (ia > now + 300_000 || now - ia > 600_000) deny('DELEGATED_OP_STALE');
    const seq = Number(uint(op.seq, 'seq'));
    const used = this.store.db.prepare('SELECT COUNT(*) n FROM v5_deleg_use WHERE delegation_id=?').get(d.delegationId);
    const usedAmt = this.store.db.prepare('SELECT amount FROM v5_deleg_use WHERE delegation_id=?').all(d.delegationId).reduce((t, r) => t + BigInt(r.amount), 0n);
    if (used.n + 1 > Number(d.maxUses)) deny('DELEGATION_MAX_USES_EXHAUSTED');
    if (usedAmt + amt > BigInt(d.cumulativeMaxYocto)) deny('OVER_DELEGATION_CUMULATIVE');
    if (this.store.db.prepare('SELECT 1 FROM v5_deleg_use WHERE delegation_id=? AND op_seq=?').get(d.delegationId, seq)) deny('DELEGATED_OP_REPLAY');
    const pv = purposeViolations(this.root.purpose, { operation: 'PAY', recipientId: op.recipientId, asset: op.asset, amountYocto: op.amountYocto, sku: null, now, capExpiresAt: Number(d.expiresAt), capIssuedAt: Number(d.grantedAt) }, this.spent())
      .filter(v => v !== 'CAPABILITY_TTL_TOO_LONG'); // a delegation's lifetime is bounded by the Root (delegationMaxTtlMs), not the per-payment cap TTL
    if (pv.length) deny('POLICY_DENY', pv.join(','));
    const paymentId = 'p_' + randomUUID().replaceAll('-', ''); const capId = randomUUID();
    const row = this.store.tx(() => {
      if (this.store.byState(['RESERVED', 'BUFFERED', 'RELEASED', 'UNKNOWN']).length + 1 > 16) fail('PENDING_COUNT_LIMIT');
      this.store.db.prepare(`INSERT INTO payments (payment_id, cap_id, cap_digest, principal_id, policy_id, policy_digest, recipient, asset, amount, intent_nonce, state, proposed_at, cap_expires_at, memo, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?, 'PROPOSED', ?,?,?,?)`).run(paymentId, capId, d5hex(V5_DOMAINS.DELEGATED_OP, op), this.root.accountId, this.root.purpose.purposeId, this.root.purposeDigest,
        op.recipientId, op.asset, op.amountYocto, randomBytes(16).toString('hex'), now, Number(d.expiresAt), JSON.stringify(String(op.memo).replace(/[^\x20-\x7e]/g, '?').slice(0, 280)), now);
      this.store.db.prepare('INSERT INTO cap_evidence (cap_id, payment_id, cap, approval, cred_id, epoch, purpose_version, sku, nonce) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(capId, paymentId, JSON.stringify({ delegated: op }), JSON.stringify({ delegateSig: sig }), d.issuerCredId, this.root.epoch, this.root.purpose.version, '-', randomBytes(16).toString('hex'));
      this.store.db.prepare('INSERT INTO v5_deleg_use (delegation_id, op_seq, payment_id, amount) VALUES (?,?,?,?)').run(d.delegationId, seq, paymentId, op.amountYocto);
      this.store.db.prepare('INSERT INTO caps_used (cap_id, payment_id) VALUES (?,?)').run(capId, paymentId);
      this.store.journal(paymentId, null, 'PROPOSED', 'delegate', { delegationId: d.delegationId, seq: String(seq), recipient: op.recipientId, amount: op.amountYocto });
      this.store.move(paymentId, 'PROPOSED', 'AUTHORIZED', 'policy', { decision: 'ALLOW', delegation: d.delegationId });
      this.store.move(paymentId, 'AUTHORIZED', 'RESERVED', 'policy', { reservedYocto: op.amountYocto });
      return this.store.move(paymentId, 'RESERVED', 'BUFFERED', 'policy', { releaseAt: now + this.cfg.bufferMs }, { release_at: now + this.cfg.bufferMs });
    });
    return this.#afterPropose(row.payment_id, { credId: d.issuerCredId, delegationId: d.delegationId, memo: op.memo });
  }

  /** Behavioural evaluation of a freshly BUFFERED payment; bounded targeted delay if the engine's predefined rule says so. */
  #afterPropose(paymentId, { credId, delegationId, memo }) {
    const now = this.now(); const row = this.store.get(paymentId);
    const flow = delegationId ? 'dg:' + delegationId : 'cred:' + credId;
    const grant = this.rapidGrantFor({ credId, delegationId, recipient: row.recipient, amount: row.amount, asset: row.asset });
    const open = this.store.db.prepare("SELECT * FROM v5_incidents WHERE flow=? AND state='OPEN' ORDER BY opened_at DESC LIMIT 1").get(flow) ?? null;
    const p = { paymentId, flow, credId, recipient: row.recipient, amount: row.amount, at: now, state: 'BUFFERED' };
    const ctx = { history: this.history(), purpose: this.root.purpose, spent: this.spentExcluding(paymentId), securityTimes: this.securityTimes(), rapid: !!grant };
    const dec = this.engine.decide(p, ctx, { openIncident: grant ? null : open, bufferPolicy: this.bufferPolicy() });
    if (!verifyObj5(V5_DOMAINS.RISK_ENGINE, dec.statement, dec.sig, this.enginePublicKey)) fail('ENGINE_DECISION_SIGNATURE'); // the vault trusts only the pinned engine key
    // P2: the four times of a payment authorization are kept apart. submission deadline = the authorization's own
    // expiresAt (checked at proposal), consumption = now, earliest release = now + buffer (+ bounded anomaly delay),
    // latest settlement = authorization issuedAt + the owner-signed settlementHorizonMs (never the risk engine's choice).
    const authIssuedAt = this.#authIssuedAt(paymentId, delegationId);
    const settleDeadline = Math.min(authIssuedAt + this.horizonMs(), Date.parse(this.root.purpose.expiresAt));
    // P4: the buffer comes from the engine's signed decision, but the vault re-derives it from the signed tier and
    // clamps it to [owner-signed floor, 600 s]; an engine statement for another policy is refused.
    if (dec.statement.bufferPolicy !== this.bufferPolicy()) fail('ENGINE_BUFFER_POLICY_MISMATCH');
    const bufferMs = Math.min(MAX_BUFFER_MS, Math.max(this.cfg.minBufferMs, tierToBufferMs(this.bufferPolicy(), dec.statement.tier)));
    this.store.db.prepare('INSERT INTO v5_pay (payment_id, flow, cred_id, delegation_id, recipient, amount, proposed_at, anomaly, delay_ms, incident_id, rapid_grant, baseline_eligible, decision, cap_expires_orig, auth_issued_at, settle_deadline, buffer_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(paymentId, flow, credId, delegationId, row.recipient, row.amount, now, 'NONE', 0, null, grant?.grantId ?? null, grant ? 0 : 1, JSON.stringify({ action: dec.statement.action, reasons: dec.ev.reasons.map(r => r.code), statement: dec.statement, sig: dec.sig }),
        row.cap_expires_at, authIssuedAt, settleDeadline, bufferMs);
    this.store.db.prepare('UPDATE v5_pay SET tier=? WHERE payment_id=?').run(dec.statement.tier === '-' ? null : Number(dec.statement.tier), paymentId);
    this.store.db.prepare("UPDATE payments SET release_at=? WHERE payment_id=? AND state='BUFFERED'").run(now + bufferMs, paymentId);
    // the vault's release check (`now >= cap_expires_at` -> EXPIRED) now enforces the latest authorized settlement
    this.store.db.prepare("UPDATE payments SET cap_expires_at=? WHERE payment_id=? AND state='BUFFERED'").run(settleDeadline, paymentId);
    if (grant) this.store.db.prepare('INSERT INTO v5_rapid_use (grant_id, payment_id, amount) VALUES (?,?,?)').run(grant.grantId, paymentId, row.amount);
    this.#j({ type: 'PAYMENT_PROPOSED', principal: this.ref(credId), relatedId: paymentId, outcome: 'BUFFERED', epoch: this.root.epoch, purposeVersion: this.root.purpose.version,
      operationDigest: row.cap_digest, data: { flow: this.ref(flow), recipient: row.recipient, amount: row.amount, rapidGrant: grant?.grantId ?? '-', decision: dec.statement.action, reasons: dec.ev.reasons.map(r => r.code).join(','), score: dec.ev.score },
      sealed: { memo: String(memo ?? '').slice(0, 280) } });
    if (dec.ev.decision !== 'NONE' || dec.statement.action !== 'NONE') this.#j({ type: 'UNUSUAL_ACTIVITY_DETECTED', principal: this.ref(credId), relatedId: paymentId, outcome: dec.statement.action,
      data: { flow: this.ref(flow), level: dec.ev.decision, reasons: dec.ev.reasons.map(r => `${r.cls}:${r.code}`).join(','), features: { ...dec.ev.features, flow: this.ref(flow) }, policy: dec.statement.policy, policyDigest: dec.statement.policyDigest } });
    if (dec.statement.action === 'DELAY' || dec.statement.action === 'DELAY_AND_END_RAPID') {
      const inc = open ?? this.#openIncident(flow, credId, dec.ev, now);
      this.store.db.prepare('UPDATE v5_incidents SET triggers=triggers+1 WHERE incident_id=?').run(inc.incident_id);
      if (open) this.store.db.prepare('UPDATE v5_incidents SET last_trigger_at=?, reasons=? WHERE incident_id=?').run(now, JSON.stringify([...new Set([...JSON.parse(open.reasons), ...dec.ev.reasons.map(r => r.code)])]), open.incident_id);
      this.#delay(paymentId, inc.incident_id, Number(dec.statement.delayMs));
      // delay every other unsettled, not-yet-released payment of the same flow (never other flows)
      for (const r of this.store.db.prepare("SELECT v.payment_id FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id WHERE v.flow=? AND p.state='BUFFERED' AND v.anomaly='NONE' AND v.payment_id<>? AND v.rapid_grant IS NULL").all(flow, paymentId))
        this.#delay(r.payment_id, inc.incident_id, Number(dec.statement.delayMs));
      this.#classify(inc.incident_id, dec.statement.riskClass === 'HIGH' ? 'HIGH' : 'LOW');
      if (dec.statement.action === 'DELAY_AND_END_RAPID' && grant) this.onRapidRule({ grantId: grant.grantId, ruleId: 'R3_VELOCITY_CEILING', evidence: dec.statement.evaluationDigest });
    }
    const out = this.store.get(paymentId);
    return { paymentId, state: out.state, releaseAt: out.release_at, anomaly: this.store.db.prepare('SELECT anomaly FROM v5_pay WHERE payment_id=?').get(paymentId).anomaly };
  }
  #openIncident(flow, credId, ev, now) {
    const id = 'inc-' + randomBytes(6).toString('hex');
    const settled = this.store.db.prepare("SELECT COUNT(*) n FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id WHERE v.flow=? AND p.state='SETTLED' AND v.proposed_at > ?").all(flow, now - 86_400_000)[0].n;
    const exposure = this.store.db.prepare("SELECT v.amount FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id WHERE v.flow=? AND p.state='SETTLED' AND v.proposed_at > ?").all(flow, now - 86_400_000).reduce((t, r) => t + BigInt(r.amount), 0n);
    this.store.db.prepare('INSERT INTO v5_incidents (incident_id, flow, cred_id, opened_at, state, last_trigger_at, delayed_count, reasons, settled_before, exposure_before) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run(id, flow, credId, now, 'OPEN', now, 0, JSON.stringify(ev.reasons.map(r => r.code)), settled, exposure.toString());
    this.#j({ type: 'INCIDENT_OPENED', principal: this.ref(credId), relatedId: id, outcome: 'ANOMALY_PAYMENT_DELAY', data: { flow: this.ref(flow), reasons: ev.reasons.map(r => r.code).join(','), settledInPrior24h: String(settled), exposureInPrior24h: exposure.toString(), note: 'settled payments cannot be retroactively stopped' } });
    const inc = this.store.db.prepare('SELECT * FROM v5_incidents WHERE incident_id=?').get(id);
    this.onIncident({ incident: inc, ev, root: this.root });
    return inc;
  }
  #authIssuedAt(paymentId, delegationId) {
    const ev = this.store.db.prepare('SELECT cap FROM cap_evidence WHERE payment_id=?').get(paymentId);
    const cap = JSON.parse(ev.cap);
    return delegationId ? isoMs(cap.delegated.issuedAt, 'issuedAt') : isoMs(cap.issuedAt, 'issuedAt');
  }
  /** Owner-signed settlement horizon from the vault's own Root replica (genesis extension), never from the engine. */
  horizonMs() { return Number(this.root.v5.config.settlementHorizonMs); }
  /** P1: an incident's risk class only ever rises (LOW -> HIGH); a HIGH incident marks all its pending payments HIGH. Deadlines never move. */
  #classify(incidentId, cls) {
    const inc = this.store.db.prepare('SELECT risk_class FROM v5_incidents WHERE incident_id=?').get(incidentId);
    const next = inc?.risk_class === 'HIGH' || cls === 'HIGH' ? 'HIGH' : 'LOW';
    this.store.db.prepare('UPDATE v5_incidents SET risk_class=? WHERE incident_id=?').run(next, incidentId);
    const n = this.store.db.prepare("UPDATE v5_pay SET risk_class=? WHERE incident_id=? AND anomaly='ANOMALY_PAYMENT_DELAY' AND risk_class<>'HIGH' AND payment_id IN (SELECT payment_id FROM payments WHERE state='BUFFERED')").run(next, incidentId).changes;
    if (next === 'HIGH' && inc?.risk_class !== 'HIGH') this.#j({ type: 'INCIDENT_ESCALATED', relatedId: incidentId, outcome: 'HIGH', data: { pendingPayments: String(n), note: 'unresolved HIGH-risk payments expire instead of settling; nothing else is frozen' } });
  }
  #delay(paymentId, incidentId, delayMs) {
    const r = this.store.get(paymentId); if (r.state !== 'BUFFERED') return;
    const v = this.store.db.prepare('SELECT buffer_ms, settle_deadline FROM v5_pay WHERE payment_id=?').get(paymentId);
    const ms = Math.min(delayMs, MAX_DELAY_MS); // the vault enforces its own cap whatever the engine asks
    const release = r.proposed_at + (v?.buffer_ms ?? this.cfg.bufferMs) + ms;
    this.store.tx(() => {
      // P2: the delay moves only the earliest release. The latest authorized settlement (cap_expires_at = issuedAt +
      // owner-signed horizon) is NOT moved: a payment whose delay ends after it expires unsettled (fail closed).
      this.store.db.prepare("UPDATE payments SET release_at=?, updated_at=? WHERE payment_id=? AND state='BUFFERED'").run(release, this.now(), paymentId);
      this.store.db.prepare("UPDATE v5_pay SET anomaly='ANOMALY_PAYMENT_DELAY', delay_ms=?, incident_id=?, baseline_eligible=0 WHERE payment_id=?").run(ms, incidentId, paymentId);
      this.store.db.prepare('UPDATE v5_incidents SET delayed_count=delayed_count+1 WHERE incident_id=?').run(incidentId);
      this.store.journal(paymentId, 'BUFFERED', 'BUFFERED', 'risk-engine', { event: 'ANOMALY_PAYMENT_DELAY', incidentId, releaseAt: release, delayMs: ms, latestSettlement: v?.settle_deadline ?? r.cap_expires_at, unchanged: 'recipient,amount,asset,purpose,authorization,settlement-horizon' });
    });
    const fl = this.store.db.prepare('SELECT flow FROM v5_pay WHERE payment_id=?').get(paymentId)?.flow;
    this.#j({ type: 'PAYMENT_DELAYED', relatedId: paymentId, outcome: 'ANOMALY_PAYMENT_DELAY', evidenceRefs: [incidentId], data: { flow: fl ? this.ref(fl) : '-', incidentId, delayMs: String(ms), releaseAt: iso(release), amount: r.amount, recipient: r.recipient } });
  }
  /** An ACTIVE Rapid-Use grant on the vault's own replica that covers exactly this payment (or null). */
  rapidGrantFor({ credId, delegationId, recipient, amount, asset }) {
    const now = this.now();
    for (const g of Object.values(this.root.v5.rapid.grants)) {
      if (g.status !== 'ACTIVE' || now >= Number(g.expiresAt) || g.epoch !== String(this.root.epoch) || g.purposeVersion !== this.root.purpose.version) continue;
      const inFlow = delegationId ? g.scope.delegationIds.includes(delegationId) : g.scope.credIds.includes(credId);
      if (!inFlow || !g.scope.recipients.includes(recipient) || asset !== g.scope.asset) continue;
      if (g.scope.credIds.some(c => this.root.creds[c]?.status !== 'active' || credentialHolds(this.root, c, now).length)) continue;
      if (g.scope.sessionCapYocto !== '-') {
        const used = this.store.db.prepare('SELECT amount FROM v5_rapid_use WHERE grant_id=?').all(g.grantId).reduce((t, r) => t + BigInt(r.amount), 0n);
        if (used + BigInt(amount) > BigInt(g.scope.sessionCapYocto)) continue;
      }
      return g;
    }
    return null;
  }
  history() {
    return this.store.db.prepare('SELECT v.payment_id, v.flow, v.cred_id, v.recipient, v.amount, v.proposed_at, v.baseline_eligible, v.tier, p.state FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id').all()
      .map(r => ({ paymentId: r.payment_id, flow: r.flow, credId: r.cred_id, recipient: r.recipient, amount: r.amount, at: r.proposed_at, state: r.state, baselineEligible: r.baseline_eligible === 1, tier: r.tier }));
  }
  spentExcluding(paymentId) {
    const rows = this.store.db.prepare(`SELECT payment_id, amount, proposed_at FROM payments WHERE state IN (${[...HOLDING, 'SETTLED'].map(() => '?').join(',')})`).all(...HOLDING, 'SETTLED').filter(r => r.payment_id !== paymentId);
    const now = this.now(); let cum = 0n, day = 0n;
    for (const r of rows) { cum += BigInt(r.amount); if (r.proposed_at > now - 86_400_000) day += BigInt(r.amount); }
    return { cumulativeYocto: cum.toString(), last24hYocto: day.toString() };
  }
  securityTimes() { return this.store.db.prepare('SELECT at FROM v5_security ORDER BY at').all().map(r => r.at); }
  /** Seed trusted history (used by the anomaly datasets to model weeks of reviewed activity; never model output). */
  seedHistory(rows) {
    this.store.tx(() => { for (const r of rows) {
      const pid = 'p_' + randomBytes(16).toString('hex');
      this.store.db.prepare(`INSERT INTO payments (payment_id, cap_id, cap_digest, principal_id, policy_id, policy_digest, recipient, asset, amount, intent_nonce, state, proposed_at, cap_expires_at, memo, updated_at, settled_at)
        VALUES (?,?,?,?,?,?,?,?,?,?, 'SETTLED', ?,?,?,?,?)`).run(pid, 'hist-' + randomUUID(), 'hist', this.root.accountId, this.root.purpose.purposeId, this.root.purposeDigest, r.recipient, 'NEAR', r.amount, randomBytes(16).toString('hex'), r.at, r.at + 3600_000, '"historical"', r.at, r.at + 600_000);
      this.store.db.prepare('INSERT INTO v5_pay (payment_id, flow, cred_id, delegation_id, recipient, amount, proposed_at, anomaly, delay_ms, incident_id, rapid_grant, baseline_eligible, decision) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(pid, r.flow ?? 'cred:' + r.credId, r.credId, null, r.recipient, r.amount, r.at, 'NONE', 0, null, null, r.baselineEligible === false ? 0 : 1, '{"seeded":"history"}');
    } });
  }

  // ------------------------------------------------ Root replica effects (V5)
  syncRoot(transitions) {
    const out = super.syncRoot(transitions);
    const now = this.now();
    for (const e of out.effects) {
      if (SECURITY_EFFECTS.has(e.type)) this.store.db.prepare('INSERT INTO v5_security (at, type) VALUES (?,?)').run(now, e.type);
      if (e.type === 'INCIDENT_REVIEWED') this.#applyReview(e);
      if (e.type === 'RAPID_USE_ACTIVATED') this.#accelerate();
      if (['RAPID_USE_REVOKED', 'RAPID_USE_EXPIRED', 'RAPID_USE_ENDED'].includes(e.type)) this.#j({ type: e.type, relatedId: e.grantId, outcome: e.reason ?? e.by ?? 'ENDED', data: { note: 'subsequent payments return to standard monitoring and delay rules' } });
    }
    return out;
  }
  #applyReview(e) {
    const inc = this.store.db.prepare('SELECT * FROM v5_incidents WHERE incident_id=?').get(e.incidentId);
    if (!inc || inc.state !== 'OPEN' && inc.state !== 'LAPSED') return;
    if (inc.cred_id !== e.credId) return; // the review must name the incident's own flow credential
    const rows = this.store.db.prepare("SELECT v.payment_id FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id WHERE v.incident_id=? AND p.state='BUFFERED' AND v.anomaly='ANOMALY_PAYMENT_DELAY'").all(inc.incident_id);
    this.store.tx(() => {
      for (const r of rows) {
        const p = this.store.get(r.payment_id);
        if (e.verdict === 'LEGITIMATE') {
          this.store.db.prepare("UPDATE payments SET release_at=?, updated_at=? WHERE payment_id=? AND state='BUFFERED'").run(Math.max(p.proposed_at + this.#bufferOf(r.payment_id), this.now()), this.now(), r.payment_id);
          this.store.db.prepare("UPDATE v5_pay SET anomaly='RELEASED_BY_REVIEW' WHERE payment_id=?").run(r.payment_id);
        } else {
          this.store.move(r.payment_id, 'BUFFERED', 'CANCELLED', 'owner-review', { reason: 'INCIDENT_FRAUD', incidentId: inc.incident_id }, { reason: 'INCIDENT_FRAUD' });
          this.store.db.prepare("UPDATE v5_pay SET anomaly='CANCELLED_FRAUD' WHERE payment_id=?").run(r.payment_id);
        }
      }
      this.store.db.prepare('UPDATE v5_incidents SET state=?, closed_at=? WHERE incident_id=?').run(e.verdict === 'LEGITIMATE' ? 'CLOSED_LEGITIMATE' : 'CLOSED_FRAUD', this.now(), inc.incident_id);
    });
    this.#j({ type: 'INCIDENT_REVIEWED', relatedId: inc.incident_id, outcome: e.verdict, data: { payments: String(rows.length), by: (e.by ?? []).map(x => this.ref(x)).join(',') } });
  }
  #bufferOf(paymentId) { return this.store.db.prepare('SELECT buffer_ms FROM v5_pay WHERE payment_id=?').get(paymentId)?.buffer_ms ?? this.cfg.bufferMs; }
  #accelerate() {
    const now = this.now(); let n = 0;
    for (const r of this.store.db.prepare("SELECT v.*, p.asset, p.proposed_at AS pa FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id WHERE p.state='BUFFERED' AND v.anomaly='ANOMALY_PAYMENT_DELAY'").all()) {
      const g = this.rapidGrantFor({ credId: r.cred_id, delegationId: r.delegation_id, recipient: r.recipient, amount: r.amount, asset: r.asset });
      if (!g) continue;
      this.store.tx(() => {
        this.store.db.prepare("UPDATE payments SET release_at=?, updated_at=? WHERE payment_id=? AND state='BUFFERED'").run(Math.max(r.pa + (r.buffer_ms ?? this.cfg.bufferMs), now), now, r.payment_id);
        this.store.db.prepare("UPDATE v5_pay SET anomaly='RELEASED_BY_RAPID', rapid_grant=? WHERE payment_id=?").run(g.grantId, r.payment_id);
        this.store.db.prepare('INSERT OR IGNORE INTO v5_rapid_use (grant_id, payment_id, amount) VALUES (?,?,?)').run(g.grantId, r.payment_id, r.amount);
      });
      this.#j({ type: 'PAYMENT_ACCELERATED_RAPID_USE', relatedId: r.payment_id, outcome: 'ANOMALY_DELAY_REMOVED', evidenceRefs: [g.grantId], data: { grantId: g.grantId, unchanged: 'recipient,amount,asset,purpose,limits' } });
      n++;
    }
    return n;
  }

  async tick() {
    const now = this.now();
    // incidents with no new trigger for 24 h lapse (their delayed payments keep their bounded release time)
    for (const i of this.store.db.prepare("SELECT * FROM v5_incidents WHERE state='OPEN' AND last_trigger_at < ?").all(now - Number(RISK_POLICY_V1.delay.incidentQuietCloseMs))) {
      this.store.db.prepare("UPDATE v5_incidents SET state='LAPSED', closed_at=? WHERE incident_id=?").run(now, i.incident_id);
      this.#j({ type: 'INCIDENT_LAPSED', relatedId: i.incident_id, outcome: 'LAPSED', data: { note: 'the end of a burst is not proof that the credential is uncompromised' } });
    }
    // targeted holds: only the affected merchant / delegation flow waits
    for (const r of this.store.db.prepare("SELECT v.payment_id, v.recipient, v.delegation_id, p.release_at FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id WHERE p.state='BUFFERED' AND p.release_at <= ?").all(now)) {
      const held = merchantHolds(this.root, r.recipient, now).length || (r.delegation_id && delegationHolds(this.root, r.delegation_id, now).length);
      if (held) this.store.db.prepare("UPDATE payments SET release_at=? WHERE payment_id=? AND state='BUFFERED'").run(now + 600_000, r.payment_id);
    }
    this.#accelerate();
    this.#settlementGate(now);
    const out = await super.tick();
    this.mirror();
    return out;
  }
  /**
   * P1 / P2 release gate, run before the V3 release-time re-check (which still checks freeze, lockdown, epoch, Purpose
   * version, approver status, lease and the latest settlement time):
   *  1. latest authorized settlement reached -> EXPIRED (SETTLEMENT_HORIZON_EXPIRED), whatever the delay or review state;
   *  2. a HIGH-risk delayed payment whose delay ended without an owner LEGITIMATE review or Rapid-Use -> EXPIRED
   *     (HIGH_RISK_UNRESOLVED): it needs renewed authorization; nothing else on the account is restricted;
   *  3. due payments: Purpose recipient / asset / validity, credential holds and the delegation are re-checked.
   */
  #settlementGate(now) {
    const rows = this.store.db.prepare(`SELECT v.*, p.release_at, p.cap_expires_at, p.asset, p.state FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id WHERE p.state='BUFFERED'`).all();
    for (const r of rows) {
      let why = null;
      if (now >= r.cap_expires_at || (r.settle_deadline !== null && now >= r.settle_deadline)) why = 'SETTLEMENT_HORIZON_EXPIRED';
      else if (r.release_at <= now && r.risk_class === 'HIGH' && r.anomaly === 'ANOMALY_PAYMENT_DELAY') why = 'HIGH_RISK_UNRESOLVED';
      else if (r.release_at <= now) {
        const pv = purposeViolations(this.root.purpose, { operation: 'PAY', recipientId: r.recipient, asset: r.asset, amountYocto: r.amount, sku: null, now, capExpiresAt: now + 1, capIssuedAt: now }, { cumulativeYocto: '0', last24hYocto: '0' })
          .filter(x => ['RECIPIENT_NOT_IN_PURPOSE', 'ASSET_NOT_IN_PURPOSE', 'PURPOSE_NOT_ACTIVE', 'OVER_PER_PAYMENT_LIMIT', 'OPERATION_NOT_IN_PURPOSE'].includes(x));
        if (pv.length) why = 'RELEASE_RECHECK_PURPOSE:' + pv.join(',');
        else if (credentialHolds(this.root, r.cred_id, now).length) why = null; // credential holds suspend the credential: the V3 re-check cancels (APPROVER_CREDENTIAL_NOT_ACTIVE); keep the reason single-sourced
        else if (r.delegation_id) { const d = this.root.v5.delegations[r.delegation_id]; if (!d || d.status === 'REVOKED') why = 'RELEASE_RECHECK_DELEGATION_REVOKED'; }
      }
      if (!why) continue;
      const to = why.startsWith('RELEASE_RECHECK') ? 'CANCELLED' : 'EXPIRED';
      this.store.tx(() => {
        this.store.move(r.payment_id, 'BUFFERED', to, 'policy', { reason: why, latestSettlement: r.settle_deadline, riskClass: r.risk_class }, { reason: why });
        if (why === 'HIGH_RISK_UNRESOLVED') this.store.db.prepare("UPDATE v5_pay SET anomaly='EXPIRED_UNRESOLVED' WHERE payment_id=?").run(r.payment_id);
      });
    }
  }
  /** Mirror the vault's own hash-chained lifecycle journal into the Footprint Journal (VAULT layer). */
  mirror() {
    if (!this.jw) return;
    for (const r of this.store.journalRows(this.mirrorSeq)) {
      this.mirrorSeq = r.seq;
      if (!r.payment_id || r.from_state === r.to_state || !r.to_state) continue;
      const type = { AUTHORIZED: 'PAYMENT_APPROVED', SETTLED: 'PAYMENT_SETTLED', CANCELLED: 'PAYMENT_CANCELLED', RELEASED: 'PAYMENT_RELEASED', FROZEN: 'PAYMENT_FROZEN', FAILED: 'PAYMENT_FAILED', EXPIRED: 'PAYMENT_EXPIRED', UNKNOWN: 'PAYMENT_UNKNOWN' }[r.to_state];
      if (!type) continue;
      const v = this.store.db.prepare('SELECT * FROM v5_pay WHERE payment_id=?').get(r.payment_id); const p = this.store.get(r.payment_id);
      let detail = {}; try { detail = JSON.parse(r.detail); } catch {}
      this.#j({ type, principal: v ? this.ref(v.cred_id) : '-', relatedId: r.payment_id, outcome: r.to_state, epoch: this.root.epoch, purposeVersion: this.root.purpose.version,
        data: { amount: p?.amount ?? '-', recipient: p?.recipient ?? '-', flow: v ? this.ref(v.flow) : '-', anomaly: v?.anomaly ?? '-', rapidGrant: v?.rapid_grant ?? '-', reason: String(detail.reason ?? detail.ledger ?? '-').slice(0, 60), txId: String(detail.txId ?? '-') } });
    }
    this.store.setControl('v5MirrorSeq', String(this.mirrorSeq));
  }
  incidents() { return this.store.db.prepare('SELECT * FROM v5_incidents ORDER BY opened_at').all(); }
  v5payments() { return this.store.db.prepare('SELECT v.*, p.state, p.release_at, p.released_at, p.settled_at, p.reason FROM v5_pay v JOIN payments p ON p.payment_id=v.payment_id ORDER BY v.proposed_at').all(); }
}
