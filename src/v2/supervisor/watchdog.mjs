// Independent Watchdog (Supervisor domain). Polls the ledger (read-only) and the Sensitive Zone
// control channel, runs the independent effect verifier, and contains confirmed breaches by
// freezing the LEDGER first (stops effects even if the Sensitive Zone itself misbehaves) and then
// the Sensitive Zone. Freeze state is persisted by the supervisor and re-applied after restarts.
// It never grants authority: its only powers are HEARTBEAT, HOLD, FREEZE and CLEAR_HOLD.
import { appendFileSync, readFileSync, existsSync } from 'node:fs';
import { verifyLedgerEffects } from './verifier.mjs';

export class FreezeStore {
  constructor(path = null) { this.path = path; this.records = []; if (path && existsSync(path)) this.records = readFileSync(path, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)); }
  #append(r) { this.records.push(r); if (this.path) appendFileSync(this.path, JSON.stringify(r) + '\n', { mode: 0o600 }); }
  freeze(r) { this.#append({ type: 'FREEZE', ...r }); }
  lift(r) { this.#append({ type: 'LIFT', ...r }); }
  anomaly(r) { this.#append({ type: 'ANOMALY', ...r }); }
  current() { let cur = null; for (const r of this.records) { if (r.type === 'FREEZE' && !cur) cur = r; if (r.type === 'LIFT') cur = null; } return cur; }
  isFrozen() { return !!this.current(); }
  freezeLog() {
    const out = []; let open = null;
    for (const r of this.records) { if (r.type === 'FREEZE' && !open) { open = { frozenAt: r.frozenAt, ledgerSeqAtFreeze: r.ledgerSeqAtFreeze ?? null, liftedAt: null, id: r.id }; out.push(open); } if (r.type === 'LIFT' && open) { open.liftedAt = r.liftedAt; open = null; } }
    return out;
  }
}

export class Watchdog {
  constructor({ ledgerRead, ledgerAdmin, sensCtl, owner, freezeStore, now, wallNow = () => Date.now(), executorKey, genesisTotalYocto, unknownHoldScans = 3, preReleaseAudit = true, drillHideFlawFlag = false }) {
    Object.assign(this, { ledgerRead, ledgerAdmin, sensCtl, owner, freezeStore, now, wallNow, executorKey, genesisTotalYocto, unknownHoldScans, preReleaseAudit, drillHideFlawFlag });
    this.seenViolations = new Set(); this.unknownStreak = 0; this.scans = 0; this.events = [];
    this.lastReport = null; this.holdReason = null;
  }

  async contain(classification, reason, evidence) {
    const detectedWall = this.wallNow(), detectedAt = this.now();
    const steps = [];
    try { await this.ledgerAdmin.call('FREEZE', { reason: `${classification}: ${reason}`.slice(0, 200) }); steps.push('LEDGER_FROZEN'); } catch (e) { steps.push('LEDGER_FREEZE_FAILED:' + e.code); }
    try { const r = await this.sensCtl.call('FREEZE', { reason: reason.slice(0, 200), classification }); steps.push('SENSITIVE_FROZEN', `buffered_frozen=${r.frozenNow.length}`); } catch (e) { steps.push('SENSITIVE_FREEZE_FAILED:' + e.code); }
    const rec = { id: 'fz_' + (this.freezeStore.records.length + 1), classification, reason, frozenAt: detectedAt, detectedAt, ledgerSeqAtFreeze: this.lastSeq ?? 0,
      wallDetectedMs: detectedWall, wallContainedMs: this.wallNow(), containmentWallMs: this.wallNow() - detectedWall, steps, evidence };
    if (!this.freezeStore.isFrozen()) this.freezeStore.freeze(rec);
    this.events.push({ type: 'CONTAIN', ...rec });
    return rec;
  }

  async scan() {
    this.scans++;
    const report = { scan: this.scans, at: this.now(), breaches: [], anomalies: [], actions: [] };
    // 1. Ledger effects, verified independently.
    let lstate, transfers, balances;
    try { lstate = await this.ledgerRead.call('STATE', {}); transfers = await this.ledgerRead.call('TRANSFERS', { sinceSeq: '0' }); balances = await this.ledgerRead.call('BALANCES', {}); }
    catch (e) { report.anomalies.push('LEDGER_UNREADABLE:' + (e.code ?? e.name)); }
    if (lstate && !lstate.journal.ok) report.breaches.push({ code: 'LEDGER_JOURNAL_TAMPERED', seq: lstate.journal.seq });
    if (transfers) {
      this.lastSeq = transfers.reduce((m, t) => Math.max(m, t.seq), this.lastSeq ?? 0);
      const v = verifyLedgerEffects({ transfers, owner: this.owner, executorKey: this.executorKey, freezeLog: this.freezeStore.freezeLog(), genesisTotalYocto: this.genesisTotalYocto, balances });
      report.verification = { effects: v.effects.length, unauthorized: v.unauthorizedCount, unauthorizedYocto: v.unauthorizedYocto, conservation: v.conservation };
      for (const x of v.violations) { const k = x.txId ?? JSON.stringify(x.codes); if (!this.seenViolations.has(k)) { this.seenViolations.add(k); report.breaches.push({ code: 'UNAUTHORIZED_LEDGER_EFFECT', ...x }); } }
    }
    // 2. Sensitive Zone health and freeze-state consistency.
    let sstate = null;
    try { sstate = await this.sensCtl.call('STATE', {}); } catch (e) { report.anomalies.push('SENSITIVE_UNREACHABLE:' + (e.code ?? e.name)); }
    if (sstate) {
      if (!sstate.journal.ok) report.breaches.push({ code: 'SENSITIVE_JOURNAL_TAMPERED', seq: sstate.journal.seq });
      if (sstate.injectFlaw && !this.drillHideFlawFlag) report.anomalies.push('INJECTED_FLAW_ACTIVE:' + sstate.injectFlaw);
      const unknown = sstate.counts.UNKNOWN ?? 0;
      this.unknownStreak = unknown > 0 ? this.unknownStreak + 1 : 0;
      if (this.unknownStreak >= this.unknownHoldScans) report.anomalies.push('PAYMENTS_STUCK_UNKNOWN:' + unknown);
      if (this.freezeStore.isFrozen() && sstate.control.level !== 'FROZEN') report.anomalies.push('FREEZE_STATE_DIVERGENCE');
      if (this.preReleaseAudit) {
        // Use of the buffer: independently audit every payment the Sensitive Zone accepted BEFORE it can be released,
        // against the owner's own issuance log (not against the Sensitive Zone's policy decision).
        let rows = [];
        try { rows = await this.sensCtl.call('PAYMENTS', {}); } catch (e) { report.anomalies.push('SENSITIVE_PAYMENTS_UNREADABLE'); }
        for (const p of rows) {
          if (!['BUFFERED', 'RESERVED', 'AUTHORIZED', 'RELEASED', 'UNKNOWN'].includes(p.state)) continue;
          const k = 'pre:' + p.payment_id; if (this.seenViolations.has(k)) continue;
          const iss = this.owner.issued.get(p.cap_id), codes = [];
          if (!iss) codes.push('NO_OWNER_CAPABILITY');
          else {
            if (p.recipient !== iss.cap.recipientId) codes.push('RECIPIENT_NOT_AUTHORIZED');
            if (BigInt(p.amount) > BigInt(iss.cap.maxAmountYocto)) codes.push('AMOUNT_OVER_AUTHORIZED');
            if (iss.cap.principalId !== p.principal_id) codes.push('PRINCIPAL_MISMATCH');
            // (A revoked-but-still-buffered payment is not a breach: the release re-check refuses it, and the
            //  post-effect verifier flags EXECUTED_AFTER_REVOCATION should it ever reach the ledger.)
          }
          if (codes.length) { this.seenViolations.add(k); report.breaches.push({ code: 'PRE_RELEASE_AUDIT_MISMATCH', paymentId: p.payment_id, capId: p.cap_id, recipient: p.recipient, amountYocto: p.amount, state: p.state, codes }); }
        }
      }
    }
    if (lstate && this.freezeStore.isFrozen() && !lstate.frozen) report.anomalies.push('LEDGER_FREEZE_DIVERGENCE');

    // 3. Decide. Confirmed breach => FREEZE (persistent). Anomaly => HOLD (no releases until reviewed).
    if (report.breaches.length) {
      report.actions.push(await this.contain('CONFIRMED_BREACH', report.breaches.map(b => b.code).join(','), report.breaches));
    } else if (this.freezeStore.isFrozen()) {
      // Persisted freeze survives restarts of any zone: re-apply wherever it is missing.
      if (report.anomalies.includes('FREEZE_STATE_DIVERGENCE') || report.anomalies.includes('LEDGER_FREEZE_DIVERGENCE')) {
        const cur = this.freezeStore.current();
        try { await this.ledgerAdmin.call('FREEZE', { reason: 'reapply ' + cur.id }); } catch {}
        try { await this.sensCtl.call('FREEZE', { reason: 'reapply ' + cur.id, classification: cur.classification }); } catch {}
        report.actions.push('FREEZE_REAPPLIED');
      }
    } else if (report.anomalies.length) {
      for (const a of report.anomalies) this.freezeStore.anomaly({ at: this.now(), code: a });
      try { await this.sensCtl.call('HOLD', { reason: report.anomalies.join(',').slice(0, 200), classification: 'UNCONFIRMED_ANOMALY' }); report.actions.push('HOLD'); this.holdReason = report.anomalies.join(','); } catch {}
    } else {
      if (sstate?.control.level === 'HOLD' && this.holdReason) {
        // Review: anomalies cleared and the independent verifier is clean.
        try { await this.sensCtl.call('CLEAR_HOLD', { reviewRef: 'wd_scan_' + this.scans }); report.actions.push('HOLD_CLEARED'); this.holdReason = null; } catch {}
      }
      try { await this.sensCtl.call('HEARTBEAT', {}); report.actions.push('HEARTBEAT'); } catch {}
    }
    this.lastReport = report;
    if (report.breaches.length || report.anomalies.length || report.actions.some(a => typeof a !== 'string' || a !== 'HEARTBEAT')) this.events.push({ type: 'SCAN', ...report });
    return report;
  }

  /** Recovery validation + operator-signed unfreeze of both ledger and Sensitive Zone. */
  async recover({ reviewRef, diagnosis }) {
    const cur = this.freezeStore.current();
    if (!cur) throw new Error('not frozen');
    const lstate = await this.ledgerRead.call('STATE', {});
    const sstate = await this.sensCtl.call('STATE', {});
    let transfers = await this.ledgerRead.call('TRANSFERS', { sinceSeq: '0' });
    // BR-001 fix: an unauthorized transfer still PENDING on the ledger must be voided BEFORE anything is unfrozen,
    // otherwise lifting the ledger freeze would let it settle.
    const pre = verifyLedgerEffects({ transfers, owner: this.owner, executorKey: this.executorKey, freezeLog: [] });
    const voidedNow = [];
    for (const v of pre.violations) if (v.txId && v.status === 'PENDING') { await this.ledgerAdmin.call('VOID_PENDING', { txId: v.txId, reason: 'recovery: unauthorized pending ' + v.codes.join(',') }); voidedNow.push(v.txId); }
    transfers = await this.ledgerRead.call('TRANSFERS', { sinceSeq: '0' });
    const post = verifyLedgerEffects({ transfers, owner: this.owner, executorKey: this.executorKey, freezeLog: [] });
    const after = transfers.filter(t => (cur.ledgerSeqAtFreeze != null ? t.seq > cur.ledgerSeqAtFreeze : t.submitted_at > cur.frozenAt) && t.status !== 'VOIDED');
    const checks = { noUnauthorizedPending: post.violations.every(v => v.status !== 'PENDING'), ledgerJournal: lstate.journal.ok, sensitiveJournal: sstate.journal.ok, noEffectsSinceFreeze: after.length === 0,
      injectedFlawCleared: !sstate.injectFlaw, diagnosisRecorded: !!diagnosis };
    const ok = Object.values(checks).every(Boolean);
    if (!ok) return { ok: false, checks, voidedNow };
    await this.ledgerAdmin.call('UNFREEZE', { unfreeze: this.owner.unfreeze('mock-ledger', lstate.frozenAt, reviewRef) });
    const r = await this.sensCtl.call('UNFREEZE', { unfreeze: this.owner.unfreeze('sensitive-zone', sstate.control.since, reviewRef) });
    this.freezeStore.lift({ liftedAt: this.now(), reviewRef, diagnosis, checks });
    this.seenViolations = new Set([...this.seenViolations]);
    return { ok: true, checks, cancelled: r.cancelled, voidedNow };
  }
}
