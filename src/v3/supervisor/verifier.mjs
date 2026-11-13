// Independent V3 verifier (supervisor domain). Trusts only: the pinned genesis digest, the pinned buffer floor, and
// what it can verify cryptographically. It replays the Root chain itself, then checks every ledger effect against the
// capability evidence (fetched from the vault, i.e. untrusted, but verified here) and the Root state AT THAT TIME.
// It also lists every authority change so a campaign can compare it against the owner's ground-truth intent.
import { genesisState, applyTransition, actionDigest } from '../root/chain.mjs';
import { verifyPaycap } from '../vault/paycap.mjs';
import { purposeViolations } from '../root/capsule.mjs';

const AUTHORITY_TYPES = new Set(['AMEND_PURPOSE', 'AMEND_MATRIX', 'UNFREEZE', 'ROTATE', 'REVOKE', 'REPLACE_VACANT', 'UNSUSPEND', 'RATIFY_BASELINE', 'RECOVERY_COMPLETE', 'RECONSTITUTE', 'RECOVERY_CANCEL']);

export function verifyV3({ genesis, pinnedChainId, transitions, ledgerTxs = [], evidence = [], minBufferMs = 600_000, ownerIntents = null, attackerCaseIds = new Set() }) {
  const out = { chainValid: true, chainError: null, financial: { effects: 0, authorized: 0, violations: [] }, authority: { changes: [], unauthorized: [] }, purpose: { versions: [], violations: [] }, takeovers: [] };
  let st;
  try { st = genesisState(genesis, { pinnedChainId }); } catch (e) { out.chainValid = false; out.chainError = 'GENESIS:' + (e.code ?? e.message); return out; }
  const snaps = [{ at: st.lastAt, state: st }];
  out.purpose.versions.push({ version: st.purpose.version, digest: st.purposeDigest, seq: 0 });
  for (const tr of transitions) {
    let r;
    try { r = applyTransition(st, tr); } catch (e) { out.chainValid = false; out.chainError = `seq ${tr.seq} ${tr.action?.type}: ${e.code ?? e.message}`; break; }
    st = r.state; snaps.push({ at: st.lastAt, state: st });
    const type = tr.action.type;
    if (st.purposeDigest !== snaps[snaps.length - 2].state.purposeDigest) {
      if (type !== 'AMEND_PURPOSE') out.purpose.violations.push({ seq: tr.seq, type, code: 'PURPOSE_CHANGED_WITHOUT_AMENDMENT' });
      out.purpose.versions.push({ version: st.purpose.version, digest: st.purposeDigest, seq: Number(tr.seq) });
    }
    if (AUTHORITY_TYPES.has(type) || (type === 'RECOVERY_CANCEL' && r.effects.some(e => e.type === 'RECOVERY_CLOSED'))) {
      const d = actionDigest(tr.action).toString('hex');
      const caseId = tr.action.body?.caseId ?? null;
      const ch = { seq: tr.seq, type, digest: d, caseId, epoch: st.epoch, effects: r.effects.map(e => e.type) };
      out.authority.changes.push(ch);
      const attackerCase = caseId && attackerCaseIds.has(caseId);
      if ((type === 'RECOVERY_COMPLETE' || type === 'RECONSTITUTE') && attackerCase) { out.takeovers.push(ch); out.authority.unauthorized.push({ ...ch, code: 'RECOVERY_TAKEOVER' }); }
      else if (ownerIntents && !ownerIntents.has(d) && !(type === 'RECOVERY_COMPLETE' || type === 'RECONSTITUTE')) out.authority.unauthorized.push({ ...ch, code: 'AUTHORITY_CHANGE_NOT_INTENDED_BY_OWNER' });
    }
  }
  out.finalState = st;
  const stateAt = (t) => { let s = snaps[0].state; for (const x of snaps) { if (x.at <= t) s = x.state; else break; } return s; };
  const evByCap = new Map(evidence.map(e => [e.cap_id, e]));
  const seenCaps = new Set(); let cum = 0n;
  for (const tx of [...ledgerTxs].sort((a, b) => a.seq - b.seq)) {
    out.financial.effects++;
    const v = []; let capId = null;
    try { capId = JSON.parse(tx.statement).capId; } catch { v.push('UNPARSEABLE_TX'); }
    const ev = evByCap.get(capId);
    if (!ev) v.push('NO_OWNER_CAPABILITY');
    else {
      let cap, approval;
      try { cap = JSON.parse(ev.cap); approval = JSON.parse(ev.approval); } catch { v.push('EVIDENCE_UNPARSEABLE'); }
      if (cap) {
        const issued = Date.parse(cap.issuedAt);
        try { verifyPaycap({ ...stateAt(issued), creds: Object.fromEntries(Object.entries(stateAt(issued).creds).map(([k, c]) => [k, { ...c, signCount: 0 }])) }, { capability: cap, approval }, { now: issued }); }
        catch (e) { v.push('CAPABILITY_INVALID_AT_ISSUANCE:' + (e.code ?? e.message)); }
        const sAt = stateAt(tx.submitted_at);
        if (String(sAt.epoch) !== cap.epoch) v.push('EFFECT_IN_OTHER_EPOCH');
        if (sAt.freeze.active) v.push('EFFECT_DURING_ROOT_FREEZE');
        if (sAt.lockdown.active) v.push('EFFECT_DURING_EMERGENCY_LOCKDOWN');
        if (sAt.creds[approval?.credId]?.status !== 'active') v.push('APPROVER_NOT_ACTIVE_AT_EFFECT');
        if (sAt.purpose.version !== cap.purposeVersion) v.push('EFFECT_UNDER_OTHER_PURPOSE_VERSION');
        if (tx.recipient !== cap.recipientId) v.push('RECIPIENT_MISMATCH');
        if (tx.amount !== cap.amountYocto) v.push('AMOUNT_NOT_EXACT');
        if (tx.submitted_at < issued + minBufferMs) v.push('BUFFER_BYPASSED');
        if (tx.submitted_at >= Date.parse(cap.expiresAt)) v.push('EFFECT_AFTER_CAPABILITY_EXPIRY');
        if (seenCaps.has(capId)) v.push('DUPLICATE_EFFECT_FOR_CAPABILITY');
        seenCaps.add(capId);
        const pv = purposeViolations(sAt.purpose, { operation: 'PAY', recipientId: tx.recipient, asset: 'NEAR', amountYocto: tx.amount, sku: cap.sku === '-' ? null : cap.sku, now: tx.submitted_at,
          capExpiresAt: Date.parse(cap.expiresAt), capIssuedAt: issued }, { cumulativeYocto: cum.toString(), last24hYocto: '0' }).filter(x => x !== 'OVER_DAILY_LIMIT' && x !== 'PURPOSE_NOT_ACTIVE');
        v.push(...pv.map(x => 'PURPOSE:' + x));
      }
    }
    cum += BigInt(tx.amount);
    if (v.length) out.financial.violations.push({ txId: tx.tx_id, capId, recipient: tx.recipient, amountYocto: tx.amount, codes: v });
    else out.financial.authorized++;
  }
  return out;
}
