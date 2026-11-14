// Independent V5 verifier (supervisor domain). It trusts NOTHING the services report about themselves:
//  * replays the Root chain from the pinned genesis with the V5 state machine (re-verifies every Command Statement,
//    every V4 intent, hold provenance, contest rules, Rapid-Use quorum, engine attestations);
//  * re-checks every ledger effect against the replayed state AT THE EFFECT TIME (projected: holds that had already
//    expired count as expired), the owner capability or the delegate-signed operation, Purpose, buffer and expiry;
//  * accepts an effect after its capability's original window only if a Risk-Engine-signed ANOMALY_DECISION covers that
//    payment and the shift is within the vault's 24 h cap;
//  * checks that a delayed payment did not settle before its delay ended unless an ACTIVE Rapid-Use grant covering it or
//    an owner LEGITIMATE review existed;
//  * lists authority changes (and flags those the owner did not intend), Rapid-Use windows (<= 24 h), hold outcomes;
//  * verifies the Footprint Journal hash chain against witness checkpoints.
// V5.1:
//  * P2: the latest authorized settlement is recomputed from the REPLAYED genesis (settlementHorizonMs signed by every
//    owner device + ORC) and the owner-/delegate-signed issuedAt; an effect at or after it is
//    EFFECT_AFTER_SETTLEMENT_HORIZON. Consumption after the authorization's own expiresAt is
//    AUTHORIZATION_CONSUMED_AFTER_DEADLINE. Neither depends on the vault's or the engine's records.
//  * P1: an effect for a payment of an incident the engine classified HIGH needs an owner LEGITIMATE review of that
//    incident or an ACTIVE covering Rapid-Use grant, else HIGH_RISK_SETTLED_WITHOUT_RESOLUTION.
import * as V5 from '../root/chain.mjs';
import { verifyPaycap } from '../../v3/vault/paycap.mjs';
import { purposeViolations } from '../../v3/root/capsule.mjs';
import { credentialHolds, merchantHolds, delegationHolds } from '../root/holds.mjs';
import { V5_DOMAINS, verifyObj5 } from '../common/v5.mjs';
import { verifyJournalChain } from '../journal/journal.mjs';
import { RISK_POLICY_V1 } from '../risk/detector.mjs';
import { tierFromInputs, tierToBufferMs, bufferFloorMs, MAX_BUFFER_MS } from '../risk/buffer.mjs';

export const AUTHORITY_TYPES_V5 = new Set(['ENROLL', 'REVOKE', 'ROTATE', 'ROTATE_FREEZE', 'AMEND_PURPOSE', 'AMEND_MATRIX', 'RECOVERY_COMPLETE', 'RECONSTITUTE', 'RECOVERY_OWNER_AUTHORIZE', 'ORC_REPLACE',
  'GOV_CASE_EXECUTE', 'GUARDIAN_ROTATE', 'CONTEST_PROTECTIVE_HOLD', 'DELEGATION_GRANT', 'RAPID_USE_ACTIVATE', 'INCIDENT_REVIEW', 'HOLD_RELEASE', 'UNSUSPEND']);
const TAKEOVER = ['RECOVERY_COMPLETE', 'RECONSTITUTE', 'GOV_CASE_EXECUTE'];
const MAX_DELAY = Number(RISK_POLICY_V1.delay.maxDelayMs);

export function verifyV5({ genesis, pinnedChainId, transitions, ledgerTxs = [], evidence = [], v5pay = [], ownerIntents = null, attackerCaseIds = new Set(), minBufferMs = 600_000, tickSlackMs = 15 * 60_000, journal = null }) {
  const out = { chainValid: true, chainError: null, financial: { effects: 0, authorized: 0, violations: [] }, authority: { changes: [], unauthorized: [] }, takeovers: [],
    rapid: { grants: [], violations: [] }, holds: {}, journal: null, delays: { delayed: 0, earlyRelease: [] } };
  let st;
  try { st = V5.genesisState(genesis, { pinnedChainId }); } catch (e) { out.chainValid = false; out.chainError = 'GENESIS:' + (e.code ?? e.message); return out; }
  const snaps = [{ at: st.lastAt, state: st }];
  for (const tr of transitions) {
    let r;
    try { r = V5.applyTransition(st, tr); } catch (e) { out.chainValid = false; out.chainError = `seq ${tr.seq} ${tr.action?.type}: ${e.code ?? e.message}`; break; }
    st = r.state; snaps.push({ at: st.lastAt, state: st });
    const type = tr.action.type;
    if (AUTHORITY_TYPES_V5.has(type)) {
      const d = V5.actionDigest(tr.action).toString('hex'); const caseId = tr.action.body?.caseId ?? null;
      const ch = { seq: tr.seq, type, digest: d, caseId, epoch: st.epoch, effects: r.effects.map(e => e.type), levels: r.effects.find(e => e.type === 'CONFIRMATION_ASSURANCE')?.levels ?? [] };
      out.authority.changes.push(ch);
      if (TAKEOVER.includes(type) && caseId && attackerCaseIds.has(caseId)) { out.takeovers.push(ch); out.authority.unauthorized.push({ ...ch, code: 'RECOVERY_TAKEOVER' }); }
      else if (ownerIntents && !ownerIntents.has(d) && !TAKEOVER.includes(type) && type !== 'RAPID_USE_ACTIVATE') out.authority.unauthorized.push({ ...ch, code: 'AUTHORITY_CHANGE_NOT_INTENDED_BY_OWNER' });
    }
  }
  out.finalState = st;
  const raw = (t) => { let s = snaps[0].state; for (const x of snaps) { if (x.at <= t) s = x.state; else break; } return s; };
  const stateAt = (t) => V5.projectState(raw(t), Math.max(t, raw(t).lastAt));
  // Rapid-Use windows
  for (const g of Object.values(st.v5.rapid.grants)) {
    const len = Number(g.expiresAt) - Number(g.activatedAt);
    out.rapid.grants.push({ grantId: g.grantId, activatedAt: g.activatedAt, expiresAt: g.expiresAt, status: g.status, endedBy: g.endedBy ?? null, approvers: Object.keys(g.approvers) });
    if (len > Number(st.v5.config.rapidMaxMs) || len > 24 * 3600_000) out.rapid.violations.push({ grantId: g.grantId, code: 'RAPID_WINDOW_OVER_24H' });
  }
  for (const h of Object.values(st.v5.holds)) { const k = `${h.class}:${h.status}`; out.holds[k] = (out.holds[k] ?? 0) + 1; }

  const evByCap = new Map(evidence.map(e => [e.cap_id, e]));
  const v5ByPay = new Map(v5pay.map(p => [p.payment_id, p]));
  const seenCaps = new Set(); const delegUse = new Map(); let cum = 0n;
  // the engine's own journaled decisions (RISK layer) cross-check the vault's delay records
  const engineDelay = new Map(); const highAt = new Map(); // incident (or 'pay:<id>' when the HIGH decision opened it) -> first HIGH decision time
  const markHigh = (k, t) => { if (!highAt.has(k) || t < highAt.get(k)) highAt.set(k, t); };
  for (const r of journal?.rows ?? []) { const e = JSON.parse(r.body); if (e.layer === 'RISK' && e.type === 'ENGINE_DECISION' && e.outcome !== 'NONE') { engineDelay.set(e.relatedId, Math.max(engineDelay.get(e.relatedId) ?? 0, Number(e.data.delayMs))); if (e.data.riskClass === 'HIGH') markHigh(e.data.incidentRef !== '-' ? e.data.incidentRef : 'pay:' + e.relatedId, Date.parse(e.at)); } }
  // a HIGH decision that opened an incident names the payment; map it to the vault's incident (the vault cannot hide the HIGH class: the engine journal holds it)
  for (const p of v5pay) if (highAt.has('pay:' + p.payment_id) && p.incident_id) markHigh(p.incident_id, highAt.get('pay:' + p.payment_id));
  const horizon = Number(st.v5.config.settlementHorizonMs);
  // P4: buffer policy and floor come from the REPLAYED owner-signed genesis, never from the vault's configuration
  const bufferPolicy = st.v5.config.bufferPolicy ?? 'FIXED_600'; const floor = bufferFloorMs(bufferPolicy);
  out.buffer = { policy: bufferPolicy, floorMs: floor, checked: 0, violations: 0 };
  const engineBuffer = new Map();
  for (const r of journal?.rows ?? []) { const e = JSON.parse(r.body); if (e.layer === 'RISK' && e.type === 'BUFFER_DECISION') engineBuffer.set(e.relatedId, e.data); }
  out.horizon = { horizonMs: horizon, violations: 0 };
  for (const tx of [...ledgerTxs].sort((a, b) => a.seq - b.seq)) {
    out.financial.effects++;
    const v = []; let capId = null, paymentId = null;
    try { const s = JSON.parse(tx.statement); capId = s.capId; paymentId = s.paymentId; } catch { v.push('UNPARSEABLE_TX'); }
    const ev = evByCap.get(capId); const vp = v5ByPay.get(paymentId);
    let credId = null, proposedAt = null, windowEnd = null, authIssued = null;
    if (!ev) v.push('NO_OWNER_CAPABILITY');
    else {
      let cap, approval;
      try { cap = JSON.parse(ev.cap); approval = JSON.parse(ev.approval); } catch { v.push('EVIDENCE_UNPARSEABLE'); }
      if (cap?.delegated) {
        // delegate-signed operation within an owner-granted delegation that was ACTIVE when the vault accepted it
        const op = cap.delegated; proposedAt = vp ? vp.proposed_at : Date.parse(op.issuedAt);
        const sP = stateAt(proposedAt); const d = sP.v5.delegations[op.delegationId];
        if (!d) v.push('DELEGATION_UNKNOWN');
        else {
          if (!verifyObj5(V5_DOMAINS.DELEGATED_OP, op, approval?.delegateSig, d.delegateKey)) v.push('DELEGATED_OP_SIGNATURE_INVALID');
          if (d.status !== 'ACTIVE' || proposedAt >= Number(d.expiresAt)) v.push('DELEGATION_NOT_ACTIVE_AT_PROPOSAL');
          if (!d.recipients.includes(tx.recipient)) v.push('RECIPIENT_NOT_IN_DELEGATION');
          if (BigInt(tx.amount) > BigInt(d.perOpMaxYocto)) v.push('OVER_DELEGATION_PER_OP');
          const u = delegUse.get(d.delegationId) ?? { n: 0, sum: 0n, seqs: new Set() };
          u.n++; u.sum += BigInt(tx.amount); if (u.seqs.has(op.seq)) v.push('DELEGATED_OP_REPLAY'); u.seqs.add(op.seq); delegUse.set(d.delegationId, u);
          if (u.n > Number(d.maxUses)) v.push('DELEGATION_MAX_USES_EXCEEDED');
          if (u.sum > BigInt(d.cumulativeMaxYocto)) v.push('OVER_DELEGATION_CUMULATIVE');
          credId = d.issuerCredId; windowEnd = Number(d.expiresAt); authIssued = Date.parse(op.issuedAt);
          const sE = stateAt(tx.submitted_at); const dE = sE.v5.delegations[op.delegationId];
          // a consumed delegated operation may settle after the delegation's own expiry, but never after its horizon (checked below)
          if (dE?.status !== 'ACTIVE' && dE?.status !== 'EXPIRED') v.push('DELEGATION_ENDED_BEFORE_EFFECT');
          if (delegationHolds(sE, op.delegationId, tx.submitted_at).length) v.push('EFFECT_DURING_DELEGATION_HOLD');
          if (tx.amount !== op.amountYocto || tx.recipient !== op.recipientId) v.push('EFFECT_NOT_EXACT');
        }
      } else if (cap) {
        const issued = Date.parse(cap.issuedAt); proposedAt = vp ? vp.proposed_at : issued;
        try { const s0 = stateAt(issued); verifyPaycap({ ...s0, creds: Object.fromEntries(Object.entries(s0.creds).map(([k, c]) => [k, { ...c, signCount: 0 }])) }, { capability: cap, approval }, { now: issued }); }
        catch (e) { v.push('CAPABILITY_INVALID_AT_ISSUANCE:' + (e.code ?? e.message)); }
        if (tx.recipient !== cap.recipientId) v.push('RECIPIENT_MISMATCH');
        if (tx.amount !== cap.amountYocto) v.push('AMOUNT_NOT_EXACT');
        if (String(stateAt(tx.submitted_at).epoch) !== cap.epoch) v.push('EFFECT_IN_OTHER_EPOCH');
        if (stateAt(tx.submitted_at).purpose.version !== cap.purposeVersion) v.push('EFFECT_UNDER_OTHER_PURPOSE_VERSION');
        credId = approval?.credId; windowEnd = Date.parse(cap.expiresAt); authIssued = issued;
        if (seenCaps.has(capId)) v.push('DUPLICATE_EFFECT_FOR_CAPABILITY'); seenCaps.add(capId);
      }
      if (proposedAt !== null) {
        const sE = stateAt(tx.submitted_at);
        if (sE.freeze.active) v.push('EFFECT_DURING_GLOBAL_HOLD');
        if (sE.lockdown.active) v.push('EFFECT_DURING_EMERGENCY_LOCKDOWN');
        if (credId && sE.creds[credId]?.status !== 'active') v.push('APPROVER_NOT_ACTIVE_AT_EFFECT');
        if (credId && credentialHolds(sE, credId, tx.submitted_at).length) v.push('EFFECT_DURING_CREDENTIAL_HOLD');
        if (merchantHolds(sE, tx.recipient, tx.submitted_at).length) v.push('EFFECT_DURING_MERCHANT_HOLD');
        // P4: the applicable buffer of THIS payment = the engine-signed tier mapped by the owner-signed policy; the
        // verifier recomputes the tier from the signed inputs, checks the signature, the journal copy and the floor.
        let payBuffer = floor;
        let decB = null; try { decB = vp?.decision ? JSON.parse(vp.decision) : null; } catch {}
        if (decB?.statement?.bufferPolicy !== undefined) {
          out.buffer.checked++;
          const s0 = decB.statement;
          const sigOk = verifyObj5(V5_DOMAINS.RISK_ENGINE, s0, decB.sig, st.v5.riskEngine.publicKey);
          const tierOk = bufferPolicy === 'FIXED_600' ? s0.tier === '-' : String(tierFromInputs(s0.tierInputs, bufferPolicy)) === s0.tier;
          const bufOk = String(tierToBufferMs(bufferPolicy, s0.tier)) === s0.bufferMs && s0.bufferPolicy === bufferPolicy;
          const jr = engineBuffer.get(paymentId); const jOk = !journal || (jr && jr.tier === s0.tier && jr.bufferMs === s0.bufferMs);
          if (!sigOk || !tierOk || !bufOk || !jOk) { v.push('BUFFER_DECISION_INVALID'); out.buffer.violations++; }
          payBuffer = Math.max(floor, Math.min(MAX_BUFFER_MS, Number(s0.bufferMs) || MAX_BUFFER_MS));
        } else if (vp) payBuffer = MAX_BUFFER_MS; // no signed buffer decision: only the maximum buffer is acceptable
        if (tx.submitted_at < proposedAt + payBuffer) { v.push('BUFFER_BYPASSED'); out.buffer.violations++; }
        // anomaly delay: verify the engine's signed decision, its bound and that the payment did not leave early
        let dec = null; try { dec = vp?.decision ? JSON.parse(vp.decision) : null; } catch {}
        const recorded = vp ? Number(vp.delay_ms) : 0; const journaled = Math.min(engineDelay.get(paymentId) ?? 0, MAX_DELAY);
        if (journaled > recorded) v.push('DELAY_RECORD_MISMATCH');
        const delayMs = Math.max(recorded, journaled);
        let shift = 0;
        if (delayMs > 0) {
          out.delays.delayed++;
          const sigOk = recorded === 0 || dec?.statement && verifyObj5(V5_DOMAINS.RISK_ENGINE, dec.statement, dec.sig, st.v5.riskEngine.publicKey);
          if (!sigOk) v.push('DELAY_WITHOUT_ENGINE_DECISION');
          if (delayMs > MAX_DELAY) v.push('DELAY_OVER_CAP');
          shift = Math.min(delayMs, MAX_DELAY);
          const due = proposedAt + payBuffer + shift;
          if (tx.submitted_at < due) {
            const review = Object.entries(sE.v5.incidentReviews).find(([id, r]) => id === vp.incident_id && r.verdict === 'LEGITIMATE');
            const grant = Object.values(sE.v5.rapid.grants).find(g => Number(g.activatedAt) <= tx.submitted_at && (g.scope.credIds.includes(vp.cred_id) || (vp.delegation_id && g.scope.delegationIds.includes(vp.delegation_id))) && g.scope.recipients.includes(tx.recipient));
            if (!review && !grant) { v.push('DELAYED_PAYMENT_RELEASED_EARLY'); out.delays.earlyRelease.push(paymentId); }
          }
        }
        // P2: submission deadline (consumption) and latest authorized settlement, from signed data + replayed genesis only
        if (windowEnd !== null && proposedAt >= windowEnd) v.push('AUTHORIZATION_CONSUMED_AFTER_DEADLINE');
        if (authIssued !== null && tx.submitted_at >= Math.min(authIssued + horizon, Date.parse(sE.purpose.expiresAt))) { v.push('EFFECT_AFTER_SETTLEMENT_HORIZON'); out.horizon.violations++; }
        // P1: HIGH-risk incident payments need an owner resolution (LEGITIMATE review) or a covering Rapid-Use grant
        const hAt = Math.min(highAt.get(vp?.incident_id) ?? Infinity, highAt.get('pay:' + paymentId) ?? Infinity);
        if (tx.submitted_at >= hAt) {
          const review = vp?.incident_id && sE.v5.incidentReviews[vp.incident_id]?.verdict === 'LEGITIMATE';
          const grant = vp && Object.values(sE.v5.rapid.grants).find(g => Number(g.activatedAt) <= tx.submitted_at && (g.scope.credIds.includes(vp.cred_id) || (vp.delegation_id && g.scope.delegationIds.includes(vp.delegation_id))) && g.scope.recipients.includes(tx.recipient));
          if (!review && !grant) v.push('HIGH_RISK_SETTLED_WITHOUT_RESOLUTION');
        }
        const pv = purposeViolations(sE.purpose, { operation: 'PAY', recipientId: tx.recipient, asset: 'NEAR', amountYocto: tx.amount, sku: null, now: tx.submitted_at, capExpiresAt: tx.submitted_at + 1, capIssuedAt: tx.submitted_at },
          { cumulativeYocto: cum.toString(), last24hYocto: '0' }).filter(x => !['OVER_DAILY_LIMIT', 'PURPOSE_NOT_ACTIVE', 'SKU_NOT_ALLOWED', 'SKU_REQUIRED'].includes(x));
        v.push(...pv.map(x => 'PURPOSE:' + x));
      }
    }
    cum += BigInt(tx.amount);
    if (v.length) out.financial.violations.push({ txId: tx.tx_id, paymentId, recipient: tx.recipient, amountYocto: tx.amount, codes: v });
    else out.financial.authorized++;
  }
  // P4 anti-splitting: a flow's signed tier never drops below the highest signed tier the same flow got in the hour before
  if (bufferPolicy !== 'FIXED_600') {
    const signed = [];
    for (const p of v5pay) { let d = null; try { d = JSON.parse(p.decision); } catch {} const s0 = d?.statement; if (!s0 || s0.tier === undefined || !verifyObj5(V5_DOMAINS.RISK_ENGINE, s0, d.sig, st.v5.riskEngine.publicKey)) continue; signed.push({ id: p.payment_id, flow: p.flow, at: p.proposed_at, tier: Number(s0.tier) }); }
    const resets = [];
    signed.forEach((x, j) => { const exp = signed.slice(0, j).filter(y => y.flow === x.flow && y.at > x.at - 3600_000).reduce((m, y) => Math.max(m, y.tier), 0); if (x.tier < exp) resets.push(x.id); });
    out.buffer.tierResets = resets.length;
    if (resets.length) { out.buffer.violations += resets.length; out.financial.violations.push({ txId: '-', paymentId: resets[0], recipient: '-', amountYocto: '0', codes: ['BUFFER_TIER_RESET'] }); }
  }
  if (journal) out.journal = verifyJournalChain(journal.rows, journal.checkpoints, journal.publicKey);
  out.ok = out.chainValid && !out.financial.violations.length && !out.authority.unauthorized.length && !out.rapid.violations.length && (!journal || out.journal.ok);
  return out;
}

/** Convenience for in-process worlds. */
export async function verifyWorld(w) {
  return verifyV5({ genesis: w.genesis, pinnedChainId: w.owner.chainId5, transitions: w.root.chain(0), ledgerTxs: await w.ledgerRead.call('TRANSFERS', { sinceSeq: '0' }),
    evidence: w.vault.evidence(), v5pay: w.vault.v5payments(), ownerIntents: w.intents, attackerCaseIds: w.attackerCaseIds,
    journal: { rows: w.journal.rows(), checkpoints: w.journal.witnesses[1].all(), publicKey: w.journal.signer.publicKey } });
}
