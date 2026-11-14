// Independent V6 verifier (supervisor domain). Runs the complete V5.1 verifier on the V6 chain (which re-verifies every
// fingerprint gate inside the replay), then re-checks the V6 additions from signed evidence and the replayed chain only:
//   * every owner payment effect under PER_TRANSACTION has a V6 owner approval whose binding, Root-pinned one-time
//     challenge, policy version, assurance and (fingerprint-only) gate verify against the replayed state at proposal;
//     challenge nonces are unique across all effects;
//   * delegated effects are allowed only under BOUNDED_DELEGATION_ALLOWED;
//   * every emergency FREEZE names an incident the Risk Engine's own journal opened (no email / link / locator can
//     invent one), and every hold-release / UNFREEZE went through the unchanged V5 rules (replay).
import { verifyV5 } from '../../v5/supervisor/verifier.mjs';
import { incidentIdFor } from '../../v5/risk/engine.mjs';
import * as V6 from '../root/chain.mjs';
import { verifyPaymentApproval } from '../vault/payment-approval.mjs';

export const EMERGENCY_REASON_RE = /^EMERGENCY_FREEZE incident=(inc-[0-9a-f]{8,64}) scope=GLOBAL via=(OWNER_CONSOLE|SAFEBOX_APP)$/;

export function verifyV6(args) {
  const { genesis, pinnedChainId, transitions, ledgerTxs = [], evidence = [], v6evidence = [], journal = null } = args;
  const out = verifyV5({ ...args, chain: V6 });
  out.v6 = { ownerApprovals: { checked: 0, violations: [] }, emergency: { freezes: 0, violations: [] }, gates: 0 };
  if (!out.chainValid) { out.ok = false; return out; }
  // replay snapshots (independent of the V5 pass; cheap at these sizes)
  let st = V6.genesisState(genesis, { pinnedChainId }); const snaps = [{ at: st.lastAt, state: st }];
  for (const tr of transitions) { const r = V6.applyTransition(st, tr); st = r.state; snaps.push({ at: st.lastAt, state: st, tr, effects: r.effects });
    out.v6.gates += (r.effects.find(e => e.type === 'BIOMETRIC_GATE_ASSURANCE')?.levels.length ?? 0); }
  const stateAt = (t) => { let s = snaps[0].state; for (const x of snaps) { if (x.at <= t) s = x.state; else break; } return V6.projectState(s, Math.max(t, s.lastAt)); };
  const policy = st.v6.policy;
  const proposalAt = new Map();
  const opened = new Set();
  for (const r of journal?.rows ?? []) {
    const e = JSON.parse(r.body); if (e.layer !== 'RISK') continue;
    if (e.type === 'BUFFER_DECISION' && !proposalAt.has(e.relatedId)) proposalAt.set(e.relatedId, Date.parse(e.at));
    if (e.type === 'ENGINE_DECISION' && e.outcome !== 'NONE' && (!e.data.incidentRef || e.data.incidentRef === '-')) opened.add(incidentIdFor(e.relatedId));
  }
  const evByCap = new Map(evidence.map(e => [e.cap_id, e]));
  const v6ByCap = new Map(v6evidence.map(e => [e.cap_id, e]));
  const nonces = new Map();
  for (const tx of ledgerTxs) {
    let capId = null, paymentId = null; try { const s = JSON.parse(tx.statement); capId = s.capId; paymentId = s.paymentId; } catch {}
    if (!capId || String(capId).startsWith('hist-')) continue;
    const ev = evByCap.get(capId); if (!ev) continue; // NO_OWNER_CAPABILITY is already flagged by the V5 pass
    let cap, approval; try { cap = JSON.parse(ev.cap); approval = JSON.parse(ev.approval); } catch { continue; }
    const codes = [];
    if (cap.delegated) { if (policy.delegation !== 'BOUNDED_DELEGATION_ALLOWED') codes.push('DELEGATED_EFFECT_WHILE_DELEGATION_DISABLED'); }
    else {
      const t = proposalAt.get(paymentId) ?? Date.parse(cap.issuedAt);
      const s0 = stateAt(t);
      if (s0.v6.policy.payment.mode === 'PER_TRANSACTION') {
        out.v6.ownerApprovals.checked++;
        const x = v6ByCap.get(capId);
        if (!x || x.payment_id !== paymentId) codes.push('OWNER_APPROVAL_MISSING');
        else {
          try {
            const v6 = { binding: JSON.parse(x.binding), grant: JSON.parse(x.grant_), ...(x.gate ? { gate: JSON.parse(x.gate) } : {}) };
            const r = verifyPaymentApproval(s0, { cap, credId: approval.credId, v6 }, t);
            if (nonces.has(r.nonce) && nonces.get(r.nonce) !== capId) codes.push('OWNER_APPROVAL_CHALLENGE_REUSED'); nonces.set(r.nonce, capId);
            if (r.level !== x.level) codes.push('OWNER_APPROVAL_LEVEL_MISREPORTED');
          } catch (e) { codes.push('OWNER_APPROVAL_INVALID:' + (e.code ?? e.message)); }
        }
      }
    }
    if (codes.length) { out.v6.ownerApprovals.violations.push({ txId: tx.tx_id, paymentId, codes }); out.financial.violations.push({ txId: tx.tx_id, paymentId, recipient: tx.recipient, amountYocto: tx.amount, codes }); }
  }
  // emergency freezes: bound to an incident the engine actually opened
  for (const h of Object.values(st.v5.holds)) {
    if (!String(h.reason).startsWith('EMERGENCY_FREEZE')) continue;
    out.v6.emergency.freezes++;
    const m = EMERGENCY_REASON_RE.exec(String(h.reason));
    if (!m) out.v6.emergency.violations.push({ holdId: h.holdId, code: 'EMERGENCY_FREEZE_REASON_MALFORMED' });
    else if (journal && !opened.has(m[1])) out.v6.emergency.violations.push({ holdId: h.holdId, code: 'EMERGENCY_FREEZE_UNKNOWN_INCIDENT' });
  }
  out.ok = out.ok && !out.v6.ownerApprovals.violations.length && !out.v6.emergency.violations.length;
  return out;
}

export async function verifyWorld6(w) {
  return verifyV6({ genesis: w.genesis, pinnedChainId: w.owner.chainId6, transitions: w.root.chain(0), ledgerTxs: await w.ledgerRead.call('TRANSFERS', { sinceSeq: '0' }),
    evidence: w.vault.evidence(), v5pay: w.vault.v5payments(), v6evidence: w.vault.v6evidence(), ownerIntents: w.intents, attackerCaseIds: w.attackerCaseIds,
    journal: { rows: w.journal.rows(), checkpoints: w.journal.witnesses[1].all(), publicKey: w.journal.signer.publicKey } });
}
