// V4 deterministic recovery matrix (mission §12): all 32 subsets of the five personal credentials, plus named scenarios.
// For every case the seven questions are answered from an actual run, never from the expected value:
//   Q1 ownerCanRecover   Q2 attackerDenied   Q3 holdOrLockdown   Q4 paymentsContinue
//   Q5 ownerInteractions Q6 latencyH         Q7 oldAuthorizationsInvalid
// "Recovered" additionally requires that the final active credential set equals the owner's approved replacement set,
// that the Purpose digest is unchanged and that no asset moved.
import { buildV4 } from '../world.mjs';
import { ACCOUNT } from '../kit.mjs';
import { openCaseV4, evidence4 as E, legitimateRecoveryV4, emergencyReplace, openGov } from './sim.mjs';

export const KEYS = ['k1-phone', 'k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'];
const H = 3600_000;
const Y = (c) => (BigInt(c) * 10n ** 22n).toString();
const active = (w) => Object.values(w.root.state.creds).filter(c => c.status === 'active').map(c => c.credId).sort();
const survivingDaily = (w, lost) => KEYS.filter(k => !lost.includes(k) && w.root.state.creds[k]?.role === 'DAILY');
export const expectedOutcome = (n) => n === 0 ? 'NO_RECOVERY_NEEDED' : n <= 2 ? 'RECOVERED' : n <= 4 ? 'NEW_EPOCH' : 'RECOVERY_IMPOSSIBLE';

/** Prepares authorizations that must die with the recovery: an unsent payment capability and an unsent intent approval. */
function prepareOld(w) {
  const pc = w.owner.paycap(w.view(), { credId: 'k1-phone', recipientId: 'merchant-a.mock', amountYocto: Y(1), sku: '-' });
  const a = w.owner.action(w.view(), 'REVOKE', { credId: 'k4-freeze', reason: 'old' });
  const aps = w.owner.authorize(w.root.state, a, ['k1-phone', 'k3-root-hw']);
  return { pc, a, aps };
}
async function oldStillWorks(w, old) {
  const p = await w.gz.request('PROPOSE', { capability: old.pc.capability, approval: old.pc.approval, recipientId: old.pc.capability.recipientId, amountYocto: old.pc.capability.amountYocto, asset: 'NEAR', memo: 'old' });
  const g = await w.submit({ action: old.a, approvals: old.aps });
  return { paycap: p.ok, intent: g.ok };
}

/** The maximal R-1 collusion against the same claimed loss: stolen DAILY K1 (if it survives), all guardians, both IDVs, all channel acks, owner silent. */
export async function attackSubset(lost) {
  const w = buildV4();
  const o = await openCaseV4(w, { lost, full: lost.length * 2 > 5, attacker: true });
  if (!o.r.ok) return { denied: true, at: 'open', code: o.r.error.code };
  for (const i of ['idv-1', 'idv-2']) await E.identity(w, i);
  if (!lost.includes('k1-phone')) await E.consent(w, 'k1-phone');
  for (const g of ['g1', 'g2', 'g3']) await E.guardian(w, g);
  for (const ch of Object.keys(w.root.state.channels)) await E.ack(w, ch, 'NO_OBJECTION', { intended: false });
  await w.advance(73 * H, 3 * H);
  const r = await w.recovery.tryComplete(w.root.state); await w.pump();
  const v = await w.verify();
  return { denied: v.takeovers.length === 0 && !r.ok, at: 'complete', code: r.ok ? 'TAKEOVER' : (r.code ?? r.state), takeovers: v.takeovers.length };
}

export async function runSubset(lost) {
  const exp = expectedOutcome(lost.length);
  // Q3 + Q4: state and payment availability during an open legitimate case
  let during = { state: '-', lockdown: false, payment: null };
  if (lost.length) {
    const w0 = buildV4(); for (const k of lost) w0.owner.dev(k).lost = true;
    const o = await openCaseV4(w0, { lost, full: lost.length * 2 > 5 });
    if (o.r.ok) { await E.identity(w0, 'idv-1'); }
    const sd = survivingDaily(w0, lost)[0];
    during = { state: w0.root.state.case?.state ?? '-', lockdown: w0.root.state.lockdown.active, payment: sd ? (await w0.pay({ credId: sd, amountYocto: Y(1) })).ok : null };
  }
  const w = buildV4();
  const before = { purpose: w.root.state.purposeDigest, balances: await w.ledgerRead.call('BALANCES', {}) };
  const old = prepareOld(w);
  for (const k of lost) w.owner.dev(k).lost = true;
  const rep = lost.length ? await legitimateRecoveryV4(w, lost) : { outcome: 'NO_RECOVERY_NEEDED', latencyMs: 0, gestures: 0, prompts: 0, independentSignerInteractions: 0, signatures: 0 };
  const st = w.root.state;
  let authoritySetMatches = null, postPayment = null, oldInvalid = null;
  if (['RECOVERED', 'NEW_EPOCH'].includes(rep.outcome)) {
    const h = st.caseHistory.at(-1); const tr = w.root.chain(0).filter(t => t.action.type === 'RECOVERY_OPEN').at(-1);
    const plan = tr.action.body.plan.map(p => p.credId);
    const want = (rep.outcome === 'NEW_EPOCH' ? plan : [...KEYS.filter(k => !lost.includes(k)), ...plan]).sort();
    authoritySetMatches = JSON.stringify(active(w)) === JSON.stringify(want);
    const daily = Object.values(st.creds).find(c => c.status === 'active' && c.role === 'DAILY');
    postPayment = (await w.pay({ credId: daily.credId, amountYocto: Y(1) })).ok;
    const o = await oldStillWorks(w, old); oldInvalid = !o.paycap && !o.intent;
    void h;
  }
  await w.advance(11 * 60_000);
  const v = await w.verify();
  const balancesAfter = await w.ledgerRead.call('BALANCES', {});
  const atk = lost.length ? await attackSubset(lost) : { denied: true, at: '-', code: 'NO_CASE' };
  return {
    lost: lost.join('+') || 'none', n: lost.length, expected: exp, outcome: rep.outcome,
    Q1_ownerCanRecover: ['RECOVERED', 'NEW_EPOCH', 'NO_RECOVERY_NEEDED'].includes(rep.outcome) && authoritySetMatches !== false,
    Q2_attackerDenied: atk.denied, attackerStoppedBy: atk.code,
    Q3_caseStateDuringCase: during.state, Q3_lockdown: during.lockdown,
    Q4_survivorPaymentDuringCase: during.payment,
    Q5_ownerGestures: rep.gestures, ownerPrompts: rep.prompts, independentSigners: rep.independentSignerInteractions, chainSignatures: rep.signatures,
    Q6_latencyH: +(rep.latencyMs / H).toFixed(2),
    Q7_oldAuthorizationsInvalid: oldInvalid,
    finalAuthorityMatchesApprovedSet: authoritySetMatches, postRecoveryPayment: postPayment,
    purposePreserved: st.purposeDigest === before.purpose,
    assetsPreserved: JSON.stringify(balancesAfter) === JSON.stringify(before.balances) || postPayment === true,
    lockdownAfter: st.lockdown.active, epoch: st.epoch, verifierClean: v.chainValid && v.takeovers.length === 0 && v.financial.violations.length === 0,
  };
}

// ------------------------------------------------------------------------------------------------ named scenarios
const row = (name, o) => ({ scenario: name, ...o });
export const SCENARIOS = {
  'stolen DAILY (K1) alone: minority claim + R-1 claim': async () => {
    const a = await attackSubset(['k2-laptop', 'k3-root-hw']); const b = await attackSubset(['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw']);
    return row('stolen DAILY', { Q1: 'n/a (no loss)', Q2: a.denied && b.denied, detail: [a.code, b.code] });
  },
  'compromised Guardians (g1+g2) block the owner: cancel, replace them (R-3), recover': async () => {
    const w = buildV4(); const lost = ['k2-laptop', 'k3-root-hw', 'k4-freeze']; for (const k of lost) w.owner.dev(k).lost = true;
    ok(await openCaseV4(w, { lost, full: true }).then(x => x.r));
    await E.identity(w, 'idv-1'); await E.identity(w, 'idv-2');
    await E.guardian(w, 'g1', 'OBJECT'); await E.guardian(w, 'g2', 'OBJECT');
    const held = w.root.state.case.state;
    ok(await E.orcCancel(w));
    // owner quorum after losing K2..K4: K1 (DAILY, protected confirmation) + K5 (RECOVERY, display)
    const g = await emergencyReplace(w, { accused: ['g1', 'g2'], owners: ['k1-phone', 'k5-recovery-hw'] });
    const newG = Object.keys(w.root.state.guardians).filter(x => w.root.state.guardians[x].status === 'active');
    const rep = await legitimateRecoveryV4(w, lost, { honestGuardians: newG });
    const v = await w.verify();
    return row('compromised guardians', { Q1: rep.outcome === 'NEW_EPOCH', Q2: v.takeovers.length === 0, Q3: held, gov: g.stage, outcome: rep.outcome, Q5: rep.gestures, Q6: +(rep.latencyMs / H).toFixed(1) });
  },
  'compromised identity verifiers refuse: replace them (R-3), recover': async () => {
    const w = buildV4();
    const g = await emergencyReplace(w, { procedure: 'IDENTITY_VERIFIER_EMERGENCY_REPLACE', accused: ['idv-1', 'idv-2'], owners: ['k1-phone', 'k3-root-hw'] });
    const lost = ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'];
    const rep = await legitimateRecoveryV4(w, lost, { honestIdvs: Object.keys(w.root.state.idvs) });
    return row('compromised IDVs', { Q1: rep.outcome === 'NEW_EPOCH', gov: g.stage, outcome: rep.outcome });
  },
  'compromised notification channel objects to the owner\'s minority recovery (overridable)': async () => {
    const w = buildV4(); const lost = ['k2-laptop'];
    ok(await openCaseV4(w, { lost }).then(x => x.r)); await E.identity(w, 'idv-1');
    await E.ack(w, 'ch-email', 'OBJECTION', { intended: false });
    const st = w.root.state.case.state;
    for (const c of ['k1-phone', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw']) await E.consent(w, c);
    for (const gg of ['g1', 'g2']) await E.guardian(w, gg);
    const ov = await E.override(w);
    await w.advance(73 * H, 3 * H); const r = await w.recovery.tryComplete(w.root.state); await w.pump();
    return row('compromised channel', { Q3: st, override: ov.ok, Q1: r.ok });
  },
  'false accusation against an honest guardian (stolen K1+K3, one bribed adjudicator)': async () => {
    const w = buildV4(); const r = await openGov(w, { accused: ['g3'], owners: ['k1-phone', 'k3-root-hw'], adj: ['adj-1'] });
    return row('false accusation', { Q2: !r.r.ok, code: r.r.error?.code });
  },
  'genuine identity dispute (IDV cannot verify): case expires; owner retries after 12 h or at once with the ORC': async () => {
    const w = buildV4(); const lost = ['k2-laptop'];
    ok(await openCaseV4(w, { lost }).then(x => x.r));
    const d = await w.submitRaw('RECOVERY_IDENTITY', { caseId: w.root.state.case.caseId, caseDigest: w.root.state.case.digest, idvId: 'idv-1', holderId: 'alice', method: 'document-and-liveness', result: 'DISPUTED' }, { attest: (a) => ({ idvSig: w.owner.idvSign(a, 'idv-1') }) });
    await w.advance(73 * H, 3 * H); await E.expire(w);
    const immediate = await openCaseV4(w, { lost }); // 12 h per-subject cooldown
    await w.advance(H + 60_000, H);                   // the V3 1 h global anti-spam interval still applies
    const rep = await legitimateRecoveryV4(w, lost);  // the owner's ORC lifts the 12 h cooldown
    return row('identity dispute', { disputed: !d.ok, disputeCode: d.error?.code, expired: w.root.state.caseHistory.at(-2)?.outcome, immediateRetry: immediate.r.error?.code, Q1: rep.outcome === 'RECOVERED', outcome: rep.outcome, Q6: +(rep.latencyMs / H).toFixed(1) });
  },
  'legitimate owner silence on an attacker case (R-1)': async () => { const a = await attackSubset(['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw']); return row('owner silence', { Q2: a.denied, code: a.code }); },
  'device replacement during the 72 h window (new plan device): ORC cancel + ORC-attested reopen': async () => {
    const w = buildV4(); const lost = ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'];
    ok(await openCaseV4(w, { lost, full: true }).then(x => x.r)); await E.identity(w, 'idv-1');
    await w.advance(20 * H, 4 * H);
    ok(await E.orcCancel(w));
    await w.advance(H + 60_000, H);                   // global 1 h anti-spam interval
    const rep = await legitimateRecoveryV4(w, lost);  // new plan device; ORC-attested reopen lifts the 12 h cooldown
    return row('device replacement', { Q1: rep.outcome === 'NEW_EPOCH', outcome: rep.outcome, Q5: rep.gestures, Q6: +(rep.latencyMs / H).toFixed(1) });
  },
  'signed cancellation (ORC) of a fraudulent case': async () => {
    const w = buildV4(); ok(await openCaseV4(w, { lost: ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], full: true, attacker: true }).then(x => x.r));
    await E.identity(w, 'idv-1'); await E.identity(w, 'idv-2'); const lk = w.root.state.lockdown.active;
    const c = await E.orcCancel(w); const p = await w.pay({ amountYocto: Y(1) });
    return row('signed cancellation', { Q3_lockdownBefore: lk, cancelled: c.ok, Q4_paymentAfter: p.ok });
  },
  'repeated reconstitution attempts (cooldown, claim budget, lockdown budget)': async () => {
    const w = buildV4(); const lost = ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw']; const res = [];
    for (let i = 0; i < 4; i++) {
      const o = await openCaseV4(w, { lost, full: true, attacker: true }); res.push(o.r.ok ? 'opened' : o.r.error.code);
      if (o.r.ok) { await E.identity(w, 'idv-1'); await E.identity(w, 'idv-2'); await w.advance(73 * H, 3 * H); await E.expire(w); }
      const imm = await openCaseV4(w, { lost, full: true, attacker: true }); if (!imm.r.ok) res.push('immediate:' + imm.r.error.code);
      await w.advance(12 * H + 60_000, 3 * H);
    }
    const lockH = w.root.state.v4.lockdowns.reduce((t, l) => t + ((l.end ?? w.now()) - l.start), 0) / H;
    return row('repeated attempts', { attempts: res, lockdownHoursTotal: +lockH.toFixed(1) });
  },
  'new-Epoch execution after recovery: new keys pay, old capability/approval refused': async () => {
    const r = await runSubset(['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw']);
    return row('new epoch', { Q1: r.Q1_ownerCanRecover, Q7: r.Q7_oldAuthorizationsInvalid, postRecoveryPayment: r.postRecoveryPayment, authoritySet: r.finalAuthorityMatchesApprovedSet });
  },
};
function ok(r) { if (!r?.ok) throw new Error('scenario precondition failed: ' + JSON.stringify(r?.error ?? r)); return r; }

export function subsets() { const out = []; for (let m = 0; m < 32; m++) out.push(KEYS.filter((_, i) => m & (1 << i))); return out; }
export { ACCOUNT };
