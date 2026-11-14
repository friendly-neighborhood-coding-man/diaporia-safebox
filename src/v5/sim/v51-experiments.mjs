// SafeBox V5.1 matched A/B experiments (mission P4 "Controlled Comparison"). Simulated time, MOCK ledger, MOCK e-mail.
//   Arm A  = Control: fixed 10-minute buffer (V5 baseline buffer policy, with the V5.1 P1-P3 changes)
//   Arm B  = Candidate: bufferSeconds(n) = min(600, 30 * 2^n), n = deterministic bounded risk tier
// Both arms run the SAME attack trajectories, the SAME legitimate transactions, the SAME owner availability and the SAME
// seeded jitter. The only difference is genesis config5.bufferPolicy (owner-signed). Nothing here touches real funds,
// real mailboxes or a real chain. Every number in the output is measured from the vault / ledger / journal records.
import { buildV5, near, ATTACKER } from '../world.mjs';
import { verifyWorld } from '../supervisor/verifier.mjs';
import { scopeOf } from './scenarios.mjs';

const MIN = 60_000, H = 3600_000, D = 86_400_000;
export const ARMS = Object.freeze({ A: { bufferPolicy: 'FIXED_600' }, B: { bufferPolicy: 'EXP_30' }, X_HV: { bufferPolicy: 'EXP_30_HV' } }); // X_*: exploratory, not part of the primary A/B
export const ATTACK_CRED = 'k1-phone', OWNER_CRED = 'k2-laptop';

/** mulberry32: small deterministic PRNG for controlled seeds (jitter only; no security decision uses it). */
export function prng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

/** 30 days of reviewed, clean history for both owner devices (identical in both arms). */
function seedHistory(w) {
  const now = w.now(); const rows = [];
  for (let d = 30; d >= 4; d--) for (const [cred, hours] of [[ATTACK_CRED, [9, 13, 19]], [OWNER_CRED, [10, 15]]]) for (const h of hours)
    rows.push({ credId: cred, recipient: h % 2 ? 'merchant-a.mock' : 'merchant-b.mock', amount: near(0.02), at: now - d * D + h * H });
  w.vault.seedHistory(rows);
}

function world(arm, { horizonMs = null, transportMode = 'OK', history = true } = {}) {
  const config5 = { ...ARMS[arm], ...(horizonMs ? { settlementHorizonMs: String(horizonMs) } : {}) };
  const w = buildV5({ config5 });
  if (history) seedHistory(w);
  w.mock.mode = transportMode;
  w.tags = new Map(); // paymentId -> 'ATTACK' | 'LEGIT'
  w.denials = { ATTACK: {}, LEGIT: {} };
  w.firstDetectAt = null;
  return w;
}
async function pay(w, who, { credId, amount = near(0.02), recipientId = 'merchant-a.mock', at = null, ttlMs = 3600_000 } = {}) {
  credId ??= who === 'ATTACK' ? ATTACK_CRED : OWNER_CRED;
  let r;
  if (at !== null) {
    const pc = w.owner.paycap(w.view(), { credId, recipientId, amountYocto: amount, at, ttlMs });
    r = await w.gz.request('PROPOSE', { capability: pc.capability, approval: pc.approval, recipientId, amountYocto: amount, asset: 'NEAR', memo: who.toLowerCase() });
  } else r = await w.pay({ credId, recipientId, amountYocto: amount, request: { memo: who.toLowerCase() } });
  if (r.ok) { w.tags.set(r.result.paymentId, who); if (r.result.anomaly !== 'NONE' && w.firstDetectAt === null) w.firstDetectAt = w.now(); }
  else { const det = String(r.error.detail ?? ''); const c = r.error.code === 'POLICY_DENY' && /^[A-Z_,]+$/.test(det) ? det.split(',')[0] : r.error.code; w.denials[who][c] = (w.denials[who][c] ?? 0) + 1; }
  return r;
}
/** owner reacts to a security incident: suspend the stolen credential (laptop) and mark the incident FRAUD */
async function ownerContain(w) {
  const out = { suspend: (await w.cmd('SUSPEND', { credId: ATTACK_CRED, holdId: w.newId('q') }, [OWNER_CRED])).ok };
  for (const inc of w.vault.incidents().filter(i => i.cred_id === ATTACK_CRED && (i.state === 'OPEN' || i.state === 'LAPSED')))
    out.fraud = (await w.cmd('INCIDENT_REVIEW', { incidentId: inc.incident_id, credId: ATTACK_CRED, verdict: 'FRAUD', evidenceDigest: 'f'.repeat(64) }, [OWNER_CRED])).ok;
  return out;
}
/** the owner confirms their OWN delayed payments as legitimate (trusted key) */
async function ownerConfirmLegit(w, credId = OWNER_CRED) {
  let n = 0;
  for (const inc of w.vault.incidents().filter(i => i.cred_id === credId && (i.state === 'OPEN' || i.state === 'LAPSED')))
    if ((await w.cmd('INCIDENT_REVIEW', { incidentId: inc.incident_id, credId, verdict: 'LEGITIMATE', evidenceDigest: 'e'.repeat(64) }, ['k3-root-hw'])).ok) n++;
  return n;
}
/** run the clock, letting an owner policy react; ownerAt(w) returns true once the owner acts */
async function run(w, ms, { step = MIN, onTick = null } = {}) { const end = w.now() + ms; while (w.now() < end) { await w.advance(Math.min(step, end - w.now()), step); if (onTick) await onTick(); } }

const pctl = (xs, p) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1))]; };
async function measure(w, extra = {}) {
  const v = await verifyWorld(w);
  const ps = w.vault.v5payments();
  const atk = ps.filter(p => w.tags.get(p.payment_id) === 'ATTACK'), leg = ps.filter(p => w.tags.get(p.payment_id) === 'LEGIT');
  const sum = (l) => l.reduce((t, p) => t + BigInt(p.amount), 0n);
  const settled = (l) => l.filter(p => p.state === 'SETTLED');
  const det = w.firstDetectAt;
  const lat = settled(leg).map(p => p.settled_at - p.proposed_at);
  const deniedLegit = Object.values(w.denials.LEGIT).reduce((a, b) => a + b, 0);
  return {
    attacker: { proposed: atk.length, settled: settled(atk).length, settledYocto: sum(settled(atk)).toString(), settledNEAR: Number(sum(settled(atk)) * 1000n / 10n ** 24n) / 1000,
      settledBeforeDetection: settled(atk).filter(p => det === null || p.settled_at <= det).length,
      settledBeforeDetectionNEAR: Number(sum(settled(atk).filter(p => det === null || p.settled_at <= det)) * 1000n / 10n ** 24n) / 1000,
      expired: atk.filter(p => p.state === 'EXPIRED').length, cancelled: atk.filter(p => p.state === 'CANCELLED').length, denied: w.denials.ATTACK },
    legit: { proposed: leg.length, attemptedIncludingDenied: leg.length + deniedLegit, settled: settled(leg).length,
      successRate: (leg.length + deniedLegit) ? settled(leg).length / (leg.length + deniedLegit) : null,
      latencyMs: lat, falsePositiveDelays: leg.filter(p => p.delay_ms > 0).length, falsePositiveCancellations: leg.filter(p => ['CANCELLED', 'EXPIRED'].includes(p.state)).length,
      deniedAtProposal: w.denials.LEGIT, pendingSlotExhaustion: w.denials.LEGIT.PENDING_COUNT_LIMIT ?? 0 },
    detection: { firstDetectAtMs: det === null ? null : det - w.t0 },
    owner: { prompts: w.owner.metrics.prompts },
    overhead: { decisionMsP50: pctl(w.vault.metrics.decisionsMs, 0.5), decisionMsP99: pctl(w.vault.metrics.decisionsMs, 0.99), journalBytes: w.journal.stats.bytes, journalEvents: w.journal.stats.appended,
      v5payBytes: ps.reduce((t, p) => t + JSON.stringify(p).length, 0) },
    verifier: { ok: v.ok, violations: v.financial.violations.map(x => x.codes).flat(), horizonViolations: v.horizon?.violations ?? null, unauthorizedAuthority: v.authority.unauthorized.length },
    ...extra,
  };
}

// ------------------------------------------------------------------------------------------------ scenarios
// Each takes (arm, rnd) and returns measure(). `rnd` is the seeded PRNG: the SAME seed gives both arms the same jitter.
const S = {};
/** 1. Single maximum-value in-Purpose theft; the owner independently notices the stolen phone after `discoverMs`. */
for (const discoverMs of [2 * MIN, 5 * MIN, 15 * MIN, null]) S[`01_single_max_theft_discover_${discoverMs === null ? 'never' : discoverMs / MIN + 'm'}`] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now();
  await run(w, Math.floor(rnd() * 50) * 1000, { step: 1000 });
  await pay(w, 'ATTACK', { amount: near(0.06) });
  let acted = false;
  await run(w, 72 * H, { step: MIN, onTick: async () => { if (!acted && discoverMs !== null && w.now() - w.t0 >= discoverMs) { acted = true; await ownerContain(w); } } });
  return measure(w);
};
/** 2. Fast payment burst (the V5 Scenario A trajectory: 0.05 NEAR every 20 s; preserves the 40-second detection case). */
for (const respondMs of [30 * MIN, null]) S[`02_fast_burst_owner_${respondMs === null ? 'offline' : respondMs / MIN + 'm'}`] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now(); let firstMail = null, acted = false;
  const tick = async () => { if (firstMail === null && w.mock.sent.length) firstMail = w.now(); if (!acted && respondMs !== null && firstMail !== null && w.now() - firstMail >= respondMs) { acted = true; await ownerContain(w); } };
  for (let i = 0; i < 30; i++) { await pay(w, 'ATTACK', { amount: near(0.05) }); await run(w, 20_000, { step: 20_000, onTick: tick }); }
  await run(w, 72 * H, { step: 5 * MIN, onTick: tick });
  return measure(w);
};
/** 2b. The preserved V5 40-second detection case: V5 Scenario A exactly (cold start, no history, 0.05 NEAR every 20 s). */
for (const respondMs of [30 * MIN, null]) S[`02b_v5_scenarioA_40s_cold_owner_${respondMs === null ? 'offline' : respondMs / MIN + 'm'}`] = async (arm, rnd) => {
  const w = world(arm, { history: false }); w.t0 = w.now(); let firstMail = null, acted = false;
  const tick = async () => { if (firstMail === null && w.mock.sent.length) firstMail = w.now(); if (!acted && respondMs !== null && firstMail !== null && w.now() - firstMail >= respondMs) { acted = true; await ownerContain(w); } };
  for (let i = 0; i < 30; i++) { await pay(w, 'ATTACK', { amount: near(0.05) }); await run(w, 20_000, { step: 20_000, onTick: tick }); }
  await run(w, 72 * H, { step: 5 * MIN, onTick: tick });
  return measure(w);
};
/** 3. Slow budget drain: one in-Purpose payment every 13 min for 72 h, owner offline. */
S['03_slow_drain_owner_offline'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now();
  for (let i = 0; i < Math.floor(72 * H / (13 * MIN)); i++) { await pay(w, 'ATTACK', { amount: near(0.05) }); await run(w, 13 * MIN + Math.floor(rnd() * 30) * 1000, { step: 13 * MIN }); }
  await run(w, 27 * H, { step: 10 * MIN });
  return measure(w);
};
/** 4. Transaction splitting: each hour, one maximum payment split into 10 x 0.006 within 2 minutes; owner discovers at 15 min. */
for (const discoverMs of [15 * MIN, null]) S[`04_splitting_discover_${discoverMs === null ? 'never' : discoverMs / MIN + 'm'}`] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now(); let acted = false;
  const tick = async () => { if (!acted && discoverMs !== null && w.now() - w.t0 >= discoverMs) { acted = true; await ownerContain(w); } };
  for (let h = 0; h < 6; h++) { for (let k = 0; k < 10; k++) { await pay(w, 'ATTACK', { amount: near(0.006) }); await run(w, 12_000, { step: 12_000, onTick: tick }); } await run(w, H - 120_000, { step: MIN, onTick: tick }); }
  await run(w, 30 * H, { step: 10 * MIN, onTick: tick });
  return measure(w);
};
/** 5. Baseline poisoning: 11 days of slowly ramped "normal" spending, then a burst; owner offline. */
S['05_baseline_poisoning'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now(); const now = w.now(); const rows = [];
  for (let d = 14; d >= 4; d--) for (let k = 0; k < 2 + (15 - d); k++) rows.push({ credId: ATTACK_CRED, recipient: 'merchant-a.mock', amount: near(0.04), at: now - d * D + k * 20 * MIN });
  w.vault.seedHistory(rows);
  for (let i = 0; i < 14; i++) { await pay(w, 'ATTACK', { amount: near(0.05) }); await run(w, 4 * MIN, { step: MIN }); }
  await run(w, 72 * H, { step: 10 * MIN });
  return measure(w);
};
/** 6. Genuine urgent payments by the owner (6 within 12 min); owner present: confirms LEGITIMATE 15 min after an alert. */
for (const confirms of [true, false]) S[`06_genuine_urgent_owner_${confirms ? 'confirms' : 'busy'}`] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now(); let firstMail = null, done = false;
  const tick = async () => { if (firstMail === null && w.mock.sent.length) firstMail = w.now(); if (confirms && !done && firstMail !== null && w.now() - firstMail >= 15 * MIN) { done = true; await ownerConfirmLegit(w); } };
  for (let i = 0; i < 6; i++) { await pay(w, 'LEGIT', { amount: near(0.04), recipientId: i % 2 ? 'merchant-a.mock' : 'merchant-b.mock' }); await run(w, 2 * MIN, { step: MIN, onTick: tick }); }
  await run(w, 30 * H, { step: 5 * MIN, onTick: tick });
  return measure(w);
};
/** 7. Legitimate low-value recurring payments (every ~4 h with seeded jitter, 72 h). */
S['07_legit_recurring'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now();
  for (let i = 0; i < 18; i++) { await pay(w, 'LEGIT', { amount: near(0.01), recipientId: i % 2 ? 'merchant-a.mock' : 'merchant-b.mock' }); await run(w, 4 * H + Math.floor((rnd() - 0.5) * 60) * MIN, { step: 2 * MIN }); }
  await run(w, 2 * H, { step: MIN });
  return measure(w);
};
/** 8. Owner offline for 72 h during a fast burst + the owner's own recurring payments on another flow. */
S['08_owner_offline_mixed'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now();
  for (let i = 0; i < 20; i++) { await pay(w, 'ATTACK', { amount: near(0.05) }); await run(w, 30_000, { step: 30_000 }); if (i % 5 === 0) await pay(w, 'LEGIT', { amount: near(0.01) }); }
  for (let i = 0; i < 12; i++) { await run(w, 6 * H, { step: 10 * MIN }); await pay(w, 'LEGIT', { amount: near(0.01) }); }
  await run(w, 2 * H, { step: MIN });
  return measure(w);
};
/** 9. Mock e-mail outage: the owner relies on e-mail and never hears about the incident. */
S['09_email_outage'] = async (arm, rnd) => {
  const w = world(arm, { transportMode: 'OUTAGE' }); w.t0 = w.now(); let firstMail = null, acted = false;
  const tick = async () => { if (firstMail === null && w.mock.sent.length) firstMail = w.now(); if (!acted && firstMail !== null && w.now() - firstMail >= 10 * MIN) { acted = true; await ownerContain(w); } };
  for (let i = 0; i < 20; i++) { await pay(w, 'ATTACK', { amount: near(0.05) }); await run(w, 20_000, { step: 20_000, onTick: tick }); }
  await run(w, 72 * H, { step: 10 * MIN, onTick: tick });
  return measure(w, { mailDelivered: w.mock.sent.length });
};
/** 10. Rapid-Use approval for genuine urgent spending, then early termination by the owner. */
S['10_rapid_use_and_early_end'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now(); const out = {};
  for (let i = 0; i < 5; i++) { await pay(w, 'LEGIT', { amount: near(0.04) }); await run(w, MIN); }
  const req = (t, b, c) => w.cmd(t, b, c);
  out.request = (await req('RAPID_USE_REQUEST', { requestId: 'rq', scope: scopeOf(w, { credIds: [OWNER_CRED] }), delayException: 'REMOVE_ANOMALY_DELAY', durationMs: String(2 * H), explanation: 'urgent supplier payments', incidentId: w.vault.incidents()[0]?.incident_id ?? '-' }, [OWNER_CRED])).ok;
  out.votes = [(await req('RAPID_USE_APPROVE', { requestId: 'rq', requestDigest: w.root.state.v5.rapid.requests.rq?.digest ?? '0'.repeat(64), decision: 'APPROVE' }, ['orc-1'])).ok,
    (await req('RAPID_USE_APPROVE', { requestId: 'rq', requestDigest: w.root.state.v5.rapid.requests.rq?.digest ?? '0'.repeat(64), decision: 'APPROVE' }, ['k3-root-hw'])).ok];
  out.activate = (await w.submit({ action: w.action('RAPID_USE_ACTIVATE', { requestId: 'rq', requestDigest: w.root.state.v5.rapid.requests.rq?.digest ?? '0'.repeat(64) }) })).ok;
  for (let i = 0; i < 10; i++) { await pay(w, 'LEGIT', { amount: near(0.04) }); await run(w, MIN); }
  out.end = (await req('RAPID_USE_REVOKE', { grantId: 'rq', reason: 'done early' }, [OWNER_CRED])).ok;
  for (let i = 0; i < 3; i++) { await pay(w, 'LEGIT', { amount: near(0.04) }); await run(w, MIN); }
  await ownerConfirmLegit(w);
  await run(w, 30 * H, { step: 10 * MIN });
  const m = await measure(w, { rapid: out });
  m.rapidBufferFloorRespected = w.vault.v5payments().filter(p => p.anomaly === 'RELEASED_BY_RAPID' && p.settled_at !== null).every(p => p.settled_at - p.proposed_at >= p.buffer_ms);
  return m;
};
/** 11. Freeze / Suspend interactions: attacker burst, owner freezes with the FREEZE key 3 min after the first payment. */
S['11_freeze_suspend'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now(); let acted = false;
  const tick = async () => { if (!acted && w.now() - w.t0 >= 3 * MIN) { acted = true; await w.cmd('FREEZE', { freezeId: 'fz', reason: 'phone stolen', source: 'owner' }, ['k4-freeze']); await ownerContain(w); } };
  for (let i = 0; i < 10; i++) { await pay(w, 'ATTACK', { amount: near(0.05) }); await run(w, 30_000, { step: 30_000, onTick: tick }); }
  await run(w, 72 * H, { step: 10 * MIN, onTick: tick });
  return measure(w, { frozen: w.frozen() });
};
/** 12. Expired payment authorization: capabilities issued near the end of their 2 h validity; an expired one. */
S['12_expired_authorization'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now();
  const expired = await pay(w, 'LEGIT', { at: w.now() - 2 * H - MIN, ttlMs: 2 * H });
  for (let i = 0; i < 4; i++) { await pay(w, 'LEGIT', { at: w.now() - 115 * MIN, ttlMs: 2 * H, amount: near(0.01) }); await run(w, MIN); }
  await run(w, 30 * H, { step: 10 * MIN });
  return measure(w, { expiredCapability: expired.ok ? 'ACCEPTED' : expired.error.code });
};
/** 13. Restart during a pending payment (vault restarts 20 s after each proposal). */
S['13_restart_pending'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now();
  for (let i = 0; i < 6; i++) { await pay(w, i % 2 ? 'LEGIT' : 'ATTACK', { amount: near(0.02) }); await run(w, 20_000, { step: 20_000 }); w.restartVault(); await run(w, 2 * H, { step: 5 * MIN }); }
  await run(w, 30 * H, { step: 10 * MIN });
  return measure(w);
};
/** 14. Multiple flows competing for pending slots: attacker floods k1 while the owner pays from k2 every 5 min. */
S['14_competing_pending_slots'] = async (arm, rnd) => {
  const w = world(arm); w.t0 = w.now();
  // attacker: 0.01 NEAR every 30 s for 30 min on k1; owner: an ordinary 0.01 NEAR payment every 30 min for 12 h on k2
  for (let i = 0; i < 60; i++) { await pay(w, 'ATTACK', { amount: near(0.01) }); if (i === 2) await pay(w, 'LEGIT', { amount: near(0.01) }); await run(w, 30_000, { step: 30_000 }); }
  for (let i = 0; i < 24; i++) { await pay(w, 'LEGIT', { amount: near(0.01) }); await run(w, 30 * MIN, { step: 5 * MIN }); }
  await run(w, 72 * H, { step: 10 * MIN });
  return measure(w);
};
export const SCENARIOS = S;

export async function runAll({ seeds = [11, 23, 37], arms = ['A', 'B'], only = null, log = () => {} } = {}) {
  const out = { generatedBy: 'src/v5/sim/v51-experiments.mjs', arms: ARMS, seeds, results: {} };
  for (const [name, f] of Object.entries(S)) {
    if (only && !only.test(name)) continue;
    out.results[name] = {};
    for (const arm of arms) {
      out.results[name][arm] = [];
      for (const seed of seeds) { const t = Date.now(); const m = await f(arm, prng(seed)); m.seed = seed; m.wallMs = Date.now() - t; out.results[name][arm].push(m); log(`${name} ${arm} seed=${seed} atk=${m.attacker.settledNEAR} legit=${m.legit.settled}/${m.legit.attemptedIncludingDenied} verifier=${m.verifier.ok}`); }
    }
  }
  return out;
}
export { MIN, H, D, ATTACKER };
