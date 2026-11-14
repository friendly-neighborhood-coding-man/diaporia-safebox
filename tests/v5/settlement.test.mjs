// V5.1 P1 (no-owner-response resolution) and P2 (explicit, owner-signed settlement horizon).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, D, Y, burst } from './helpers.mjs';
import { verifyWorld } from '../../src/v5/supervisor/verifier.mjs';
import { genesisState, V5_DEFAULT_CONFIG } from '../../src/v5/root/chain.mjs';
import { OwnerWorldV5 } from '../../src/v5/kit.mjs';
import { T0 } from '../../src/v5/world.mjs';

const MIN = 60_000;
const codes = (v) => v.financial.violations.flatMap(x => x.codes);
const byState = (w, cred = 'k1-phone') => { const o = {}; for (const p of w.vault.v5payments().filter(p => p.cred_id === cred)) o[p.state] = (o[p.state] ?? 0) + 1; return o; };
const reasons = (w, cred = 'k1-phone') => [...new Set(w.vault.v5payments().filter(p => p.cred_id === cred && p.reason).map(p => p.reason))].sort();
const propose = (w, { at, ttlMs = 3600_000, credId = 'k1-phone', amountYocto = Y(3) }) => {
  const pc = w.owner.paycap(w.view(), { credId, recipientId: 'merchant-a.mock', amountYocto, at, ttlMs });
  return w.gz.request('PROPOSE', { capability: pc.capability, approval: pc.approval, recipientId: 'merchant-a.mock', amountYocto, asset: 'NEAR', memo: 'p' });
};

test('P2: settlementHorizonMs (26 h) is part of the genesis extension every owner device and the ORC sign; out-of-range values are refused', () => {
  assert.equal(V5_DEFAULT_CONFIG.settlementHorizonMs, String(26 * H));
  const w = buildV5();
  assert.equal(w.root.state.v5.config.settlementHorizonMs, String(26 * H));
  assert.equal(w.vault.horizonMs(), 26 * H, 'the vault reads the horizon from its own Root replica');
  for (const bad of [String(30 * 60_000), String(73 * H)]) {
    const o = new OwnerWorldV5({ t0: T0, config5: { settlementHorizonMs: bad } });
    assert.throws(() => genesisState(o.genesis5(), { pinnedChainId: o.chainId5 }), /V5_CONFIG_SETTLEMENT_HORIZON/);
  }
  // a tampered horizon (not what the owner devices signed) breaks the genesis signatures
  const o = new OwnerWorldV5({ t0: T0 }); const g = o.genesis5();
  const forged = { ...g, ext: { ...g.ext, action: { ...g.ext.action, body: { ...g.ext.action.body, config: { ...g.ext.action.body.config, settlementHorizonMs: String(72 * H) } } } } };
  assert.throws(() => genesisState(forged, { pinnedChainId: o.chainId5 }), /SIGNATURE|CHALLENGE_MISMATCH/);
});

test('P2: the four times stay separate; a delay moves only the earliest release, never the latest settlement', async () => {
  const w = buildV5();
  const issued = w.now();
  await burst(w, 4);
  for (const p of w.vault.v5payments()) {
    assert.equal(p.settle_deadline, p.auth_issued_at + 26 * H, 'latest settlement = issuedAt + owner-signed horizon');
    assert.ok(p.cap_expires_orig <= p.auth_issued_at + 3600_000, 'submission deadline = the capability\'s own expiresAt');
    assert.ok(p.release_at <= p.settle_deadline, 'release inside the horizon');
    assert.ok(p.auth_issued_at >= issued);
  }
  const before = new Map(w.vault.v5payments().map(p => [p.payment_id, p.settle_deadline]));
  await burst(w, 3); // re-evaluation inside the open incident
  for (const p of w.vault.v5payments()) if (before.has(p.payment_id)) assert.equal(p.settle_deadline, before.get(p.payment_id), 'deadline never extended by re-evaluation');
});

test('P2: the vault enforces the horizon independently of the risk engine (2 h horizon < 6 h delay -> expired, not settled)', async () => {
  const w = buildV5({ config5: { settlementHorizonMs: String(2 * H) } });
  await burst(w, 4);
  assert.ok(w.vault.v5payments().some(p => p.anomaly === 'ANOMALY_PAYMENT_DELAY' && p.release_at > p.settle_deadline));
  await w.advance(8 * H, 10 * MIN);
  const st = byState(w);
  assert.equal(st.SETTLED ?? 0, 0, JSON.stringify(st));
  assert.deepEqual(reasons(w), ['SETTLEMENT_HORIZON_EXPIRED']);
  const v = await verifyWorld(w); assert.equal(v.ok, true, JSON.stringify(v.financial.violations));
});

test('P2: an authorization issued near the end of its 2 h validity expires at its horizon when the delay would cross it', async () => {
  const w = buildV5();
  // four payments, the last two with capabilities issued 115 min before proposal (still inside their 2 h validity)
  ok(await w.pay({})); await w.advance(MIN); ok(await w.pay({})); await w.advance(MIN);
  ok(await propose(w, { at: w.now() - 115 * MIN, ttlMs: 2 * H })); await w.advance(MIN);
  // a hostile engine requests the 24 h maximum delay for everything: release would be issuedAt + 115 min + 10 min + 24 h > 26 h
  const eng = w.vault.engine; const orig = eng.decide.bind(eng);
  eng.policy = { ...eng.policy, delay: { ...eng.policy.delay, anomalyDelayMs: String(24 * H) } };
  ok(await propose(w, { at: w.now() - 115 * MIN, ttlMs: 2 * H }));
  eng.decide = orig;
  await w.advance(27 * H, 10 * MIN);
  const late = w.vault.v5payments().filter(p => p.auth_issued_at < p.proposed_at - 100 * MIN);
  assert.ok(late.length >= 1);
  assert.ok(late.some(p => p.release_at >= p.settle_deadline), JSON.stringify(late.map(p => [p.release_at - p.settle_deadline, p.delay_ms, p.state])));
  for (const p of late) if (p.release_at >= p.settle_deadline) assert.equal(p.state, 'EXPIRED');
  const v = await verifyWorld(w);
  assert.equal(codes(v).includes('EFFECT_AFTER_SETTLEMENT_HORIZON'), false);
});

test('P2: verifier flags a settlement after the horizon even when the vault records are rewritten', async () => {
  const w = buildV5({ config5: { settlementHorizonMs: String(2 * H) } });
  await burst(w, 4);
  // compromised vault: erase the deadline and the HIGH/LOW class, push release past the horizon
  w.vault.store.db.prepare('UPDATE payments SET cap_expires_at=?').run(w.now() + 30 * D);
  w.vault.store.db.prepare("UPDATE v5_pay SET settle_deadline=NULL, risk_class='LOW'").run();
  await w.advance(7 * H, 10 * MIN);
  assert.ok((byState(w).SETTLED ?? 0) >= 1);
  const v = await verifyWorld(w);
  assert.ok(codes(v).includes('EFFECT_AFTER_SETTLEMENT_HORIZON'), JSON.stringify(codes(v)));
  assert.ok(v.horizon.violations >= 1);
});

test('P1: LOW risk (short burst) -> bounded delay, then conditional settlement with the owner offline', async () => {
  const w = buildV5();
  await burst(w, 4);
  const inc = w.vault.incidents()[0];
  assert.equal(inc.risk_class, 'LOW');
  await w.advance(25 * H, 10 * MIN); // the 4th payment received the escalated (24 h) delay; still LOW, still inside 26 h
  assert.deepEqual(byState(w), { SETTLED: 4 });
  const v = await verifyWorld(w); assert.equal(v.ok, true);
});

test('P1: HIGH risk (hard ceiling) with the owner offline 72 h -> every delayed payment expires, none settles; no global freeze', async () => {
  const w = buildV5();
  await burst(w, 8, { step: MIN }); // 6 in 10 min = BURST_10M hard ceiling
  assert.equal(w.vault.incidents()[0].risk_class, 'HIGH');
  assert.ok(w.vault.v5payments().filter(p => p.state === 'BUFFERED').every(p => p.risk_class === 'HIGH'));
  // another flow (the owner's laptop) is not frozen
  const other = ok(await w.pay({ credId: 'k2-laptop' }));
  assert.equal(other.anomaly, 'NONE');
  await w.advance(72 * H, 15 * MIN);
  const st = byState(w);
  assert.equal(st.SETTLED ?? 0, 0, JSON.stringify(st));
  assert.deepEqual(reasons(w), ['HIGH_RISK_UNRESOLVED']);
  assert.equal(w.vault.v5payments().find(p => p.payment_id === other.paymentId).state, 'SETTLED');
  assert.equal(w.frozen(), false);
  ok(await w.pay({ credId: 'k2-laptop' }), 'owner keeps paying from another flow');
  // the HIGH payment needs a renewed authorization: a fresh owner capability on k1 is evaluated normally again
  const v = await verifyWorld(w); assert.equal(v.ok, true, JSON.stringify(v.financial.violations));
});

test('P1: HIGH risk resolved by the owner (trusted LEGITIMATE review) settles; FRAUD cancels', async () => {
  for (const verdict of ['LEGITIMATE', 'FRAUD']) {
    const w = buildV5();
    await burst(w, 8, { step: MIN });
    const inc = w.vault.incidents()[0].incident_id;
    ok(await w.cmd('INCIDENT_REVIEW', { incidentId: inc, credId: 'k1-phone', verdict, evidenceDigest: 'b'.repeat(64) }, verdict === 'LEGITIMATE' ? ['k3-root-hw'] : ['k2-laptop']));
    await w.advance(30 * MIN);
    const st = byState(w);
    if (verdict === 'LEGITIMATE') assert.equal(st.SETTLED, 8, JSON.stringify(st)); else assert.equal(st.SETTLED ?? 0, 0);
    assert.equal((await verifyWorld(w)).ok, true);
  }
});

test('P1: a LOW incident that escalates to HIGH marks its pending payments HIGH (deadlines unchanged)', async () => {
  const w = buildV5();
  await burst(w, 4);
  assert.equal(w.vault.incidents()[0].risk_class, 'LOW');
  const dl = new Map(w.vault.v5payments().map(p => [p.payment_id, p.settle_deadline]));
  await burst(w, 3);
  assert.equal(w.vault.incidents()[0].risk_class, 'HIGH');
  for (const p of w.vault.v5payments().filter(p => p.state === 'BUFFERED')) { assert.equal(p.risk_class, 'HIGH'); if (dl.has(p.payment_id)) assert.equal(p.settle_deadline, dl.get(p.payment_id)); }
});

test('P1: verifier flags a HIGH-risk payment settled without owner resolution (vault record downgraded to LOW)', async () => {
  const w = buildV5();
  await burst(w, 8, { step: MIN });
  w.vault.store.db.prepare("UPDATE v5_pay SET risk_class='LOW'").run();
  await w.advance(25 * H, 15 * MIN);
  assert.ok((byState(w).SETTLED ?? 0) >= 1);
  assert.ok(codes(await verifyWorld(w)).includes('HIGH_RISK_SETTLED_WITHOUT_RESOLUTION'));
});

test('P1: release-time re-check: a delegation revoked while its payment waits cancels it', async () => {
  const w = buildV5();
  const k = w.owner.newDelegate('d1');
  ok(await w.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w.iso(w.now() + 2 * D), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  const r = await w.payDelegated('d1', 1, { amountYocto: Y(1) });
  ok(await w.cmd('DELEGATION_REVOKE', { delegationId: 'd1' }, ['k1-phone']));
  await w.advance(12 * MIN);
  const p = w.vault.v5payments().find(x => x.payment_id === r.paymentId);
  assert.notEqual(p.state, 'SETTLED');
});

test('P1: vault restart during a pending HIGH-risk payment: class, deadline and expiry survive', async () => {
  const w = buildV5();
  await burst(w, 8, { step: MIN });
  await w.advance(H, 10 * MIN);
  w.restartVault();
  assert.ok(w.vault.v5payments().filter(p => p.state === 'BUFFERED').every(p => p.risk_class === 'HIGH' && p.settle_deadline));
  await w.advance(25 * H, 15 * MIN);
  assert.equal(byState(w).SETTLED ?? 0, 0);
});

test('P2: an ordinary reserved payment settles inside its window with no second signature', async () => {
  const w = buildV5();
  const prompts = w.owner.metrics.prompts;
  const r = ok(await w.pay({}));
  await w.advance(11 * MIN);
  assert.equal(w.vault.v5payments().find(p => p.payment_id === r.paymentId).state, 'SETTLED');
  assert.equal(w.owner.metrics.prompts, prompts);
});

test('P1: riskClassOf is a deterministic function of the evaluation: each HIGH rule on its own', async () => {
  const { riskClassOf } = await import('../../src/v5/risk/engine.mjs');
  const ev = (o = {}) => ({ hard: false, score: '2', decision: 'DELAY', features: { securityCorrelated: 'false' }, ...o });
  assert.equal(riskClassOf(ev(), null), 'LOW');
  assert.equal(riskClassOf(ev({ hard: true }), null), 'HIGH', 'hard ceiling');
  assert.equal(riskClassOf(ev({ score: '4' }), null), 'HIGH', 'score >= 2 x delay threshold');
  assert.equal(riskClassOf(ev({ score: '3.5' }), null), 'LOW');
  assert.equal(riskClassOf(ev({ features: { securityCorrelated: 'true' } }), null), 'HIGH', 'security-correlated delay');
  assert.equal(riskClassOf(ev({ features: { securityCorrelated: 'true' }, decision: 'WATCH' }), { triggers: 0, risk_class: 'LOW' }), 'LOW', 'security correlation alone (no delay) is not HIGH');
  assert.equal(riskClassOf(ev(), { triggers: 2, risk_class: 'LOW', delayed_count: 9 }), 'LOW', 'payments swept into the incident do not escalate it');
  assert.equal(riskClassOf(ev(), { triggers: 3, risk_class: 'LOW' }), 'HIGH', 'third prior delay decision escalates');
  assert.equal(riskClassOf(ev(), { triggers: 0, risk_class: 'HIGH' }), 'HIGH', 'an incident never de-escalates');
});
