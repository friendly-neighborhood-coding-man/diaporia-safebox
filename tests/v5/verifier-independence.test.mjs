// V5.1 independent-verifier repairs (findings F1, F3, F4, F6 of the V5.1 independent verification).
// Each test simulates a COMPROMISED vault that rewrites its own records; the verifier must still flag the effect from
// signed evidence (owner / delegate signatures) and the engine's own append-only RISK journal.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, H, D, Y, near, burst } from './helpers.mjs';
import { verifyWorld } from '../../src/v5/supervisor/verifier.mjs';

const MIN = 60_000;
const codes = (v) => v.financial.violations.flatMap(x => x.codes);
function warm(policy = 'EXP_30') {
  const w = buildV5({ config5: { bufferPolicy: policy } });
  w.clock.advance(10 * H); w.wall.t += 1;
  const now = w.now(); const rows = [];
  for (let d = 30; d >= 4; d--) for (const cred of ['k1-phone', 'k2-laptop']) for (const h of [0, 5]) rows.push({ credId: cred, recipient: 'merchant-a.mock', amount: near(0.02), at: now - d * D + h * H });
  w.vault.seedHistory(rows);
  return w;
}
const pay = async (w, o = {}) => { const r = ok(await w.pay(o)); return w.vault.v5payments().find(p => p.payment_id === r.paymentId); };

test('F1: clearing the vault\'s incident_id / flow / risk_class does not hide a HIGH payment settled without resolution', async () => {
  const w = buildV5();
  await burst(w, 8, { step: MIN });
  assert.ok(w.vault.v5payments().some(p => p.risk_class === 'HIGH'));
  w.vault.store.db.prepare("UPDATE v5_pay SET risk_class='LOW', incident_id=NULL, flow='cred:someone-else', cred_id='someone-else'").run();
  await w.advance(25 * H, 15 * MIN);
  assert.ok(w.vault.v5payments().some(p => p.state === 'SETTLED'));
  assert.ok(codes(await verifyWorld(w)).includes('HIGH_RISK_SETTLED_WITHOUT_RESOLUTION'));
});

test('F1 control: an honest HIGH incident resolved LEGITIMATE by a trusted key verifies clean', async () => {
  const w = buildV5();
  await burst(w, 8, { step: MIN });
  const inc = w.vault.incidents()[0].incident_id;
  ok(await w.cmd('INCIDENT_REVIEW', { incidentId: inc, credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: 'b'.repeat(64) }, ['k3-root-hw']));
  await w.advance(30 * MIN);
  const v = await verifyWorld(w);
  assert.ok(w.vault.v5payments().filter(p => p.state === 'SETTLED').length >= 1);
  assert.equal(v.ok, true, JSON.stringify(codes(v)));
});

test('F3: an effect whose V5 record was deleted, or whose proposal time was rewritten, is flagged', async () => {
  const w = warm();
  const p = await pay(w, { amountYocto: near(0.05) });
  assert.ok(p.buffer_ms > 30_000);
  w.vault.store.db.prepare('UPDATE payments SET release_at=? WHERE payment_id=?').run(p.proposed_at + 30_000, p.payment_id);
  await w.advance(2 * MIN, 10_000);
  w.vault.store.db.exec('DROP TRIGGER v5_pay_no_delete'); // a compromised vault can drop its own guard
  w.vault.store.db.prepare('DELETE FROM v5_pay WHERE payment_id=?').run(p.payment_id);
  const c = codes(await verifyWorld(w));
  assert.ok(c.includes('EFFECT_WITHOUT_V5_EVALUATION_RECORD') && c.includes('BUFFER_BYPASSED'), JSON.stringify(c));
  const w2 = warm();
  const q = await pay(w2, { amountYocto: near(0.05) });
  w2.vault.store.db.prepare('UPDATE payments SET release_at=? WHERE payment_id=?').run(q.proposed_at + 30_000, q.payment_id);
  await w2.advance(2 * MIN, 10_000);
  w2.vault.store.db.prepare('UPDATE v5_pay SET proposed_at=proposed_at-? WHERE payment_id=?').run(q.buffer_ms, q.payment_id); // hide the early release
  const c2 = codes(await verifyWorld(w2));
  assert.ok(c2.includes('PROPOSAL_TIME_MISMATCH') && c2.includes('BUFFER_BYPASSED'), JSON.stringify(c2));
});

test('F4: rewriting the vault\'s flow column does not hide a tier reset (flows come from signed evidence)', async () => {
  const w = warm();
  await pay(w, { amountYocto: near(0.005) }); await w.advance(MIN, MIN);
  const p2 = await pay(w, { amountYocto: near(0.005) }); assert.ok(Number(p2.tier) >= 1);
  await w.advance(11 * MIN, MIN);
  w.vault.store.db.prepare('UPDATE v5_pay SET tier=0').run();
  const q = await pay(w, { amountYocto: near(0.005) });
  assert.ok(Number(q.tier) < Number(p2.tier));
  w.vault.store.db.prepare("UPDATE v5_pay SET flow='cred:other' WHERE payment_id<>?").run(q.payment_id);
  const v = await verifyWorld(w);
  assert.ok(v.buffer.tierResets >= 1 && codes(v).includes('BUFFER_TIER_RESET'), JSON.stringify(codes(v)));
});

test('F6: a delegated op accepted long after its signed issuedAt is flagged (DELEGATED_OP_STALE_AT_PROPOSAL)', async () => {
  const w = buildV5();
  const k = w.owner.newDelegate('d1');
  ok(await w.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w.iso(w.now() + 2 * D), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  const { op, sig } = w.delegateOp('d1', 1, { amountYocto: Y(1) });
  await w.advance(15 * MIN);
  // a compromised vault skips its own freshness check (simulated by a vault clock that lags the real one)
  const real = w.vault.now; const lag = w.now() - 15 * MIN; w.vault.now = () => lag;
  try { w.vault.proposeDelegated({ op, sig }); } finally { w.vault.now = real; }
  await w.advance(15 * MIN, MIN);
  const c = codes(await verifyWorld(w));
  assert.ok(c.includes('DELEGATED_OP_STALE_AT_PROPOSAL'), JSON.stringify(c));
  // control: a fresh op verifies without the stale code
  const w2 = buildV5(); const k2 = w2.owner.newDelegate('d1');
  ok(await w2.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k2.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w2.iso(w2.now() + 2 * D), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  await w2.payDelegated('d1', 1, { amountYocto: Y(1) });
  await w2.advance(15 * MIN, MIN);
  assert.ok(!codes(await verifyWorld(w2)).includes('DELEGATED_OP_STALE_AT_PROPOSAL'));
});

// ---- second independent re-verification (N1-N5) ----
import { verifyV5 } from '../../src/v5/supervisor/verifier.mjs';
import { V2_DOMAINS } from '../../src/v2/common/crypto.mjs';
import { LEDGER_TX_VERSION } from '../../src/v2/mock-ledger/ledger.mjs';
import { iso } from '../../src/v3/common/canon.mjs';
const inputs = async (w) => ({ genesis: w.genesis, pinnedChainId: w.owner.chainId5, transitions: w.root.chain(0), ledgerTxs: await w.ledgerRead.call('TRANSFERS', { sinceSeq: '0' }), evidence: w.vault.evidence(), v5pay: w.vault.v5payments(), ownerIntents: w.intents, attackerCaseIds: w.attackerCaseIds, journal: { rows: w.journal.rows(), checkpoints: w.journal.witnesses[1].all(), publicKey: w.journal.signer.publicKey } });

test('N1: a ledger effect spending capability X under an older payment id Y is flagged (cap not bound to payment)', async () => {
  const w = buildV5();
  const y = ok(await w.pay({ amountYocto: Y(1) }));
  w.vault.store.move(y.paymentId, 'BUFFERED', 'CANCELLED', 'vault', { reason: 'x' }, { reason: 'x' });
  await w.advance(2 * H, 5 * MIN);
  const x = ok(await w.pay({ amountYocto: Y(2) }));
  const vx = w.vault; const rx = vx.store.get(x.paymentId);
  const keyNonce = (BigInt(vx.store.getControl('lastKeyNonce')) + 1n).toString(); vx.store.setControl('lastKeyNonce', keyNonce);
  const signed = vx.executor.sign(V2_DOMAINS.LEDGER_TX, { v: LEDGER_TX_VERSION, paymentId: y.paymentId, capId: rx.cap_id, intentNonce: rx.intent_nonce, keyNonce, sender: vx.cfg.executorAccount, recipient: rx.recipient, asset: rx.asset, amountYocto: rx.amount, issuedAt: iso(w.now()) });
  await vx.ledger.call('SUBMIT_TX', { tx: signed });
  const v = await verifyWorld(w);
  assert.equal(v.ok, false); assert.ok(codes(v).includes('EFFECT_CAP_NOT_BOUND_TO_PAYMENT'), JSON.stringify(codes(v)));
});

test('N2: a crash after the v5_pay insert but before the evaluation completes leaves the payment cancelled on restart', async () => {
  const w = buildV5({ config5: { bufferPolicy: 'EXP_30' } });
  await burst(w, 3, { amountYocto: Y(1) });
  const db = w.vault.store.db; const prep = db.prepare.bind(db); const mv = w.vault.store.move.bind(w.vault.store);
  let crashed = false;
  db.prepare = (sql) => { if (!crashed && sql.startsWith('UPDATE v5_pay SET tier=')) { crashed = true; throw new Error('process killed'); } return prep(sql); };
  w.vault.store.move = (...a) => { if (crashed && a[2] === 'CANCELLED') throw new Error('process already dead'); return mv(...a); };
  await w.pay({ amountYocto: Y(1) });
  db.prepare = prep; w.vault.store.move = mv;
  assert.ok(crashed);
  w.restartVault();
  const last = w.vault.v5payments().at(-1);
  assert.equal(last.state, 'CANCELLED');
  await w.advance(10 * MIN, 10_000);
  assert.notEqual(w.vault.v5payments().at(-1).state, 'SETTLED');
});

test('N3: an owner LEGITIMATE review of a different incident id does not resolve the HIGH incident', async () => {
  const w = buildV5();
  await burst(w, 8, { step: MIN, amountYocto: Y(1) });
  ok(await w.cmd('INCIDENT_REVIEW', { incidentId: 'unrelated-incident-1', credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: 'b'.repeat(64) }, ['k3-root-hw']));
  w.vault.store.db.prepare("UPDATE v5_pay SET anomaly='RELEASED_BY_REVIEW', risk_class='LOW' WHERE payment_id IN (SELECT payment_id FROM payments WHERE state='BUFFERED')").run();
  w.vault.store.db.prepare("UPDATE payments SET release_at=proposed_at+600000 WHERE state='BUFFERED'").run();
  await w.advance(30 * MIN, MIN);
  assert.ok(w.vault.v5payments().some(p => p.state === 'SETTLED'));
  assert.ok(codes(await verifyWorld(w)).includes('HIGH_RISK_SETTLED_WITHOUT_RESOLUTION'));
});

test('N4 (honest, no false positive): a reviewed LOW incident\'s payments settle cleanly although a later HIGH incident opens meanwhile', async () => {
  const w = buildV5();
  await burst(w, 4, { amountYocto: Y(1) });
  const inc = w.vault.incidents()[0].incident_id;
  ok(await w.cmd('INCIDENT_REVIEW', { incidentId: inc, credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: 'b'.repeat(64) }, ['k3-root-hw']));
  await burst(w, 5, { amountYocto: Y(1), step: 30_000 });
  assert.ok(w.vault.incidents().some(i => i.risk_class === 'HIGH'));
  await w.advance(30 * H, 15 * MIN);
  assert.ok(w.vault.v5payments().filter(p => p.state === 'SETTLED').length >= 4);
  const v = await verifyWorld(w);
  assert.equal(v.ok, true, JSON.stringify(codes(v)));
});

test('N5: without the engine journal the verifier never reports ok for a ledger with effects', async () => {
  const w = buildV5();
  await burst(w, 2);
  await w.advance(20 * MIN);
  const b = await inputs(w);
  assert.equal(verifyV5(b).ok, true);
  const noJ = verifyV5({ ...b, journal: null });
  assert.equal(noJ.ok, false); assert.ok(codes(noJ).includes('ENGINE_JOURNAL_REQUIRED'));
});

test('N3b: a compromised vault that hands the engine an already-reviewed incident (to borrow its review) is flagged', async () => {
  const w = buildV5();
  await burst(w, 4, { amountYocto: Y(1) });
  const inc = w.vault.incidents()[0];
  ok(await w.cmd('INCIDENT_REVIEW', { incidentId: inc.incident_id, credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: 'b'.repeat(64) }, ['k3-root-hw']));
  await w.advance(MIN);
  const eng = w.vault.engine; const orig = eng.decide.bind(eng);
  eng.decide = (p, ctx, o) => orig(p, ctx, { ...o, openIncident: { ...inc, state: 'OPEN', risk_class: 'HIGH' } });
  await w.pay({ amountYocto: Y(1) });
  eng.decide = orig;
  await w.advance(2 * H, 15 * MIN);
  assert.ok(codes(await verifyWorld(w)).includes('ENGINE_DECISION_ON_FOREIGN_OR_CLOSED_INCIDENT'));
});
