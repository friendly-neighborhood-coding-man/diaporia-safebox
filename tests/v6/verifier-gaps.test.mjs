// Security closeout (issue #12 A): the three verifier gaps documented in docs/v51/SECURITY-EVALUATION.md.
// Each test is a COMPROMISED-vault reproducer (the vault rewrites its own records; Root, engine journal and signed
// evidence stay honest) plus an honest control. All three reproducers settle money and verified CLEAN on the pre-fix
// verifier at 6586a14 (evidence: docs/evidence/closeout/verifier-gaps-prefix.txt); they must be flagged now.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, H, Y, burst, rapidRequest, rapidVote, rapidActivate, scopeOf } from '../v5/helpers.mjs';
import { verifyWorld } from '../../src/v5/supervisor/verifier.mjs';

const MIN = 60_000;
const codes = (v) => [...v.financial.violations.flatMap(x => x.codes), ...v.rapid.violations.map(x => x.code)];

async function e1World(hide) {
  const w = buildV5();
  await burst(w, 8, { step: MIN, amountYocto: Y(1) });
  const inc = w.vault.incidents()[0];
  // 10 minutes before the incident's 24 h quiet close (inside the old 15-minute tick slack)
  await w.advance(inc.last_trigger_at + 24 * H - 10 * MIN - w.now(), 15 * MIN);
  if (hide) w.vault.store.db.prepare("UPDATE v5_incidents SET state='LAPSED'").run();
  ok(await w.pay({ amountYocto: Y(1) }));
  const p = w.vault.v5payments().at(-1);
  await w.advance(2 * H, 15 * MIN);
  return { w, p: w.vault.v5payments().find(x => x.payment_id === p.payment_id) };
}

test('E1: a vault that hides an open incident in its final 15 minutes is flagged (ENGINE_CONTEXT_OMITTED_OPEN_INCIDENT)', async () => {
  const { w, p } = await e1World(true);
  assert.equal(p.anomaly, 'NONE'); assert.equal(p.state, 'SETTLED'); // the attack works against the vault
  assert.ok(codes(await verifyWorld(w)).includes('ENGINE_CONTEXT_OMITTED_OPEN_INCIDENT'));
});
test('E1 control: the honest vault delays the same payment and verifies clean', async () => {
  const { w, p } = await e1World(false);
  assert.equal(p.anomaly, 'ANOMALY_PAYMENT_DELAY');
  const v = await verifyWorld(w); assert.deepEqual(codes(v), []);
});

async function e3World(tamper) {
  const w = buildV5();
  await burst(w, 8, { step: MIN, amountYocto: Y(1) }); // incident A (the owner's own burst)
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  for (let i = 0; i < 150 && w.root.state.v5.rapid.grants['rq-1'].status === 'ACTIVE'; i++) { await w.pay({ amountYocto: Y(1) }); await w.advance(38_000, 38_000); }
  await w.advance(7 * H, 15 * MIN);
  const [A, B] = w.vault.incidents(); // B was opened by DELAY_AND_END_RAPID while A was still open
  assert.equal(A.state, 'OPEN'); assert.equal(B.state, 'OPEN');
  if (tamper) w.vault.store.db.prepare('UPDATE v5_incidents SET opened_at=? WHERE incident_id=?').run(A.opened_at - 1, B.incident_id); // hand the OLDER incident to the engine
  const before = new Set(w.vault.v5payments().map(p => p.payment_id));
  ok(await w.pay({ amountYocto: Y(1) }));
  const P = w.vault.v5payments().find(p => !before.has(p.payment_id));
  await w.advance(5 * MIN, MIN);
  ok(await w.cmd('INCIDENT_REVIEW', { incidentId: A.incident_id, credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: 'b'.repeat(64) }, ['k3-root-hw'])); // the owner clears A only
  await w.advance(40 * MIN, MIN);
  return { w, A, B, P: w.vault.v5payments().find(p => p.payment_id === P.payment_id) };
}
test('E3: with two open incidents, a decision bound to the OLDER one (borrowing its review) is flagged', async () => {
  const { w, A, P } = await e3World(true);
  assert.equal(P.incident_id, A.incident_id); assert.equal(P.state, 'SETTLED');
  assert.ok(codes(await verifyWorld(w)).includes('ENGINE_DECISION_ON_OLDER_OPEN_INCIDENT'));
});
test('E3 control: the honest vault binds the newest incident; the review of the older one does not release it', async () => {
  const { w, B, P } = await e3World(false);
  assert.equal(P.incident_id, B.incident_id); assert.notEqual(P.state, 'SETTLED');
  assert.deepEqual(codes(await verifyWorld(w)), []);
});

async function rapidWorld(tamper) {
  const w = buildV5();
  await burst(w, 8, { step: MIN, amountYocto: Y(1) }); // 8 delayed payments of 0.01 NEAR
  ok(await rapidRequest(w, 'k1-phone', { scope: scopeOf(w, { sessionCapYocto: Y(3) }) })); // session cap 0.03 NEAR
  ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  if (tamper) {
    w.vault.store.db.prepare("UPDATE v5_pay SET anomaly='RELEASED_BY_RAPID', rapid_grant='rq-1' WHERE anomaly='ANOMALY_PAYMENT_DELAY'").run();
    w.vault.store.db.prepare("UPDATE payments SET release_at=proposed_at+600000 WHERE state='BUFFERED'").run();
  }
  await w.advance(40 * MIN, MIN);
  return { w, settled: w.vault.v5payments().filter(p => p.state === 'SETTLED') };
}
test('Rapid-Use: a vault applying a grant beyond its session cap is flagged (only cap-covered payments verify)', async () => {
  const { w, settled } = await rapidWorld(true);
  assert.equal(settled.length, 8);
  const v = await verifyWorld(w); const c = codes(v);
  assert.ok(c.includes('RAPID_GRANT_LIMIT_OR_ASSET_EXCEEDED'), JSON.stringify(c));
  assert.equal(v.financial.violations.filter(x => x.txId !== '-').length, 5); // exactly the 5 payments over the cap
  assert.equal(v.rapid.covered, 3);
});
test('Rapid-Use control: the honest vault accelerates exactly the cap (3 x 0.01) and verifies clean', async () => {
  const { w, settled } = await rapidWorld(false);
  assert.equal(settled.length, 3);
  assert.deepEqual(codes(await verifyWorld(w)), []);
});
test('Rapid-Use: per-payment maximum and asset are part of the grant scope', async () => {
  const { w } = await rapidWorld(true);
  const g = w.root.state.v5.rapid.grants['rq-1'];
  assert.equal(g.scope.asset, 'NEAR'); assert.ok(BigInt(g.scope.perPaymentMaxYocto) >= BigInt(Y(1)));
});
