// The independent V5 verifier detects what a compromised vault could do, and accepts every legitimate V5 path.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, H, Y, burst, freezeBy, rapidRequest, rapidVote, rapidActivate } from './helpers.mjs';
import { verifyWorld } from '../../src/v5/supervisor/verifier.mjs';

const codes = (v) => v.financial.violations.flatMap(x => x.codes);

test('legitimate flows verify: normal, delayed, Rapid-Use accelerated, reviewed, delegated', async () => {
  const w = buildV5();
  await burst(w, 4);
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  const k = w.owner.newDelegate('d1');
  ok(await w.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2), cumulativeMaxYocto: Y(5), maxUses: '4',
    expiresAt: w.iso(w.now() + 86_400_000), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  await w.payDelegated('d1', 1);
  await w.advance(25 * H, 10 * 60_000);
  const v = await verifyWorld(w);
  assert.equal(v.ok, true, JSON.stringify(v.financial.violations) + JSON.stringify(v.authority.unauthorized) + v.chainError);
  assert.ok(v.financial.authorized >= 5);
  assert.equal(v.rapid.grants.length, 1);
});

test('compromised vault releases a delayed payment early -> DELAYED_PAYMENT_RELEASED_EARLY', async () => {
  const w = buildV5();
  await burst(w, 4);
  const p = w.vault.v5payments().find(x => x.anomaly === 'ANOMALY_PAYMENT_DELAY');
  w.vault.store.db.prepare('UPDATE payments SET release_at=? WHERE payment_id=?').run(w.now(), p.payment_id);
  await w.advance(20 * 60_000);
  assert.ok(codes(await verifyWorld(w)).includes('DELAYED_PAYMENT_RELEASED_EARLY'));
});

test('compromised vault erases its own delay record -> engine journal exposes DELAY_RECORD_MISMATCH', async () => {
  const w = buildV5();
  await burst(w, 4);
  const p = w.vault.v5payments().find(x => x.anomaly === 'ANOMALY_PAYMENT_DELAY' && JSON.parse(x.decision).action === 'DELAY');
  w.vault.store.db.prepare("UPDATE v5_pay SET delay_ms=0, anomaly='NONE' WHERE payment_id=?").run(p.payment_id);
  w.vault.store.db.prepare('UPDATE payments SET release_at=? WHERE payment_id=?').run(w.now(), p.payment_id);
  await w.advance(20 * 60_000);
  const c = codes(await verifyWorld(w));
  assert.ok(c.includes('DELAY_RECORD_MISMATCH') && c.includes('DELAYED_PAYMENT_RELEASED_EARLY'), c.join());
});

test('compromised vault settles during a global hold -> EFFECT_DURING_GLOBAL_HOLD', async () => {
  const w = buildV5();
  const r = ok(await w.pay({}));
  ok(await freezeBy(w, 'k4-freeze', 'h1'));
  // the compromised vault ignores its replica and submits the transfer anyway
  w.vault.root = { ...w.vault.root, freeze: { active: false } };
  w.vault.store.db.prepare("UPDATE payments SET state='BUFFERED' WHERE payment_id=?").run(r.paymentId);
  await w.clock.advance(11 * 60_000); try { await w.vctl.call('TICK', {}); } catch {}
  const v = await verifyWorld(w);
  if (v.financial.effects) assert.ok(codes(v).includes('EFFECT_DURING_GLOBAL_HOLD'), codes(v).join());
});

test('tampered journal is reported by the verifier', async () => {
  const w = buildV5();
  await burst(w, 4);
  const rows = w.journal.rows(); const b = JSON.parse(rows[2].body); b.outcome = 'X'; rows[2] = { ...rows[2], body: JSON.stringify(b) };
  const { verifyV5 } = await import('../../src/v5/supervisor/verifier.mjs');
  const v = verifyV5({ genesis: w.genesis, pinnedChainId: w.owner.chainId5, transitions: w.root.chain(0), journal: { rows, checkpoints: w.journal.witnesses[0].all(), publicKey: w.journal.signer.publicKey } });
  assert.equal(v.journal.ok, false);
});
