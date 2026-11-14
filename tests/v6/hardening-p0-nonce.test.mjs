// V6 hardening P0.3 (issue #14): one Root-issued payment challenge must yield AT MOST ONE payment, under crashes at
// every state transition and under interleaved workers sharing the Vault database.
// Attacker / fault model: the owner device signed two capabilities under one binding+challenge (a device retry after
// a timeout, or a confused device), OR a second Vault worker races the first; the process can die at any point.
// Invariant I-NONCE: |{payments whose V6 evidence or whose capability taskRef uses challenge nonce N}| <= 1, and every
// committed owner payment has its v6_challenges + v6_evidence rows (no payment without its approval evidence).
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildV6, ok, Y } from './helpers6.mjs';
import { paycapDigest } from '../../src/v3/vault/paycap.mjs';
import { nonce as mkNonce } from '../../src/v3/common/canon.mjs';
import { ExecutionVaultV5 } from '../../src/v5/vault/vault.mjs';
import { verifyWorld6 } from '../../src/v6/supervisor/verifier.mjs';

const args = (pa) => ({ capability: pa.capability, approval: pa.approval, recipientId: pa.capability.recipientId, amountYocto: pa.capability.amountYocto, asset: 'NEAR', memo: 'p0 nonce' });
/** A second capability under the SAME binding and the SAME Root challenge, validly signed by the owner device. */
function twin(w, pa, credId = 'k1-phone') {
  const cap = { ...pa.capability, capId: randomUUID(), nonce: mkNonce() };
  const approval = { ...w.owner.dev(credId).approvePaycap(paycapDigest(cap), { uv: true }), v6: pa.approval.v6 };
  return { capability: cap, approval };
}
function approval(w, credId = 'k1-phone') {
  const pa = w.owner.paymentApproval(w.root.state, { credId, recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  (w.__taskRefs ??= {})[pa.approval.v6.binding.challengeNonce] = pa.capability.taskRef; return pa;
}
/** Payments whose capability commits (taskRef) to the binding carrying this challenge nonce (independent of V6 rows). */
const paymentsFor = (w, nonce) => w.vault.store.db.prepare('SELECT payment_id, cap FROM cap_evidence').all().filter((r) => JSON.parse(r.cap).taskRef === w.__taskRefs?.[nonce]);
const evidenceGap = (w) => w.vault.store.db.prepare('SELECT p.payment_id FROM payments p LEFT JOIN v6_evidence e ON e.payment_id=p.payment_id WHERE e.payment_id IS NULL').all();
/** Run fn while ExecutionVaultV5.prototype.propose is wrapped (test-only fault injection; restored afterwards). */
function withV5Propose(wrap, fn) {
  const orig = ExecutionVaultV5.prototype.propose;
  ExecutionVaultV5.prototype.propose = function (a) { return wrap.call(this, orig, a); };
  try { return fn(); } finally { ExecutionVaultV5.prototype.propose = orig; }
}

test('P0.3-crash: a crash right after the payment commit must not leave the challenge reusable or the payment without evidence', async () => {
  const w = buildV6();
  const pa = approval(w); const nonce = pa.approval.v6.binding.challengeNonce;
  // crash (process death) after the V5/V3 payment transaction committed, before anything else ran
  assert.throws(() => withV5Propose(function (orig, a) { orig.call(this, a); throw Object.assign(new Error('CRASH after payment commit'), { code: 'CRASH' }); },
    () => w.vault.propose(args(pa))), (e) => e.code === 'CRASH');
  w.restartVault();
  // after restart: the committed payment must carry its approval evidence, and the challenge must be spent
  assert.deepEqual(evidenceGap(w), [], 'payment committed without v6_evidence / v6_challenges');
  const r = await w.gz.request('PROPOSE', args(twin(w, pa)));
  assert.equal(r.ok, false, 'the same challenge approved a second payment after the crash');
  assert.match(r.error.code + ':' + (r.error.detail ?? ''), /CHALLENGE_ALREADY_CONSUMED/);
  assert.equal(paymentsFor(w, nonce).length, 1);
});

test('P0.3-race: two Vault workers interleaving on one database admit at most one payment per challenge, never a payment without evidence', async () => {
  const w = buildV6();
  const pa = approval(w); const nonce = pa.approval.v6.binding.challengeNonce; const tw = twin(w, pa);
  const other = w.openVault(); // a second worker process on the same vault.db
  let first;
  // worker 1 passed its pre-checks for the twin; worker 2 runs the original proposal in between (the earlier-signed
  // capability first, so the WebAuthn sign counter does not mask the race); then worker 1 continues
  try {
    first = withV5Propose(function (orig, a) {
      if (this !== other && !this.__raced) { this.__raced = true; try { other.propose(args(pa)); } catch {} }
      return orig.call(this, a);
    }, () => w.vault.propose(args(tw)));
  } catch (e) { first = { error: e.code }; }
  other.store.close();
  w.restartVault();
  assert.deepEqual(evidenceGap(w), [], 'a payment was committed without its approval evidence');
  assert.equal(paymentsFor(w, nonce).length, 1, 'one challenge, more than one payment');
  assert.ok(first, 'worker 1 returned');
});

test('P0.3-faults: a crash at every write inside the proposal leaves either nothing or the complete record', async () => {
  // fault injection on every SQL write the proposal performs (statement-level crash points)
  const w0 = buildV6(); const probe = approval(w0);
  let writes = 0;
  const count = (db) => { const p = db.prepare.bind(db); db.prepare = (sql) => { const st = p(sql); if (/^\s*(INSERT|UPDATE)/i.test(sql)) { const run = st.run.bind(st); st.run = (...a) => { writes++; return run(...a); }; } return st; }; return () => { db.prepare = p; }; };
  const undo = count(w0.vault.store.db); ok(await w0.gz.request('PROPOSE', args(probe))); undo();
  assert.ok(writes >= 8, 'probe saw the writes: ' + writes);
  for (let k = 1; k <= writes; k++) {
    const w = buildV6(); const pa = approval(w); const nonce = pa.approval.v6.binding.challengeNonce;
    const db = w.vault.store.db; const p = db.prepare.bind(db); let n = 0;
    db.prepare = (sql) => { const st = p(sql); if (/^\s*(INSERT|UPDATE)/i.test(sql)) { const run = st.run.bind(st); st.run = (...a) => { if (++n === k) throw Object.assign(new Error('CRASH at write ' + k), { code: 'CRASH' }); return run(...a); }; } return st; };
    try { w.vault.propose(args(pa)); } catch {}
    db.prepare = p; w.restartVault();
    const pays = w.vault.store.db.prepare('SELECT payment_id FROM payments').all().length;
    const nonceRow = !!w.vault.store.db.prepare('SELECT 1 FROM v6_challenges WHERE nonce=?').get(nonce);
    assert.deepEqual(evidenceGap(w), [], `crash at write ${k}: payment without evidence`);
    assert.equal(nonceRow, pays === 1, `crash at write ${k}: challenge row ${nonceRow} but payments ${pays}`);
    // recovery: a retry of the SAME approval is either the one payment already made or a clean first proposal
    const r = await w.gz.request('PROPOSE', args(pa));
    const total = paymentsFor(w, nonce).length;
    assert.equal(total, 1, `crash at write ${k}: retry produced ${total} payments (retry ok=${r.ok})`);
    const v = await verifyWorld6(w); assert.equal(v.ok, true, `crash at write ${k}: verifier ${JSON.stringify(v.v6?.issues ?? v)}`.slice(0, 300));
  }
});

test('P0.3-bypass: an owner paycap that reaches the V3/V5 core without the V6 verification is refused (fail closed)', async () => {
  const w = buildV6();
  const pa = approval(w);
  const { v6, ...plain } = pa.approval; // a caller/subclass bug that skips the V6 layer and calls the core directly
  assert.throws(() => ExecutionVaultV5.prototype.propose.call(w.vault, { ...args(pa), approval: plain }), (e) => e.code === 'V6_PAYMENT_APPROVAL_REQUIRED');
  assert.equal(w.vault.store.db.prepare('SELECT COUNT(*) n FROM payments').get().n, 0);
});

test('P0.3-settle: a crash after the ledger accepted the transfer, and two release workers, never settle twice', async () => {
  const w = buildV6();
  ok(await w.pay({ credId: 'k1-phone', amountYocto: Y(1) }));
  await w.advance(9 * 60_000); // inside the FIXED_600 buffer
  // crash: the ledger accepts and settles the transfer, the vault process dies before recording it
  const real = w.vault.ledger; let crashed = false;
  w.vault.ledger = { call: async (op, a) => { const r = await real.call(op, a); if (op === 'SUBMIT_TX' && !crashed) { crashed = true; throw Object.assign(new Error('CRASH after ledger accept'), { code: 'CRASH' }); } return r; } };
  try { await w.advance(2 * 60_000); } catch {}
  assert.ok(crashed, 'the release reached the ledger');
  // a second worker starts ticking at the same time as the restarted one
  w.restartVault(); const other = w.openVault();
  await Promise.all([w.vault.tick(), other.tick()]);
  other.store.close();
  await w.advance(2 * 60_000);
  const mine = w.ledger.transfers(0).filter((t) => t.sender === w.ACCOUNT || t.statement?.sender === w.ACCOUNT);
  const pays = w.vault.v5payments();
  assert.equal(pays.length, 1); assert.equal(pays[0].state, 'SETTLED', JSON.stringify(pays));
  assert.equal(mine.length, 1, 'exactly one ledger transfer: ' + JSON.stringify(mine).slice(0, 200));
  const v = await verifyWorld6(w); assert.equal(v.ok, true, JSON.stringify(v).slice(0, 300));
});
