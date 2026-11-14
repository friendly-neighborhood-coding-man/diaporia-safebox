// Workflow A at the Root/Vault layer: per-transaction owner approval (V6 binding + Root-pinned one-time challenge +
// fingerprint gate for fingerprint-only credentials) on top of the unchanged V5 Vault rules.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildV6, ok, deny, Y, D, H, MIN } from './helpers6.mjs';
import { paycapDigest } from '../../src/v3/vault/paycap.mjs';
import { nonce as mkNonce } from '../../src/v3/common/canon.mjs';
import { verifyWorld6 } from '../../src/v6/supervisor/verifier.mjs';
import { SimulatedFingerprintGate } from '../../src/v6/device/biometric.mjs';

const fp = (o = {}) => buildV6({ fingerprintOnly: ['k2-laptop'], ...o });

test('A-honest: UV phone and fingerprint-only laptop approvals settle after FIXED_600; verifier clean; evidence journaled', async () => {
  const w = fp();
  const a = ok(await w.pay({ credId: 'k1-phone' })); assert.equal(a.state, 'BUFFERED');
  const b = ok(await w.pay({ credId: 'k2-laptop' }));
  assert.equal(w.lastApproval.assurance, 'FINGERPRINT_ONLY');
  await w.advance(9 * MIN); assert.ok(w.vault.v5payments().every(p => p.state === 'BUFFERED'), 'buffer not skipped');
  await w.advance(3 * MIN); assert.ok(w.vault.v5payments().every(p => p.state === 'SETTLED'));
  const ev = w.vault.v6evidence(); assert.equal(ev.length, 2); assert.deepEqual(ev.map(e => e.level).sort(), ['LOCAL_FINGERPRINT_GATE_PASSED', 'UV']);
  const v = await verifyWorld6(w); assert.equal(v.ok, true, JSON.stringify(v.v6)); assert.equal(v.v6.ownerApprovals.checked, 2);
  assert.ok(a.paymentId && b.paymentId);
});

test('A-binding: every bound field is checked (amount, recipient, asset, Purpose, credential, Epoch, policy version, request, expiry, assurance)', async () => {
  const cases = [
    [(b) => { b.amountYocto = Y(2); }, 'V6_BINDING_MISMATCH'], [(b) => { b.recipientId = 'merchant-b.mock'; }, 'V6_BINDING_MISMATCH'], [(b) => { b.asset = 'USDC'; }, 'V6_BINDING_MISMATCH'],
    [(b) => { b.purposeVersion = '99'; }, 'V6_BINDING_MISMATCH'], [(b) => { b.credId = 'k2-laptop'; }, 'V6_BINDING_MISMATCH'], [(b) => { b.epoch = '7'; }, 'V6_BINDING_MISMATCH'],
    [(b) => { b.policyVersion = '0'; }, 'V6_BINDING_MISMATCH'], [(b) => { b.accountId = 'vault-bob.mock'; }, 'V6_BINDING_MISMATCH'], [(b) => { b.requestDigest = 'f'.repeat(64); }, 'CHALLENGE_NOT_FOR_THIS_REQUEST'],
    [(b) => { b.requestId = 'BAD ID'; }, 'V6_BINDING_REQUEST'], [(b) => { b.approvalExpiresAt = new Date(Date.parse(b.approvalExpiresAt) + 1).toISOString(); }, 'V6_APPROVAL_EXPIRY_MISMATCH|V6_APPROVAL_TTL'],
[(b) => { b.challengeNonce = '0'.repeat(64); }, 'CHALLENGE_NONCE_MISMATCH'], [(b) => { b.v = 'safebox.v5.x'; }, 'V6_BINDING_VERSION'],
  ];
  for (const [tamper, code] of cases) {
    const w = fp();
    deny(await w.pay({ credId: 'k1-phone', amountYocto: Y(3), tamper: (b) => { tamper(b); } }), code);
    assert.equal(w.vault.v5payments().length, 0);
  }
  // assurance downgrade: a fingerprint-only credential's approval claiming plain UV (and skipping the gate)
  const w = fp();
  deny(await w.pay({ credId: 'k2-laptop', noGate: true, tamper: (b) => { b.assurance = 'UV'; } }), 'V6_ASSURANCE_MISMATCH');
});

test('A-challenge: reuse with a fresh signature, expiry, forged issuer -> refused', async () => {
  const w = fp();
  ok(await w.pay({ credId: 'k1-phone' }));
  const pa = w.lastApproval;
  const cap2 = { ...pa.capability, capId: randomUUID(), nonce: mkNonce() };
  const ap2 = { ...w.owner.dev('k1-phone').approvePaycap(paycapDigest(cap2), { uv: true }), v6: pa.approval.v6 };
  deny(await w.gz.request('PROPOSE', { capability: cap2, approval: ap2, recipientId: cap2.recipientId, amountYocto: cap2.amountYocto, asset: 'NEAR', memo: 'x' }), 'CHALLENGE_ALREADY_CONSUMED');
  // survives a Vault restart (consumed nonces are durable)
  w.restartVault();
  const cap3 = { ...pa.capability, capId: randomUUID(), nonce: mkNonce() };
  const ap3 = { ...w.owner.dev('k1-phone').approvePaycap(paycapDigest(cap3), { uv: true }), v6: pa.approval.v6 };
  deny(await w.gz.request('PROPOSE', { capability: cap3, approval: ap3, recipientId: cap3.recipientId, amountYocto: cap3.amountYocto, asset: 'NEAR', memo: 'x' }), 'CHALLENGE_ALREADY_CONSUMED');
  // expired one-time challenge (approval held back past the 120 s grant window)
  const late = w.owner.paymentApproval(w.root.state, { credId: 'k1-phone', recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  await w.advance(3 * MIN);
  deny(await w.gz.request('PROPOSE', { capability: late.capability, approval: late.approval, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'late' }), 'CHALLENGE_EXPIRED');
  // a grant signed by a non-Root-pinned issuer
  const forged = w.owner.paymentApproval(w.root.state, { credId: 'k1-phone', recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  forged.approval.v6.grant.sig = forged.approval.v6.grant.sig.replace(/^./, (c) => (c === 'A' ? 'B' : 'A'));
  deny(await w.gz.request('PROPOSE', { capability: forged.capability, approval: forged.approval, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'f' }), 'CHALLENGE_SIGNATURE|CHALLENGE');
});

test('A-epoch: an approval made before an Epoch change is refused after it', async () => {
  const w = fp();
  const pa = w.owner.paymentApproval(w.root.state, { credId: 'k1-phone', recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  ok(await w.ownerAct('REVOKE', { credId: 'k4-freeze', reason: 'lost' }, ['k2-laptop', 'k3-root-hw']));
  deny(await w.gz.request('PROPOSE', { capability: pa.capability, approval: pa.approval, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'old epoch' }), 'EPOCH|V6_BINDING_MISMATCH');
});

test('A-fingerprint: no gate, PIN only, no match, lockout, timeout, unsupported sensor, wrong digest, stale or foreign gate -> no payment', async () => {
  for (const outcome of ['PIN_ONLY', 'NO_MATCH', 'LOCKOUT', 'TIMEOUT', 'UNSUPPORTED', 'CANCELLED']) {
    const w = fp(); w.gates['k2-laptop'].next(outcome);
    const r = await w.pay({ credId: 'k2-laptop' }); assert.equal(r.ok, false, outcome); assert.equal(r.declined, true);
    assert.equal(w.vault.v5payments().length, 0);
  }
  const w = fp();
  deny(await w.pay({ credId: 'k2-laptop', noGate: true }), 'FINGERPRINT_GATE_REQUIRED');
  // gate of payment #1 swapped into payment #2 (different capability digest)
  const p1 = w.owner.paymentApproval(w.root.state, { credId: 'k2-laptop', recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  const p2 = w.owner.paymentApproval(w.root.state, { credId: 'k2-laptop', recipientId: 'merchant-a.mock', amountYocto: Y(2), at: w.now() });
  p2.approval.v6.gate = p1.approval.v6.gate;
  deny(await w.gz.request('PROPOSE', { capability: p2.capability, approval: p2.approval, recipientId: 'merchant-a.mock', amountYocto: Y(2), asset: 'NEAR', memo: 'swap' }), 'GATE_NOT_FOR_THIS');
  // a gate from an UNENROLLED fingerprint device (attacker's own sensor) for the right digest
  const rogue = new SimulatedFingerprintGate({ credId: 'k2-laptop' });
  const p3 = w.owner.paymentApproval(w.root.state, { credId: 'k2-laptop', recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  p3.approval.v6.gate = rogue.attest({ accountId: p3.capability.accountId, chainId: p3.capability.chainId, subject: 'PAYMENT', boundDigestHex: paycapDigest(p3.capability).toString('hex'), challengeNonce: p3.approval.v6.binding.challengeNonce, at: w.now() });
  deny(await w.gz.request('PROPOSE', { capability: p3.capability, approval: p3.approval, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'rogue' }), 'GATE_BAD_SIGNATURE');
  // the gate subject must be PAYMENT (a COMMAND gate for a freeze cannot authorize a payment)
  const p4 = w.owner.paymentApproval(w.root.state, { credId: 'k2-laptop', recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  p4.approval.v6.gate = w.gates['k2-laptop'].attest({ accountId: p4.capability.accountId, chainId: p4.capability.chainId, subject: 'COMMAND', boundDigestHex: paycapDigest(p4.capability).toString('hex'), challengeNonce: p4.approval.v6.binding.challengeNonce, at: w.now() });
  deny(await w.gz.request('PROPOSE', { capability: p4.capability, approval: p4.approval, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'subject' }), 'GATE_WRONG_SUBJECT');
  assert.equal(w.vault.v5payments().length, 0);
  // no gate device enrolled for a fingerprint-only credential: fail closed at the device
  const w2 = fp({ noGateDevice: ['k2-laptop'] });
  const r = await w2.pay({ credId: 'k2-laptop' }); assert.equal(r.ok, false); assert.equal(r.error.code, 'FINGERPRINT_ONLY_UNSUPPORTED');
  ok(await w2.pay({ credId: 'k1-phone' }), 'recovery path: other credentials keep working');
});

test('A-stolen PAY key: a stolen software key / V5-only paycap (no V6 approval) cannot pay under PER_TRANSACTION', async () => {
  const w = fp();
  deny(await w.v5pay({ credId: 'k1-phone' }), 'V6_PAYMENT_APPROVAL_REQUIRED');
  const pa = w.owner.paymentApproval(w.root.state, { credId: 'k1-phone', recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  delete pa.approval.v6;
  deny(await w.gz.request('PROPOSE', { capability: pa.capability, approval: pa.approval, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'x' }), 'V6_PAYMENT_APPROVAL_REQUIRED');
});

test('A-delegation: bounded delegation is its own owner-signed policy; DISABLED refuses delegated effects', async () => {
  const w = buildV6({ policy6: { delegation: 'DELEGATION_DISABLED' } });
  const k = w.owner.newDelegate('d1');
  ok(await w.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w.iso(w.now() + 2 * D), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  await assert.rejects(w.payDelegated('d1', 1), (e) => e.code === 'DELEGATION_DISABLED_BY_POLICY');
  const w2 = buildV6();
  const k2 = w2.owner.newDelegate('d1');
  ok(await w2.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k2.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w2.iso(w2.now() + 2 * D), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  const r = await w2.payDelegated('d1', 1); assert.ok(r.paymentId ?? r.ok ?? r);
});

test('A-preserved: anomaly delay, HIGH-risk expiry and the 26 h horizon are unchanged under V6 approvals', async () => {
  const w = fp();
  for (let i = 0; i < 5; i++) { ok(await w.pay({ credId: 'k1-phone', amountYocto: Y(1) })); await w.advance(MIN); }
  const ps = w.vault.v5payments();
  assert.ok(ps.some(p => p.anomaly === 'ANOMALY_PAYMENT_DELAY'), 'burst is delayed by the Risk Engine');
  for (const p of ps) assert.ok(Number(p.settle_deadline ?? 0) === 0 || Number(p.settle_deadline) - Number(p.proposed_at) <= 26 * H, 'horizon');
  await w.advance(27 * H, 30 * MIN);
  assert.ok(w.vault.v5payments().every(p => ['SETTLED', 'EXPIRED', 'CANCELLED'].includes(p.state)), JSON.stringify(w.vault.v5payments().map(p => p.state)));
  const v = await verifyWorld6(w); assert.equal(v.ok, true, JSON.stringify({ v6: v.v6, f: v.financial.violations }));
});

test('A-verifier: a vault that drops or rewrites approval evidence is flagged', async () => {
  const w = fp();
  ok(await w.pay({ credId: 'k1-phone' })); ok(await w.pay({ credId: 'k2-laptop' }));
  await w.advance(12 * MIN);
  w.vault.store.db.prepare('DELETE FROM v6_evidence WHERE cap_id=(SELECT cap_id FROM v6_evidence LIMIT 1)').run();
  const v = await verifyWorld6(w); assert.equal(v.ok, false); assert.ok(v.v6.ownerApprovals.violations.some(x => x.codes.includes('OWNER_APPROVAL_MISSING')));
});
