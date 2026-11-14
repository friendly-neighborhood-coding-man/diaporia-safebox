// Tests added for V6 mutation survivors (scripts/v6/mutations.mjs): each pins one check that no earlier test isolated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildV6, ok, deny, Y, MIN, incidentWorld, consoleForWorld, client, CONFIRM_PHRASE } from './helpers6.mjs';
import { verifyGate, SimulatedFingerprintGate } from '../../src/v6/device/biometric.mjs';
import { V6_DOMAINS } from '../../src/v6/common/v6.mjs';
import { genesisState } from '../../src/v6/root/chain.mjs';
import { paycapDigest } from '../../src/v3/vault/paycap.mjs';
import { nonce as mkNonce } from '../../src/v3/common/canon.mjs';
import { verifyWorld6 } from '../../src/v6/supervisor/verifier.mjs';

const T = Date.parse('2026-11-14T00:00:00Z');
const DIG = 'ab'.repeat(32), NON = 'cd'.repeat(32);
function gateCase() {
  const g = new SimulatedFingerprintGate({ credId: 'k2-laptop' });
  const ctx = { accountId: 'acc', chainId: 'ch', credId: 'k2-laptop', subject: 'COMMAND', boundDigestHex: DIG, challengeNonce: NON, notBeforeMs: T - 60_000, notAfterMs: T + 10 * 60_000,
    at: T, maxAgeMs: 60_000, skewMs: 30_000, gateKeys: { 'k2-laptop': { gateKeyId: g.gateKeyId, spki: g.key.spki } } };
  const base = g.attest({ accountId: 'acc', chainId: 'ch', subject: 'COMMAND', boundDigestHex: DIG, challengeNonce: NON, at: T });
  const resign = (mut) => { const st = { ...base.statement }; mut(st); return { statement: st, sig: g.key.signObj(V6_DOMAINS.BIOMETRIC_GATE, st) }; };
  return { g, ctx, base, resign };
}

test('gate: every statement field is checked even under a VALID gate-key signature (a lying or buggy helper)', () => {
  const { ctx, base, resign } = gateCase();
  assert.equal(verifyGate(base, ctx).level, 'LOCAL_FINGERPRINT_GATE_PASSED');
  const cases = [
    [(s) => { s.method = 'WINDOWS_HELLO_PIN'; }, 'GATE_METHOD_NOT_FINGERPRINT'],
    [(s) => { s.result = 'NO_MATCH'; }, 'GATE_RESULT_NOT_MATCH'],
    [(s) => { s.boundDigest = 'ef'.repeat(32); }, 'GATE_NOT_FOR_THIS_DIGEST'],
    [(s) => { s.challengeNonce = '01'.repeat(32); }, 'GATE_NOT_FOR_THIS_CHALLENGE'],
    [(s) => { s.credId = 'k1-phone'; }, 'GATE_WRONG_CREDENTIAL'],
    [(s) => { s.gateKeyId = 'other-gate'; }, 'GATE_WRONG_CREDENTIAL'],
    [(s) => { s.subject = 'PAYMENT'; }, 'GATE_WRONG_SUBJECT'],
    [(s) => { s.accountId = 'other'; }, 'GATE_WRONG_ACCOUNT'],
  ];
  for (const [mut, code] of cases) assert.throws(() => verifyGate(resign(mut), ctx), (e) => e.code === code, code);
  // stale: inside the challenge window, but older than the policy's max gate age
  assert.throws(() => verifyGate(resign((s) => { s.verifiedAt = new Date(T - 2 * 60_000 + 30_000).toISOString(); }), { ...ctx, notBeforeMs: T - 5 * 60_000 }), (e) => e.code === 'GATE_STALE');
});

test('genesis: a gate key whose proof of possession is for another credential is refused', () => {
  const w = buildV6({ fingerprintOnly: ['k2-laptop'] });
  const gen = structuredClone(w.genesis);
  const k = gen.ext.action.body.gateKeys['k2-laptop'];
  k.pop = w.gates['k2-laptop'].key.signObj(V6_DOMAINS.GATE_POP, { accountId: gen.ext.action.accountId, v5ChainId: gen.ext.action.v5ChainId, credId: 'k1-phone', gateKeyId: k.gateKeyId });
  assert.throws(() => genesisState(gen), (e) => e.code === 'GATE_KEY_POP');
});

test('genesis RP: the loopback exception is exactly http://localhost:<port>', () => {
  for (const origin of ['http://evil.example:47610', 'http://localhost.evil.example:47610', 'http://localhost', 'http://127.0.0.1:47610']) {
    assert.throws(() => buildV6({ rp: { rpId: 'localhost', origin } }), (e) => e.code === 'GENESIS_RP', origin);
  }
  assert.ok(buildV6({ rp: { rpId: 'localhost', origin: 'http://localhost:47610' } }));
});

test('payment: the capability taskRef must be the binding hash', async () => {
  const w = buildV6();
  const pa = w.owner.paymentApproval(w.root.state, { credId: 'k1-phone', recipientId: 'merchant-a.mock', amountYocto: Y(1), at: w.now() });
  const cap = { ...pa.capability, taskRef: 'v6pa-' + '0'.repeat(58) };
  const ap = { ...w.owner.dev('k1-phone').approvePaycap(paycapDigest(cap), { uv: true }), v6: pa.approval.v6 };
  deny(await w.gz.request('PROPOSE', { capability: cap, approval: ap, recipientId: cap.recipientId, amountYocto: cap.amountYocto, asset: 'NEAR', memo: 'x' }), 'V6_BINDING_MISMATCH');
  assert.equal(w.vault.v5payments().length, 0);
});

test('payment: a Root-pinned challenge issued to another credential cannot be used', async () => {
  const w = buildV6();
  const svc = w.owner.payChallenge; const issue = svc.issue.bind(svc);
  svc.issue = (o) => issue({ ...o, credId: 'k1-phone' });
  deny(await w.pay({ credId: 'k2-laptop' }), 'CHALLENGE_NOT_FOR_THIS_CREDENTIAL');
  assert.equal(w.vault.v5payments().length, 0);
});

test('console: an approval carrying another proposal\'s challenge is refused before Root', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
  const pr = await k.post('/api/freeze/prepare', { locator });
  const pr2 = await k.post('/api/freeze/prepare', { locator });
  const ap = w.owner.approvePrepared(w.root.state, pr, 'k2-laptop', { at: w.now() });
  const r = await k.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm: CONFIRM_PHRASE, approval: { ...ap, grant: pr2.grant } });
  assert.equal(r.error.code, 'APPROVAL_NOT_FOR_PREPARED_CHALLENGE');
});

test('device: a prepared challenge not signed by the Root-pinned issuer is not signed', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
  const pr = await k.post('/api/freeze/prepare', { locator });
  const bad = { ...pr, grant: { ...pr.grant, sig: pr.grant.sig.replace(/^./, (x) => (x === 'A' ? 'B' : 'A')) } };
  assert.equal(w.owner.approvePrepared(w.root.state, bad, 'k2-laptop', { at: w.now() }), null);
  assert.equal(w.owner.gateErrors.at(-1).code, 'PREPARED_GRANT_NOT_ROOT_PINNED');
});

test('verifier6: a dishonest Vault that forgets consumed challenges, misreports levels or ignores the delegation policy is flagged', async () => {
  // (1) challenge reuse: the Vault's consumed-nonce table is wiped, so a second capability rides the same approval
  const w = buildV6();
  ok(await w.pay({ credId: 'k1-phone' }));
  const pa = w.lastApproval;
  const db = w.vault.store.db; const prep = db.prepare.bind(db);
  db.prepare = (sql) => sql.includes('FROM v6_challenges WHERE nonce') ? { get: () => undefined } : sql.includes('INSERT INTO v6_challenges') ? { run: () => ({}) } : prep(sql);
  const cap2 = { ...pa.capability, capId: randomUUID(), nonce: mkNonce() };
  const ap2 = { ...w.owner.dev('k1-phone').approvePaycap(paycapDigest(cap2), { uv: true }), v6: pa.approval.v6 };
  ok(await w.gz.request('PROPOSE', { capability: cap2, approval: ap2, recipientId: cap2.recipientId, amountYocto: cap2.amountYocto, asset: 'NEAR', memo: 'reuse' }));
  await w.advance(12 * MIN);
  let v = await verifyWorld6(w); assert.equal(v.ok, false);
  assert.ok(v.v6.ownerApprovals.violations.some(x => x.codes.includes('OWNER_APPROVAL_CHALLENGE_REUSED')), JSON.stringify(v.v6.ownerApprovals));
  // (2) level misreported in the Vault's evidence
  const w2 = buildV6();
  ok(await w2.pay({ credId: 'k1-phone' })); await w2.advance(12 * MIN);
  const ev = w2.vault.v6evidence.bind(w2.vault); w2.vault.v6evidence = () => ev().map(r => ({ ...r, level: 'LOCAL_FINGERPRINT_GATE_PASSED' }));
  v = await verifyWorld6(w2); assert.equal(v.ok, false);
  assert.ok(v.v6.ownerApprovals.violations.some(x => x.codes.includes('OWNER_APPROVAL_LEVEL_MISREPORTED')));
  // (3) delegated payment settled although the owner-signed policy disables delegation
  const w3 = buildV6({ policy6: { delegation: 'DELEGATION_DISABLED' } });
  const pol = w3.vault.policy6.bind(w3.vault); w3.vault.policy6 = () => ({ ...pol(), delegation: 'BOUNDED_DELEGATION_ALLOWED' });
  const dk = w3.owner.newDelegate('d1');
  ok(await w3.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: dk.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w3.iso(w3.now() + 2 * 86_400_000), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  await w3.payDelegated('d1', 1); await w3.advance(12 * MIN);
  v = await verifyWorld6(w3); assert.equal(v.ok, false);
  assert.ok(v.v6.ownerApprovals.violations.some(x => x.codes.includes('DELEGATED_EFFECT_WHILE_DELEGATION_DISABLED')), JSON.stringify(v.v6.ownerApprovals));
});
