// V3 core: Purpose Root governance, payments bound to epoch/purpose, rotation, revocation, freeze/unfreeze.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV3 } from '../../src/v3/world.mjs';

const Y = (c) => (BigInt(c) * 10n ** 22n).toString();
const ok = (r) => { assert.equal(r.ok, true, JSON.stringify(r.error)); return r.result; };
const deny = (r, code) => { assert.equal(r.ok, false, 'expected denial'); if (code) assert.match(`${r.error.code}:${r.error.detail ?? ''}`, new RegExp(code)); return r.error; };

test('legitimate payment: K1 passkey (UV) -> buffered -> settled; verifier authorizes the effect', async () => {
  const w = buildV3();
  const r = ok(await w.pay({ amountYocto: Y(3), sku: 'coffee-beans' }));
  assert.equal(r.state, 'BUFFERED');
  await w.advance(11 * 60_000);
  assert.equal(ok(await w.gz.request('STATUS', { paymentId: r.paymentId })).state, 'SETTLED');
  const v = await w.verify();
  assert.equal(v.chainValid, true); assert.equal(v.financial.effects, 1); assert.equal(v.financial.violations.length, 0);
});

test('PAY: K2 works, K3/K4/K5 can never pay, UV=false refused, exact amount and recipient bound', async () => {
  const w = buildV3();
  ok(await w.pay({ credId: 'k2-laptop', amountYocto: Y(2) }));
  for (const c of ['k3-root-hw', 'k4-freeze', 'k5-recovery-hw']) deny(await w.pay({ credId: c }), 'PAYCAP_ROLE_NOT_AUTHORIZED');
  const pc = w.owner.paycap(w.view(), { credId: 'k1-phone', recipientId: 'merchant-a.mock', amountYocto: Y(2), uv: false });
  deny(await w.gz.request('PROPOSE', { ...pc, recipientId: 'merchant-a.mock', amountYocto: Y(2), asset: 'NEAR', memo: 'x' }), 'WEBAUTHN_NO_USER_VERIFICATION');
  deny(await w.pay({ amountYocto: Y(2), request: { amountYocto: Y(1) } }), 'AMOUNT_NOT_EXACT');
  deny(await w.pay({ amountYocto: Y(2), request: { recipientId: 'attacker.mock' } }), 'RECIPIENT_NOT_BOUND');
  deny(await w.pay({ recipientId: 'attacker.mock', amountYocto: Y(1) }), 'RECIPIENT_NOT_IN_PURPOSE');
  deny(await w.pay({ amountYocto: Y(7) }), 'OVER_PER_PAYMENT_LIMIT');
  deny(await w.pay({ sku: 'coffee-beans', amountYocto: Y(2) }), 'PRODUCT_AMOUNT_NOT_EXACT');
});

test('Purpose amendment needs K1+K2+K3 with UV; immutable fields can never change; any 2 keys fail', async () => {
  const w = buildV3();
  const c2 = { ...w.owner.capsule, version: '2', perPaymentMaxYocto: Y(5) };
  for (const set of [['k1-phone', 'k2-laptop'], ['k1-phone', 'k3-root-hw'], ['k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], ['k1-phone', 'k3-root-hw', 'k5-recovery-hw']])
    deny(await w.ownerAct('AMEND_PURPOSE', { capsule: c2 }, set, { notIntended: true }), 'QUORUM_NOT_SATISFIED');
  deny(await w.ownerAct('AMEND_PURPOSE', { capsule: { ...c2, recipients: [...c2.recipients, 'attacker.mock'], statement: 'Pay anyone the agent chooses for anything.' } }, ['k1-phone', 'k2-laptop', 'k3-root-hw'], { notIntended: true }), 'IMMUTABLE_statement');
  ok(await w.ownerAct('AMEND_PURPOSE', { capsule: c2 }, ['k1-phone', 'k2-laptop', 'k3-root-hw']));
  assert.equal(w.vault.root.purpose.version, '2');
  // capability bound to the old purpose version is stale
  const pcOld = w.owner.paycap({ ...w.view(), purposeVersion: '1' }, { recipientId: 'merchant-a.mock', amountYocto: Y(1) });
  deny(await w.gz.request('PROPOSE', { ...pcOld, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'x' }), 'STALE_PURPOSE_VERSION');
  const v = await w.verify(); assert.equal(v.authority.unauthorized.length, 0); assert.equal(v.purpose.versions.length, 2);
});

test('rotation is role-preserving, bumps the epoch and invalidates outstanding capabilities and buffered payments', async () => {
  const w = buildV3();
  const pend = ok(await w.pay({ amountYocto: Y(1) }));
  const nd = w.owner.newDevice({ credId: 'k1-phone-2', role: 'DAILY', holderId: 'alice', channelId: 'ch-phone', kind: 'passkey' });
  const enroll = (a) => nd.enrollment('vault-alice.mock', `vault-alice.mock:${a}`);
  const view = w.view(); const action = w.owner.action(view, 'ROTATE', { credId: 'k1-phone', newCredential: null });
  action.body.newCredential = enroll(action.nonce);
  const r = await w.admin.request('SUBMIT', { request: { action, approvals: w.owner.approvals(action, ['k1-phone', 'k2-laptop']) } });
  ok(r); w.intents.add((await import('../../src/v3/root/chain.mjs')).actionDigest(action).toString('hex'));
  await w.pump();
  assert.equal(w.vault.root.epoch, 2);
  assert.equal(ok(await w.gz.request('STATUS', { paymentId: pend.paymentId })).reason, 'STALE_EPOCH');
  deny(await w.pay({ credId: 'k1-phone' }), 'PAYCAP_CREDENTIAL_NOT_ACTIVE');
  ok(await w.pay({ credId: 'k1-phone-2', amountYocto: Y(1) }));
  // old-epoch capability from K2 also dead
  const stale = w.owner.paycap({ ...w.view(), epoch: 1 }, { credId: 'k2-laptop', recipientId: 'merchant-a.mock', amountYocto: Y(1) });
  deny(await w.gz.request('PROPOSE', { ...stale, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'x' }), 'STALE_EPOCH');
});

test('K4 freezes alone but cannot unfreeze; unfreeze needs K3 + a daily key; frozen payments are cancelled not released', async () => {
  const w = buildV3();
  const p = ok(await w.pay({ amountYocto: Y(1) }));
  ok(await w.ownerAct('FREEZE', { freezeId: 'f1', reason: 'phone stolen', source: 'owner' }, ['k4-freeze']));
  deny(await w.pay({ amountYocto: Y(1) }), 'FREEZE_ACTIVE');
  deny(await w.ownerAct('UNFREEZE', { freezeId: 'f1' }, ['k4-freeze'], { notIntended: true }), 'QUORUM_NOT_SATISFIED');
  deny(await w.ownerAct('UNFREEZE', { freezeId: 'f1' }, ['k4-freeze', 'k5-recovery-hw'], { notIntended: true }), 'QUORUM_NOT_SATISFIED');
  await w.advance(15 * 60_000);
  ok(await w.ownerAct('UNFREEZE', { freezeId: 'f1' }, ['k3-root-hw', 'k2-laptop']));
  assert.equal(ok(await w.gz.request('STATUS', { paymentId: p.paymentId })).state, 'CANCELLED');
  ok(await w.pay({ amountYocto: Y(1) }));
});

test('supervisor breach freeze needs a repair certificate for THIS freeze in addition to the owner quorum', async () => {
  const w = buildV3();
  ok(await w.submitRaw('FREEZE', { freezeId: 'sup-1', reason: 'verifier: unauthorized effect', source: 'supervisor' }, { attest: (a) => ({ supervisorSig: w.owner.supervisorFreezeSign(a) }) }));
  deny(await w.ownerAct('UNFREEZE', { freezeId: 'sup-1' }, ['k3-root-hw', 'k1-phone'], { notIntended: true }), 'UNFREEZE_ATTESTATION|UNEXPECTED');
  const bad = w.owner.repairCert({ freezeId: 'sup-1', verdict: 'REPAIRED', exactReplay: 'DENIED_FOR_INVARIANT', mutations: 'ALL_DENIED', regression: 'FAIL', legitimate: 'PASS', candidate: 'abc' });
  deny(await w.ownerAct('UNFREEZE', { freezeId: 'sup-1' }, ['k3-root-hw', 'k1-phone'], { attestation: () => ({ repair: bad }), notIntended: true }), 'REPAIR_NOT_COMPLETE');
  const other = w.owner.repairCert({ freezeId: 'sup-0', verdict: 'REPAIRED', exactReplay: 'DENIED_FOR_INVARIANT', mutations: 'ALL_DENIED', regression: 'PASS', legitimate: 'PASS', candidate: 'abc' });
  deny(await w.ownerAct('UNFREEZE', { freezeId: 'sup-1' }, ['k3-root-hw', 'k1-phone'], { attestation: () => ({ repair: other }), notIntended: true }), 'REPAIR_CERT_WRONG_FREEZE');
  const good = w.owner.repairCert({ freezeId: 'sup-1', verdict: 'REPAIRED', exactReplay: 'DENIED_FOR_INVARIANT', mutations: 'ALL_DENIED', regression: 'PASS', legitimate: 'PASS', candidate: 'abc' });
  ok(await w.ownerAct('UNFREEZE', { freezeId: 'sup-1' }, ['k3-root-hw', 'k1-phone'], { attestation: () => ({ repair: good }) }));
});

test('revoking a compromised key needs two OTHER keys, bumps the epoch, and the vacancy is refilled by K3 + daily', async () => {
  const w = buildV3();
  deny(await w.ownerAct('REVOKE', { credId: 'k2-laptop', reason: 'compromised' }, ['k2-laptop', 'k1-phone'], { notIntended: true }), 'REVOKE_SELF_APPROVAL');
  deny(await w.ownerAct('REVOKE', { credId: 'k2-laptop', reason: 'compromised' }, ['k4-freeze', 'k5-recovery-hw'], { notIntended: true }), 'QUORUM_NOT_SATISFIED');
  ok(await w.ownerAct('REVOKE', { credId: 'k2-laptop', reason: 'compromised' }, ['k1-phone', 'k3-root-hw']));
  assert.equal(w.vault.root.epoch, 2);
  deny(await w.pay({ credId: 'k2-laptop' }), 'NOT_ACTIVE');
  const nd = w.owner.newDevice({ credId: 'k2-tablet', role: 'DAILY', holderId: 'alice', channelId: 'ch-email', kind: 'passkey' });
  const a = w.owner.action(w.view(), 'REPLACE_VACANT', { revokedCredId: 'k2-laptop', newCredential: null });
  a.body.newCredential = nd.enrollment('vault-alice.mock', `vault-alice.mock:${a.nonce}`);
  ok(await w.admin.request('SUBMIT', { request: { action: a, approvals: w.owner.approvals(a, ['k3-root-hw', 'k1-phone']) } }));
  await w.pump();
  ok(await w.pay({ credId: 'k2-tablet', amountYocto: Y(1) }));
  // ROOT vacancy can never be refilled by daily keys
  ok(await w.ownerAct('REVOKE', { credId: 'k3-root-hw', reason: 'lost' }, ['k1-phone', 'k2-tablet']));
  const nr = w.owner.newDevice({ credId: 'k3-root-new', role: 'ROOT', holderId: 'alice', channelId: 'ch-postal', kind: 'ed25519' });
  const b = w.owner.action(w.view(), 'REPLACE_VACANT', { revokedCredId: 'k3-root-hw', newCredential: null });
  b.body.newCredential = nr.enrollment('vault-alice.mock', `vault-alice.mock:${b.nonce}`);
  deny(await w.admin.request('SUBMIT', { request: { action: b, approvals: w.owner.approvals(b, ['k1-phone', 'k2-tablet']) } }), 'VACANCY_REQUIRES_RECOVERY_PROTOCOL');
});
