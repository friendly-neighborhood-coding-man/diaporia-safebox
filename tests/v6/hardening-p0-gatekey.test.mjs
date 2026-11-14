// V6 hardening P0.1 (issue #14): same-user signing with the fingerprint-gate key.
// Attacker capability: code running as the owner's Windows user (same-user malware). The gate key is a per-user CNG key
// (non-exportable, TPM-backed when available, NO UI protection); any same-user process can open it by name and sign,
// without the helper and without a finger. In this test the simulated gate's own key object stands in for that handle.
// Not modelled: the Windows Hello passkey itself. Windows Hello requires a user gesture for every assertion (PIN OR
// fingerprint); same-user code cannot obtain one without the owner acting, but it can ask for one (and a PIN suffices).
//
// What must hold after P0.1:
//  * LOCAL_GATE (default): a forged gate alone authorizes nothing; it still needs the owner's own UV assertion. A forged
//    gate next to a UV-only (possibly PIN) assertion IS accepted as LOCAL_FINGERPRINT_GATE_PASSED: that is the bound
//    (fingerprint-only degrades to Windows Hello UV), documented as INHERENT_RESIDUAL for a same-user key.
//  * HIGH_ASSURANCE: no enrolled gate key kind available today is isolated from same-user code, so every fingerprint-
//    only approval FAILS CLOSED (no prompt, no payment, no command); UV credentials keep working.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV6, Y, ok, deny } from './helpers6.mjs';
import { GATE_V } from '../../src/v6/device/biometric.mjs';
import { V6_DOMAINS, GATE_METHOD, parsePolicy, DEFAULT_ASSURANCE_POLICY } from '../../src/v6/common/v6.mjs';
import { paycapDigest } from '../../src/v3/vault/paycap.mjs';
import { commandDigest } from '../../src/v5/root/command.mjs';
import { rootView } from '../../src/v6/root/chain.mjs';

/** Same-user malware: signs a MATCH statement with the gate key directly (no helper, no sensor). */
function forgeGate(g, { accountId, chainId, subject, boundDigestHex, challengeNonce, at }) {
  const statement = { v: GATE_V, accountId, chainId, credId: g.credId, gateKeyId: g.gateKeyId, method: GATE_METHOD, result: 'MATCH', subject,
    boundDigest: boundDigestHex, challengeNonce, verifiedAt: new Date(at).toISOString(), sensorClass: g.sensorClass };
  return { statement, sig: g.key.signObj(V6_DOMAINS.BIOMETRIC_GATE, statement) };
}
const payArgs = (pa, memo) => ({ capability: pa.capability, approval: pa.approval, recipientId: pa.capability.recipientId, amountYocto: pa.capability.amountYocto, asset: 'NEAR', memo });
/** A UV-only payment approval from the owner's passkey (e.g. the owner typed the PIN), plus a forged gate. */
function uvPlusForged(w, amount = Y(2)) {
  const g = w.gates['k2-laptop']; g.next('NO_MATCH'); // nobody touches the sensor
  const pa = w.owner.paymentApproval(w.root.state, { credId: 'k2-laptop', recipientId: 'merchant-a.mock', amountYocto: amount, at: w.now(), noGate: true });
  pa.approval.v6.gate = forgeGate(g, { accountId: pa.capability.accountId, chainId: pa.capability.chainId, subject: 'PAYMENT', boundDigestHex: paycapDigest(pa.capability).toString('hex'),
    challengeNonce: pa.approval.v6.binding.challengeNonce, at: w.now() });
  return pa;
}
const HIGH = { fingerprintOnly: ['k2-laptop'], policy6: { fingerprintAssurance: 'HIGH_ASSURANCE' } };

test('P0.1-bound: a forged gate without the owner\'s own UV assertion authorizes no payment', async () => {
  const w = buildV6({ fingerprintOnly: ['k2-laptop'] });
  const pa = uvPlusForged(w);
  // malware has the gate key but not the passkey: it substitutes its own capability under the owner's approval
  const cap = { ...pa.capability, recipientId: 'attacker.mock' };
  pa.approval.v6.gate = forgeGate(w.gates['k2-laptop'], { accountId: cap.accountId, chainId: cap.chainId, subject: 'PAYMENT', boundDigestHex: paycapDigest(cap).toString('hex'), challengeNonce: pa.approval.v6.binding.challengeNonce, at: w.now() });
  const r = await w.gz.request('PROPOSE', { ...payArgs(pa, 'forged'), capability: cap, recipientId: 'attacker.mock' });
  assert.equal(r.ok, false); assert.equal(w.vault.v5payments().length, 0);
});

test('P0.1-residual (LOCAL_GATE): a forged gate next to a UV-only assertion is accepted, so fingerprint-only degrades to Windows Hello UV', async () => {
  const w = buildV6({ fingerprintOnly: ['k2-laptop'] });
  assert.equal(w.gates['k2-laptop'].log.length, 0);
  const pa = uvPlusForged(w);
  ok(await w.gz.request('PROPOSE', payArgs(pa, 'uv + forged gate')));
  assert.equal(w.vault.v6evidence().at(-1).level, 'LOCAL_FINGERPRINT_GATE_PASSED');
  // the Root view states what the gate key can and cannot prove
  const v = rootView(w.root.state).assurancePolicy;
  assert.equal(v.fingerprintAssurance, 'LOCAL_GATE');
  assert.equal(v.gateKeyProtection['k2-laptop'], 'SAME_USER_KEY');
});

test('P0.1-high: HIGH_ASSURANCE fails closed for every fingerprint-only payment (honest or forged) and never prompts the sensor', async () => {
  const w = buildV6(HIGH);
  const g = w.gates['k2-laptop'];
  deny(await w.pay({ credId: 'k2-laptop', amountYocto: Y(1) }), 'FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE|OWNER_DECLINED|APPROVAL');
  assert.ok(w.owner.gateErrors.some((e) => e.code === 'FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE'), JSON.stringify(w.owner.gateErrors));
  assert.equal(g.log.length, 0, 'the sensor was prompted for an approval that cannot be accepted');
  deny(await w.gz.request('PROPOSE', payArgs(uvPlusForged(w), 'forged')), 'FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE');
  assert.equal(w.vault.v5payments().length, 0);
  // UV credentials are unaffected
  ok(await w.pay({ credId: 'k1-phone', amountYocto: Y(1) }));
  const v = rootView(w.root.state).assurancePolicy;
  assert.equal(v.fingerprintAssurance, 'HIGH_ASSURANCE');
});

test('P0.1-high: HIGH_ASSURANCE fails closed for fingerprint-only commands (FREEZE), honest or forged, at the Root', async () => {
  const w = buildV6(HIGH);
  const a = w.action('FREEZE', { freezeId: 'h-fp', reason: 'freeze by k2', source: 'owner' });
  const honest = await w.submit({ action: a, approvals: w.owner.authorize4(w.root.state, a, ['k2-laptop'], { at: w.now() }) });
  assert.equal(honest.ok, false); assert.equal(w.frozen(), false);
  assert.equal(w.gates['k2-laptop'].log.length, 0);
  const ap = w.owner.approveCommand(w.root.state, a, 'k2-laptop', { at: w.now(), noGate: true, withGate: false });
  const forged = { ...ap, gate: forgeGate(w.gates['k2-laptop'], { accountId: ap.command.accountId, chainId: ap.command.chainId, subject: 'COMMAND', boundDigestHex: commandDigest(ap.command).toString('hex'), challengeNonce: ap.grant.statement.challengeNonce, at: w.now() }) };
  const r = await w.submit({ action: a, approvals: [forged] });
  deny(r, 'FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE');
  assert.equal(w.frozen(), false);
});

test('P0.1-policy: the assurance mode is owner-signed at genesis, optional (default LOCAL_GATE, digest unchanged) and strictly validated', () => {
  assert.equal(parsePolicy({ ...DEFAULT_ASSURANCE_POLICY }).fingerprintAssurance, undefined);
  assert.equal(parsePolicy({ ...DEFAULT_ASSURANCE_POLICY, fingerprintAssurance: 'HIGH_ASSURANCE' }).fingerprintAssurance, 'HIGH_ASSURANCE');
  for (const bad of ['high', 'NONE', '', 1, null]) assert.throws(() => parsePolicy({ ...DEFAULT_ASSURANCE_POLICY, fingerprintAssurance: bad }), (e) => e.code === 'V6_POLICY_FP_ASSURANCE', String(bad));
});

test('P0.1-high: the console gate service refuses a HIGH_ASSURANCE fingerprint-only command before any prompt', async () => {
  const { consoleGate } = await import('../../src/v6/device/gate-service.mjs');
  const w = buildV6(HIGH);
  assert.throws(() => consoleGate({ rootState: () => w.root.state, gates: w.gates, now: w.now }, { subject: 'COMMAND', credId: 'k2-laptop', action: {}, grant: {}, command: {} }),
    (e) => e.code === 'FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE');
  assert.equal(w.gates['k2-laptop'].log.length, 0);
});
