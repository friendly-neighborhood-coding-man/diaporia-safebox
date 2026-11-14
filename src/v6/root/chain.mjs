// SafeBox V6 Purpose Root state machine = the V5 Root (every V5 handler and invariant reused UNCHANGED) plus an
// owner-signed ASSURANCE POLICY in a V6 genesis extension:
//   * per-transaction payment approval mode and its TTL (the Vault enforces it on payments, see vault.mjs);
//   * credentials whose every approval must be FINGERPRINT_ONLY (WebAuthn UV + a local fingerprint-gate attestation
//     bound to the exact Command Statement / Authorization Intent digest and the Root-issued one-time challenge);
//   * enrolled gate keys (ES256), the allowlisted SafeBox emergency origin, delegation policy.
// The policy can only be set at genesis (every owner credential AND the ORC sign it); there is no amendment path in V6,
// so no single key, email, MCP client or fingerprint can weaken it later.
// The wrapper verifies gates BEFORE the V5 transition (fail closed), strips them, runs V5, and commits the transition as
// stored (gates included) into the hash chain. Root replicas (Vault) and the verifier run exactly this code.
import { fail, exactFields, isoMs, clone } from '../../v3/common/canon.mjs';
import { transitionHash } from '../../v3/root/chain.mjs';
import { verifyAssertion } from '../../v3/webauthn/verify.mjs';
import { edVerifyDigest } from '../../v3/common/canon.mjs';
import * as V5 from '../../v5/root/chain.mjs';
import { commandDigest } from '../../v5/root/command.mjs';
import { intentDigest } from '../../v4/intent/intent.mjs';
import { V6_DOMAINS, PROTOCOL6, d6, d6hex, parsePolicy, verifyEs256Obj } from '../common/v6.mjs';
import { verifyGate, gateKeyProtection } from '../device/biometric.mjs';

export * from '../../v5/root/chain.mjs';
export const EXT6_V = 'safebox.v6.genesis-ext';
export const TR_V = V5.TR_V;

export function genesisState(gen, { pinnedChainId = null } = {}) {
  exactFields(gen, ['v5', 'ext'], [], 'GENESIS6_FIELDS');
  const st = V5.genesisState(gen.v5, {});
  const e = exactFields(gen.ext, ['action', 'approvals'], [], 'GENESIS6_EXT_FIELDS');
  const a = exactFields(e.action, ['v', 'v5ChainId', 'accountId', 'nonce', 'issuedAt', 'body'], [], 'GENESIS6_EXT_ACTION');
  if (a.v !== EXT6_V || a.v5ChainId !== st.chainId || a.accountId !== st.accountId) fail('GENESIS6_EXT_BINDING');
  const b = exactFields(a.body, ['policy', 'gateKeys'], [], 'GENESIS6_EXT_BODY');
  const policy = parsePolicy(b.policy);
  const gateKeys = {};
  for (const [credId, k] of Object.entries(b.gateKeys ?? {})) {
    if (!st.creds[credId]) fail('GATE_KEY_FOR_UNKNOWN_CREDENTIAL', credId);
    exactFields(k, ['gateKeyId', 'spki', 'sensorClass', 'kind', 'pop'], [], 'GATE_KEY_FIELDS');
    if (!['SIMULATED', 'WINBIO_TPM', 'WINBIO_SOFTWARE_KEY'].includes(k.kind)) fail('GATE_KEY_KIND');
    // proof of possession of the gate key, bound to this account / V5 chain / credential
    if (!verifyEs256Obj(V6_DOMAINS.GATE_POP, { accountId: st.accountId, v5ChainId: st.chainId, credId, gateKeyId: k.gateKeyId }, k.pop, k.spki)) fail('GATE_KEY_POP');
    gateKeys[credId] = { gateKeyId: k.gateKeyId, spki: k.spki, sensorClass: k.sensorClass, kind: k.kind };
  }
  for (const c of policy.fingerprintOnlyCreds) if (!st.creds[c]) fail('FINGERPRINT_ONLY_UNKNOWN_CREDENTIAL', c);
  // a fingerprint-only credential without an enrolled gate key is allowed in the policy: it then FAILS CLOSED
  // (FINGERPRINT_ONLY_UNSUPPORTED) for every approval, and the owner keeps the separate ORC / recovery routes.
  const extDigest = d6(V6_DOMAINS.GENESIS_EXT, a);
  const signed = new Set();
  for (const ap of e.approvals ?? []) {
    if (!ap || signed.has(ap.credId)) fail('GENESIS6_APPROVAL');
    const c = st.creds[ap.credId];
    if (c && c.kind === 'passkey') { const r = verifyAssertion(ap.webauthn, { rp: st.rp, expectedChallenge: extDigest, credential: { ...c.webauthn, signCount: c.signCount }, requireUV: true }); c.signCount = r.signCount; }
    else if (c) { if (!edVerifyDigest(V6_DOMAINS.GENESIS_EXT, extDigest, ap.sig, c.publicKey)) fail('GENESIS6_SIGNATURE', ap.credId); }
    else if (st.v4.orcs[ap.credId]) { if (!edVerifyDigest(V6_DOMAINS.GENESIS_EXT, extDigest, ap.sig, st.v4.orcs[ap.credId].publicKey)) fail('GENESIS6_ORC_SIGNATURE'); }
    else fail('GENESIS6_APPROVAL_UNKNOWN');
    signed.add(ap.credId);
  }
  if (signed.size !== Object.keys(st.creds).length + Object.keys(st.v4.orcs).length) fail('GENESIS6_NOT_APPROVED_BY_ALL');
  const chainId = d6hex(V6_DOMAINS.GENESIS, { v5ChainId: st.chainId, ext: extDigest.toString('hex') });
  if (pinnedChainId && chainId !== pinnedChainId) fail('GENESIS_NOT_PINNED');
  st.v5ChainId = st.chainId; st.chainId = chainId;
  st.usedNonces[a.nonce] = 0;
  st.v6 = { protocol: PROTOCOL6, policy, gateKeys, policyDigest: d6hex(V6_DOMAINS.GENESIS_EXT, { policy, gateKeys }) };
  return st;
}

/** Credentials that must present a fingerprint gate with EVERY approval. */
export const fingerprintOnly = (s, credId) => s.v6.policy.fingerprintOnlyCreds.includes(credId);

/** The exact digest an approval's credential signed (V5 Command Statement or V4 Authorization Intent). */
function approvedDigestHex(ap) {
  if (ap && typeof ap === 'object' && ap.command && typeof ap.command === 'object') return commandDigest(ap.command).toString('hex');
  if (ap && typeof ap === 'object' && ap.intent && typeof ap.intent === 'object') return intentDigest(ap.intent).toString('hex');
  return null;
}

/**
 * Gate check for every approval of a transition (runs before the V5 state machine; any failure rejects the whole
 * transition). Returns the approvals with the `gate` field removed, and the per-approval assurance levels.
 */
export function checkGates(s, tr, at) {
  const out = []; const levels = [];
  for (const ap of tr.approvals ?? []) {
    if (!ap || typeof ap !== 'object' || Array.isArray(ap)) { out.push(ap); continue; }
    const { gate, ...rest } = ap;
    const need = typeof ap.credId === 'string' && !s.v4.orcs[ap.credId] && s.creds[ap.credId] && fingerprintOnly(s, ap.credId);
    if (need || gate !== undefined) {
      if (!s.creds[ap.credId] || s.v4.orcs[ap.credId]) fail('GATE_ON_NON_OWNER_CREDENTIAL');
      const dig = approvedDigestHex(ap); const g = ap.grant?.statement;
      if (!dig || !g || typeof g.challengeNonce !== 'string') fail('FINGERPRINT_GATE_NEEDS_BOUND_APPROVAL', 'only command- or intent-bound approvals can carry a gate');
      verifyGate(gate, { accountId: s.accountId, chainId: s.chainId, credId: ap.credId, subject: 'COMMAND', boundDigestHex: dig, challengeNonce: g.challengeNonce,
        notBeforeMs: isoMs(g.issuedAt, 'issuedAt'), notAfterMs: isoMs(g.expiresAt, 'expiresAt'), at, maxAgeMs: Number(s.v6.policy.gateMaxAgeMs), skewMs: Number(s.config.skewMs), gateKeys: s.v6.gateKeys, assurance: s.v6.policy.fingerprintAssurance ?? 'LOCAL_GATE' });
      levels.push(`${ap.credId}:LOCAL_FINGERPRINT_GATE_PASSED`);
    }
    out.push(rest);
  }
  return { approvals: out, levels };
}

export function applyTransition(state0, tr) {
  if (state0.v6?.protocol !== PROTOCOL6) fail('PROTOCOL_MISMATCH');
  exactFields(tr, ['v', 'seq', 'prev', 'at', 'action'], ['approvals', 'guardianApprovals', 'attestation'], 'TRANSITION_FIELDS');
  const at = isoMs(tr.at, 'at');
  // gates are checked against the state the transition starts from (credential set, policy and keys are genesis-pinned)
  const { approvals, levels } = checkGates(state0, tr, at);
  const inner = { ...tr }; if (tr.approvals !== undefined) inner.approvals = approvals;
  const r = V5.applyTransition(state0, inner);
  r.state.head = transitionHash(state0.head, tr); // commit the transition AS STORED (gates included)
  if (levels.length) r.effects.push({ type: 'BIOMETRIC_GATE_ASSURANCE', levels });
  return r;
}

export function replayChain(genesis, transitions, { pinnedChainId }) {
  let st = genesisState(genesis, { pinnedChainId }); const log = [];
  for (const tr of transitions) { const r = applyTransition(st, tr); st = r.state; log.push({ seq: tr.seq, type: tr.action.type, effects: r.effects }); }
  return { state: st, log };
}
export function rootView(st) {
  return { ...V5.rootView(st), protocol6: PROTOCOL6, assurancePolicy: { version: st.v6.policy.version, paymentMode: st.v6.policy.payment.mode, fingerprintOnlyCreds: [...st.v6.policy.fingerprintOnlyCreds],
    gateCreds: Object.keys(st.v6.gateKeys), emergencyOrigin: st.v6.policy.emergency.origin,
    fingerprintAssurance: st.v6.policy.fingerprintAssurance ?? 'LOCAL_GATE', gateKeyProtection: Object.fromEntries(Object.entries(st.v6.gateKeys).map(([c, k]) => [c, gateKeyProtection(k)])) } };
}
export { clone };
