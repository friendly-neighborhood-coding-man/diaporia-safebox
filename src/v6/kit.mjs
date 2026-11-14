// V6 owner-side world: the V5 owner world (simulated devices, ORC, engine, contacts, delegates) plus the owner-signed
// assurance policy, fingerprint-gate devices per credential, and the owner device's per-transaction PAYMENT APPROVAL
// ceremony (Workflow A). Everything here is the OWNER side: the external AI never holds any of it.
import { randomUUID, createHash } from 'node:crypto';
import { iso, nonce as mkNonce } from '../v3/common/canon.mjs';
import { PAYCAP_V, paycapDigest } from '../v3/vault/paycap.mjs';
import { ChallengeService } from '../v4/intent/intent.mjs';
import { intentDigest } from '../v4/intent/intent.mjs';
import { OwnerWorldV5, ACCOUNT, Device } from '../v5/kit.mjs';
import { projectState } from '../v5/root/chain.mjs';
import { buildCommand, commandDigest } from '../v5/root/command.mjs';
import { actionDigest } from '../v3/root/chain.mjs';
import { canon } from '../v3/common/canon.mjs';
import { actionDetailLines, reviewPrepared } from './device/command-review.mjs';
import { highAssuranceGate } from './device/biometric.mjs';
import { V4_DOMAINS, verifyObj } from '../v4/common/v4.mjs';
import { V5_DOMAINS, signDigest5With } from '../v5/common/v5.mjs';
import { V6_DOMAINS, d6, d6hex, DEFAULT_ASSURANCE_POLICY } from './common/v6.mjs';
import { EXT6_V } from './root/chain.mjs';
import { BINDING_V, PAY_ACTION_TYPE, taskRefFor, paymentSummary, summaryDigestOf, requiredAssurance } from './vault/payment-approval.mjs';

export { ACCOUNT, Device };
export { actionDetailLines };
const clonePolicy = (p) => JSON.parse(JSON.stringify(p));

export class OwnerWorldV6 extends OwnerWorldV5 {
  constructor(opts = {}) {
    super(opts);
    this.policy6 = clonePolicy({ ...DEFAULT_ASSURANCE_POLICY, ...(opts.policy6 ?? {}) });
    this.gates = { ...(opts.gates ?? {}) }; // credId -> fingerprint gate device (SimulatedFingerprintGate or a real-device bridge)
    this.gateErrors = [];
    // opt-in real run: the PRIMARY owner's verified security contact becomes the consenting test recipient (Root-pinned
    // through the genesis contact attestations like every other contact); every other contact stays a mock address
    if (opts.ownerRecipient) { const h = this.devices[0].holderId; this.addressBook = { ...this.addressBook, [h]: [String(opts.ownerRecipient)] }; }
  }
  challengeService(now) {
    super.challengeService(now);
    // payment approvals use the SAME Root-pinned challenge issuer key, with its own per-credential rate budget
    this.payChallenge ??= new ChallengeService({ signer: this.issuerSigner, now, maxPerCredPerHour: 240 });
    return this.challenge;
  }
  genesis6() {
    const gen5 = this.genesis5();
    const v5ChainId = this.chainId5;
    const gateKeys = Object.fromEntries(Object.entries(this.gates).map(([credId, g]) => [credId, g.enrollment({ accountId: ACCOUNT, v5ChainId })]));
    const action = { v: EXT6_V, v5ChainId, accountId: ACCOUNT, nonce: mkNonce(), issuedAt: iso(this.t0), body: { policy: this.policy6, gateKeys } };
    const dig = d6(V6_DOMAINS.GENESIS_EXT, action);
    const approvals = this.devices.map(d => d.kind === 'passkey' ? { credId: d.credId, webauthn: d.auth.assert({ ...this.rp, challenge: dig, uv: true }) } : { credId: d.credId, sig: d.signer.signDigest(V6_DOMAINS.GENESIS_EXT, dig) });
    for (const [k, s] of Object.entries(this.orcs)) approvals.push({ credId: k, sig: s.signDigest(V6_DOMAINS.GENESIS_EXT, dig) });
    this.genesis6Record = { v5: gen5, ext: { action, approvals } };
    this.chainId6 = d6hex(V6_DOMAINS.GENESIS, { v5ChainId, ext: dig.toString('hex') });
    return this.genesis6Record;
  }
  fpOnly(credId) { return this.policy6.fingerprintOnlyCreds.includes(credId); }
  /** P0.1: under HIGH_ASSURANCE a same-user gate key can never satisfy fingerprint-only; refuse before prompting the sensor. */
  #highUnavailable(g) { return (this.policy6.fingerprintAssurance ?? 'LOCAL_GATE') !== 'LOCAL_GATE' && !highAssuranceGate({ kind: g.kind }); }
  /** Attach the fingerprint gate to an approval (only on a MATCH; any other outcome discards the approval: fail closed). */
  #gate(ap, { subject, digestHex, nonce, at, display = null }) {
    const g = this.gates[ap.credId];
    if (!g) { this.gateErrors.push({ credId: ap.credId, code: 'FINGERPRINT_ONLY_UNSUPPORTED' }); return null; }
    if (this.#highUnavailable(g)) { this.gateErrors.push({ credId: ap.credId, code: 'FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE' }); return null; }
    try { return { ...ap, gate: g.attest({ accountId: ACCOUNT, chainId: this.chainId6, subject, boundDigestHex: digestHex, challengeNonce: nonce, at, display }) }; }
    catch (e) { this.gateErrors.push({ credId: ap.credId, code: e.code ?? 'BIOMETRIC_FAILED' }); return null; }
  }
  /** V5 command ceremony + fingerprint gate for fingerprint-only credentials. `noGate` models a client that skips it. */
  /** Wrap `decide` so the gate window repeats exactly the text the device itself built and showed (P0.2 display). */
  #shown(opts) { const shown = {}; const decide = opts.decide ?? this.decide; return { shown, opts: { ...opts, decide: (sum, text, ctx) => { shown[ctx?.credId] = String(text); return decide(sum, text, ctx); } } }; }
  approveCommand(state, action, credId, opts = {}) {
    const { shown, opts: o } = this.#shown(opts);
    const ap = super.approveCommand(state, action, credId, o);
    if (!ap || this.orcs[credId] || opts.noGate || !(this.fpOnly(credId) || opts.withGate)) return ap;
    const display = [shown[credId], ...actionDetailLines(action)].filter(Boolean).join('\n') || null;
    return this.#gate(ap, { subject: 'COMMAND', digestHex: commandDigest(ap.command).toString('hex'), nonce: ap.grant.statement.challengeNonce, at: opts.at ?? state.lastAt, display });
  }
  authorize4(state, action, credIds, opts = {}) {
    const { shown, opts: o } = this.#shown(opts);
    const aps = super.authorize4(state, action, credIds, o);
    return aps.map(ap => (!ap?.intent || this.orcs[ap.credId] || opts.noGate || !(this.fpOnly(ap.credId) || opts.withGate)) ? ap
      : this.#gate(ap, { subject: 'COMMAND', digestHex: intentDigest(ap.intent).toString('hex'), nonce: ap.grant.statement.challengeNonce, at: opts.at ?? state.lastAt, display: shown[ap.credId] ?? null })).filter(Boolean);
  }
  /**
   * Owner device, console route: approve a command PREPARED by the SafeBox Owner Console. The device does not trust the
   * page: it rebuilds the Command Statement from its OWN verified Root projection and the issuer-signed grant, refuses
   * any difference (substituted action / scope / statement), shows its own text, lets the human decide, and only then
   * signs (plus the fingerprint gate for fingerprint-only credentials). Returns null on decline / mismatch / gate failure.
   */
  approvePrepared(state, { action, grant, command }, credId, { decide = this.decide, at = null, noGate = false, tamper = null, apc = true } = {}) {
    // one rule for every owner-side path (P0.2 review): the shared reviewer rebuilds and checks the prepared command
    let rv; try { rv = reviewPrepared(state, { action, grant, command }, credId, at ?? state.lastAt); }
    catch (e) { this.gateErrors.push({ credId, code: e.code ?? 'PREPARED_REJECTED' }); return null; }
    const { statement, base, text } = rv;
    const m = this.metrics; m.prompts++; m.byCred[credId] = (m.byCred[credId] ?? 0) + 1;
    if (!decide({ title: action.type, text }, text, { credId, action, via: 'OWNER_CONSOLE' })) { m.declined++; return null; }
    this.onIntent?.(actionDigest(action).toString('hex')); // the human approved THIS action (ground truth for the verifier oracle)
    const st = tamper ? tamper(JSON.parse(JSON.stringify(statement))) ?? statement : statement;
    const dig = commandDigest(st);
    m.gestures++; m.signatures++;
    const d = this.dev(credId);
    let ap = { credId, command: st, grant };
    if (d.kind === 'passkey') { ap.webauthn = d.auth.assert({ ...this.rp, challenge: dig, uv: true }); if (apc && this.apc[credId]) ap.apc = { sig: this.apc[credId].confirm(base, dig.toString('hex')) }; } // protected confirmation shows the Root summary verbatim
    else ap.sig = signDigest5With(d.signer, V5_DOMAINS.COMMAND, dig);
    if (!noGate && this.fpOnly(credId)) ap = this.#gate(ap, { subject: 'COMMAND', digestHex: dig.toString('hex'), nonce: grant.statement.challengeNonce, at: at ?? state.lastAt, display: text });
    return ap;
  }
  /** Owner device: answer a console LOGIN challenge (authorizes nothing; proves possession + UV for a session). */
  loginAssertion(credId, challengeHex, { origin = null, rpId = null, uv = true } = {}) {
    const d = this.dev(credId); const dig = Buffer.from(challengeHex, 'hex');
    // same derivation as the console page: the passkey never signs a raw server-chosen digest at login
    if (d.kind === 'passkey') return { webauthn: d.auth.assert({ rpId: rpId ?? this.rp.rpId, origin: origin ?? this.rp.origin, challenge: createHash('sha256').update(Buffer.concat([Buffer.from('safebox.v6.console-login:'), dig])).digest(), uv }) };
    return { sig: d.signer.signDigest(V6_DOMAINS.SESSION, dig) };
  }
  /**
   * Owner device: per-transaction PAYMENT APPROVAL (Workflow A). Builds everything it shows from its own VERIFIED Root
   * projection, obtains a Root-pinned one-time challenge bound to the request, shows the canonical summary, lets the
   * human decide, runs the fingerprint gate (fingerprint-only credentials), and only then signs the exact capability.
   * Returns null when the human declines or the gate fails (never a weaker approval).
   */
  paymentApproval(rootState, { credId = 'k1-phone', recipientId, amountYocto, asset = 'NEAR', requestId = null, requestDigest = null, memo = null, at, ttlMs = null,
    decide = this.decide, noGate = false, tamper = null } = {}) {
    const s = projectState(rootState, at);
    requestId ??= 'owner-' + randomUUID().slice(0, 18);
    requestDigest ??= d6hex(V6_DOMAINS.PAYMENT_APPROVAL, { ownerInitiated: requestId, recipientId, amountYocto: String(amountYocto), asset });
    const grant = this.payChallenge.issue({ accountId: s.accountId, chainId: s.chainId, actionType: PAY_ACTION_TYPE, actionDigestHex: requestDigest, credId });
    const ttl = Math.min(ttlMs ?? Number(this.policy6.payment.approvalTtlMs), Number(this.policy6.payment.approvalTtlMs));
    const binding = { v: BINDING_V, accountId: s.accountId, chainId: s.chainId, credId, recipientId, asset, amountYocto: String(amountYocto), purposeId: s.purpose.purposeId,
      purposeVersion: s.purpose.version, epoch: String(s.epoch), policyVersion: s.v6.policy.version, requestId, requestDigest, challengeNonce: grant.statement.challengeNonce,
      approvalExpiresAt: iso(at + ttl), summaryDigest: '', assurance: requiredAssurance(s, credId) };
    // the device shows the requester note (UNTRUSTED), the digest covers the canonical Root-derived lines only (P0.2)
    const lines = paymentSummary(s, binding, { memo }); binding.summaryDigest = summaryDigestOf(paymentSummary(s, binding, { memo: null }));
    const m = this.metrics; m.prompts++; m.byCred[credId] = (m.byCred[credId] ?? 0) + 1;
    if (!decide({ title: 'PAYMENT', text: lines.join('\n') }, lines.join('\n'), { credId, binding })) { m.declined++; return null; }
    if (tamper) tamper(binding);
    const cap = { v: PAYCAP_V, capId: randomUUID(), accountId: s.accountId, chainId: s.chainId, epoch: String(s.epoch), matrixVersion: s.matrix.version, purposeId: s.purpose.purposeId,
      purposeVersion: s.purpose.version, operation: 'PAY', recipientId, asset, amountYocto: String(amountYocto), sku: '-', taskRef: taskRefFor(binding), nonce: mkNonce(),
      issuedAt: iso(at), expiresAt: binding.approvalExpiresAt };
    const dig = paycapDigest(cap);
    let gate;
    if (!noGate && (binding.assurance === 'FINGERPRINT_ONLY')) {
      const g = this.gates[credId];
      if (!g) { this.gateErrors.push({ credId, code: 'FINGERPRINT_ONLY_UNSUPPORTED' }); return null; }
      if ((s.v6.policy.fingerprintAssurance ?? 'LOCAL_GATE') !== 'LOCAL_GATE' && !highAssuranceGate(s.v6.gateKeys[credId])) { this.gateErrors.push({ credId, code: 'FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE' }); return null; }
      try { gate = g.attest({ accountId: s.accountId, chainId: s.chainId, subject: 'PAYMENT', boundDigestHex: dig.toString('hex'), challengeNonce: grant.statement.challengeNonce, at, display: lines.join('\n') }); }
      catch (e) { this.gateErrors.push({ credId, code: e.code ?? 'BIOMETRIC_FAILED' }); return null; }
    }
    m.gestures++; m.signatures++;
    const approval = { ...this.dev(credId).approvePaycap(dig, { uv: true }), v6: { binding, grant, ...(gate ? { gate } : {}) } };
    return { capability: cap, approval, summary: lines, assurance: binding.assurance };
  }
}
