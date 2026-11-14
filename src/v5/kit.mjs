// V5 owner-side world: the V4 devices + ORC, plus the Risk Policy Engine key (an independent deterministic service, not
// an owner key), verified security-notification contacts, delegate (AI agent) keys and the V5 command ceremony.
// approveCommand models the owner's device: fetch a one-time grant, build the Command Statement from a VERIFIED replica
// projection of the Root state, show the deterministic summary, let the human decide, and only then sign.
import { OwnerWorldV4, Device, ACCOUNT, RP, SimulatedProtectedConfirmation } from '../v4/kit.mjs';
import { iso, nonce as mkNonce, canon, newEdSigner } from '../v3/common/canon.mjs';
import { actionDigest } from '../v3/root/chain.mjs';
import { V5_DOMAINS, d5, sha256hex, newSigner5, signDigest5With } from './common/v5.mjs';
import { EXT5_V, V5_DEFAULT_CONFIG, projectState } from './root/chain.mjs';
import { buildCommand, commandDigest } from './root/command.mjs';

export { ACCOUNT, RP, Device, SimulatedProtectedConfirmation };
export const contactRefOf = (address) => sha256hex(Buffer.from('safebox-contact\u0000' + String(address).trim().toLowerCase()));
export const signObj5With = (v3signer, domain, obj) => v3signer.signDigest(domain, Buffer.from(canon(obj)));

export class OwnerWorldV5 extends OwnerWorldV4 {
  constructor(opts = {}) {
    super(opts);
    this.config5 = { ...V5_DEFAULT_CONFIG, ...(opts.config5 ?? {}) };
    this.riskEngine = newSigner5('risk-policy-engine');
    // security-notification contacts (mock addresses on a reserved test domain; never real mailboxes)
    const holders = [...new Set(this.devices.map(d => d.holderId))];
    this.addressBook = opts.addressBook ?? Object.fromEntries(holders.map(h => [h, [`${h}@security.example.test`]]));
    this.delegates = {};
  }
  /** The notification service's verification ceremony (code sent through the MOCK transport and echoed back) yields an attestation. */
  contactAttestations(at) {
    const n = this.serviceKeyPairs.notifier; const out = {};
    for (const [holderId, addrs] of Object.entries(this.addressBook)) out[holderId] = addrs.map(addr => {
      const contactRef = contactRefOf(addr), verifiedAt = iso(at);
      return { contactRef, verifiedAt, sig: signObj5With(n, V5_DOMAINS.CONTACT, { accountId: ACCOUNT, holderId, contactRef, verifiedAt }) };
    });
    return out;
  }
  genesis5() {
    const gen4 = this.genesis4();
    const action = { v: EXT5_V, v4ChainId: this.chainId4, accountId: ACCOUNT, nonce: mkNonce(), issuedAt: iso(this.t0), body: {
      config: this.config5, riskEngine: { id: 'risk-engine', publicKey: this.riskEngine.publicKey }, contacts: this.contactAttestations(this.t0) } };
    const dig = d5(V5_DOMAINS.GENESIS_EXT, action);
    const approvals = this.devices.map(d => d.kind === 'passkey' ? { credId: d.credId, webauthn: d.auth.assert({ ...this.rp, challenge: dig, uv: true }) } : { credId: d.credId, sig: signDigest5With(d.signer, V5_DOMAINS.GENESIS_EXT, dig) });
    for (const [k, s] of Object.entries(this.orcs)) approvals.push({ credId: k, sig: signDigest5With(s, V5_DOMAINS.GENESIS_EXT, dig) });
    this.genesis5Record = { v4: gen4, ext: { action, approvals } };
    this.chainId5 = d5(V5_DOMAINS.GENESIS, { v4ChainId: this.chainId4, ext: dig.toString('hex') }).toString('hex');
    return this.genesis5Record;
  }
  /** Device-side V5 command ceremony for ONE credential (or ORC). Returns null if the human declines. */
  approveCommand(state, action, credId, { decide = this.decide, apc = true, at = null, challenge = null, tamper = null } = {}) {
    const svc = challenge ?? this.challenge;
    const s = projectState(state, at ?? state.lastAt);
    const grant = svc.issue({ accountId: s.accountId, chainId: s.chainId, actionType: action.type, actionDigestHex: actionDigest(action).toString('hex'), credId });
    const party = this.orcs[credId] ? { credId, role: 'ORC', holderId: s.v4.orcs[credId]?.holderId ?? 'alice' } : s.creds[credId];
    const { statement, text } = buildCommand(s, action, grant.statement, party);
    if (tamper) tamper(statement);
    const m = this.metrics; m.prompts++; m.byCred[credId] = (m.byCred[credId] ?? 0) + 1;
    if (!decide({ title: action.type, text }, text, { credId, action })) { m.declined++; return null; }
    m.gestures++; m.signatures++;
    const dig = commandDigest(statement);
    const ap = { credId, command: statement, grant };
    if (this.orcs[credId]) ap.sig = signDigest5With(this.orcSigner(credId), V5_DOMAINS.COMMAND, dig);
    else {
      const d = this.dev(credId);
      if (d.kind === 'passkey') { ap.webauthn = d.auth.assert({ ...this.rp, challenge: dig, uv: true }); if (apc && this.apc[credId]) ap.apc = { sig: this.apc[credId].confirm(text, dig.toString('hex')) }; }
      else ap.sig = signDigest5With(d.signer, V5_DOMAINS.COMMAND, dig);
    }
    return ap;
  }
  authorize5(state, action, credIds, opts = {}) { return credIds.map(c => this.approveCommand(state, action, c, opts)).filter(Boolean); }
  /** V4 intents against the projected state (for V4 operations inside a V5 chain). */
  authorize4(state, action, credIds, opts = {}) { return this.authorize(projectState(state, opts.at ?? state.lastAt), action, credIds, opts); }
  newDelegate(id) { const k = newSigner5('delegate-' + id); this.delegates[id] = k; return k; }
  engineAttest(obj) { return this.riskEngine.signObj(V5_DOMAINS.RISK_ENGINE, obj); }
}

/** Multi-owner profile helper: N admins (distinct humans unless `holders` repeats one), each with a protected-confirmation key. */
export function multiOwnerWorld({ t0, admins = ['alice', 'bob', 'carol'], extraKeys = [] } = {}) {
  const devices = admins.map((h) => new Device({ credId: `${h}-admin`, role: 'ADMIN', holderId: h, channelId: 'ch-' + h, kind: 'passkey' }));
  for (const [credId, holderId] of extraKeys) devices.push(new Device({ credId, role: 'ADMIN', holderId, channelId: 'ch-' + holderId, kind: 'passkey' }));
  devices.push(new Device({ credId: 'ops-freeze', role: 'FREEZE', holderId: 'ops', channelId: 'ch-ops', kind: 'passkey' }));
  devices.push(new Device({ credId: 'ops-recovery', role: 'RECOVERY', holderId: 'ops', channelId: 'ch-ops', kind: 'ed25519' }));
  const w = new OwnerWorldV5({ t0, profile: 'multi-admin', devices, apcCreds: devices.filter(d => d.kind === 'passkey').map(d => d.credId), displays: ['ops-recovery'] });
  // multi-admin channels: one per holder (the V3 constructor only creates alice/bob/carol/ops)
  for (const h of new Set(devices.map(d => d.holderId))) if (!w.channels['ch-' + h]) { const k = newEdSigner('ch-' + h); w.channels['ch-' + h] = { publicKey: k.publicKey, holderId: h }; w.channelKeys['ch-' + h] = k; }
  w.addressBook = Object.fromEntries([...new Set(devices.map(d => d.holderId))].map(h => [h, [`${h}@security.example.test`]]));
  return w;
}
