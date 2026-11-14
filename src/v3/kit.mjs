// Test/simulation kit: the OWNER-SIDE world (devices, guardians, identity verifiers, registrars, notification channels).
// Everything here lives outside SafeBox: in the OS-isolated deployment it runs in the owner/device principal, never in
// the General Zone. Devices sign only what the scenario's owner intends; the AI never holds any of these keys.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { V3_DOMAINS, newEdSigner, nonce as mkNonce, iso, b64u } from './common/canon.mjs';
import { SoftAuthenticator } from './webauthn/soft-authenticator.mjs';
import { enrollmentChallenge } from './authority/enroll.mjs';
import { defaultPersonalMatrix, defaultMultiAdminMatrix } from './authority/matrix.mjs';
import { ACTION_V, TR_V, DEFAULT_CONFIG, actionDigest, genesisState } from './root/chain.mjs';
import { CAPSULE_V } from './root/capsule.mjs';
import { PAYCAP_V, paycapDigest } from './vault/paycap.mjs';

export const RP = Object.freeze({ rpId: 'safebox.local', origin: 'https://safebox.local' });
export const ACCOUNT = 'vault-alice.mock';
const seedCommit = () => createHash('sha256').update(randomBytes(32)).digest('hex');

/** A device holding ONE credential (passkey or external Ed25519 key). */
export class Device {
  constructor({ credId, role, holderId, channelId, kind, syncProvider = 'none', backupEligible = false, deviceId = null, seedCommitment = null, rp = RP, authenticator = null }) {
    Object.assign(this, { credId, role, holderId, channelId, kind });
    this.rp = rp; // the WebAuthn relying party this device's passkey is scoped to (the owner world sets its own RP)
    this.provenance = { deviceId: deviceId ?? ('dev-' + credId + '-' + randomBytes(3).toString('hex')), seedCommitment: seedCommitment ?? seedCommit(), syncProvider };
    // `authenticator` lets an owner world plug in a different WebAuthn authenticator with the same register/assert API
    // (V6: a bridge to a REAL platform authenticator in a browser). Default: the software authenticator (simulation).
    if (kind === 'passkey') this.auth = authenticator ?? new SoftAuthenticator({ label: credId, backupEligible });
    else this.signer = newEdSigner(credId);
    this.lost = false; // a lost device can no longer sign for the owner (it may be in a thief's hands: see stolenBy)
  }
  enrollment(accountId, context) {
    const e = { credId: this.credId, role: this.role, holderId: this.holderId, channelId: this.channelId, kind: this.kind, provenance: { ...this.provenance } };
    const ch = enrollmentChallenge(accountId, e, context);
    if (this.kind === 'passkey') e.registration = this.auth.register({ ...this.rp, challenge: ch });
    else { e.publicKey = this.signer.publicKey; e.pop = this.signer.signDigest(V3_DOMAINS.ENROLL, ch); }
    return e;
  }
  /** Approve ONE action digest. opts let attack tests forge variants (uv false, wrong origin, ...). */
  approve(dig, opts = {}) {
    if (this.kind === 'passkey') return { credId: this.credId, webauthn: this.auth.assert({ rpId: opts.rpId ?? this.rp.rpId, origin: opts.origin ?? this.rp.origin, challenge: dig, uv: opts.uv ?? true, up: opts.up ?? true, type: opts.type }) };
    return { credId: this.credId, sig: this.signer.signDigest(V3_DOMAINS.ACTION, dig) };
  }
  approvePaycap(dig, opts = {}) {
    if (this.kind === 'passkey') return { credId: this.credId, webauthn: this.auth.assert({ rpId: opts.rpId ?? this.rp.rpId, origin: opts.origin ?? this.rp.origin, challenge: dig, uv: opts.uv ?? true }) };
    return { credId: this.credId, sig: this.signer.signDigest(V3_DOMAINS.PAYCAP, dig) };
  }
}

export function defaultCapsule(t0, over = {}) {
  return { v: CAPSULE_V, purposeId: 'household-shopping', accountId: ACCOUNT, principalId: 'alice', version: '1', policyEpoch: '1',
    statement: 'Pay allow-listed household merchants for owner-requested purchases only.', allowedOperations: ['PAY'], asset: 'NEAR',
    recipients: ['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock'],
    products: [{ sku: 'coffee-beans', recipientId: 'merchant-a.mock', amountYocto: (3n * 10n ** 22n).toString() },
      { sku: 'usb-cable', recipientId: 'merchant-b.mock', amountYocto: (2n * 10n ** 22n).toString() }],
    exactProductsOnly: 'false', perPaymentMaxYocto: (6n * 10n ** 22n).toString(), cumulativeLimitYocto: (10n ** 26n).toString(), dailyLimitYocto: (5n * 10n ** 24n).toString(),
    maxCapabilityTtlMs: String(2 * 3600_000), validFrom: iso(t0 - 60_000), expiresAt: iso(t0 + 400 * 86_400_000), ...over };
}

/**
 * The owner world. profile 'personal': K1/K2 passkeys (DAILY), K3 external key (ROOT), K4 passkey (FREEZE), K5 external
 * key (RECOVERY); 3 guardians, 2 identity verifiers, 1 registrar, owner channels. profile 'multi-admin': 3 admins.
 */
export class OwnerWorld {
  constructor({ t0, profile = 'personal', config = {}, capsule = {}, guardians = 3, devices = null, rp = RP } = {}) {
    this.t0 = t0; this.profile = profile; this.rp = Object.freeze({ rpId: rp.rpId, origin: rp.origin });
    this.channels = {}; this.channelKeys = {};
    const ch = (cid, holderId) => { const k = newEdSigner('ch-' + cid); this.channels[cid] = { publicKey: k.publicKey, holderId }; this.channelKeys[cid] = k; return cid; };
    if (profile === 'personal') {
      ['ch-phone', 'ch-email', 'ch-postal'].forEach(c => ch(c, 'alice'));
      this.devices = devices ?? [
        new Device({ credId: 'k1-phone', role: 'DAILY', holderId: 'alice', channelId: 'ch-phone', kind: 'passkey' }),
        new Device({ credId: 'k2-laptop', role: 'DAILY', holderId: 'alice', channelId: 'ch-email', kind: 'passkey' }),
        new Device({ credId: 'k3-root-hw', role: 'ROOT', holderId: 'alice', channelId: 'ch-postal', kind: 'ed25519' }),
        new Device({ credId: 'k4-freeze', role: 'FREEZE', holderId: 'alice', channelId: 'ch-phone', kind: 'passkey' }),
        new Device({ credId: 'k5-recovery-hw', role: 'RECOVERY', holderId: 'alice', channelId: 'ch-postal', kind: 'ed25519' }),
      ];
    } else {
      for (const h of ['alice', 'bob', 'carol']) ch('ch-' + h, h);
      ch('ch-ops', 'ops');
      this.devices = devices ?? [
        new Device({ credId: 'alice-admin', role: 'ADMIN', holderId: 'alice', channelId: 'ch-alice', kind: 'passkey' }),
        new Device({ credId: 'bob-admin', role: 'ADMIN', holderId: 'bob', channelId: 'ch-bob', kind: 'passkey' }),
        new Device({ credId: 'carol-admin', role: 'ADMIN', holderId: 'carol', channelId: 'ch-carol', kind: 'passkey' }),
        new Device({ credId: 'ops-freeze', role: 'FREEZE', holderId: 'ops', channelId: 'ch-ops', kind: 'passkey' }),
        new Device({ credId: 'ops-recovery', role: 'RECOVERY', holderId: 'ops', channelId: 'ch-ops', kind: 'ed25519' }),
      ];
    }
    for (const d of this.devices) d.rp = this.rp;
    this.guardianKeys = {}; this.guardians = {};
    for (let i = 1; i <= guardians; i++) { const k = newEdSigner('g' + i); this.guardianKeys['g' + i] = k; this.guardians['g' + i] = { publicKey: k.publicKey, holderId: 'guardian-' + i }; }
    this.idvKeys = { 'idv-1': newEdSigner('idv-1'), 'idv-2': newEdSigner('idv-2') };
    this.registrarKeys = { 'reg-gov': newEdSigner('reg-gov') };
    this.serviceKeyPairs = { supervisorFreeze: newEdSigner('sup-freeze'), supervisorRepair: newEdSigner('sup-repair'), notifier: newEdSigner('notifier') };
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.capsule = defaultCapsule(t0, capsule);
    this.matrix = profile === 'personal' ? defaultPersonalMatrix() : defaultMultiAdminMatrix();
  }
  dev(credId) { const d = this.devices.find(x => x.credId === credId); if (!d) throw new Error('no device ' + credId); return d; }
  genesis() {
    const n = mkNonce();
    const action = { v: ACTION_V, type: 'GENESIS', accountId: ACCOUNT, nonce: n, issuedAt: iso(this.t0), body: {
      rp: { ...this.rp }, config: { ...this.config }, matrix: this.matrix, capsule: this.capsule, channels: this.channels,
      credentials: this.devices.map(d => d.enrollment(ACCOUNT, 'genesis:' + n)),
      guardians: this.guardians, identityVerifiers: Object.fromEntries(Object.entries(this.idvKeys).map(([k, v]) => [k, { publicKey: v.publicKey, holderId: k }])),
      registrars: Object.fromEntries(Object.entries(this.registrarKeys).map(([k, v]) => [k, { publicKey: v.publicKey, holderId: k }])),
      serviceKeys: Object.fromEntries(Object.entries(this.serviceKeyPairs).map(([k, v]) => [k, v.publicKey])) } };
    const dig = actionDigest(action);
    const gen = { action, approvals: this.devices.map(d => d.approve(dig)), at: iso(this.t0) };
    this.genesisRecord = gen; this.chainId = dig.toString('hex');
    return gen;
  }
  /** Builds an action header bound to the given root view (epoch, versions). */
  action(view, type, body, { ttlMs = 3600_000, at = null, nonce = null } = {}) {
    const t = at ?? view.now;
    return { v: ACTION_V, type, accountId: ACCOUNT, chainId: view.chainId, epoch: String(view.epoch), matrixVersion: view.matrixVersion, purposeVersion: view.purposeVersion,
      nonce: nonce ?? mkNonce(), issuedAt: iso(t), expiresAt: iso(t + ttlMs), body };
  }
  approvals(action, credIds, opts = {}) { const dig = actionDigest(action); return credIds.map(c => this.dev(c).approve(dig, opts)); }
  guardianSign(action, gid, decision = 'APPROVE') { return this.guardianKeys[gid].signStatement(V3_DOMAINS.GUARDIAN, { actionDigest: actionDigest(action).toString('hex'), decision }); }
  guardianApprovals(action, gids) { return gids.map(g => ({ guardianId: g, sig: this.guardianSign(action, g) })); }
  idvSign(action, idv) { return this.idvKeys[idv].signDigest(V3_DOMAINS.IDENTITY, actionDigest(action)); }
  registrarSign(action, reg) { return this.registrarKeys[reg].signDigest(V3_DOMAINS.OFFICIAL, actionDigest(action)); }
  channelSign(action, cid) { return this.channelKeys[cid].signDigest(V3_DOMAINS.CHANNEL, actionDigest(action)); }
  notifierSign(action) { return this.serviceKeyPairs.notifier.signDigest(V3_DOMAINS.DISPATCH, actionDigest(action)); }
  supervisorFreezeSign(action) { return this.serviceKeyPairs.supervisorFreeze.signDigest(V3_DOMAINS.SUPERVISOR_FREEZE, actionDigest(action)); }
  repairCert(statement) { return { statement, sig: this.serviceKeyPairs.supervisorRepair.signStatement(V3_DOMAINS.REPAIR, statement) }; }

  /** Owner-authorized payment capability (K1 or K2 passkey with user verification). */
  paycap(view, { credId = 'k1-phone', recipientId, amountYocto, sku = '-', taskRef = 'task', ttlMs = 3600_000, uv = true, at = null, over = {} }) {
    const t = at ?? view.now;
    const cap = { v: PAYCAP_V, capId: randomUUID(), accountId: ACCOUNT, chainId: view.chainId, epoch: String(view.epoch), matrixVersion: view.matrixVersion,
      purposeId: this.capsule.purposeId, purposeVersion: view.purposeVersion, operation: 'PAY', recipientId, asset: 'NEAR', amountYocto: String(amountYocto), sku, taskRef,
      nonce: mkNonce(), issuedAt: iso(t), expiresAt: iso(t + ttlMs), ...over };
    return { capability: cap, approval: this.dev(credId).approvePaycap(paycapDigest(cap), { uv }) };
  }
  newDevice(spec) { const d = new Device({ rp: this.rp, ...spec }); this.devices.push(d); return d; }
}

/** Transition envelope helper. */
export function tr(state, at, action, extra = {}) { return { v: TR_V, seq: String(state.seq + 1), prev: state.head, at: iso(at), action, ...extra }; }
export const viewOf = (st, now) => ({ chainId: st.chainId, epoch: st.epoch, matrixVersion: st.matrix.version, purposeVersion: st.purpose.version, now });
export { genesisState };
