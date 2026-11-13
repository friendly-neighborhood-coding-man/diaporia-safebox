// Owner authority simulation (SYNTHETIC keys only). Lives in the Supervisor domain.
// The owner is the only party that can create spending authority: an owner-signed policy
// (standing limits) and owner-signed single-use task capabilities (one per intended payment).
// The owner's issuance log is the independent verifier's ground truth of "authorized".
import { randomUUID } from 'node:crypto';
import { appendFileSync, existsSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { V2_DOMAINS, newSigner, makeSigner } from '../common/crypto.mjs';
import { POLICY_V, CAP_V, REVOKE_V, UNFREEZE_V } from '../sensitive/statements.mjs';

const iso = (t) => new Date(t).toISOString();

export class OwnerSimulator {
  constructor({ principals = ['owner_alice', 'owner_bob'], signers = null, now, logPath = null }) {
    this.now = now; this.logPath = logPath;
    this.signers = signers ?? Object.fromEntries(principals.map(p => [p, newSigner(p)]));
    this.operator = this.signers.__operator ?? newSigner('operator');
    this.issued = new Map();   // capId -> {cap, signed, issuedAtMs}
    this.revoked = new Map();  // capId -> revokedAtMs
    this.policies = new Map(); // policyId -> policy object
  }
  static fromPrivateKeys(map, now, logPath = null) { // { principalId: KeyObject, __operator: KeyObject }
    const signers = Object.fromEntries(Object.entries(map).map(([k, v]) => [k, makeSigner(v, k)]));
    return new OwnerSimulator({ signers, now, logPath });
  }
  #log(r) { if (this.logPath) appendFileSync(this.logPath, JSON.stringify(r) + '\n', { mode: 0o600 }); }
  /** Read-only view of an issuance log written by another supervisor process (same OS principal). */
  static view(logPath) {
    const v = { issued: new Map(), revoked: new Map(), policies: new Map(), offset: 0,
      refresh() {
        // Incremental: read only bytes appended since the last refresh (the log is append-only).
        if (!existsSync(logPath)) return v;
        const size = statSync(logPath).size;
        if (size === v.offset) return v;
        const fd = openSync(logPath, 'r'); const buf = Buffer.alloc(size - v.offset);
        readSync(fd, buf, 0, buf.length, v.offset); closeSync(fd);
        const text = buf.toString('utf8'); const cut = text.lastIndexOf('\n') + 1;
        v.offset += Buffer.byteLength(text.slice(0, cut));
        const lines = text.slice(0, cut).split('\n');
        for (const l of lines) { if (!l) continue; const r = JSON.parse(l);
          if (r.type === 'CAP') v.issued.set(r.cap.capId, { cap: r.cap, issuedAtMs: r.issuedAtMs });
          else if (r.type === 'REVOKE') v.revoked.set(r.capId, r.at);
          else if (r.type === 'POLICY') v.policies.set(r.policy.policyId, r.policy); }
        return v;
      } };
    return v.refresh();
  }
  trustedOwnerKeys() { return Object.fromEntries(Object.entries(this.signers).filter(([k]) => k !== '__operator').map(([k, s]) => [k, s.publicKey])); }
  get operatorKey() { return this.operator.publicKey; }

  policy(principalId, over = {}) {
    const s = this.signers[principalId];
    const t = this.now();
    const p = { v: POLICY_V, policyId: 'pol_' + principalId.replace('owner_', '') + '_1', principalId, ownerKey: s.publicKey, asset: 'NEAR',
      allowedRecipients: ['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock'], maxPerPaymentYocto: '60000000000000000000000',
      maxCumulativeYocto: '25000000000000000000000000', maxPendingCount: '20', maxPendingExposureYocto: '500000000000000000000000',
      maxExecutions: '2000', bufferMs: '600000', maxCapabilityTtlMs: '3600000', validFrom: iso(t - 60_000), expiresAt: iso(t + 26 * 3600_000), ...over };
    p.allowedRecipients = [...p.allowedRecipients].sort();
    this.policies.set(p.policyId, p);
    this.#log({ type: 'POLICY', policy: p });
    return s.sign(V2_DOMAINS.POLICY, p);
  }

  issueCapability({ principalId = 'owner_alice', policyId, recipientId, maxAmountYocto, taskRef, ttlMs = 30 * 60_000, issuedAt, amountMode }) {
    const t = issuedAt ?? this.now();
    const cap = { v: CAP_V, capId: randomUUID(), principalId, policyId: policyId ?? 'pol_' + principalId.replace('owner_', '') + '_1', recipientId, asset: 'NEAR',
      maxAmountYocto, taskRef, issuedAt: iso(t), expiresAt: iso(t + ttlMs), ...(amountMode ? { amountMode } : {}) };
    const signed = this.signers[principalId].sign(V2_DOMAINS.CAPABILITY, cap);
    this.issued.set(cap.capId, { cap, signed, issuedAtMs: t });
    this.#log({ type: 'CAP', cap, issuedAtMs: t });
    return { cap, signed };
  }

  revoke(principalId, capId) {
    this.revoked.set(capId, this.now());
    this.#log({ type: 'REVOKE', capId, at: this.now() });
    return this.signers[principalId].sign(V2_DOMAINS.REVOKE_CAP, { v: REVOKE_V, capId, principalId, issuedAt: iso(this.now()) });
  }

  unfreeze(target, frozenAt, reviewRef) {
    return this.operator.sign(V2_DOMAINS.UNFREEZE, { v: UNFREEZE_V, target, frozenAt: String(frozenAt), reviewRef, issuedAt: iso(this.now()) });
  }
}
