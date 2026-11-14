// Owner authority simulation (SYNTHETIC keys only). Lives in the Supervisor domain.
// The owner is the only party that can create spending authority: an owner-signed policy
// (standing limits) and owner-signed single-use task capabilities (one per intended payment).
// The owner's issuance log is the independent verifier's ground truth of "authorized".
import { randomUUID } from 'node:crypto';
import { closeSync, fstatSync, openSync, readSync, writeSync, constants as C } from 'node:fs';
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
  // Writer side of the issuance log (PR #28 condition on #24): append through one O_NOFOLLOW descriptor, so a symlink
  // planted at logPath is refused (OWNER_LOG_SYMLINK) instead of diverting the issuance record into its target.
  #log(r) {
    if (!this.logPath) return;
    let fd;
    try { fd = openSync(this.logPath, C.O_WRONLY | C.O_APPEND | C.O_CREAT | (C.O_NOFOLLOW ?? 0), 0o600); }
    catch (e) { if (e.code === 'ELOOP') { const err = new Error('OWNER_LOG_SYMLINK'); err.code = 'OWNER_LOG_SYMLINK'; throw err; } throw e; }
    try {
      if (!fstatSync(fd).isFile()) { const err = new Error('OWNER_LOG_NOT_A_FILE'); err.code = 'OWNER_LOG_NOT_A_FILE'; throw err; }
      const buf = Buffer.from(JSON.stringify(r) + '\n'); let off = 0;
      while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    } finally { closeSync(fd); }
  }
  /** Read-only view of an issuance log written by another supervisor process (same OS principal). */
  static view(logPath) {
    const v = { issued: new Map(), revoked: new Map(), policies: new Map(), offset: 0,
      refresh() {
        // Incremental: read only bytes appended since the last refresh (the log is append-only).
        // Open with O_NOFOLLOW and read that descriptor, so a symlink cannot be swapped in
        // between the size check and the read.
        let fd;
        try { fd = openSync(logPath, C.O_RDONLY | C.O_NOFOLLOW); }
        catch (e) {
          if (e.code === 'ENOENT') return v;
          if (e.code === 'ELOOP') { const err = new Error('OWNER_LOG_SYMLINK'); err.code = 'OWNER_LOG_SYMLINK'; throw err; }
          throw e;
        }
        try {
          const st = fstatSync(fd);
          if (!st.isFile()) { const err = new Error('OWNER_LOG_NOT_A_FILE'); err.code = 'OWNER_LOG_NOT_A_FILE'; throw err; }
          if (st.size < v.offset) { const err = new Error('OWNER_LOG_TRUNCATED'); err.code = 'OWNER_LOG_TRUNCATED'; throw err; }
          if (st.size === v.offset) return v;
          const buf = Buffer.alloc(st.size - v.offset);
          let off = 0;
          while (off < buf.length) {
            const n = readSync(fd, buf, off, buf.length - off, v.offset + off);
            if (n === 0) break;
            off += n;
          }
          const text = buf.subarray(0, off).toString('utf8'); const cut = text.lastIndexOf('\n') + 1;
          v.offset += Buffer.byteLength(text.slice(0, cut));
        const lines = text.slice(0, cut).split('\n');
        for (const l of lines) { if (!l) continue; const r = JSON.parse(l);
          if (r.type === 'CAP') v.issued.set(r.cap.capId, { cap: r.cap, issuedAtMs: r.issuedAtMs });
          else if (r.type === 'REVOKE') v.revoked.set(r.capId, r.at);
          else if (r.type === 'POLICY') v.policies.set(r.policy.policyId, r.policy); }
          return v;
        } finally { closeSync(fd); }
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
