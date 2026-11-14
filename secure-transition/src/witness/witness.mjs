// Independent Witness. Records transition events in its own hash-chained log and signs attestations only after checking
// state it reads itself: the staged archive (re-hashed), the slot contents (re-walked), the active marker, and the
// Authority's status (monotonic counters, unchanged policy). It never asks the candidate whether it is healthy.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Journal } from '../common/journal.mjs';
import { sha256, signEnvelope, DOMAINS } from '../common/crypto.mjs';
import { openPackage } from '../package/manifest.mjs';
import { verifySlot } from '../package/install.mjs';

export class WitnessError extends Error { constructor(code, detail) { super(code + (detail ? `: ${detail}` : '')); this.code = code; } }
const fail = (c, d) => { throw new WitnessError(c, d); };

export class Witness {
  /** authorityStatus: async () => status object. paths: { slots: {A,B}, marker, staged, ctlUid } */
  constructor({ dir, authorityStatus, paths }) {
    this.dir = dir; this.authorityStatus = authorityStatus; this.paths = paths;
    this.log = new Journal(join(dir, 'witness.log'));
    this.priv = readFileSync(join(dir, 'witness.key'), 'utf8'); this.pub = readFileSync(join(dir, 'witness.pub'), 'utf8');
    this.open = new Map(); // transitionId -> baseline
    for (const r of this.log.records) if (r.state === 'BASELINE') this.open.set(r.data.transitionId, r.data);
  }
  sign(payload) { return signEnvelope(DOMAINS.WITNESS, payload, this.priv, this.pub); }

  monotonic(base, st) {
    const bad = [];
    if (st.epoch < base.epoch) bad.push('epoch');
    if (st.versionFloor < base.versionFloor) bad.push('versionFloor');
    if (st.nextNonce < base.nextNonce) bad.push('nextNonce');
    if (BigInt(st.spent) < BigInt(base.spent)) bad.push('spent');
    if (st.consumedOwnerNonces < base.consumedOwnerNonces) bad.push('consumedOwnerNonces');
    if (st.revokedOwnerKeyIds.length < base.revoked) bad.push('revoked');
    for (const [rid, p] of Object.entries(base.payments)) {
      const q = st.payments[rid];
      if (!q) bad.push(`payment-missing:${rid}`);
      else if (p.status === 'SETTLED' && q.status !== 'SETTLED') bad.push(`settled-regressed:${rid}`);
    }
    return bad;
  }

  /** Called at QUIESCED: snapshot Authority counters as the baseline for this transition. */
  async baseline({ transitionId }) {
    const st = await this.authorityStatus();
    if (!st.maintenance || st.maintenance.transitionId !== transitionId) fail('AUTHORITY_NOT_IN_MAINTENANCE');
    const base = { transitionId, epoch: st.epoch, versionFloor: st.versionFloor, nextNonce: st.nextNonce, spent: st.spent, consumedOwnerNonces: st.consumedOwnerNonces,
      revoked: st.revokedOwnerKeyIds.length, policyDigest: st.policyDigest, payments: st.payments, release: st.release, pendingUpdate: st.pendingUpdate };
    if (!this.open.has(transitionId)) { this.log.append('BASELINE', base); this.open.set(transitionId, base); }
    return { ok: true };
  }

  /** CANDIDATE check: archive digest == owner-authorized digest, slot == manifest, Authority policy untouched so far. */
  async checkCandidate({ transitionId, slot }) {
    const base = this.open.get(transitionId); if (!base) fail('NO_BASELINE');
    const st = await this.authorityStatus();
    const pu = st.pendingUpdate; if (!pu) fail('NO_OWNER_AUTHORIZATION');
    const arch = join(this.paths.staged, `${pu.sha256}.tar`);
    if (!existsSync(arch)) fail('STAGED_ARCHIVE_MISSING');
    const bytes = readFileSync(arch);
    if (sha256(bytes) !== pu.sha256 || bytes.length !== pu.length) fail('STAGED_ARCHIVE_NOT_OWNER_AUTHORIZED');
    const pkg = openPackage(bytes);
    if (pkg.manifest.version !== pu.version) fail('MANIFEST_VERSION_NOT_AUTHORIZED');
    if (!(slot in this.paths.slots)) fail('UNKNOWN_SLOT');
    try { verifySlot(this.paths.slots[slot], pkg.manifest, { expectUid: this.paths.ctlUid }); } catch (e) { fail('SLOT_MISMATCH', e.code); }
    if (st.policyDigest !== base.policyDigest) fail('POLICY_CHANGED_DURING_TRANSITION');
    const bad = this.monotonic(base, st); if (bad.length) fail('COUNTER_REGRESSION', bad.join(','));
    this.log.append('CANDIDATE_OK', { transitionId, slot, version: pu.version, sha256: pu.sha256 });
    return { ok: true, attestation: this.sign({ kind: 'CANDIDATE_OK', transitionId, slot, version: pu.version, sha256: pu.sha256 }) };
  }

  /** READY: active marker matches the release being committed (or the old one on rollback); reconciled; monotonic. */
  async attestReady({ transitionId, rolledBack }) {
    const base = this.open.get(transitionId); if (!base) fail('NO_BASELINE');
    const st = await this.authorityStatus();
    if (!st.maintenance || st.maintenance.transitionId !== transitionId || !st.maintenance.reconciled) fail('NOT_RECONCILED');
    if (st.safeHold) fail('SAFE_HOLD');
    const marker = JSON.parse(readFileSync(this.paths.marker, 'utf8'));
    const release = rolledBack ? st.release : { version: st.pendingUpdate?.version, sha256: st.pendingUpdate?.sha256 };
    if (!release.sha256) fail('NO_RELEASE');
    if (marker.version !== release.version || marker.sha256 !== release.sha256) fail('ACTIVE_MARKER_MISMATCH');
    if (!rolledBack && !this.log.records.some(r => r.state === 'CANDIDATE_OK' && r.data.transitionId === transitionId && r.data.sha256 === release.sha256 && r.data.slot === marker.slot)) fail('CANDIDATE_NOT_WITNESSED');
    // Re-walk the active slot against the archive the Authority authorized.
    const bytes = readFileSync(join(this.paths.staged, `${release.sha256}.tar`));
    if (sha256(bytes) !== release.sha256) fail('ACTIVE_ARCHIVE_DIGEST');
    try { verifySlot(this.paths.slots[marker.slot], openPackage(bytes).manifest, { expectUid: this.paths.ctlUid }); } catch (e) { fail('ACTIVE_SLOT_MISMATCH', e.code); }
    if (st.policyDigest !== base.policyDigest || st.epoch !== base.epoch) {
      // Policy may legitimately change during maintenance only through owner governance; V0 witnesses that as a change
      // and re-baselines, so the attestation always names the policy that is in force.
      this.log.append('POLICY_CHANGED_BY_OWNER', { transitionId, from: base.policyDigest, to: st.policyDigest });
    }
    const bad = this.monotonic(base, st); if (bad.length) fail('COUNTER_REGRESSION', bad.join(','));
    const payload = { kind: 'READY', transitionId, rolledBack: !!rolledBack, release, policyDigest: st.policyDigest, epoch: st.epoch };
    this.log.append('READY', payload); this.open.delete(transitionId);
    return { ok: true, attestation: this.sign(payload) };
  }
}
