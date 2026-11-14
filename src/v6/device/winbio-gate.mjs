// REAL fingerprint gate (Windows only): wraps tools/winbio-gate/winbio-gate.exe. Same interface as
// SimulatedFingerprintGate (enrollment / attest), so Root, Vault and the console treat both identically; the
// difference is only who decides MATCH: here the physical sensor through WinBioIdentify (current Windows user only).
// The helper signs a SHA-256 hash; this wrapper builds the exact statement and hashes (domain || canonical(statement)),
// which is what verifyEs256Obj checks. Nothing biometric crosses this boundary: only {ok, result, sig} or an error code.
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { canon, fail, iso, b64u } from '../../v3/common/canon.mjs';
import { V6_DOMAINS, GATE_METHOD } from '../common/v6.mjs';
import { GATE_V } from './biometric.mjs';

const hashOf = (domain, obj) => createHash('sha256').update(Buffer.concat([Buffer.from(domain), Buffer.from(canon(obj))])).digest('hex');
const KNOWN = new Set(['BIOMETRIC_NO_MATCH', 'BIOMETRIC_TIMEOUT', 'BIOMETRIC_LOCKOUT', 'BIOMETRIC_CANCELLED', 'FINGERPRINT_ONLY_UNSUPPORTED']);

export class WinBioGate {
  constructor({ credId, exe, keyName = 'SafeBoxGate-' + credId, gateKeyId = 'winbio-' + credId, timeoutS = 30, onPrompt = null } = {}) {
    Object.assign(this, { credId, exe, keyName, gateKeyId, timeoutS, onPrompt }); this.kind = null; this.log = [];
  }
  #run(args, timeoutMs = 15_000) {
    let out;
    const [cmd, ...pre] = Array.isArray(this.exe) ? this.exe : [this.exe];
    try { out = execFileSync(cmd, [...pre, ...args], { timeout: timeoutMs, windowsHide: false, stdio: ['ignore', 'pipe', 'inherit'] }).toString(); }
    catch (e) { out = e.stdout?.toString() ?? ''; if (!out) fail('FINGERPRINT_ONLY_UNSUPPORTED', 'helper did not answer: ' + String(e.code ?? e.message).slice(0, 60)); }
    let j; try { j = JSON.parse(out.trim().split('\n').at(-1)); } catch { fail('FINGERPRINT_ONLY_UNSUPPORTED', 'helper output'); }
    return j;
  }
  probe() { return this.#run(['probe']); }
  publicKey() {
    const j = this.#run(['key', '--name', this.keyName]);
    if (!j.ok) fail('FINGERPRINT_ONLY_UNSUPPORTED', j.code);
    const k = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64u(Buffer.from(j.x, 'hex')), y: b64u(Buffer.from(j.y, 'hex')) }, format: 'jwk' });
    this.kind = j.kind; return { spki: b64u(k.export({ format: 'der', type: 'spki' })), kind: j.kind };
  }
  #sign(hashHex, purpose) {
    this.onPrompt?.(purpose);
    const j = this.#run(['verify-sign', '--name', this.keyName, '--hash', hashHex, '--timeout', String(this.timeoutS)], (this.timeoutS + 10) * 1000);
    this.log.push({ purpose, ok: !!j.ok, code: j.code ?? null, hr: j.hr ?? null });
    if (!j.ok) fail(KNOWN.has(j.code) ? j.code : 'FINGERPRINT_ONLY_UNSUPPORTED', j.code + (j.hr ? ' ' + j.hr : ''));
    if (j.result !== 'MATCH' || !/^[0-9a-f]{128}$/.test(j.sig)) fail('FINGERPRINT_ONLY_UNSUPPORTED', 'helper result');
    return b64u(Buffer.from(j.sig, 'hex'));
  }
  /** Genesis enrollment: proof of possession, itself gated by a real fingerprint MATCH. */
  enrollment({ accountId, v5ChainId }) {
    const { spki, kind } = this.publicKey();
    const pop = this.#sign(hashOf(V6_DOMAINS.GATE_POP, { accountId, v5ChainId, credId: this.credId, gateKeyId: this.gateKeyId }), 'ENROLL_GATE_KEY');
    return { gateKeyId: this.gateKeyId, spki, sensorClass: 'WINBIO_SYSTEM_POOL', kind, pop };
  }
  attest({ accountId, chainId, subject, boundDigestHex, challengeNonce, at }) {
    const statement = { v: GATE_V, accountId, chainId, credId: this.credId, gateKeyId: this.gateKeyId, method: GATE_METHOD, result: 'MATCH', subject,
      boundDigest: boundDigestHex, challengeNonce, verifiedAt: iso(at), sensorClass: 'WINBIO_SYSTEM_POOL' };
    return { statement, sig: this.#sign(hashOf(V6_DOMAINS.BIOMETRIC_GATE, statement), subject + ' ' + boundDigestHex.slice(0, 16)) };
  }
}
