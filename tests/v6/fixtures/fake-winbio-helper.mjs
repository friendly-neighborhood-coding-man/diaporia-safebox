// TEST FIXTURE ONLY: emulates the winbio-gate.exe JSON contract with a software key so the Node wrapper and the Root /
// Vault verification can be tested off Windows. FAKE_WINBIO_OUTCOME scripts the "sensor" result. Never a real gate.
import { generateKeyPairSync, createPrivateKey, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
const [cmd, ...a] = process.argv.slice(2); const arg = (k) => a[a.indexOf(k) + 1];
const store = process.env.FAKE_WINBIO_KEYFILE;
const key = () => { if (!existsSync(store)) writeFileSync(store, generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' })); return createPrivateKey(readFileSync(store)); };
// minimal P-256 ECDSA over a precomputed digest (BigInt, test fixture only; deterministic-enough random k)
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn, N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n, A = P - 3n;
const G = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n];
const mod = (a, m) => ((a % m) + m) % m; const inv = (a, m) => { let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return mod(s0, m); };
const add = (p, q) => { if (!p) return q; if (!q) return p; if (p[0] === q[0] && mod(p[1] + q[1], P) === 0n) return null;
  const l = p[0] === q[0] && p[1] === q[1] ? mod((3n * p[0] * p[0] + A) * inv(2n * p[1], P), P) : mod((q[1] - p[1]) * inv(q[0] - p[0], P), P);
  const x = mod(l * l - p[0] - q[0], P); return [x, mod(l * (p[0] - x) - p[1], P)]; };
const mul = (k, p) => { let r = null; while (k) { if (k & 1n) r = add(r, p); p = add(p, p); k >>= 1n; } return r; };
const big = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));
function ecdsaSignDigest(priv, h) {
  const d = big(Buffer.from(priv.export({ format: 'jwk' }).d, 'base64url')); const z = big(h);
  for (;;) { const k = mod(big(randomBytes(32)), N); if (!k) continue; const r = mod(mul(k, G)[0], N); if (!r) continue; const s = mod(inv(k, N) * (z + r * d), N); if (!s) continue;
    return Buffer.concat([Buffer.from(r.toString(16).padStart(64, '0'), 'hex'), Buffer.from(s.toString(16).padStart(64, '0'), 'hex')]); }
}
const out = (o) => { process.stdout.write(JSON.stringify(o) + '\n'); process.exit(o.ok ? 0 : 1); };
if (cmd === 'probe') out({ ok: true, units: 1, systemPoolSession: 'OPENED' });
if (cmd === 'key') { const j = key().export({ format: 'jwk' }); out({ ok: true, kind: 'WINBIO_SOFTWARE_KEY', x: Buffer.from(j.x, 'base64url').toString('hex'), y: Buffer.from(j.y, 'base64url').toString('hex') }); }
if (cmd === 'identify') { const o = process.env.FAKE_WINBIO_OUTCOME ?? 'MATCH'; out(o === 'MATCH' ? { ok: true, result: 'MATCH', unit: 1 } : { ok: false, code: o }); }
if (cmd === 'verify-sign') {
  const o = process.env.FAKE_WINBIO_OUTCOME ?? 'MATCH';
  if (o !== 'MATCH') out({ ok: false, code: o });
  // sign the pre-computed hash: ECDSA over the digest (equivalent to signing the message with SHA-256)
  const h = Buffer.from(arg('--hash'), 'hex');
  const sig = ecdsaSignDigest(key(), h); // ECDSA over the given SHA-256 digest (what CNG NCryptSignHash does)
  if (process.env.FAKE_WINBIO_OLD_HELPER === '1') out({ ok: true, result: 'MATCH', unit: 1, kind: 'WINBIO_SOFTWARE_KEY', sig: sig.toString('hex') }); // pre-confirmation build
  out({ ok: true, result: 'MATCH', unit: 1, kind: 'WINBIO_SOFTWARE_KEY', sig: sig.toString('hex'), ownerConfirmed: true });
}
out({ ok: false, code: 'USAGE' });
