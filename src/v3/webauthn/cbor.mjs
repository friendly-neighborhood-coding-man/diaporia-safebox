// Minimal, strict CBOR decoder (RFC 8949 subset) for WebAuthn attestation objects and COSE keys.
// Supports unsigned/negative ints, byte/text strings, arrays, maps, simple false/true/null. Indefinite lengths,
// floats, tags and trailing bytes are rejected. Depth and length are bounded.
import { SafeBoxError } from '../../v1/canonical.mjs';
const bad = (d) => { throw new SafeBoxError('CBOR_INVALID', d); };

export function decodeCbor(buf, { allowTrailing = false } = {}) {
  const b = Buffer.from(buf); let p = 0;
  const need = (n) => { if (p + n > b.length) bad('truncated'); };
  const len = (ai) => {
    if (ai < 24) return ai;
    if (ai === 24) { need(1); return b[p++]; }
    if (ai === 25) { need(2); const v = b.readUInt16BE(p); p += 2; return v; }
    if (ai === 26) { need(4); const v = b.readUInt32BE(p); p += 4; return v; }
    if (ai === 27) { need(8); const v = b.readBigUInt64BE(p); p += 8; if (v > 2n ** 32n) bad('length'); return Number(v); }
    bad('indefinite or reserved length');
  };
  const item = (depth) => {
    if (depth > 8) bad('depth');
    need(1); const ib = b[p++]; const mt = ib >> 5, ai = ib & 31;
    switch (mt) {
      case 0: return len(ai);
      case 1: return -1 - len(ai);
      case 2: { const n = len(ai); need(n); const v = b.subarray(p, p + n); p += n; return Buffer.from(v); }
      case 3: { const n = len(ai); need(n); const v = b.subarray(p, p + n).toString('utf8'); p += n; return v; }
      case 4: { const n = len(ai); if (n > 64) bad('array'); const a = []; for (let i = 0; i < n; i++) a.push(item(depth + 1)); return a; }
      case 5: { const n = len(ai); if (n > 64) bad('map'); const m = new Map(); for (let i = 0; i < n; i++) { const k = item(depth + 1); if (m.has(k)) bad('duplicate key'); m.set(k, item(depth + 1)); } return m; }
      case 7: if (ai === 20) return false; if (ai === 21) return true; if (ai === 22) return null; bad('float/simple');
      default: bad('tag');
    }
  };
  const v = item(0);
  if (!allowTrailing && p !== b.length) bad('trailing bytes');
  return allowTrailing ? { value: v, end: p } : v;
}

// Minimal encoder used only by the software test authenticator.
export function encodeCbor(v) {
  const head = (mt, n) => n < 24 ? Buffer.from([(mt << 5) | n]) : n < 256 ? Buffer.from([(mt << 5) | 24, n]) : n < 65536 ? Buffer.from([(mt << 5) | 25, n >> 8, n & 255]) : (() => { const x = Buffer.alloc(5); x[0] = (mt << 5) | 26; x.writeUInt32BE(n, 1); return x; })();
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (typeof v === 'string') { const s = Buffer.from(v, 'utf8'); return Buffer.concat([head(3, s.length), s]); }
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(encodeCbor)]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [encodeCbor(k), encodeCbor(x)])]);
  if (v === false) return Buffer.from([0xf4]); if (v === true) return Buffer.from([0xf5]); if (v === null) return Buffer.from([0xf6]);
  throw new Error('cbor encode: unsupported');
}
