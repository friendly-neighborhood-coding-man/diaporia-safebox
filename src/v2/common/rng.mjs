// Seeded deterministic PRNG (sfc32 seeded via a SHA-256 of the seed string). Not cryptographic:
// used only for workload scheduling, never for keys or nonces.
import { createHash } from 'node:crypto';

export function makeRng(seed) {
  const h = createHash('sha256').update(String(seed)).digest();
  let a = h.readUInt32LE(0), b = h.readUInt32LE(4), c = h.readUInt32LE(8), d = h.readUInt32LE(12);
  const next = () => {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    const t = (a + b) | 0; a = b ^ (b >>> 9); b = (c + (c << 3)) | 0; c = (c << 21) | (c >>> 11);
    d = (d + 1) | 0; const r = (t + d) | 0; c = (c + r) | 0;
    return (r >>> 0) / 4294967296;
  };
  for (let i = 0; i < 16; i++) next();
  return {
    float: next,
    int(lo, hi) { return lo + Math.floor(next() * (hi - lo + 1)); }, // inclusive
    pick(arr) { return arr[Math.floor(next() * arr.length)]; },
    /** weighted: [[value, weightInt], ...] with integer weights (exact, no float accumulation drift) */
    weighted(table) {
      const total = table.reduce((s, [, w]) => s + w, 0);
      let x = Math.floor(next() * total);
      for (const [v, w] of table) { if (x < w) return v; x -= w; }
      return table[table.length - 1][0];
    },
    hex(nBytes) { let s = ''; for (let i = 0; i < nBytes; i++) s += Math.floor(next() * 256).toString(16).padStart(2, '0'); return s; },
  };
}
