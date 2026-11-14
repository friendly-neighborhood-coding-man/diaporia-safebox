// Independent reproducer for the Root handler-dispatch defect (PR #28 §PR #20). MOCK worlds only.
// Usage: node root-dispatch.mjs <repoRoot>
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const R = process.argv[2];
const imp = (p) => import(pathToFileURL(join(R, p)).href);
const NAMES = ['toString', 'constructor', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', '__proto__', '__defineGetter__', '__lookupGetter__', 'tostring', 'constructor.prototype'];
const snap = (s) => ({ seq: s.seq, head: (s.head ?? '').toString?.().slice(0, 16), nonces: Object.keys(s.usedNonces ?? {}).length, epoch: s.epoch });
const out = {};
async function probe(label, w, sub) {
  const rows = [];
  for (const t of [...NAMES, 'PLANTED_ON_PROTO']) {
    const b = snap(w.root.state);
    let r; try { r = await sub(t); } catch (e) { r = { ok: false, error: { code: 'THROW', detail: e.message } }; }
    const a = snap(w.root.state);
    rows.push({ type: t, ok: r.ok, code: r.error?.code ?? null, advanced: JSON.stringify(a) !== JSON.stringify(b), before: b, after: a });
  }
  out[label] = rows;
}
// Planted inherited function (requires prior in-process JS execution; models the "any inherited function" variant).
Object.defineProperty(Object.prototype, 'PLANTED_ON_PROTO', { value: function (s) { if (s && typeof s === 'object' && 'epoch' in s) s.epoch = 99; }, configurable: true, writable: true, enumerable: false });
try {
  const { buildV3 } = await imp('src/v3/world.mjs');
  { const w = buildV3(); await probe('V3', w, (t) => w.submitRaw(t, {})); }
  const { buildV4 } = await imp('src/v4/world.mjs');
  { const w = buildV4(); await probe('V4', w, (t) => w.submitRaw(t, {})); }
  const { buildV5 } = await imp('src/v5/world.mjs');
  { const w = buildV5(); await probe('V5', w, (t) => w.submit({ action: w.action(t, {}) })); }
  const { buildV6 } = await imp('src/v6/world.mjs');
  { const w = buildV6({ fingerprintOnly: ['k2-laptop'] }); await probe('V6', w, (t) => w.submit({ action: w.action(t, {}) })); }
  // Control: a real handler is still reached.
  { const w = buildV5(); const r = await w.submit({ action: w.action('HOLD_EXPIRE', { holdId: 'nope' }) }); out.control_V5_HOLD_EXPIRE = { ok: r.ok, code: r.error?.code }; }
  { const w = buildV6({ fingerprintOnly: ['k2-laptop'] }); const r = await w.submit({ action: w.action('HOLD_EXPIRE', { holdId: 'nope' }) }); out.control_V6_HOLD_EXPIRE = { ok: r.ok, code: r.error?.code }; }
} finally { delete Object.prototype.PLANTED_ON_PROTO; }
const summary = {};
for (const [k, rows] of Object.entries(out)) if (Array.isArray(rows)) summary[k] = { committed: rows.filter(r => r.ok && r.advanced).map(r => r.type), advancedWithoutOk: rows.filter(r => !r.ok && r.advanced).map(r => r.type), epoch99: rows.filter(r => r.after.epoch === 99).map(r => r.type) };
console.log(JSON.stringify({ repo: R, summary, controls: { V5: out.control_V5_HOLD_EXPIRE, V6: out.control_V6_HOLD_EXPIRE }, detail: out }, null, 1));
