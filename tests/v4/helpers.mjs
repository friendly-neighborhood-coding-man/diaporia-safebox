import assert from 'node:assert/strict';
export const H = 3600_000, D = 24 * H;
export const Y = (c) => (BigInt(c) * 10n ** 22n).toString();
export const ok = (r, m = '') => { assert.equal(r.ok, true, m + JSON.stringify(r.error ?? r.code)); return r.result; };
export const deny = (r, code) => {
  assert.equal(r.ok, false, 'expected denial for ' + code);
  const c = r.error ? `${r.error.code}:${r.error.detail ?? ''}` : String(r.code);
  if (code) assert.match(c, new RegExp(code));
  assert.doesNotMatch(c, /^FREEZE_ACTIVE/);
  return r.error ?? r;
};
export const cs = (w) => w.root.state.case;
export const last = (w) => w.root.state.caseHistory.at(-1);
