import assert from 'node:assert/strict';
export { buildV5, T0, near } from '../../src/v5/world.mjs';
export const H = 3600_000, D = 24 * H;
export const Y = (c) => (BigInt(c) * 10n ** 22n).toString();
export const ok = (r, m = '') => { assert.equal(r.ok, true, m + ' ' + JSON.stringify(r.error ?? r.code)); return r.result; };
export const deny = (r, code) => {
  assert.equal(r.ok, false, 'expected denial for ' + code);
  const c = `${r.error.code}:${r.error.detail ?? ''}`;
  if (code) assert.match(c, new RegExp(code));
  return r.error;
};
export const GLOBAL = { kind: 'GLOBAL', target: '*' };
export const freezeBy = (w, cred, id = 'h-' + cred) => w.cmd('FREEZE', { freezeId: id, reason: `freeze by ${cred}`, source: 'owner' }, [cred]);
export const holdBy = (w, cred, id, { cls = 'PROVISIONAL_HOLD', scope = GLOBAL, dur = 20 * H, reinforces } = {}) =>
  w.cmd('HOLD_CREATE', { holdId: id, class: cls, scope, reason: `hold by ${cred}`, durationMs: String(dur), ...(reinforces ? { reinforces } : {}) }, Array.isArray(cred) ? cred : [cred]);
export const confirm = (w, cred, id) => w.cmd('HOLD_CONFIRM', { holdId: id, holdDigest: w.holdDigest(id) }, [cred]);
export const release = (w, creds, id, extra = {}) => w.cmd('HOLD_RELEASE', { holdId: id, holdDigest: w.holdDigest(id) }, creds, extra);
export const contest = (w, suspect, holdIds, creds = ['orc-1', 'k3-root-hw'], id = 'c-' + suspect) => w.cmd('CONTEST_PROTECTIVE_HOLD', { contestId: id, holdIds, suspectCredId: suspect, reason: 'stolen key froze my vault' }, creds);
export const status = (w) => Object.fromEntries(Object.values(w.root.state.creds).map(c => [c.credId, c.status]));
export const active = (w) => w.effectiveHolds().map(h => h.holdId).sort();
