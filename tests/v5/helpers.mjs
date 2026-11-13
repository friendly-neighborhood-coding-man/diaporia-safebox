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
export const scopeOf = (w, { credIds = ['k1-phone'], delegationIds = [], recipients = null, sessionCapYocto = '-' } = {}) => {
  const p = w.root.state.purpose;
  return { credIds, delegationIds, recipients: recipients ?? [...p.recipients], asset: p.asset, purposeId: p.purposeId, purposeVersion: p.version,
    perPaymentMaxYocto: p.perPaymentMaxYocto, dailyLimitYocto: p.dailyLimitYocto, cumulativeLimitYocto: p.cumulativeLimitYocto, sessionCapYocto };
};
export const rapidRequest = (w, by, { id = 'rq-1', scope = null, durationMs = 4 * 3600_000, incidentId = '-', explanation = 'urgent purchases are mine' } = {}) =>
  w.cmd('RAPID_USE_REQUEST', { requestId: id, scope: scope ?? scopeOf(w), delayException: 'REMOVE_ANOMALY_DELAY', durationMs: String(durationMs), explanation, incidentId }, [by]);
export const rapidVote = (w, by, id = 'rq-1', decision = 'APPROVE') => w.cmd('RAPID_USE_APPROVE', { requestId: id, requestDigest: w.root.state.v5.rapid.requests[id].digest, decision }, [by]);
export const rapidActivate = (w, id = 'rq-1') => w.submit({ action: w.action('RAPID_USE_ACTIVATE', { requestId: id, requestDigest: w.root.state.v5.rapid.requests[id].digest }) });
export const burst = async (w, n, { credId = 'k1-phone', step = 60_000, amountYocto } = {}) => { const out = []; for (let i = 0; i < n; i++) { const r = await w.pay({ credId, ...(amountYocto ? { amountYocto } : {}) }); out.push(r); await w.advance(step); } return out; };
