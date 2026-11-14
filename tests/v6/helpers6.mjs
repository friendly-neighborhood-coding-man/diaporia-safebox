// V6 test helpers: a V6 world with a fingerprint-only laptop credential, an incident, and an Owner Console client.
import { createHash } from 'node:crypto';
import { buildV6 } from '../../src/v6/world.mjs';
import { consoleForWorld, CONFIRM_PHRASE } from '../../src/v6/emergency/console.mjs';
export { buildV6, consoleForWorld, CONFIRM_PHRASE };
export { ok, deny, H, D, Y, burst } from '../v5/helpers.mjs';
export const MIN = 60_000;

/** V6 world (k2-laptop fingerprint-only) with one Risk-Engine incident on k1-phone and its emailed locator. */
export async function incidentWorld(opts = {}) {
  const w = buildV6({ fingerprintOnly: ['k2-laptop'], ...opts });
  for (let i = 0; i < 4; i++) { await w.pay({ credId: 'k1-phone', amountYocto: (1n * 10n ** 22n).toString() }); await w.advance(MIN); }
  const row = w.notify.outbox().find(o => o.kind === 'INCIDENT' && o.locator);
  return { w, incidentId: row?.incident, locator: row?.locator, outboxId: row?.id };
}

/** Console client (cookie jar + CSRF), speaking the console's HTTP-shaped interface. */
export function client(c, { origin = c.origin } = {}) {
  const k = { cookie: '', csrf: '' };
  k.get = async (path, headers = {}) => { const r = await c.handle({ method: 'GET', path, headers: { cookie: k.cookie, ...headers } }); return { ...r, json: r.headers['content-type']?.startsWith('application/json') && r.body ? JSON.parse(r.body) : null }; };
  k.raw = (method, path, body, headers = {}) => c.handle({ method, path, headers: { origin, 'content-type': 'application/json', cookie: k.cookie, ...(k.csrf ? { 'x-safebox-csrf': k.csrf } : {}), ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  k.post = async (path, body, headers = {}) => { const r = await k.raw('POST', path, body, headers); if (r.headers['set-cookie']) k.cookie = r.headers['set-cookie'].split(';')[0]; return JSON.parse(r.body); };
  k.login = async (w, credId, assertOpts = {}) => {
    const st = await k.post('/api/login/start', { credId }); if (!st.ok) return st;
    const fin = await k.post('/api/login/finish', { loginId: st.loginId, ...w.owner.loginAssertion(credId, st.challengeHex, assertOpts) });
    if (fin.ok) k.csrf = fin.csrf; return fin;
  };
  /** Full emergency freeze: prepare -> device approves the exact statement -> confirm. */
  k.freeze = async (w, credId, { incidentId, locator, approve = {}, confirm = CONFIRM_PHRASE } = {}) => {
    const pr = await k.post('/api/freeze/prepare', { ...(incidentId ? { incidentId } : {}), ...(locator ? { locator } : {}) }); if (!pr.ok) return { pr };
    const ap = w.owner.approvePrepared(w.root.state, pr, credId, { at: w.now(), ...approve });
    if (!ap) return { pr, ap };
    return { pr, ap, cf: await k.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm, approval: ap }) };
  };
  k.command = async (w, type, body, signers) => {
    const cp = await k.post('/api/command/prepare', { type, body }); if (!cp.ok) return cp;
    for (const { cl, credId } of signers) {
      const ch = await cl.post('/api/command/challenge', { bundleId: cp.bundleId }); if (!ch.ok) return ch;
      const ap = w.owner.approvePrepared(w.root.state, ch, credId, { at: w.now() }); if (!ap) return { ok: false, error: { code: 'DEVICE_REFUSED' } };
      const sg = await cl.post('/api/command/sign', { bundleId: cp.bundleId, approval: ap }); if (!sg.ok) return sg;
    }
    return k.post('/api/command/submit', { bundleId: cp.bundleId });
  };
  return k;
}

/** Digest of every piece of security state (Root chain, Vault DB rows, outbox, locators, console proposals/sessions). */
export function stateDigest(w, c) {
  const db = w.vault.store.db; const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all().map(r => r.name);
  const vault = tables.map(t => [t, db.prepare(`SELECT * FROM "${t}"`).all()]);
  const ndb = w.notify.db; const nt = ndb.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all().map(r => r.name);
  const notify = nt.map(t => [t, ndb.prepare(`SELECT * FROM "${t}"`).all()]);
  const consoleState = c ? { proposals: [...c.proposals.values()].map(p => [p.pid, p.state]), sessions: c.sessions.size, bundles: c.bundles.size } : null;
  return createHash('sha256').update(JSON.stringify({ head: w.root.state.head, seq: w.root.state.seq, vault, notify, consoleState }, (k, v) => typeof v === 'bigint' ? String(v) : v)).digest('hex');
}
