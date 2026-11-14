// V6 Owner Console (Workflow B): the trusted SafeBox page an Emergency Freeze link NAVIGATES to, and the direct-entry
// surface for recovery / sensitive commands. It is a SafeBox-side service: it reads Root (and the Vault's incident
// table), issues Root-pinned one-time challenges, and SUBMITS owner-signed commands to Root. It holds no owner key and
// can authorize nothing by itself: Root re-verifies every command (V5 matrix, holds, quorum) and the V6 fingerprint
// gate. Security properties enforced here (defence in depth; Root is the authority):
//   * GET / HEAD / preview / scanner visits never change any state: every GET handler is read-only, and a link
//     locator only *names* an incident (resolution is read-only, never consumed).
//   * The owner is authenticated independently of the email: a WebAuthn assertion (or hardware-key signature) over a
//     console login challenge, verified against the credential enrolled in Root, for the console's own RP origin.
//   * Every state-changing call is POST + exact Origin + JSON content type + session cookie (HttpOnly, SameSite=Strict)
//     + per-session CSRF token. Cross-site forms, replayed requests and scanner POSTs fail before any side effect.
//   * FREEZE is prepared from TRUSTED state only: the incident must exist in the Vault's incident table (opened by the
//     Risk Engine); scope is always GLOBAL; the exact action, one-time grant and Command Statement are fixed at prepare
//     time and the proposal is single-use, bound to the session and the credential, and expires with the grant.
//   * Confirmation needs an explicit confirm phrase AND a fresh device approval of the exact statement (plus the
//     fingerprint gate for fingerprint-only credentials, enforced by Root). The console then checks that Root AND the
//     Vault replica report the hold (so "frozen" is never claimed from the HTTP response alone).
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { canon, fail, iso, edVerifyDigest } from '../../v3/common/canon.mjs';
import { verifyAssertion } from '../../v3/webauthn/verify.mjs';
import { buildCommand, commandDigest } from '../../v5/root/command.mjs';
import * as V6 from '../root/chain.mjs';
import { V6_DOMAINS, d6 } from '../common/v6.mjs';
import { LOCATOR_RE } from '../notify/notify6.mjs';
import { CONSOLE_PAGE } from './page.mjs';
import { actionDetailLines } from '../kit.mjs';

export const SESSION_V = 'safebox.v6.owner-session';
export const CONFIRM_PHRASE = 'FREEZE EVERYTHING';
/** WebAuthn login challenge = SHA-256(prefix || session-statement digest), derived by the device side (page / kit), so a
 * compromised console API cannot pass a command digest off as a login challenge (review finding 3). */
export const LOGIN_PREFIX = 'safebox.v6.console-login:';
export const loginChallengeOf = (digest) => createHash('sha256').update(Buffer.concat([Buffer.from(LOGIN_PREFIX), Buffer.from(digest)])).digest();
export const emergencyReason = (incidentId, via = 'OWNER_CONSOLE') => `EMERGENCY_FREEZE incident=${incidentId} scope=GLOBAL via=${via}`;
const rid = (p, n = 12) => p + randomBytes(n).toString('hex');
const INCIDENT_RE = /^inc-[0-9a-f]{8,64}$/;
/** Commands the console may PREPARE for direct entry. Root alone decides whether the collected approvals suffice. */
export const DIRECT_COMMANDS = new Set(['HOLD_RELEASE', 'HOLD_CONFIRM', 'SUSPEND', 'UNSUSPEND', 'RAPID_USE_REQUEST', 'RAPID_USE_APPROVE', 'RAPID_USE_END', 'FREEZE']);
const HOLD_BOUND = new Set(['HOLD_RELEASE', 'HOLD_CONFIRM']);

class HttpError extends Error { constructor(status, code, detail = '') { super(code); this.status = status; this.code = code; this.detail = detail; } }
const deny = (status, code, detail) => { throw new HttpError(status, code, detail); };
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };

export class OwnerConsole {
  /**
   * deps: { origin, rootState(), submit(req) -> env, challenge (Root-pinned ChallengeService), buildAction(type, body, opts),
   *         incident(id) -> row|null, incidents() -> rows, locators (IncidentLocators), vaultStatus() -> {frozen, holds}, now() }
   */
  constructor(deps) {
    Object.assign(this, deps);
    if (!/^https?:\/\/[a-z0-9.:-]+$/.test(String(deps.origin))) fail('CONSOLE_ORIGIN_INVALID');
    // the device-local fingerprint gate helper (loopback only); the page may talk to it and to nothing else
    this.gateOrigin = deps.gateOrigin ?? 'http://127.0.0.1:47613';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):[0-9]{2,5}$/.test(this.gateOrigin)) fail('GATE_ORIGIN_NOT_LOOPBACK');
    this.sessionTtlMs = deps.sessionTtlMs ?? 10 * 60_000; this.loginTtlMs = deps.loginTtlMs ?? 120_000;
    this.logins = new Map(); this.sessions = new Map(); this.proposals = new Map(); this.bundles = new Map();
    this.counts = new Map(); // credId -> highest WebAuthn signCount seen by the console (clone / replay signal)
    this.audit = []; // metadata only (no secrets): what was requested, by whom, outcome
  }
  #state() { const s = this.rootState(); return V6.projectState(s, Math.max(this.now(), s.lastAt)); }
  #log(op, outcome, data = {}) { this.audit.push({ at: iso(this.now()), op, outcome, ...data }); }

  // ------------------------------------------------------------------ HTTP-shaped entry point (pure; used by tests and by listen())
  /** req: { method, path, headers (lower-case), body (string) } -> { status, headers, body } */
  async handle(req) {
    const method = String(req.method ?? 'GET').toUpperCase(); const url = new URL(req.path ?? '/', 'http://x'); const p = url.pathname;
    const headers = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY',
      'content-security-policy': `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' ${this.gateOrigin}; frame-ancestors 'none'; form-action 'none'; base-uri 'none'` };
    try {
      if (method === 'GET' || method === 'HEAD') {
        let res;
        if (p === '/' || p === '/app') res = this.#page(null);
        else if (p.startsWith('/e/')) res = this.#page(p.slice(3));
        else if (p === '/api/incident') res = { json: this.#incidentView(this.#session(req, { csrf: false }), url.searchParams) };
        else if (p === '/api/status') res = { json: this.#status(this.#session(req, { csrf: false })) };
        else deny(404, 'NOT_FOUND');
        return this.#reply(res, headers, method === 'HEAD');
      }
      if (method !== 'POST') deny(405, 'METHOD_NOT_ALLOWED');
      this.#postGuards(req);
      let body; try { body = JSON.parse(req.body ?? ''); } catch { deny(400, 'BODY_NOT_JSON'); }
      if (!body || typeof body !== 'object' || Array.isArray(body)) deny(400, 'BODY_NOT_OBJECT');
      if (p === '/api/login/start') return this.#reply({ json: this.#loginStart(body) }, headers);
      if (p === '/api/login/finish') { const r = this.#loginFinish(body); return this.#reply({ json: r.json, cookie: r.cookie }, headers); }
      const sess = this.#session(req, { csrf: true });
      if (p === '/api/logout') { this.sessions.delete(sess.sid); return this.#reply({ json: { ok: true }, cookie: 'sb_sid=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict' }, headers); }
      if (p === '/api/freeze/prepare') return this.#reply({ json: this.#freezePrepare(sess, body) }, headers);
      if (p === '/api/freeze/confirm') return this.#reply({ json: await this.#freezeConfirm(sess, body) }, headers);
      if (p === '/api/command/prepare') return this.#reply({ json: this.#cmdPrepare(sess, body) }, headers);
      if (p === '/api/command/challenge') return this.#reply({ json: this.#cmdChallenge(sess, body) }, headers);
      if (p === '/api/command/sign') return this.#reply({ json: this.#cmdSign(sess, body) }, headers);
      if (p === '/api/command/submit') return this.#reply({ json: await this.#cmdSubmit(sess, body) }, headers);
      deny(404, 'NOT_FOUND');
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 400; const code = e.code ?? 'ERROR';
      this.#log('HTTP', code, { method, path: p.startsWith('/e/') ? '/e/<locator>' : p });
      return { status, headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ ok: false, error: { code, detail: String(e.detail ?? '').slice(0, 160) } }) };
    }
  }
  #reply(res, headers, head = false) {
    const h = { ...headers };
    if (res.cookie) h['set-cookie'] = res.cookie;
    if (res.html !== undefined) { h['content-type'] = 'text/html; charset=utf-8'; return { status: 200, headers: h, body: head ? '' : res.html }; }
    h['content-type'] = 'application/json'; return { status: 200, headers: h, body: head ? '' : JSON.stringify({ ok: true, ...res.json }) };
  }
  /** The page is static: it embeds no incident data, no token and no authority; the locator is only echoed (validated). */
  #page(locator) {
    if (locator !== null && !LOCATOR_RE.test(locator)) return { html: CONSOLE_PAGE({ locator: null, gateOrigin: this.gateOrigin, notice: 'This link is not a valid SafeBox link. Nothing has been changed.' }) };
    return { html: CONSOLE_PAGE({ locator, gateOrigin: this.gateOrigin, notice: null }) };
  }
  #postGuards(req) {
    const h = req.headers ?? {};
    if (!h.origin || h.origin !== this.origin) deny(403, 'ORIGIN_REJECTED', String(h.origin ?? 'none'));
    if (h['sec-fetch-site'] && !['same-origin', 'none'].includes(h['sec-fetch-site'])) deny(403, 'CROSS_SITE_REQUEST');
    if (!/^application\/json(;|$)/.test(String(h['content-type'] ?? ''))) deny(415, 'CONTENT_TYPE_NOT_JSON');
  }
  #session(req, { csrf }) {
    const m = /(?:^|;\s*)sb_sid=([0-9a-f]{64})(?:;|$)/.exec(String(req.headers?.cookie ?? ''));
    const sess = m && this.sessions.get(m[1]);
    if (!sess) deny(401, 'NOT_AUTHENTICATED');
    if (this.now() >= sess.expiresAt) { this.sessions.delete(sess.sid); deny(401, 'SESSION_EXPIRED'); }
    const s = this.#state(); const c = s.creds[sess.credId];
    if (!c || c.status !== 'active' || String(s.epoch) !== sess.epoch) { this.sessions.delete(sess.sid); deny(401, 'SESSION_CREDENTIAL_OR_EPOCH_CHANGED'); }
    if (csrf && !eq(req.headers?.['x-safebox-csrf'] ?? '', sess.csrf)) deny(403, 'CSRF_TOKEN_INVALID');
    return sess;
  }

  // ------------------------------------------------------------------ owner authentication (independent of email)
  #loginStart({ credId }) {
    const s = this.#state(); const c = s.creds[String(credId)];
    if (!c || c.status !== 'active') deny(403, 'LOGIN_CREDENTIAL_NOT_ACTIVE');
    const loginId = rid('lg-'); const t = this.now();
    const statement = { v: SESSION_V, origin: this.origin, accountId: s.accountId, chainId: s.chainId, credId: c.credId, loginId, nonce: randomBytes(32).toString('hex'),
      issuedAt: iso(t), expiresAt: iso(t + this.loginTtlMs), purpose: 'OWNER_CONSOLE_LOGIN_AUTHORIZES_NOTHING' };
    this.logins.set(loginId, { statement, digest: d6(V6_DOMAINS.SESSION, statement), used: false });
    for (const [k, v] of this.logins) if (Date.parse(v.statement.expiresAt) < t) this.logins.delete(k);
    this.#log('LOGIN_START', 'ISSUED', { credId: c.credId });
    return { loginId, statement, challengeHex: this.logins.get(loginId).digest.toString('hex'), kind: c.kind, credentialId: c.webauthn?.credentialId ?? null, rpId: s.rp?.rpId ?? null };
  }
  #loginFinish({ loginId, webauthn, sig }) {
    const L = this.logins.get(String(loginId)); if (!L) deny(403, 'LOGIN_UNKNOWN');
    if (L.used) deny(403, 'LOGIN_ALREADY_USED');
    L.used = true; // single use whatever the outcome
    if (this.now() >= Date.parse(L.statement.expiresAt)) deny(403, 'LOGIN_EXPIRED');
    const s = this.#state(); const c = s.creds[L.statement.credId];
    if (!c || c.status !== 'active') deny(403, 'LOGIN_CREDENTIAL_NOT_ACTIVE');
    if (c.kind === 'passkey') {
      if (!webauthn) deny(403, 'LOGIN_WEBAUTHN_REQUIRED');
      const floor = Math.max(Number(c.signCount ?? 0), this.counts.get(c.credId) ?? 0);
      let r; try { r = verifyAssertion(webauthn, { rp: s.rp, expectedChallenge: loginChallengeOf(L.digest), credential: { ...c.webauthn, signCount: floor }, requireUV: true }); }
      catch (e) { this.#log('LOGIN_FINISH', e.code ?? 'WEBAUTHN_INVALID', { credId: c.credId }); deny(403, e.code ?? 'WEBAUTHN_INVALID'); }
      this.counts.set(c.credId, r.signCount);
    } else {
      if (typeof sig !== 'string' || !edVerifyDigest(V6_DOMAINS.SESSION, L.digest, sig, c.publicKey)) deny(403, 'LOGIN_BAD_SIGNATURE');
    }
    const sid = randomBytes(32).toString('hex'); const csrf = randomBytes(32).toString('hex');
    this.sessions.set(sid, { sid, csrf, credId: c.credId, holderId: c.holderId, role: c.role, epoch: String(s.epoch), createdAt: this.now(), expiresAt: this.now() + this.sessionTtlMs });
    this.#log('LOGIN_FINISH', 'SESSION_OPENED', { credId: c.credId });
    const secure = this.origin.startsWith('https:') ? '; Secure' : '';
    return { json: { csrf, credId: c.credId, role: c.role, expiresAt: iso(this.now() + this.sessionTtlMs) }, cookie: `sb_sid=${sid}; Path=/; HttpOnly; SameSite=Strict${secure}; Max-Age=${Math.floor(this.sessionTtlMs / 1000)}` };
  }

  // ------------------------------------------------------------------ read-only views (trusted state only)
  #incidentPublic(row) {
    if (!row) return null;
    return { incidentId: row.incident_id, state: row.state, riskClass: row.risk_class ?? 'LOW', openedAt: iso(Number(row.opened_at)), affectedCredential: row.cred_id,
      delayedPayments: Number(row.delayed_count ?? 0), triggers: Number(row.triggers ?? 0), reasons: (() => { try { return JSON.parse(row.reasons); } catch { return []; } })() };
  }
  #incidentView(sess, q) {
    let id = q.get('incidentId');
    const loc = q.get('locator');
    if (loc !== null) { const r = this.locators.resolve(loc); if (!r.ok) deny(404, r.code); id = r.incidentId; }
    const s = this.#state();
    const out = { freeze: this.#freezeStatus(s), signedInAs: { credId: sess.credId, role: sess.role } };
    if (id !== null) { if (!INCIDENT_RE.test(id)) deny(400, 'INCIDENT_ID_FORMAT'); const row = this.incident(id); if (!row) deny(404, 'INCIDENT_UNKNOWN'); out.incident = this.#incidentPublic(row); }
    else out.incidents = this.incidents().map(r => this.#incidentPublic(r));
    out.freezeScope = { kind: 'GLOBAL', effect: 'every unsettled payment of this account is held; settled payments cannot be undone; nothing else changes', class: 'PROVISIONAL_HOLD (24 h unless confirmed)' };
    return out;
  }
  #freezeStatus(s) {
    const holds = V6.effectiveHolds(s, this.now()).map(h => ({ holdId: h.holdId, class: h.class, scope: `${h.scope.kind}:${h.scope.target}`, reason: h.reason, expiresAt: h.expiresAt ? iso(Number(h.expiresAt)) : null }));
    return { rootFrozen: !!s.freeze.active, vault: this.vaultStatus(), holds };
  }
  #status(sess) { return { signedInAs: { credId: sess.credId, role: sess.role }, freeze: this.#freezeStatus(this.#state()) }; }

  // ------------------------------------------------------------------ Emergency FREEZE (single-use exact command)
  #freezePrepare(sess, { incidentId, locator }) {
    let id = incidentId ?? null;
    if (locator !== undefined && locator !== null) { const r = this.locators.resolve(String(locator)); if (!r.ok) deny(404, r.code); if (id !== null && id !== r.incidentId) deny(400, 'LOCATOR_INCIDENT_MISMATCH'); id = r.incidentId; }
    if (typeof id !== 'string' || !INCIDENT_RE.test(id)) deny(400, 'INCIDENT_ID_FORMAT');
    const row = this.incident(id); if (!row) deny(404, 'INCIDENT_UNKNOWN', 'no incident with this id was opened by the Risk Engine');
    const action = this.buildAction('FREEZE', { freezeId: rid('ef-', 8), reason: emergencyReason(id), source: 'owner' }, { ttlMs: 10 * 60_000 });
    const prop = this.#challengeFor(sess, action);
    const pid = rid('fp-');
    this.proposals.set(pid, { pid, kind: 'FREEZE', sid: sess.sid, credId: sess.credId, incidentId: id, action, ...prop, state: 'PREPARED' });
    this.#log('FREEZE_PREPARE', 'PREPARED', { credId: sess.credId, incidentId: id, freezeId: action.body.freezeId });
    return { proposalId: pid, incident: this.#incidentPublic(row), scope: 'GLOBAL', action, grant: prop.grant, command: prop.command, text: prop.text, digestHex: prop.digestHex,
      gateRequired: V6.fingerprintOnly(this.#state(), sess.credId), confirmPhrase: CONFIRM_PHRASE, expiresAt: prop.grant.statement.expiresAt, ...this.#credHints(sess.credId) };
  }
  #credHints(credId) { const s = this.#state(); return { credentialId: s.creds[credId]?.webauthn?.credentialId ?? null, rpId: s.rp?.rpId ?? null }; }
  #challengeFor(sess, action) {
    const s = this.#state();
    const grant = this.challenge.issue({ accountId: s.accountId, chainId: s.chainId, actionType: action.type, actionDigestHex: V6.actionDigest(action).toString('hex'), credId: sess.credId });
    const { statement, text } = buildCommand(s, action, grant.statement, s.creds[sess.credId]);
    return { grant, command: statement, text: [text, ...actionDetailLines(action)].join('\n'), digestHex: commandDigest(statement).toString('hex') };
  }
  /** Approval must be for EXACTLY the prepared statement / grant / credential (no substitution). */
  #checkApproval(prop, ap) {
    if (!ap || typeof ap !== 'object') deny(400, 'APPROVAL_REQUIRED');
    if (ap.credId !== prop.credId) deny(403, 'APPROVAL_WRONG_CREDENTIAL');
    if (canon(ap.command ?? null) !== canon(prop.command)) deny(403, 'APPROVAL_NOT_FOR_PREPARED_COMMAND');
    if (canon(ap.grant ?? null) !== canon(prop.grant)) deny(403, 'APPROVAL_NOT_FOR_PREPARED_CHALLENGE');
  }
  async #freezeConfirm(sess, { proposalId, confirm, approval }) {
    const prop = this.proposals.get(String(proposalId)); if (!prop || prop.kind !== 'FREEZE') deny(404, 'PROPOSAL_UNKNOWN');
    if (prop.sid !== sess.sid) deny(403, 'PROPOSAL_NOT_FOR_THIS_SESSION');
    if (prop.state !== 'PREPARED') deny(409, 'PROPOSAL_ALREADY_USED', prop.state);
    if (this.now() >= Date.parse(prop.grant.statement.expiresAt)) { prop.state = 'EXPIRED'; deny(410, 'PROPOSAL_EXPIRED'); }
    if (confirm !== CONFIRM_PHRASE) deny(400, 'EXPLICIT_CONFIRMATION_REQUIRED');
    this.#checkApproval(prop, approval);
    if (this.incident(prop.incidentId) === null) deny(404, 'INCIDENT_UNKNOWN');
    prop.state = 'SUBMITTING'; // single use from here on, whatever Root answers
    const env = await this.submit({ action: prop.action, approvals: [approval] });
    if (!env.ok) { prop.state = 'REJECTED'; this.#log('FREEZE_CONFIRM', env.error.code, { credId: sess.credId }); deny(403, 'ROOT_REJECTED:' + env.error.code, env.error.detail ?? ''); }
    prop.state = 'SUBMITTED';
    const s = this.#state(); const h = s.v5.holds[prop.action.body.freezeId];
    const vault = this.vaultStatus();
    this.#log('FREEZE_CONFIRM', 'ACCEPTED', { credId: sess.credId, seq: env.result.seq, freezeId: prop.action.body.freezeId, vaultFrozen: vault.frozen });
    return { seq: env.result.seq, holdId: prop.action.body.freezeId, holdClass: h?.class ?? null, rootFrozen: !!s.freeze.active, vaultFrozen: !!vault.frozen, vault };
  }

  // ------------------------------------------------------------------ direct entry: recovery / sensitive commands (Root decides quorum)
  #cmdPrepare(sess, { type, body = {} }) {
    if (!DIRECT_COMMANDS.has(type)) deny(400, 'COMMAND_NOT_AVAILABLE_HERE', String(type));
    const b = { ...body };
    const s = this.#state();
    if (HOLD_BOUND.has(type)) { const h = s.v5.holds[String(b.holdId)]; if (!h) deny(404, 'HOLD_UNKNOWN'); b.holdDigest = V6.holdDigest(s, h); }
    if (type === 'FREEZE') { if (String(b.reason ?? '').startsWith('EMERGENCY_FREEZE')) deny(400, 'USE_EMERGENCY_FREEZE_FLOW'); b.source = 'owner'; b.freezeId ??= rid('of-', 8); }
    const action = this.buildAction(type, b, { ttlMs: 30 * 60_000 });
    const bid = rid('cb-');
    this.bundles.set(bid, { bid, action, createdBy: sess.credId, approvals: new Map(), challenges: new Map(), state: 'OPEN', expiresAt: Date.parse(action.expiresAt) });
    this.#log('COMMAND_PREPARE', 'PREPARED', { credId: sess.credId, type });
    return { bundleId: bid, action, actionDigest: V6.actionDigest(action).toString('hex') };
  }
  #bundle(id) { const b = this.bundles.get(String(id)); if (!b) deny(404, 'BUNDLE_UNKNOWN'); if (b.state !== 'OPEN') deny(409, 'BUNDLE_CLOSED', b.state); if (this.now() >= b.expiresAt) { b.state = 'EXPIRED'; deny(410, 'BUNDLE_EXPIRED'); } return b; }
  #cmdChallenge(sess, { bundleId }) {
    const b = this.#bundle(bundleId); const prop = this.#challengeFor(sess, b.action);
    b.challenges.set(sess.credId, { ...prop, credId: sess.credId, sid: sess.sid });
    return { bundleId: b.bid, action: b.action, grant: prop.grant, command: prop.command, text: prop.text, digestHex: prop.digestHex, gateRequired: V6.fingerprintOnly(this.#state(), sess.credId), ...this.#credHints(sess.credId) };
  }
  #cmdSign(sess, { bundleId, approval }) {
    const b = this.#bundle(bundleId); const ch = b.challenges.get(sess.credId);
    if (!ch || ch.sid !== sess.sid) deny(403, 'NO_CHALLENGE_FOR_THIS_SESSION');
    this.#checkApproval(ch, approval);
    b.approvals.set(sess.credId, approval);
    return { bundleId: b.bid, signers: [...b.approvals.keys()] };
  }
  async #cmdSubmit(sess, { bundleId }) {
    const b = this.#bundle(bundleId);
    if (!b.approvals.size) deny(400, 'NO_APPROVALS');
    b.state = 'SUBMITTING';
    const env = await this.submit({ action: b.action, approvals: [...b.approvals.values()] });
    if (!env.ok) { b.state = 'REJECTED'; this.#log('COMMAND_SUBMIT', env.error.code, { type: b.action.type }); deny(403, 'ROOT_REJECTED:' + env.error.code, env.error.detail ?? ''); }
    b.state = 'SUBMITTED';
    this.#log('COMMAND_SUBMIT', 'ACCEPTED', { type: b.action.type, seq: env.result.seq, signers: [...b.approvals.keys()].join('+') });
    return { seq: env.result.seq, type: b.action.type, freeze: this.#freezeStatus(this.#state()) };
  }

  // ------------------------------------------------------------------ real HTTP listener (loopback by default)
  listen({ port = 0, host = '127.0.0.1' } = {}) {
    const srv = createServer(async (req, res) => {
      const chunks = []; let size = 0;
      req.on('data', (c) => { size += c.length; if (size > 64 * 1024) req.destroy(); else chunks.push(c); });
      req.on('end', async () => {
        const out = await this.handle({ method: req.method, path: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
        res.writeHead(out.status, out.headers); res.end(out.body);
      });
    });
    return new Promise((ok) => srv.listen(port, host, () => ok(srv)));
  }
}

/** Wire a console to a V6 world (in-process). */
export function consoleForWorld(w, { origin = w.owner.policy6.emergency.origin, ...rest } = {}) {
  return new OwnerConsole({
    origin, now: w.now, rootState: () => w.root.state, submit: (req) => w.submit(req), challenge: w.owner.challenge,
    buildAction: (type, body, opts) => w.action(type, body, opts),
    incident: (id) => w.vault.store.db.prepare('SELECT * FROM v5_incidents WHERE incident_id=?').get(id) ?? null,
    incidents: () => w.vault.store.db.prepare('SELECT * FROM v5_incidents ORDER BY opened_at DESC LIMIT 20').all(),
    locators: w.notify.locators,
    vaultStatus: () => { const vs = V6.projectState(w.vault.root, Math.max(w.now(), w.vault.root.lastAt)); return { frozen: !!vs.freeze.active, seq: w.vault.root.seq }; },
    ...rest,
  });
}
