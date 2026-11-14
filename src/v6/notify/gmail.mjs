// Gmail API transport for the existing V5 notification outbox (users.messages.send only).
// * OAuth 2.0 with exactly ONE scope: https://www.googleapis.com/auth/gmail.send (send-only: it cannot read, modify or
//   delete mail). A token response that reports any other scope is refused and nothing is sent.
// * OFF by default: sends only when SAFEBOX_ALLOW_REAL_EMAIL=1 AND operator-provided OAuth credentials AND the
//   recipient is on the operator's consenting-recipient allowlist (in addition to the Root-pinned verified contacts
//   the outbox already enforces). Otherwise NOT_CONNECTED and nothing leaves the process.
// * A 200 from messages.send means GMAIL_API_ACCEPTED. It is NOT proof of inbox delivery (spam filtering, bounces and
//   recipient-side rules happen later); inbox receipt is a separate, manually attested state.
// * Secrets (client secret, refresh / access tokens) are held in memory only, never logged, never journaled. Request
//   and response metadata are logged with recipient / subject reduced to hashes and the message id truncated.
import { createHash, randomUUID } from 'node:crypto';
import { openSync, fstatSync, readFileSync, closeSync, constants as FS } from 'node:fs';

export const GMAIL_SEND_SCOPE = 'https://www.googleapis.com/auth/gmail.send';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const API_BASE = 'https://gmail.googleapis.com';
const h16 = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, 16);
const asciiHeader = (s) => String(s).replace(/[\r\n]/g, ' ').replace(/[^\x20-\x7e]/g, '?').slice(0, 200);

export function buildRfc822({ from, to, subject, text, idempotencyKey, domain = 'safebox.local' }) {
  if (/[\r\n]/.test(from + to)) throw Object.assign(new Error('header injection'), { code: 'HEADER_INJECTION' });
  const body = String(text).replace(/\r?\n/g, '\r\n');
  return [`From: ${from}`, `To: ${to}`, `Subject: ${asciiHeader(subject)}`, `Message-ID: <${idempotencyKey.slice(0, 40)}.${randomUUID().slice(0, 8)}@${domain}>`,
    `X-SafeBox-Idempotency-Key: ${idempotencyKey.slice(0, 64)}`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: 8bit', '', body].join('\r\n');
}

/** Loads operator OAuth credentials from a JSON file OUTSIDE the repository: {client_id, client_secret, refresh_token, sender}. */
export function loadGmailCredentials(path) {
  if (!path) throw Object.assign(new Error('no credentials path'), { code: 'GMAIL_CREDENTIALS_MISSING' });
  // CodeQL js/file-system-race: open once and read through the same descriptor (no stat-then-read by path). O_NOFOLLOW
  // where the platform has it (POSIX); a symlinked or non-regular credentials file is refused.
  const fd = openSync(path, FS.O_RDONLY | (FS.O_NOFOLLOW ?? 0) | (FS.O_NONBLOCK ?? 0)); // O_NONBLOCK: a FIFO cannot hang the loader
  let raw;
  try {
    if (!fstatSync(fd).isFile()) throw Object.assign(new Error('credentials path is not a regular file'), { code: 'GMAIL_CREDENTIALS_INVALID' });
    raw = readFileSync(fd, 'utf8');
  } finally { closeSync(fd); }
  const j = JSON.parse(raw);
  for (const k of ['client_id', 'client_secret', 'refresh_token', 'sender']) if (typeof j[k] !== 'string' || !j[k]) throw Object.assign(new Error('credentials field ' + k), { code: 'GMAIL_CREDENTIALS_INVALID' });
  return { clientId: j.client_id, clientSecret: j.client_secret, refreshToken: j.refresh_token, sender: j.sender };
}

export class GmailTransport {
  constructor({ clientId, clientSecret, refreshToken, sender, allowedRecipients = [], fetchImpl = globalThis.fetch, env = process.env, now = () => Date.now(), tokenUrl = TOKEN_URL, apiBase = API_BASE, timeoutMs = 15_000 } = {}) {
    this.kind = 'GMAIL'; this.sender = sender; this.allowed = new Set(allowedRecipients.map(a => String(a).trim().toLowerCase()));
    this.enabled = env.SAFEBOX_ALLOW_REAL_EMAIL === '1' && !!clientId && !!clientSecret && !!refreshToken && !!sender && this.allowed.size > 0;
    Object.defineProperty(this, 'secrets', { value: { clientId, clientSecret, refreshToken }, enumerable: false });
    this.fetch = fetchImpl; this.now = now; this.tokenUrl = tokenUrl; this.apiBase = apiBase; this.timeoutMs = timeoutMs;
    this.token = null; this.log = []; // metadata only
  }
  toJSON() { return { kind: this.kind, enabled: this.enabled, sender: this.sender ? h16(this.sender) : null, allowedRecipients: [...this.allowed].map(h16) }; }
  async #post(url, init) {
    const ac = new AbortController(); const t = setTimeout(() => ac.abort(), this.timeoutMs);
    try { return await this.fetch(url, { ...init, signal: ac.signal }); } finally { clearTimeout(t); }
  }
  async #accessToken(force = false) {
    if (!force && this.token && this.now() < this.token.expiresAt - 60_000) return this.token.value;
    const body = new URLSearchParams({ grant_type: 'refresh_token', client_id: this.secrets.clientId, client_secret: this.secrets.clientSecret, refresh_token: this.secrets.refreshToken });
    let r;
    try { r = await this.#post(this.tokenUrl, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: body.toString() }); }
    catch (e) { const x = new Error('token endpoint unreachable'); x.code = 'TEMPORARY_FAILURE'; x.detail = 'NETWORK_ERROR:' + String(e.name); throw x; }
    let j = {}; try { j = await r.json(); } catch {}
    this.log.push({ at: this.now(), op: 'TOKEN_REFRESH', http: r.status, error: j.error ?? null, scope: j.scope ?? null });
    if (r.status === 400 || r.status === 401) { const e = new Error('reauthentication required'); e.code = 'AUTH_FAILED'; e.detail = String(j.error ?? r.status); throw e; }
    if (r.status >= 500 || r.status === 429) { const e = new Error('token endpoint unavailable'); e.code = 'TEMPORARY_FAILURE'; throw e; }
    if (r.status !== 200 || typeof j.access_token !== 'string') { const e = new Error('token refresh failed'); e.code = 'AUTH_FAILED'; e.detail = String(r.status); throw e; }
    // least privilege: the granted scope set must be exactly gmail.send
    const scopes = String(j.scope ?? '').split(/\s+/).filter(Boolean);
    if (scopes.length !== 1 || scopes[0] !== GMAIL_SEND_SCOPE) { const e = new Error('token scope is not exactly gmail.send'); e.code = 'SCOPE_NOT_MINIMAL'; e.detail = scopes.join(' '); throw e; }
    this.token = { value: j.access_token, expiresAt: this.now() + Number(j.expires_in ?? 3600) * 1000 };
    return this.token.value;
  }
  /** Outbox transport contract: returns {status, providerId?, error?, meta}. Never throws. */
  async send({ to, subject, text, idempotencyKey }) {
    const meta = { at: this.now(), op: 'MESSAGES_SEND', recipient: h16(String(to).toLowerCase()), subject: h16(subject), bytes: Buffer.byteLength(String(text)), idempotencyKey: String(idempotencyKey).slice(0, 16) };
    if (!this.enabled) { this.log.push({ ...meta, outcome: 'NOT_CONNECTED' }); return { status: 'NOT_CONNECTED', error: 'Gmail transport disabled (needs SAFEBOX_ALLOW_REAL_EMAIL=1, OAuth credentials and a consenting recipient allowlist); nothing was sent', meta }; }
    if (!this.allowed.has(String(to).trim().toLowerCase())) { this.log.push({ ...meta, outcome: 'RECIPIENT_NOT_ALLOWLISTED' }); return { status: 'PERMANENT_FAILURE', error: 'RECIPIENT_NOT_ALLOWLISTED', meta }; }
    let raw;
    try { raw = Buffer.from(buildRfc822({ from: this.sender, to, subject, text, idempotencyKey })).toString('base64url'); }
    catch (e) { this.log.push({ ...meta, outcome: e.code }); return { status: 'PERMANENT_FAILURE', error: e.code, meta }; }
    for (let attempt = 0; attempt < 2; attempt++) {
      let token;
      try { token = await this.#accessToken(attempt > 0); }
      catch (e) { this.log.push({ ...meta, outcome: e.code, detail: e.detail ?? null }); return { status: e.code === 'TEMPORARY_FAILURE' ? 'TEMPORARY_FAILURE' : 'AUTH_FAILED', error: e.code + (e.detail ? ':' + e.detail : ''), meta }; }
      let r;
      try { r = await this.#post(`${this.apiBase}/gmail/v1/users/me/messages/send`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ raw }) }); }
      catch (e) { this.log.push({ ...meta, outcome: 'NETWORK_ERROR', detail: String(e.name) }); return { status: 'TEMPORARY_FAILURE', error: 'NETWORK_ERROR', meta }; }
      let j = {}; try { j = await r.json(); } catch {}
      const reason = j?.error?.errors?.[0]?.reason ?? j?.error?.status ?? null;
      const resMeta = { ...meta, http: r.status, reason, retryAfter: r.headers?.get?.('retry-after') ?? null };
      if (r.status === 200 && typeof j.id === 'string') {
        this.log.push({ ...resMeta, outcome: 'GMAIL_API_ACCEPTED', messageId: j.id.slice(0, 6) + '…', labelIds: (j.labelIds ?? []).slice(0, 4) });
        return { status: 'ACCEPTED', providerId: 'gmail:' + j.id, threadRef: j.threadId ? h16(j.threadId) : null, meta: resMeta };
      }
      if (r.status === 401 && attempt === 0) { this.token = null; this.log.push({ ...resMeta, outcome: 'REAUTH_RETRY' }); continue; }
      this.log.push({ ...resMeta, outcome: 'SEND_FAILED' });
      if (r.status === 401) return { status: 'AUTH_FAILED', error: 'HTTP_401', meta: resMeta };
      if (r.status === 429 || r.status >= 500 || (r.status === 403 && /rateLimit|userRateLimit|backendError/i.test(String(reason)))) return { status: 'TEMPORARY_FAILURE', error: `HTTP_${r.status}${reason ? ':' + reason : ''}`, meta: resMeta };
      return { status: 'PERMANENT_FAILURE', error: `HTTP_${r.status}${reason ? ':' + reason : ''}`, meta: resMeta };
    }
    return { status: 'AUTH_FAILED', error: 'HTTP_401', meta };
  }
}
