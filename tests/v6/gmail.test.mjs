// Gmail API transport (users.messages.send, gmail.send scope only) against a FAKE Google endpoint (no network), and the
// V6 outbox's provider-honest delivery states. No real email is sent by these tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GmailTransport, GMAIL_SEND_SCOPE, buildRfc822, loadGmailCredentials } from '../../src/v6/notify/gmail.mjs';
import { DELIVERY } from '../../src/v6/notify/notify6.mjs';
import { buildV6, MIN } from './helpers6.mjs';

const SECRET = 'cs-SUPER-SECRET-xyz', REFRESH = '1//refresh-SECRET-abc', ACCESS = 'ya29.ACCESS-SECRET';
const ENV = { SAFEBOX_ALLOW_REAL_EMAIL: '1' };
/** Fake Google: token endpoint + messages.send. `script` decides responses; every request is recorded. */
function fakeGoogle(script = {}) {
  const calls = [];
  const res = (status, body, headers = {}) => ({ status, json: async () => body, headers: { get: (k) => headers[k.toLowerCase()] ?? null } });
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url.includes('/token')) { const r = script.token?.(calls) ?? [200, { access_token: ACCESS, expires_in: 3599, scope: GMAIL_SEND_SCOPE, token_type: 'Bearer' }]; return res(...r); }
    if (url.includes('/messages/send')) { const r = script.send?.(calls) ?? [200, { id: '18c0ffee0000abcd', threadId: '18c0ffee0000abcd', labelIds: ['SENT'] }]; return res(...r); }
    return res(404, {});
  };
  return { calls, fetchImpl };
}
const mk = (g, o = {}) => new GmailTransport({ clientId: 'cid.apps.googleusercontent.com', clientSecret: SECRET, refreshToken: REFRESH, sender: 'safebox.test@example.com',
  allowedRecipients: ['owner@example.com'], fetchImpl: g.fetchImpl, env: ENV, tokenUrl: 'https://fake/token', apiBase: 'https://fake', ...o });
const MSG = { to: 'owner@example.com', subject: 'SafeBox security alert', text: 'line 1\nline 2', idempotencyKey: 'a'.repeat(64) };

test('G-off-by-default: without SAFEBOX_ALLOW_REAL_EMAIL=1, credentials and an allowlist nothing leaves the process', async () => {
  for (const o of [{ env: {} }, { env: { SAFEBOX_ALLOW_REAL_EMAIL: 'true' } }, { clientSecret: '' }, { refreshToken: undefined }, { allowedRecipients: [] }]) {
    const g = fakeGoogle(); const t = mk(g, o);
    const r = await t.send(MSG); assert.equal(r.status, 'NOT_CONNECTED'); assert.equal(g.calls.length, 0);
  }
  const g = fakeGoogle(); const r = await mk(g).send({ ...MSG, to: 'stranger@example.com' });
  assert.equal(r.error, 'RECIPIENT_NOT_ALLOWLISTED'); assert.equal(g.calls.length, 0);
});

test('G-send: refresh -> messages.send with Bearer + base64url RFC 822; 200 means GMAIL_API_ACCEPTED (not delivered)', async () => {
  const g = fakeGoogle(); const t = mk(g);
  const r = await t.send(MSG);
  assert.equal(r.status, 'ACCEPTED'); assert.equal(r.providerId, 'gmail:18c0ffee0000abcd');
  assert.equal(g.calls.length, 2);
  const tok = new URLSearchParams(g.calls[0].init.body); assert.equal(tok.get('grant_type'), 'refresh_token'); assert.equal(tok.get('refresh_token'), REFRESH);
  const send = g.calls[1]; assert.equal(send.url, 'https://fake/gmail/v1/users/me/messages/send'); assert.equal(send.init.headers.authorization, 'Bearer ' + ACCESS);
  const raw = Buffer.from(JSON.parse(send.init.body).raw, 'base64url').toString();
  assert.match(raw, /^From: safebox\.test@example\.com\r\nTo: owner@example\.com\r\nSubject: SafeBox security alert\r\n/); assert.ok(raw.endsWith('\r\n\r\nline 1\r\nline 2'));
  await t.send(MSG); assert.equal(g.calls.length, 3, 'access token cached');
  const logged = JSON.stringify(t.log) + JSON.stringify(t) + JSON.stringify(r.meta);
  for (const s of [SECRET, REFRESH, ACCESS, 'owner@example.com', 'safebox.test@example.com', '18c0ffee0000abcd']) assert.ok(!logged.includes(s), 'never logged: ' + s.slice(0, 6));
});

test('G-scope: a token whose scope is not exactly gmail.send is refused and nothing is sent (least privilege)', async () => {
  for (const scope of ['https://mail.google.com/', `${GMAIL_SEND_SCOPE} https://www.googleapis.com/auth/gmail.readonly`, '', 'https://www.googleapis.com/auth/gmail.modify']) {
    const g = fakeGoogle({ token: () => [200, { access_token: ACCESS, expires_in: 3599, scope }] });
    const r = await mk(g).send(MSG); assert.equal(r.status, 'AUTH_FAILED'); assert.match(r.error, /SCOPE_NOT_MINIMAL/); assert.equal(g.calls.filter(c => c.url.includes('send')).length, 0);
  }
});

test('G-errors: revoked grant -> AUTH_FAILED; 401 -> one refresh retry; 429/5xx/rateLimit -> TEMPORARY; 400 -> PERMANENT; network -> TEMPORARY', async () => {
  let g = fakeGoogle({ token: () => [400, { error: 'invalid_grant' }] }); let r = await mk(g).send(MSG); assert.equal(r.status, 'AUTH_FAILED'); assert.match(r.error, /invalid_grant/);
  let n = 0; g = fakeGoogle({ send: () => (++n === 1 ? [401, { error: { status: 'UNAUTHENTICATED' } }] : [200, { id: 'x1y2z3w4' }]) }); r = await mk(g).send(MSG); assert.equal(r.status, 'ACCEPTED'); assert.equal(g.calls.filter(c => c.url.includes('/token')).length, 2);
  g = fakeGoogle({ send: () => [401, {}] }); r = await mk(g).send(MSG); assert.equal(r.status, 'AUTH_FAILED');
  for (const [st, body] of [[429, {}], [503, {}], [403, { error: { errors: [{ reason: 'userRateLimitExceeded' }] } }]]) { g = fakeGoogle({ send: () => [st, body] }); assert.equal((await mk(g).send(MSG)).status, 'TEMPORARY_FAILURE', String(st)); }
  for (const [st, body] of [[400, { error: { status: 'INVALID_ARGUMENT' } }], [403, { error: { errors: [{ reason: 'insufficientPermissions' }] } }]]) { g = fakeGoogle({ send: () => [st, body] }); assert.equal((await mk(g).send(MSG)).status, 'PERMANENT_FAILURE'); }
  const t = mk({ fetchImpl: async () => { throw Object.assign(new Error('ECONNRESET'), { name: 'TypeError' }); } }); assert.equal((await t.send(MSG)).status, 'TEMPORARY_FAILURE');
  g = fakeGoogle({ token: () => [503, {}] }); assert.equal((await mk(g).send(MSG)).status, 'TEMPORARY_FAILURE');
});

test('G-headers: CR/LF header injection in recipient/sender is refused; subject is flattened to one ASCII line', () => {
  assert.throws(() => buildRfc822({ from: 'a@x', to: 'b@x\r\nBcc: evil@x', subject: 's', text: 't', idempotencyKey: 'k'.repeat(64) }), /header injection/);
  const raw = buildRfc822({ from: 'a@x', to: 'b@x', subject: 'hi\r\nBcc: evil@x é', text: 't', idempotencyKey: 'k'.repeat(64) });
  assert.match(raw, /^Subject: hi  Bcc: evil@x \?\r$/m); assert.ok(!/^Bcc:/m.test(raw));
});

test('G-credentials: loaded from a file outside the repo; missing / incomplete files are refused', () => {
  const d = mkdtempSync(join(tmpdir(), 'gm-')); const p = join(d, 'gmail.json');
  writeFileSync(p, JSON.stringify({ client_id: 'c', client_secret: 's', refresh_token: 'r', sender: 'x@example.com' })); chmodSync(p, 0o600);
  assert.equal(loadGmailCredentials(p).sender, 'x@example.com');
  writeFileSync(p, JSON.stringify({ client_id: 'c' })); assert.throws(() => loadGmailCredentials(p), /credentials field/);
  assert.throws(() => loadGmailCredentials(null), /no credentials path/);
});

test('G-outbox: incident alert through Gmail -> API_ACCEPTED (inbox NOT verified) -> manual receipt attestation; revoked grant -> REAUTH_REQUIRED, no retry storm', async () => {
  const g = fakeGoogle();
  const w = buildV6({ fingerprintOnly: ['k2-laptop'], transport: mk(g, { allowedRecipients: [] }) });
  // recipients come from the Root-pinned address book; allowlist them for the consenting-test transport
  const addrs = [...w.notify.book.values()].flat().map(x => x.address);
  w.notify.transport = mk(g, { allowedRecipients: addrs });
  for (let i = 0; i < 4; i++) { await w.pay({ credId: 'k1-phone', amountYocto: (1n * 10n ** 22n).toString() }); await w.advance(MIN); }
  const rows = w.notify.outbox().filter(o => o.kind === 'INCIDENT');
  assert.ok(rows.length >= 1); assert.ok(rows.every(o => o.state === 'API_ACCEPTED'));
  const st = w.notify.deliveryStatus(rows[0].id); assert.equal(st.api, DELIVERY.GMAIL_API_ACCEPTED); assert.equal(st.inbox, DELIVERY.INBOX_RECEIPT_NOT_VERIFIED);
  const sent = Buffer.from(JSON.parse(g.calls.find(c => c.url.includes('send')).init.body).raw, 'base64url').toString();
  assert.match(sent, /https:\/\/safebox\.local\/e\/l[0-9a-f]{32}/); assert.ok(sent.includes('This link carries no approval'));
  w.notify.attestReceipt(rows[0].id, { observedAt: w.now(), evidence: 'screenshot-of-inbox' });
  assert.equal(w.notify.deliveryStatus(rows[0].id).inbox, DELIVERY.INBOX_RECEIPT_CONFIRMED);
  assert.throws(() => w.notify.attestReceipt('nope', { observedAt: 1, evidence: 'x' }), /RECEIPT_WITHOUT_ACCEPTANCE|receipt only/);
  // revoked grant: REAUTH_REQUIRED, not retried until the operator re-authenticates
  const g2 = fakeGoogle({ token: () => [400, { error: 'invalid_grant' }] }); w.notify.transport = mk(g2, { allowedRecipients: addrs });
  w.report('DAILY'); await w.advance(MIN);
  const rep = w.notify.outbox().filter(o => o.kind === 'REPORT');
  assert.ok(rep.length && rep.every(o => o.state === 'REAUTH_REQUIRED'));
  const n = g2.calls.length; await w.advance(30 * MIN, 5 * MIN); assert.equal(g2.calls.length, n, 'no retry storm');
  assert.equal(w.notify.deliveryStatus(rep[0].id).api, DELIVERY.SEND_FAILED);
  w.notify.transport = mk(fakeGoogle(), { allowedRecipients: addrs }); assert.ok(w.notify.requeueAfterReauth() >= 1); await w.advance(MIN);
  assert.ok(w.notify.outbox().filter(o => o.kind === 'REPORT').every(o => o.state === 'API_ACCEPTED'));
});

test('G-no-links fallback: linkMode NO_LINKS keeps the V5 "do not use links" text and no URL at all', async () => {
  const w = buildV6({ notifyOpts: { linkMode: 'NO_LINKS' } });
  for (let i = 0; i < 4; i++) { await w.pay({ credId: 'k1-phone', amountYocto: (1n * 10n ** 22n).toString() }); await w.advance(MIN); }
  const row = w.notify.outbox().find(o => o.kind === 'INCIDENT');
  const body = w.notify.messageBody(row.id);
  assert.ok(!/https?:\/\//.test(body)); assert.ok(body.includes('do not use links in emails')); assert.equal(row.locator, null);
});
