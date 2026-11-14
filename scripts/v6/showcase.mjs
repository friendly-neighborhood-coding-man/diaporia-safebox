#!/usr/bin/env node
// SafeBox V6 reproducible showcase runner: the main demo (Workflow A + Workflow B) and 10 attack clips, executed LIVE
// against the real code (MCP gateway, Root, Vault, Risk Engine, outbox, Owner Console, V6 verifier), recorded with
// Playwright (Chromium) and converted to MP4 with ffmpeg. Every on-screen line is an event emitted by the run itself.
//
//   node scripts/v6/showcase.mjs                       # MOCK: mock ledger, simulated devices, mock email
//   node scripts/v6/showcase.mjs --no-video            # same, traces only
//   SAFEBOX_ALLOW_REAL_EMAIL=1 node scripts/v6/showcase.mjs --real-gmail --gmail-creds <file outside repo> --to <consenting address>
//
// Labels are derived from what actually ran: MOCK LEDGER always; SIMULATED DEVICE whenever the WebAuthn authenticator is
// Chromium's virtual authenticator or the soft authenticator and the fingerprint gate is the simulated gate; REAL GMAIL
// only when the Gmail API accepted the alert; FINGERPRINT ONLY NOT PROVEN while the gate is simulated; NOT RUN for
// anything that did not run. The browser's WebAuthn credential is the SAME key Root enrolled (injected into Chromium's
// virtual authenticator over CDP): this is protocol-real but NOT a hardware or biometric proof.
import { createRequire } from 'node:module';
import { consoleGate } from '../../src/v6/device/gate-service.mjs';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdirSync, existsSync, writeFileSync, readdirSync, readFileSync, renameSync, rmSync, statSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const IX = join(REPO, 'integrations/external-interactor');
const argv = process.argv.slice(2); const flag = (k) => argv.includes(k); const opt = (k, d = null) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
const VIDEO = !flag('--no-video'); const REAL_GMAIL = flag('--real-gmail');
const PORT = Number(opt('--port', '47610')), VIEW = PORT + 1, GATE = PORT + 3, EVIL = PORT + 4;
const ORIGIN = `http://localhost:${PORT}`, GATE_ORIGIN = `http://127.0.0.1:${GATE}`, EVIL_ORIGIN = `http://127.0.0.1:${EVIL}`;
const stamp = new Date().toISOString().replace(/[:.]/g, '').slice(0, 15) + 'Z';
const OUT = resolve(opt('--out', join(REPO, 'docs/evidence/v6/showcase', stamp + (REAL_GMAIL ? '-real-gmail' : '-mock'))));
if (existsSync(OUT)) { console.error('refusing to overwrite existing evidence directory ' + OUT); process.exit(2); }
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, VIDEO ? ms : 0));
const sha = (b) => createHash('sha256').update(b).digest('hex');

// ------------------------------------------------------------------ build the interactor dist if needed, load modules
if (!existsSync(join(IX, 'dist/harness/mockWorld.js'))) execFileSync('npm', ['run', 'build'], { cwd: IX, stdio: 'inherit' });
const { startHarness } = await import(pathToFileURL(join(IX, 'dist/harness/mockWorld.js')).href);
const { call, callError, mcpClient, obtainTokens } = await import(pathToFileURL(join(IX, 'dist/harness/client.js')).href);
const { consoleForWorld, CONFIRM_PHRASE, emergencyReason } = await import('../../src/v6/emergency/console.mjs');
const { verifyWorld6 } = await import('../../src/v6/supervisor/verifier.mjs');
const { GmailTransport, loadGmailCredentials } = await import('../../src/v6/notify/gmail.mjs');
const { termSafe } = await import('../../src/v6/common/term.mjs');
const { MockTransport } = await import('../../src/v5/notify/notify.mjs');
const { LABELS } = await import('../../src/v6/common/v6.mjs');
let chromium = null;
if (VIDEO) { try { ({ chromium } = createRequire(import.meta.url)('playwright')); } catch { console.error('playwright not available: use --no-video'); process.exit(2); } }
const ffmpeg = (() => { for (const p of ['ffmpeg', '/usr/bin/ffmpeg']) { try { execFileSync(p, ['-version'], { stdio: 'ignore' }); return p; } catch { /* next */ } } return null; })();

// ------------------------------------------------------------------ transport (mock by default; real Gmail strictly opt-in)
let transport = new MockTransport(); let realTo = null;
if (REAL_GMAIL) {
  if (process.env.SAFEBOX_ALLOW_REAL_EMAIL !== '1') { console.error('NOT_RUN: --real-gmail needs SAFEBOX_ALLOW_REAL_EMAIL=1'); process.exit(3); }
  realTo = opt('--to'); const credPath = opt('--gmail-creds');
  if (!realTo || !credPath) { console.error('NOT_RUN: --real-gmail needs --gmail-creds <file> and --to <consenting recipient>'); process.exit(3); }
  if (resolve(credPath).startsWith(REPO)) { console.error('NOT_RUN: credentials must live outside the repository'); process.exit(3); }
  transport = new GmailTransport({ ...loadGmailCredentials(credPath), allowedRecipients: [realTo] });
  if (!transport.enabled) { console.error('NOT_RUN: Gmail transport not enabled'); process.exit(3); }
}

// ------------------------------------------------------------------ world: interactor harness with V6 worlds
const POLICY6 = { emergency: { origin: ORIGIN, locatorTtlMs: String(72 * 3600_000) } };
const h = await startHarness({ v6: { fingerprintOnly: ['k2-laptop'], rp: { rpId: 'localhost', origin: ORIGIN }, policy6: POLICY6, transport, ...(realTo ? { ownerRecipient: realTo } : {}) } });
const w = h.worlds['sbx-alice']; const dev = h.devices['sbx-alice'];
const c = consoleForWorld(w, { gateOrigin: GATE_ORIGIN });
const consoleSrv = await c.listen({ port: PORT, host: '127.0.0.1' });

// ------------------------------------------------------------------ event bus + narration viewer
const events = []; let clip = 'main';
const labelsUsed = new Set([LABELS.MOCK_LEDGER, LABELS.SIMULATED_DEVICE, LABELS.FINGERPRINT_ONLY_NOT_PROVEN]);
function ev(kind, text, data = undefined) {
  const e = { n: events.length, clip, at: new Date().toISOString(), mockTime: new Date(w.now()).toISOString(), kind, text, ...(data !== undefined ? { data } : {}) };
  // CodeQL js/log-injection: event text can carry request-derived strings (memo, subject, hold reason). The terminal
  // line is one line per event: CR/LF and other control characters are made visible, never interpreted.
  events.push(e); console.log(`[${clip}] ${kind.padEnd(7)} ${termSafe(text)}`); return e;
}
const VIEWER = (id) => `<!DOCTYPE html><html><head><meta charset="utf-8"><title>SafeBox showcase</title><style>
body{margin:0;font:15px/1.4 ui-monospace,Menlo,Consolas,monospace;background:#0f1419;color:#d6dde6}
header{padding:12px 18px;background:#18212b;border-bottom:1px solid #2b3846}h1{font:600 18px system-ui;margin:0 0 6px}
.l{display:inline-block;font:600 12px system-ui;padding:3px 8px;border-radius:5px;margin-right:6px;background:#2d3b4a;color:#fff}.l.warn{background:#7a5600}.l.no{background:#5a2020}
#log{padding:10px 18px}.e{padding:3px 0;border-bottom:1px solid #1c2630;white-space:pre-wrap}.k{display:inline-block;width:76px;color:#7fa7c9}
.ok .k{color:#7bd88f}.deny .k{color:#ff8a80}.ai .k{color:#c7a6ff}.owner .k{color:#ffd479}.root .k{color:#80deea}.mail .k{color:#f48fb1}.t{color:#5c6b7a;font-size:12px}
</style></head><body><header><h1 id="title"></h1><div id="labels"></div></header><div id="log"></div><script>
const id=${JSON.stringify(id)};let seen=-1;
async function tick(){const r=await fetch('/events?clip='+encodeURIComponent(id)+'&after='+seen).then(r=>r.json());
document.getElementById('title').textContent=r.title;document.getElementById('labels').innerHTML=r.labels.map(l=>'<span class="l '+(l.includes('NOT')?'no':l.includes('PIN')?'warn':'')+'">'+l+'</span>').join('');
for(const e of r.events){seen=e.n;const d=document.createElement('div');d.className='e '+e.kind.toLowerCase();d.innerHTML='<span class="k">'+e.kind+'</span>'+e.text.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))+' <span class="t">mock '+e.mockTime.slice(11,19)+'</span>';document.getElementById('log').appendChild(d);window.scrollTo(0,document.body.scrollHeight);}
setTimeout(tick,250);}tick();</script></body></html>`;
const titles = {}; const clipLabels = {};
const viewSrv = createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname.startsWith('/v/')) { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(VIEWER(decodeURIComponent(u.pathname.slice(3)))); }
  if (u.pathname === '/events') { const id = u.searchParams.get('clip'); const after = Number(u.searchParams.get('after'));
    res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ title: titles[id] ?? id, labels: [...(clipLabels[id] ?? [])], events: events.filter(e => e.clip === id && e.n > after) })); }
  res.writeHead(404).end();
});
await new Promise((r) => viewSrv.listen(VIEW, '127.0.0.1', r));

// ------------------------------------------------------------------ simulated fingerprint gate helper (same HTTP contract as the WinBio helper)
const gateSrv = createServer((req, res) => {
  const cors = { 'access-control-allow-origin': ORIGIN, 'access-control-allow-methods': 'POST', 'access-control-allow-headers': 'content-type', 'content-type': 'application/json', vary: 'origin' };
  if (req.headers.origin && req.headers.origin !== ORIGIN) { res.writeHead(403, { 'content-type': 'application/json' }); return res.end('{"ok":false,"code":"GATE_ORIGIN_REJECTED"}'); }
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => {
    // P0.2 review: the same gate decision as the real-device runner (rebuild from Root, show that text, refuse otherwise)
    try { const q = JSON.parse(b); const gate = consoleGate({ rootState: () => w.root.state, gates: w.gates, now: w.now }, q);
      ev('OWNER', `SIMULATED fingerprint gate: MATCH for ${q.credId}, bound to the command rebuilt from Root ${gate.statement.boundDigest.slice(0, 16)}… (not a real sensor)`); res.writeHead(200, cors); res.end(JSON.stringify({ ok: true, gate })); }
    catch (e) { ev('DENY', `SIMULATED fingerprint gate refused: ${e.code ?? e.message}`); res.writeHead(200, cors); res.end(JSON.stringify({ ok: false, code: e.code ?? 'GATE_ERROR' })); }
  });
});
await new Promise((r) => gateSrv.listen(GATE, '127.0.0.1', r));
// look-alike / cross-site origin (phishing + CSRF clips): serves attacker pages only
const evilPages = {};
const evilSrv = createServer((req, res) => { const p = evilPages[new URL(req.url, 'http://x').pathname]; res.writeHead(p ? 200 : 404, { 'content-type': 'text/html' }); res.end(p ?? ''); });
await new Promise((r) => evilSrv.listen(EVIL, '127.0.0.1', r));

// ------------------------------------------------------------------ browser
let browser = null;
const results = [];
async function withClip(id, title, labels, fn) {
  clip = id; titles[id] = title; clipLabels[id] = new Set(labels); labels.forEach((l) => labelsUsed.add(l));
  const checks = []; const expect = (cond, what) => { checks.push({ what, ok: !!cond }); ev(cond ? 'OK' : 'DENY', (cond ? 'CHECK PASS: ' : 'CHECK FAIL: ') + what); };
  let ctx = null, page = null, cdp = null;
  if (VIDEO) {
    ctx = await browser.newContext({ recordVideo: { dir: join(OUT, '.raw', id), size: { width: 1280, height: 800 } }, viewport: { width: 1280, height: 800 } });
    page = await ctx.newPage(); await page.goto(`http://127.0.0.1:${VIEW}/v/${encodeURIComponent(id)}`); await sleep(900);
  }
  let error = null;
  try { await fn({ expect, page, ctx, newCdp: async () => (cdp = await ctx.newCDPSession(page)) }); } catch (e) { error = String(e.stack ?? e).slice(0, 600); ev('DENY', 'RUNNER ERROR: ' + String(e.message).slice(0, 200)); checks.push({ what: 'no runner error', ok: false }); }
  if (page) { if (!page.url().includes(`/v/`)) { await page.goto(`http://127.0.0.1:${VIEW}/v/${encodeURIComponent(id)}`); } await sleep(1800); }
  let video = null;
  if (ctx) { const v = page.video(); await ctx.close(); const raw = await v.path(); video = raw; }
  const pass = checks.length > 0 && checks.every((x) => x.ok);
  results.push({ id, title, labels: [...clipLabels[id]], pass, checks, error, video });
  return pass;
}
if (VIDEO) browser = await chromium.launch({ args: ['--host-resolver-rules=MAP localhost 127.0.0.1'] });

/** Inject the Root-enrolled k2-laptop key into Chromium's virtual authenticator (SIMULATED DEVICE, protocol-real). */
async function virtualAuthenticator(cdp, credId) {
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  const a = w.owner.dev(credId).auth;
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: { credentialId: a.credentialId.toString('base64'), isResidentCredential: false, rpId: 'localhost', privateKey: a.priv.export({ format: 'der', type: 'pkcs8' }).toString('base64'), signCount: a.counter } });
  return { sync: async () => { const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId }); a.counter = Math.max(a.counter, credentials[0].signCount); } };
}
const NEAR = (y) => `${Number(BigInt(y) * 1000n / 10n ** 24n) / 1000} NEAR`;
const Y = (n) => (BigInt(n) * 10n ** 22n).toString();
const PAY = { recipientId: 'merchant-a.mock', amountYocto: Y(3), asset: 'NEAR' };
let keyN = 0; const idem = () => 'showcase-' + String(++keyN).padStart(12, '0');
async function aiSession(login = h.logins.alice) { const t = await obtainTokens(h.url, login); return { t, ai: await mcpClient(h.url, t.access) }; }
async function causeIncident(n = 4) { for (let i = 0; i < n; i++) { await w.pay({ credId: 'k1-phone', amountYocto: Y(1) }); await w.advance(60_000); } return w.notify.outbox().filter((o) => o.kind === 'INCIDENT' && o.locator).at(-1); }
const lastConsoleAudit = () => c.audit.at(-1);

// ================================================================== MAIN DEMO
const mainLabels = [LABELS.MOCK_LEDGER, LABELS.SIMULATED_DEVICE, LABELS.FINGERPRINT_ONLY_NOT_PROVEN, REAL_GMAIL ? 'REAL GMAIL (pending provider result)' : 'REAL GMAIL: ' + LABELS.NOT_RUN, 'REAL DEVICE AUTH: ' + LABELS.NOT_RUN];
await withClip('main', 'SafeBox V6 main demo: AI-prepared payment with owner fingerprint approval, then Gmail alert -> Emergency Freeze -> recovery', mainLabels, async ({ expect, page, newCdp }) => {
  ev('INFO', 'Workflow A: an external AI may only PREPARE a payment. Only the enrolled owner device can approve it.');
  const { ai } = await aiSession(); await sleep(600);
  const tools = (await ai.listTools()).tools.map((x) => x.name).sort();
  ev('AI', 'MCP tools offered to the AI host: ' + tools.join(', ')); expect(!tools.some((t) => /sign|approve|settle|key|biometric|freeze/.test(t)), 'no signing / approval / biometric / key tool is reachable over MCP');
  await sleep(700);
  const prep = await call(ai, 'prepare_payment', { ...PAY, memo: 'order #1001 (coffee beans)', idempotencyKey: idem() });
  ev('AI', `prepare_payment ${NEAR(PAY.amountYocto)} -> ${PAY.recipientId}: ${prep.state}, signed=${prep.signed}, paymentEffect=${prep.paymentEffect}`);
  expect(prep.state === 'AWAITING_OWNER_APPROVAL' && w.vault.v5payments().length === 0, 'preparing created no Vault payment');
  await sleep(900);
  const rev = await dev.review(prep.requestId);
  ev('OWNER', 'Owner device (k2-laptop, fingerprint-only policy) shows its OWN Root-derived summary:');
  const res = await dev.approve(prep.requestId, { credId: 'k2-laptop' });
  for (const line of dev.lastV6.summary) { ev('OWNER', '  │ ' + line); await sleep(160); }
  ev('OWNER', `SIMULATED fingerprint gate MATCH -> one signature over the exact capability (assurance ${dev.lastV6.assurance})`);
  ev('ROOT', `Vault: ${res.state} / ${res.vaultState} (V6 binding, one-time challenge, gate verified; FIXED_600 buffer starts)`);
  expect(res.state === 'SUBMITTED_TO_VAULT' && res.vaultState === 'BUFFERED' && rev.problems.length === 0, 'owner approval accepted by the Vault and buffered');
  await sleep(700);
  await w.advance(9 * 60_000); const mid = await call(ai, 'get_payment_status', { requestId: prep.requestId });
  ev('INFO', `+9 min (mock clock): vault=${mid.vault.vaultState}, settledVerified=${mid.settledVerified}`); expect(mid.settledVerified === false, 'buffer is not skipped (FIXED_600)');
  await sleep(600);
  await dev.settle(); const fin = await call(ai, 'get_payment_status', { requestId: prep.requestId });
  ev('OK', `+12 min: vault=${fin.vault.vaultState}, ledger=${fin.ledgerReceipt.ledgerStatus}, receipt matches request=${fin.ledgerReceipt.matchesRequest} (MOCK LEDGER)`);
  expect(fin.settledVerified === true, 'settled on the MOCK ledger, receipt matches the approved request');
  await ai.close(); await sleep(900);

  ev('INFO', 'Workflow B: a burst of payments from k1-phone looks like a stolen key. The Risk Engine opens an incident.');
  const row = await causeIncident();
  const body = w.notify.messageBody(row.id); const linkLine = body.split('\n').find((l) => l.includes('/e/'));
  const st = w.notify.deliveryStatus(row.id);
  ev('MAIL', `Alert ${row.state} via ${transport.kind}: "${row.subject}"`);
  ev('MAIL', '  │ ' + linkLine.replace(/^.*?(http\S+).*$/, 'Emergency Freeze link: $1 (navigation only: no token, no approval)'));
  ev('MAIL', `  │ delivery: api=${st.api}, inbox=${st.inbox}`);
  if (REAL_GMAIL) { const ok = st.api === 'GMAIL_API_ACCEPTED'; clipLabels.main.delete('REAL GMAIL (pending provider result)'); clipLabels.main.add(ok ? LABELS.REAL_GMAIL + ' (API accepted; inbox receipt not verified)' : 'REAL GMAIL: SEND_FAILED'); }
  await sleep(1200);
  const locator = row.locator;
  if (page) {
    const va = await virtualAuthenticator(await newCdp(), 'k2-laptop');
    ev('OWNER', 'Owner opens the link in the browser (Chromium virtual authenticator holds the enrolled key: SIMULATED DEVICE)');
    await page.goto(`${ORIGIN}/e/${locator}`); await sleep(1500);
    await page.click('#signin'); await page.waitForSelector('#freeze:not([hidden])', { timeout: 15000 }); await sleep(2500);
    await page.locator('#freeze').scrollIntoViewIfNeeded(); await sleep(1500);
    await page.type('#confirm', CONFIRM_PHRASE, { delay: 70 }); await sleep(700);
    await page.click('#go'); await page.waitForFunction(() => document.getElementById('freezeOut').textContent.length > 0, null, { timeout: 15000 }); await sleep(2500);
    ev('OWNER', 'Console result: ' + (await page.textContent('#freezeOut')));
    await va.sync();
    await page.goto(`http://127.0.0.1:${VIEW}/v/main`); await sleep(600);
  } else {
    // headless path: same console API through the HTTP-shaped interface (simulated device)
    const kk = { cookie: '', csrf: '' };
    const post = async (p, b) => { const r = await c.handle({ method: 'POST', path: p, headers: { origin: ORIGIN, 'content-type': 'application/json', cookie: kk.cookie, ...(kk.csrf ? { 'x-safebox-csrf': kk.csrf } : {}) }, body: JSON.stringify(b) }); if (r.headers['set-cookie']) kk.cookie = r.headers['set-cookie'].split(';')[0]; return JSON.parse(r.body); };
    const s0 = await post('/api/login/start', { credId: 'k2-laptop' }); const f0 = await post('/api/login/finish', { loginId: s0.loginId, ...w.owner.loginAssertion('k2-laptop', s0.challengeHex) }); kk.csrf = f0.csrf;
    const pr = await post('/api/freeze/prepare', { locator }); const ap = w.owner.approvePrepared(w.root.state, pr, 'k2-laptop', { at: w.now() });
    const cf = await post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm: CONFIRM_PHRASE, approval: ap });
    ev('OWNER', `Console result: rootFrozen=${cf.rootFrozen}, vaultFrozen=${cf.vaultFrozen}, hold ${cf.holdId}`);
  }
  expect(w.frozen() === true, 'Root and Vault replica report the GLOBAL hold');
  const hold = Object.values(w.root.state.v5.holds).find((x) => x.reason === emergencyReason(row.incident));
  ev('ROOT', `Root hold ${hold?.holdId}: ${hold?.class}, reason "${hold?.reason}"`);
  const r2 = await w.pay({ credId: 'k1-phone' });
  ev(r2.ok ? 'OK' : 'DENY', `payment attempt while frozen: ${r2.ok ? 'ACCEPTED' : r2.error.code}`); expect(!r2.ok && r2.error.code === 'FREEZE_ACTIVE', 'the Vault refuses new payments while frozen');
  await w.advance(30 * 60_000, 5 * 60_000);
  const settledAfter = w.vault.v5payments().filter((p) => p.state === 'SETTLED' && Number(p.settled_at ?? 0) > Date.parse(hold?.createdAt ? new Date(Number(hold.createdAt)).toISOString() : 0));
  ev('ROOT', `+30 min frozen: buffered incident payments settled = ${settledAfter.length}; states ${JSON.stringify(w.vault.v5payments().map((p) => p.state))}`);
  await sleep(900);
  ev('INFO', 'Recovery through direct entry (no email): the hold\'s own issuer signs HOLD_RELEASE on the device (unchanged V5 rule).');
  const kk = { cookie: '', csrf: '' };
  const post = async (p, b) => { const r = await c.handle({ method: 'POST', path: p, headers: { origin: ORIGIN, 'content-type': 'application/json', cookie: kk.cookie, ...(kk.csrf ? { 'x-safebox-csrf': kk.csrf } : {}) }, body: JSON.stringify(b) }); if (r.headers['set-cookie']) kk.cookie = r.headers['set-cookie'].split(';')[0]; return JSON.parse(r.body); };
  const s1 = await post('/api/login/start', { credId: 'k2-laptop' }); const f1 = await post('/api/login/finish', { loginId: s1.loginId, ...w.owner.loginAssertion('k2-laptop', s1.challengeHex) }); kk.csrf = f1.csrf;
  const cp = await post('/api/command/prepare', { type: 'HOLD_RELEASE', body: { holdId: hold.holdId } }); const ch = await post('/api/command/challenge', { bundleId: cp.bundleId });
  const ap = w.owner.approvePrepared(w.root.state, ch, 'k2-laptop', { at: w.now() }); await post('/api/command/sign', { bundleId: cp.bundleId, approval: ap });
  const sub = await post('/api/command/submit', { bundleId: cp.bundleId });
  ev(sub.ok ? 'OK' : 'DENY', `HOLD_RELEASE: ${sub.ok ? 'accepted, Root seq ' + sub.seq : sub.error.code}; frozen now ${w.frozen()}`);
  expect(sub.ok && !w.frozen(), 'recovery released the hold through the provenance rule');
  const v = await verifyWorld6(w);
  ev(v.ok ? 'OK' : 'DENY', `Independent V6 verifier: ok=${v.ok}, owner approvals checked=${v.v6.ownerApprovals.checked}, emergency freezes=${v.v6.emergency.freezes}, violations=${v.financial.violations.length + v.v6.emergency.violations.length}`);
  expect(v.ok, 'independent V6 verifier: no unauthorized effect, freeze bound to an engine-opened incident');
});

// ================================================================== 10 ATTACK CLIPS
const SIM = [LABELS.MOCK_LEDGER, LABELS.SIMULATED_DEVICE];
await withClip('01-stolen-mcp-token', 'Attack 01: stolen MCP access token', SIM, async ({ expect }) => {
  const { t } = await aiSession(); const thief = await mcpClient(h.url, t.access, 'thief-host');
  ev('AI', 'Thief replays the owner\'s OAuth access token from another host.');
  const p = await call(thief, 'prepare_payment', { recipientId: 'merchant-a.mock', amountYocto: Y(5), asset: 'NEAR', memo: 'URGENT: approve now', idempotencyKey: idem() });
  ev('AI', `thief prepare_payment -> ${p.state} (an approval REQUEST only)`);
  const tools = (await thief.listTools()).tools.map((x) => x.name);
  const e = await callError(thief, 'approve_payment', { requestId: p.requestId }).catch((x) => ({ code: 'NO_SUCH_TOOL', message: String(x.message).slice(0, 80) }));
  ev('DENY', `thief calls a signing tool: ${e.code ?? 'refused'} (tools available: ${tools.join(', ')})`);
  await w.advance(40 * 60_000, 10 * 60_000);
  const st = await call(thief, 'get_payment_status', { requestId: p.requestId });
  ev('DENY', `after 40 min: request ${st.requestState}, settledVerified=${st.settledVerified}`);
  expect(st.settledVerified === false && !tools.some((x) => /approve|sign/.test(x)), 'without the owner device nothing is approved or settled');
  await thief.close();
});
await withClip('02-missing-fingerprint', 'Attack 02: approval without the fingerprint (gate skipped, PIN only, lockout)', [...SIM, LABELS.FINGERPRINT_ONLY_NOT_PROVEN], async ({ expect }) => {
  const { ai } = await aiSession();
  const a = await call(ai, 'prepare_payment', { ...PAY, memo: 'a', idempotencyKey: idem() }); const b = await call(ai, 'prepare_payment', { ...PAY, memo: 'b', idempotencyKey: idem() });
  const r1 = await dev.approve(a.requestId, { credId: 'k2-laptop', noGate: true });
  ev('DENY', `client skips the fingerprint gate: ${r1.state} ${r1.vaultCode}`);
  w.gates['k2-laptop'].next('PIN_ONLY'); const r2 = await dev.approve(b.requestId, { credId: 'k2-laptop' });
  ev('DENY', `PIN instead of fingerprint: device refuses (${r2.refusedByDevice}) - never silently substituted`);
  w.gates['k2-laptop'].next('LOCKOUT'); const r3 = await dev.approve(b.requestId, { credId: 'k2-laptop' });
  ev('DENY', `sensor lockout: ${r3.refusedByDevice}`);
  expect(r1.vaultCode === 'FINGERPRINT_GATE_REQUIRED' && String(r2.refusedByDevice) === 'BIOMETRIC_PIN_NOT_ACCEPTED' && String(r3.refusedByDevice) === 'BIOMETRIC_LOCKOUT', 'no fingerprint, no payment');
  await ai.close();
});
await withClip('03-amount-substitution', 'Attack 03: substituted amount / recipient after the owner saw the summary', SIM, async ({ expect }) => {
  const { ai } = await aiSession(); const p = await call(ai, 'prepare_payment', { ...PAY, memo: 'c', idempotencyKey: idem() });
  const r1 = await dev.approve(p.requestId, { credId: 'k1-phone', tamperBinding: (b) => { b.amountYocto = Y(6); } }).catch((e) => ({ code: e.code, fields: e.details?.fields }));
  ev('DENY', `binding amount changed 0.03 -> 0.06 NEAR: ${r1.code} [${r1.fields}]`);
  const r2 = await dev.approve(p.requestId, { credId: 'k1-phone', tamper: (cap) => { cap.recipientId = 'merchant-b.mock'; } }).catch((e) => ({ code: e.code, fields: e.details?.fields }));
  ev('DENY', `capability recipient swapped: ${r2.code} [${r2.fields}]`);
  expect(r1.code === 'CAPABILITY_MISMATCH' && r2.code === 'CAPABILITY_MISMATCH', 'substitution refused before the Vault; the Vault re-checks the binding too');
  await ai.close();
});
await withClip('04-challenge-replay', 'Attack 04: replaying a genuine owner approval', SIM, async ({ expect }) => {
  const { ai } = await aiSession(); const p = await call(ai, 'prepare_payment', { ...PAY, memo: 'd', idempotencyKey: idem() });
  const r = await dev.approve(p.requestId, { credId: 'k1-phone' }); ev('OK', `genuine approval: ${r.state}`);
  const pa = dev.lastV6;
  const again = await w.gz.request('PROPOSE', { capability: pa.capability, approval: pa.approval, recipientId: PAY.recipientId, amountYocto: PAY.amountYocto, asset: 'NEAR', memo: 'replay' });
  ev('DENY', `same approval replayed at the Vault: ${again.error?.code}`);
  const v5 = await w.v5pay({ credId: 'k1-phone' }); ev('DENY', `stolen PAY key signs a V5-style paycap (no V6 approval): ${v5.error?.code}`);
  expect(!again.ok && !v5.ok && v5.error.code === 'V6_PAYMENT_APPROVAL_REQUIRED', 'one approval = one payment; no approval = no payment');
  await ai.close();
});
await withClip('05-scanner-get', 'Attack 05: mail scanner / link preview visits the Emergency Freeze link', SIM, async ({ expect, page }) => {
  const row = w.notify.outbox().filter((o) => o.kind === 'INCIDENT' && o.locator).at(-1);
  const digest = () => sha(JSON.stringify({ head: w.root.state.head, holds: w.root.state.v5.holds, props: [...c.proposals.values()].map((p) => p.state), loc: w.notify.locators.resolve(row.locator) }));
  const before = digest(); ev('INFO', `state digest before: ${before.slice(0, 16)}…`);
  for (let i = 0; i < 6; i++) await c.handle({ method: i % 2 ? 'HEAD' : 'GET', path: `/e/${row.locator}`, headers: { 'user-agent': 'SafeLinks/1.0' } });
  ev('INFO', '6 scanner GET/HEAD requests sent');
  if (page) { await page.goto(`${ORIGIN}/e/${row.locator}`); await sleep(2200); await page.goto(`http://127.0.0.1:${VIEW}/v/05-scanner-get`); }
  const after = digest(); ev(before === after ? 'OK' : 'DENY', `state digest after:  ${after.slice(0, 16)}… (frozen=${w.frozen()})`);
  expect(before === after && !w.frozen(), 'visiting the link changed nothing and froze nothing');
});
await withClip('06-phishing-origin', 'Attack 06: phishing look-alike origin tries to harvest a login', SIM, async ({ expect, page, newCdp }) => {
  if (page) {
    evilPages['/'] = `<!DOCTYPE html><html><body style="font:16px system-ui;padding:30px"><h2>SafeBox Security (look-alike)</h2><p id="o">trying WebAuthn for rpId "localhost" from ${EVIL_ORIGIN} ...</p><script>
      navigator.credentials.get({publicKey:{challenge:new Uint8Array(32),rpId:'localhost',userVerification:'required'}}).then(()=>{o.textContent='GOT ASSERTION'}).catch(e=>{o.textContent='Browser refused: '+e.name+': '+e.message})</script></body></html>`;
    await virtualAuthenticator(await newCdp(), 'k1-phone');
    await page.goto(`${EVIL_ORIGIN}/`); await page.waitForFunction(() => !document.getElementById('o').textContent.includes('trying'), null, { timeout: 10000 }); await sleep(2200);
    ev('DENY', 'browser on the look-alike origin: ' + (await page.textContent('#o')).slice(0, 140));
    await page.goto(`http://127.0.0.1:${VIEW}/v/06-phishing-origin`);
  }
  const st = JSON.parse((await c.handle({ method: 'POST', path: '/api/login/start', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: '{"credId":"k1-phone"}' })).body);
  const relayed = w.owner.loginAssertion('k1-phone', st.challengeHex, { origin: 'https://safebox-login.example' });
  const fin = JSON.parse((await c.handle({ method: 'POST', path: '/api/login/finish', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify({ loginId: st.loginId, ...relayed }) })).body);
  ev('DENY', `assertion produced on the phishing origin, relayed to SafeBox: ${fin.error.code}`);
  expect(fin.error.code === 'WEBAUTHN_ORIGIN_MISMATCH', 'origin-bound WebAuthn: a phished assertion is useless');
});
await withClip('07-csrf', 'Attack 07: cross-site request forgery against a signed-in owner', SIM, async ({ expect, page }) => {
  const n0 = c.audit.length; const head0 = w.root.state.head;
  if (page) {
    evilPages['/csrf'] = `<!DOCTYPE html><html><body style="font:16px system-ui;padding:30px"><h2>Free coupon!</h2><p id="o">sending hidden POSTs to ${ORIGIN} ...</p><script>
      Promise.allSettled([fetch('${ORIGIN}/api/freeze/prepare',{method:'POST',credentials:'include',headers:{'content-type':'text/plain'},body:'{"incidentId":"inc-00000000"}'}),
      fetch('${ORIGIN}/api/command/prepare',{method:'POST',credentials:'include',mode:'no-cors',body:'{"type":"HOLD_RELEASE"}'})]).then(r=>{o.textContent='attacker page sees: '+r.map(x=>x.status+(x.value?(':'+x.value.type):'')).join(', ')})</script></body></html>`;
    await page.goto(`${EVIL_ORIGIN}/csrf`); await page.waitForFunction(() => document.getElementById('o').textContent.startsWith('attacker'), null, { timeout: 10000 }); await sleep(2000);
    ev('INFO', (await page.textContent('#o')).slice(0, 140));
    await page.goto(`http://127.0.0.1:${VIEW}/v/07-csrf`);
  } else {
    await c.handle({ method: 'POST', path: '/api/freeze/prepare', headers: { origin: EVIL_ORIGIN, 'content-type': 'text/plain' }, body: '{}' });
  }
  const seen = c.audit.slice(n0).map((a) => a.outcome);
  ev('DENY', `SafeBox console refused: ${seen.join(', ') || '(blocked by the browser before reaching SafeBox)'}`);
  expect(w.root.state.head === head0 && seen.every((x) => /ORIGIN_REJECTED|CROSS_SITE|CONTENT_TYPE|NOT_AUTHENTICATED/.test(x)), 'no state change from a cross-site request');
});
await withClip('08-forged-freeze', 'Attack 08: forged / wrong-incident emergency freeze', SIM, async ({ expect }) => {
  const kk = { cookie: '', csrf: '' };
  const post = async (p, b) => { const r = await c.handle({ method: 'POST', path: p, headers: { origin: ORIGIN, 'content-type': 'application/json', cookie: kk.cookie, ...(kk.csrf ? { 'x-safebox-csrf': kk.csrf } : {}) }, body: JSON.stringify(b) }); if (r.headers['set-cookie']) kk.cookie = r.headers['set-cookie'].split(';')[0]; return JSON.parse(r.body); };
  const s = await post('/api/login/start', { credId: 'k1-phone' }); const f = await post('/api/login/finish', { loginId: s.loginId, ...w.owner.loginAssertion('k1-phone', s.challengeHex) }); kk.csrf = f.csrf;
  const r1 = await post('/api/freeze/prepare', { incidentId: 'inc-' + 'ab'.repeat(12) }); ev('DENY', `console: freeze for an incident the engine never opened: ${r1.error.code}`);
  const r2 = await post('/api/freeze/prepare', { locator: 'l' + '0'.repeat(32) }); ev('DENY', `console: made-up locator: ${r2.error.code}`);
  const fz = await w.cmd('FREEZE', { freezeId: 'ef-forged-1', reason: emergencyReason('inc-' + 'cd'.repeat(12)), source: 'owner' }, ['k1-phone']);
  ev('INFO', `a stolen k1 key bypasses the console and freezes directly with a fake incident: Root ${fz.ok ? 'accepts the PROVISIONAL_HOLD (owner protective hold, 24 h max)' : fz.error.code}`);
  const v = await verifyWorld6(w); ev('DENY', `independent verifier: ${v.v6.emergency.violations.map((x) => x.code).join(', ')}`);
  expect(r1.error.code === 'INCIDENT_UNKNOWN' && r2.error.code === 'LOCATOR_UNKNOWN' && v.v6.emergency.violations.some((x) => x.code === 'EMERGENCY_FREEZE_UNKNOWN_INCIDENT'), 'unknown incidents refused; a forged emergency reason is flagged');
  ev('INFO', 'clean-up: the malicious hold is released by its own issuer (provenance rule)');
  await w.cmd('HOLD_RELEASE', { holdId: 'ef-forged-1', holdDigest: w.holdDigest('ef-forged-1') }, ['k1-phone']);
});
await withClip('09-forged-unfreeze', 'Attack 09: forged UNFREEZE (release by someone who did not place the hold)', SIM, async ({ expect }) => {
  const fz = await w.cmd('FREEZE', { freezeId: 'ef-owner-2', reason: 'owner protective freeze', source: 'owner' }, ['k2-laptop']); ev('OK', `owner k2-laptop freezes: ${fz.ok}`);
  const r1 = await w.cmd('HOLD_RELEASE', { holdId: 'ef-owner-2', holdDigest: w.holdDigest('ef-owner-2') }, ['k1-phone']); ev('DENY', `stolen k1 key tries to release it: ${r1.error?.code}`);
  const r2 = await w.submitRaw('UNFREEZE', { freezeId: 'ef-owner-2' }); ev('DENY', `legacy UNFREEZE command: ${r2.error?.code}`);
  const r3 = await w.cmd('HOLD_RELEASE', { holdId: 'ef-owner-2', holdDigest: 'f'.repeat(64) }, ['k2-laptop']); ev('DENY', `release with a wrong hold digest: ${r3.error?.code}`);
  expect(!r1.ok && !r2.ok && !r3.ok && w.frozen(), 'only the hold\'s own valid parties can release it');
  const ok = await w.cmd('HOLD_RELEASE', { holdId: 'ef-owner-2', holdDigest: w.holdDigest('ef-owner-2') }, ['k2-laptop']); ev('OK', `genuine release by its issuer: ${ok.ok}`);
});
await withClip('10-email-cannot-approve', 'Attack 10: compromised / forwarded email tries to approve or confirm', SIM, async ({ expect }) => {
  const row = w.notify.outbox().filter((o) => o.kind === 'INCIDENT' && o.locator).at(-1);
  const body = w.notify.messageBody(row.id);
  ev('MAIL', `the email contains ${(body.match(/https?:\/\/\S+/g) ?? []).length} URL(s), all of the form ${ORIGIN}/e/<opaque locator>`);
  const r1 = JSON.parse((await c.handle({ method: 'POST', path: '/api/freeze/confirm', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify({ proposalId: row.locator, confirm: CONFIRM_PHRASE }) })).body);
  ev('DENY', `forwarded-mail holder posts the locator as a confirmation: ${r1.error.code}`);
  const r2 = JSON.parse((await c.handle({ method: 'POST', path: '/api/login/finish', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify({ loginId: row.locator }) })).body);
  ev('DENY', `locator used as a login: ${r2.error.code}`);
  const words = /reply with|enter (?:your )?code|click (?:here )?to (?:approve|confirm|release)|approve (?:this|the) payment/i.test(body);
  expect(r1.error.code === 'NOT_AUTHENTICATED' && r2.error.code === 'LOGIN_UNKNOWN' && !words, 'email carries no authority and asks for nothing');
});

// ------------------------------------------------------------------ finish: MP4s, traces, summary, hashes
if (browser) await browser.close();
for (const s of [consoleSrv, viewSrv, gateSrv, evilSrv]) s.close();
await h.close();
mkdirSync(join(OUT, 'traces'), { recursive: true });
const ffLog = [];
for (const r of results) {
  writeFileSync(join(OUT, 'traces', r.id + '.jsonl'), events.filter((e) => e.clip === r.id).map((e) => JSON.stringify(e)).join('\n') + '\n');
  if (r.video) {
    const mp4 = join(OUT, (r.id === 'main' ? '00-main-demo' : r.id) + '.mp4');
    if (ffmpeg) { try { execFileSync(ffmpeg, ['-y', '-loglevel', 'error', '-i', r.video, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', '-r', '25', mp4]); r.mp4 = mp4.slice(OUT.length + 1); } catch (e) { ffLog.push(r.id + ': ' + String(e.message).slice(0, 200)); } }
    if (!r.mp4) { const webm = join(OUT, r.id + '.webm'); renameSync(r.video, webm); r.mp4 = null; r.webm = webm.slice(OUT.length + 1); }
    delete r.video;
  }
}
rmSync(join(OUT, '.raw'), { recursive: true, force: true });
const summary = { runner: 'scripts/v6/showcase.mjs', startedAt: stamp, mode: REAL_GMAIL ? 'REAL_GMAIL' : 'MOCK', video: VIDEO, ffmpeg: !!ffmpeg, ffmpegErrors: ffLog,
  git: (() => { try { return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO }).toString().trim(); } catch { return null; } })(),
  labelsShown: [...new Set([...labelsUsed, ...Object.values(clipLabels).flatMap((s) => [...s])])].filter((l) => !l.includes('pending provider result')), notRun: ['REAL DEVICE AUTH (Windows Hello)', 'FINGERPRINT_ONLY on a real sensor', ...(REAL_GMAIL ? [] : ['REAL GMAIL'])],
  honesty: 'All lines on screen are events emitted by this run. Devices are SIMULATED (Chromium virtual authenticator holding the Root-enrolled key; simulated fingerprint gate). Ledger is MOCK.',
  clips: results.map((r) => ({ id: r.id, title: r.title, pass: r.pass, checks: r.checks, labels: r.labels, mp4: r.mp4 ?? null, webm: r.webm ?? null, error: r.error })) };
writeFileSync(join(OUT, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
const files = []; const walk = (d) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) walk(p); else if (f !== 'SHA256SUMS') files.push(p); } }; walk(OUT);
writeFileSync(join(OUT, 'SHA256SUMS'), files.sort().map((p) => `${sha(readFileSync(p))}  ${p.slice(OUT.length + 1)}`).join('\n') + '\n');
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} clips passed -> ${OUT}`);
process.exit(failed.length ? 1 : 0);
