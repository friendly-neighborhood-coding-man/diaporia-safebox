#!/usr/bin/env node
// SafeBox V6 REAL-DEVICE run (owner's Windows laptop, owner present). Workflow A and Workflow B with:
//   * the owner's REAL platform authenticator (Windows Hello) through the device bridge page (src/v6/device/browser-bridge.mjs);
//   * the REAL fingerprint gate (tools/winbio-gate/winbio-gate.exe, WinBioIdentify + CNG key) when it works on this
//     laptop; otherwise k2-laptop stays UV-only and the run is labelled FINGERPRINT ONLY NOT PROVEN / PIN FALLBACK POSSIBLE;
//   * REAL Gmail only when SAFEBOX_ALLOW_REAL_EMAIL=1 + --gmail-creds + --to (approved recipient); otherwise mock outbox;
//   * MOCK ledger always (no real funds).
//
//   node scripts/v6/real-device.mjs [--helper tools\winbio-gate\winbio-gate.exe] [--gmail-creds <file> --to <addr>] [--record] [--port 47610]
//
//   --only-workflow-a: Workflow A only (no alert, no freeze), used for the PIN-fallback check.
//   --attack-denials: after Workflow A, run representative attack attempts against the SAME world (stolen MCP token,
//     substituted amount / recipient, replay of the owner's real approval, stolen PAY key without a V6 approval,
//     non-browser and foreign-origin calls to the fingerprint gate) and, after the alert, scanner GET/HEAD visits of the
//     Emergency Freeze link. None of them prompts the owner or touches the real authenticator: attackers use the
//     simulated k1-phone credential or replay recorded artefacts. Each one must be refused or change nothing.
//   --demo: recording mode. The terminal never shows the per-run bridge secret (the full link is written to
//     --bridge-url-file, default .demo-bridge-url in the repo root, mode 0600, and on Windows also copied to the
//     clipboard) and evidence paths are printed relative to the repository.
// Nothing here presses a button, touches a sensor or clicks a link for the owner. The runner waits for the human.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdirSync, existsSync, writeFileSync, readdirSync, readFileSync, statSync, lstatSync, unlinkSync, openSync, writeSync, closeSync, constants as FS } from 'node:fs';
import { join, resolve, dirname, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync, spawn } from 'node:child_process';
import { BrowserBridge, RealAuthenticator } from '../../src/v6/device/browser-bridge.mjs';
import { WinBioGate } from '../../src/v6/device/winbio-gate.mjs';
import { consoleGate } from '../../src/v6/device/gate-service.mjs';
import { consoleForWorld, emergencyReason } from '../../src/v6/emergency/console.mjs';
import { verifyWorld6 } from '../../src/v6/supervisor/verifier.mjs';
import { commandDigest } from '../../src/v5/root/command.mjs';
import { GmailTransport, loadGmailCredentials } from '../../src/v6/notify/gmail.mjs';
import { termSafe } from '../../src/v6/common/term.mjs';
import { MockTransport } from '../../src/v5/notify/notify.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const IX = join(REPO, 'integrations/external-interactor');
const argv = process.argv.slice(2); const opt = (k, d = null) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; }; const flag = (k) => argv.includes(k);
const PORT = Number(opt('--port', '47610')), GATE = PORT + 3, ORIGIN = `http://localhost:${PORT}`, GATE_ORIGIN = `http://127.0.0.1:${GATE}`;
const stamp = new Date().toISOString().replace(/[:.]/g, '').slice(0, 15) + 'Z';
const OUT = resolve(opt('--out', join(REPO, 'docs/evidence/v6/real-device', stamp)));
if (existsSync(OUT)) { console.error('refusing to overwrite ' + OUT); process.exit(2); }
mkdirSync(OUT, { recursive: true });
const sha = (b) => createHash('sha256').update(b).digest('hex');
const events = []; const ev = (kind, text, data) => { const e = { at: new Date().toISOString(), kind, text, ...(data ? { data } : {}) }; events.push(e); console.log(`${kind.padEnd(6)} ${termSafe(text)}`); };
const DEMO = flag('--demo'); const shown = (p) => (DEMO ? relative(REPO, p) || '.' : p);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = {};

// ------------------------------------------------------------------ recording (desktop, ffmpeg gdigrab) if requested and available
let rec = null;
if (flag('--record')) {
  const ff = opt('--ffmpeg', 'ffmpeg');
  try { execFileSync(ff, ['-hide_banner', '-devices'], { stdio: 'pipe' }).toString().includes('gdigrab') || (() => { throw new Error('no gdigrab'); })();
    rec = spawn(ff, ['-y', '-loglevel', 'error', '-f', 'gdigrab', '-framerate', '12', '-i', 'desktop', '-c:v', 'libx264', '-preset', 'veryfast', '-pix_fmt', 'yuv420p', join(OUT, 'real-device-run.mp4')], { stdio: ['pipe', 'ignore', 'inherit'] });
    ev('INFO', 'desktop recording started (ffmpeg gdigrab) -> real-device-run.mp4');
  } catch (e) { ev('INFO', 'recording NOT RUN: ' + String(e.message).slice(0, 80)); }
}

// ------------------------------------------------------------------ device bridge (RP origin) + console forwarding
let consoleObj = null;
const bridge = new BrowserBridge({ port: PORT, origin: ORIGIN, handler: async (req) => consoleObj ? consoleObj.handle(req) : { status: 503, headers: { 'content-type': 'text/plain' }, body: 'SafeBox is starting' } });
await bridge.ready();
if (DEMO) {
  const uf = resolve(opt('--bridge-url-file', join(REPO, '.demo-bridge-url')));
  // exclusive create (no symlink follow, fresh 0600 mode); a stale file from an earlier run is replaced only if it is a regular file
  try { if (lstatSync(uf).isFile()) unlinkSync(uf); else { console.error('refusing: ' + shown(uf) + ' is not a regular file'); process.exit(2); } } catch (e) { if (e.code !== 'ENOENT') throw e; }
  const ufd = openSync(uf, FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | (FS.O_NOFOLLOW ?? 0), 0o600); try { writeSync(ufd, bridge.url() + '\n'); } finally { closeSync(ufd); }
  process.on('exit', () => { try { unlinkSync(uf); } catch { /* already gone */ } }); // the per-run secret dies with the run
  let clip = false; if (process.platform === 'win32') { try { execFileSync('clip', [], { input: bridge.url() }); clip = true; } catch { /* file only */ } }
  console.log(`STEP   Open the bridge link in Microsoft Edge on THIS laptop and keep that tab open: ${ORIGIN}/bridge#t=<per-run secret, redacted> (full link ${clip ? 'copied to the clipboard and ' : ''}in ${shown(uf)}).`);
} else console.log(`STEP   Open ${bridge.url()} in Microsoft Edge on THIS laptop and keep that tab open (copy the whole link, including the part after #).`);
events.push({ at: new Date().toISOString(), kind: 'STEP', text: `Open ${ORIGIN}/bridge#t=<per-run secret, redacted> in Microsoft Edge` }); // the secret never reaches the evidence
for (let i = 0; ; i++) { if (Date.now() - (await bridge.lastPoll()) < 3000) break; if (i > 1200) { ev('FAIL', 'bridge page never opened (10 min)'); process.exit(4); } await sleep(500); }
ev('OK', 'bridge page connected');

// ------------------------------------------------------------------ fingerprint gate
const helper = opt('--helper');
let gates = {}, fpOnly = [], gateProbe = null, sensorCheck = [], wbg = null;
const TOUCH = (p) => `SAFEBOX FINGERPRINT GATE (${p}): in the small "SafeBox fingerprint gate" window, click "Start fingerprint check", then touch the sensor. Nothing is approved without that click and a fresh touch.`;
if (helper) {
  const g = wbg = new WinBioGate({ credId: 'k2-laptop', exe: helper.endsWith('.mjs') ? [process.execPath, resolve(helper)] : resolve(helper), timeoutS: Number(opt('--touch-timeout', '60')),
    onPrompt: (p) => { ev('TOUCH', `Touch the fingerprint sensor now (${p})`); bridge.notice(TOUCH(p)); }, onDone: () => bridge.notice(null) });
  try { gateProbe = g.probe(); } catch (e) { gateProbe = { ok: false, code: e.code }; }
  ev(gateProbe.ok ? 'OK' : 'INFO', 'WinBio probe: ' + JSON.stringify(gateProbe));
  if (gateProbe.ok && gateProbe.systemPoolSession === 'OPENED') {
    // preflight: one sensor check (nothing is signed) BEFORE any enrollment, up to 3 attempts, so a sensor that never
    // reaches the helper is found before the owner approves the genesis records
    ev('STEP', 'Fingerprint sensor check (nothing is signed): touch the sensor when the bridge page asks');
    for (let i = 1; i <= 3; i++) {
      let j; try { j = g.identify(`SafeBox sensor check ${i} of 3 (nothing is signed)`); } catch (e) { j = { ok: false, code: e.code ?? 'HELPER_ERROR' }; }
      sensorCheck.push({ attempt: i, ok: !!j.ok, code: j.code ?? null, hr: j.hr ?? null });
      ev(j.ok ? 'OK' : 'INFO', `sensor check ${i}: ${j.ok ? 'MATCH (current Windows user)' : j.code + (j.hr ? ' ' + j.hr : '')}`);
      if (j.ok || ['FINGERPRINT_ONLY_UNSUPPORTED', 'BIOMETRIC_LOCKOUT'].includes(j.code)) break;
    }
    if (sensorCheck.some((x) => x.ok)) { gates = { 'k2-laptop': g }; fpOnly = ['k2-laptop']; }
  }
}
if (!fpOnly.length) ev('INFO', 'k2-laptop runs UV-only: FINGERPRINT ONLY NOT PROVEN, PIN FALLBACK POSSIBLE');

// ------------------------------------------------------------------ transport
let transport = new MockTransport(); const to = opt('--to');
if (opt('--gmail-creds')) {
  if (process.env.SAFEBOX_ALLOW_REAL_EMAIL !== '1' || !to) { ev('FAIL', 'real Gmail needs SAFEBOX_ALLOW_REAL_EMAIL=1 and --to'); process.exit(3); }
  transport = new GmailTransport({ ...loadGmailCredentials(opt('--gmail-creds')), allowedRecipients: [to] });
}

// ------------------------------------------------------------------ world (interactor harness; bob's world stays fully simulated)
const realAuth = new RealAuthenticator({ bridge, label: 'k2-laptop' });
bridge.display = 'ENROLL: register this laptop\'s passkey as SafeBox credential k2-laptop and sign the account genesis records\n(account vault-alice.mock, MOCK ledger; one Windows Hello prompt per record)';
bridge.expected = { [bridge.display.split('\n')[0]]: 6 }; // passkey creation + one signature per genesis record (counted in the selftest)
ev('STEP', 'Enrollment: approve each "ENROLL" request on the bridge page (Windows Hello)' + (fpOnly.length ? ' and touch the sensor for the gate-key enrollment' : ''));
const { startHarness } = await import(pathToFileURL(join(IX, 'dist/harness/mockWorld.js')).href);
const { call, callError, mcpClient, obtainTokens } = await import(pathToFileURL(join(IX, 'dist/harness/client.js')).href);
const policy6 = { emergency: { origin: ORIGIN, locatorTtlMs: String(72 * 3600_000) } };
const harness = (fp, gs, auth) => startHarness({ v6: { fingerprintOnly: fp, gates: gs, rp: { rpId: 'localhost', origin: ORIGIN }, policy6, transport, authenticators: { 'k2-laptop': auth }, ...(to ? { ownerRecipient: to } : {}) },
  v6Bob: { rp: { rpId: 'localhost', origin: ORIGIN }, policy6 } });
let h, gateEnrollment = fpOnly.length ? 'PENDING' : 'NOT_ATTEMPTED', activeAuth = realAuth;
try { h = await harness(fpOnly, gates, realAuth); if (fpOnly.length) gateEnrollment = 'ENROLLED'; }
catch (e) {
  if (!fpOnly.length || !/^(BIOMETRIC_|FINGERPRINT_ONLY_UNSUPPORTED)/.test(String(e.code))) throw e;
  // fail closed to a LABELLED UV-only run (no gate key is enrolled; nothing is presented as fingerprint-verified)
  gateEnrollment = 'FAILED:' + e.code; fpOnly = []; gates = {};
  ev('INFO', `gate-key enrollment failed (${e.code}): continuing UV-only, FINGERPRINT ONLY NOT PROVEN, PIN FALLBACK POSSIBLE`);
  ev('STEP', 'Enrollment again without the gate key: approve the new ENROLL requests on the bridge page (Windows Hello)');
  bridge.counts = new Map();
  activeAuth = new RealAuthenticator({ bridge, label: 'k2-laptop' });
  h = await harness([], {}, activeAuth);
}
const w = h.worlds['sbx-alice']; const dev = h.devices['sbx-alice'];
w.owner.decide = (prompt, text, ctx) => { if ((ctx?.credId ?? ctx?.binding?.credId ?? 'k2-laptop') === 'k2-laptop') bridge.display = String(text); // simulated credentials never change what the real bridge shows
   ev('OWNER', 'device shows: ' + String(text).split('\n')[0]); return true; }; // the real decision is the owner's Approve/Decline on the bridge page
ev('OK', `enrolled: k2-laptop credential ${w.root.state.creds['k2-laptop'].webauthn.credentialId.slice(0, 12)}…, gate key ${w.root.state.v6.gateKeys['k2-laptop']?.kind ?? 'none'}`);
consoleObj = consoleForWorld(w, { gateOrigin: GATE_ORIGIN });

// gate server for the console page (same contract as the simulated one)
const gateSrv = createServer((req, res) => {
  const cors = { 'access-control-allow-origin': ORIGIN, 'access-control-allow-methods': 'POST', 'access-control-allow-headers': 'content-type', 'content-type': 'application/json', vary: 'origin' };
  // review: a request WITHOUT an Origin (a local non-browser process) is refused too
  if (req.headers.origin !== ORIGIN) { res.writeHead(403); return res.end('{"ok":false,"code":"GATE_ORIGIN_REJECTED"}'); }
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => {
    try { const q = JSON.parse(b);
      // P0.2: rebuilt from the runner's Root replica; the console's proposal list is not consulted
      const gate = consoleGate({ rootState: () => w.root.state, gates: w.gates, now: w.now }, q);
      ev('OK', 'REAL fingerprint gate MATCH for the console command'); res.writeHead(200, cors); res.end(JSON.stringify({ ok: true, gate })); }
    catch (e) { ev('DENY', 'fingerprint gate: ' + (e.code ?? e.message)); res.writeHead(200, cors); res.end(JSON.stringify({ ok: false, code: e.code ?? 'GATE_ERROR' })); }
  });
});
await new Promise((r) => gateSrv.listen(GATE, '127.0.0.1', r));

let lastPaymentId = null;
const ATTACKS = flag('--attack-denials'); const attacks = [];
const denial = (id, what, refused, detail) => { attacks.push({ id, what, refused: !!refused, detail }); ev(refused ? 'DENY' : 'FAIL', `ATTACK ${id} ${what}: ${detail}${refused ? '' : '  <-- NOT REFUSED'}`); };
// ================================================================== Workflow A
try {
  ev('STEP', 'Workflow A: the AI prepares a payment over MCP; approve it on the bridge page' + (fpOnly.length ? ' and touch the sensor' : ''));
  const t = await obtainTokens(h.url, h.logins.alice); let ai = await mcpClient(h.url, t.access);
  const prep = await call(ai, 'prepare_payment', { recipientId: 'merchant-a.mock', amountYocto: (3n * 10n ** 22n).toString(), asset: 'NEAR', memo: 'real-device run', idempotencyKey: 'real-device-000000000001' });
  ev('AI', `prepare_payment: ${prep.state}`);
  const r = await dev.approve(prep.requestId, { credId: 'k2-laptop' }); lastPaymentId = r.paymentId; results.workflowA = { prepared: prep.state, submitted: r.state ?? r.refusedByDevice ?? r };
  ev(r.state === 'SUBMITTED_TO_VAULT' ? 'OK' : 'DENY', 'owner approval -> ' + JSON.stringify(r));
  if (ATTACKS) { // attack 1: the owner's genuine approval is replayed at the Vault at once (still inside its validity window)
    const pa = dev.lastV6;
    if (pa?.capability) { const again = await w.gz.request('PROPOSE', { capability: pa.capability, approval: pa.approval, recipientId: 'merchant-a.mock', amountYocto: (3n * 10n ** 22n).toString(), asset: 'NEAR', memo: 'replay' });
      // only replay-specific refusals count (review 3c): a refusal for an unrelated reason is reported as NOT refused
      const REPLAY_CODES = ['CHALLENGE_ALREADY_CONSUMED', 'OWNER_APPROVAL_CHALLENGE_REUSED', 'WEBAUTHN_SIGNCOUNT_NOT_INCREASING', 'CAPABILITY_ALREADY_USED', 'CAPABILITY_NONCE_REUSED', 'DUPLICATE_EFFECT_FOR_CAPABILITY', 'DUPLICATE_APPROVAL'];
      denial('01', "immediate replay of the owner's real approval", !again.ok && REPLAY_CODES.includes(again.error?.code), again.ok ? 'ACCEPTED' : again.error?.code); }
    else denial('01', "immediate replay of the owner's real approval", false, 'NOT_RUN (no approval to replay)');
  }
  await w.advance(12 * 60_000);
  // the owner may take minutes at the real prompt: reconnect the AI client (fresh tokens) before the status read
  let st; try { st = await call(ai, 'get_payment_status', { requestId: prep.requestId }); }
  catch (e) { ev('INFO', 'AI client reconnect after: ' + (e.code ?? e.message)); try { await ai.close(); } catch {}
    // same OAuth client + access token (requests are client-scoped); the idle keep-alive socket was the likely casualty
    ai = await mcpClient(h.url, t.access); st = await call(ai, 'get_payment_status', { requestId: prep.requestId }); }
  results.workflowA = { prepared: prep.state, submitted: r.state ?? r.refusedByDevice ?? r, assurance: dev.lastV6?.assurance ?? null, settledVerified: st.settledVerified,
    vaultState: w.vault.v5payments().find((x) => x.payment_id === r.paymentId)?.state ?? null };
  ev(st.settledVerified ? 'OK' : 'DENY', `MOCK settlement after the 10-minute buffer: settledVerified=${st.settledVerified}`);
  await ai.close();
} catch (e) { results.workflowA = { ...(results.workflowA ?? {}), error: e.code ?? e.message, ...(typeof lastPaymentId === 'string' ? { vaultState: w.vault.v5payments().find((x) => x.payment_id === lastPaymentId)?.state ?? null } : {}) }; ev('FAIL', 'Workflow A: ' + (e.code ?? e.message)); }

// ================================================================== attack denials (optional, --attack-denials)
// Representative attacks against the same world (attack 1 runs inside Workflow A, attack 7 after the alert). Nothing here prompts the owner:
// the attacker side uses the SIMULATED k1-phone credential or replays artefacts recorded from Workflow A.
if (ATTACKS) try {
  ev('STEP', 'Attack denials: each attempt below must be refused or change nothing (no owner action needed; MOCK ledger)');
  // 2-3. outside-purpose recipient; a rogue AI client with a valid MCP session for the owner's account (a fresh login under another client name, standing in for a stolen token) access token used from another host: it can only PREPARE; there is no signing tool; nothing settles
  const t1 = await obtainTokens(h.url, h.logins.alice); const thief = await mcpClient(h.url, t1.access, 'thief-host');
  const tools = (await thief.listTools()).tools.map((x) => x.name);
  const tx = await callError(thief, 'prepare_payment', { recipientId: 'attacker.mock', amountYocto: (5n * 10n ** 22n).toString(), asset: 'NEAR', memo: 'URGENT: approve now', idempotencyKey: 'real-device-attack-00000' }).catch((e) => ({ code: 'CALL_FAILED', message: String(e.message).slice(0, 80) }));
  denial('02', 'AI asks to pay an address outside the purpose', tx.code === 'NOT_PREPARABLE', `${tx.code}${tx.details?.policyViolations ? ' ' + tx.details.policyViolations.join(',') : ''} (no approval request created)`);
  const tp = await call(thief, 'prepare_payment', { recipientId: 'merchant-a.mock', amountYocto: (5n * 10n ** 22n).toString(), asset: 'NEAR', memo: 'URGENT: approve now', idempotencyKey: 'real-device-attack-00001' });
  await w.advance(40 * 60_000, 10 * 60_000);
  const tst = await call(thief, 'get_payment_status', { requestId: tp.requestId });
  denial('03', 'rogue AI client with a valid MCP session', !tools.some((x) => /approve|sign|settle|key|biometric|freeze/i.test(x)) && tst.settledVerified === false,
    `prepare -> ${tp.state}; tools offered: ${tools.join(', ')}; after 40 min settledVerified=${tst.settledVerified}`);
  // 4. substituted amount / recipient after the device built the owner summary (simulated k1-phone)
  const sp = await call(thief, 'prepare_payment', { recipientId: 'merchant-a.mock', amountYocto: (3n * 10n ** 22n).toString(), asset: 'NEAR', memo: 'substitution', idempotencyKey: 'real-device-attack-00002' });
  const s1 = await dev.approve(sp.requestId, { credId: 'k1-phone', tamperBinding: (b) => { b.amountYocto = (6n * 10n ** 22n).toString(); } }).catch((e) => ({ code: e.code, fields: e.details?.fields }));
  denial('04a', 'amount changed 0.03 -> 0.06 NEAR after the summary', s1.code === 'CAPABILITY_MISMATCH', `${s1.code ?? s1.state} [${s1.fields ?? ''}]`);
  const s2 = await dev.approve(sp.requestId, { credId: 'k1-phone', tamper: (cap) => { cap.recipientId = 'merchant-b.mock'; } }).catch((e) => ({ code: e.code, fields: e.details?.fields }));
  denial('04b', 'recipient swapped after the summary', s2.code === 'CAPABILITY_MISMATCH', `${s2.code ?? s2.state} [${s2.fields ?? ''}]`);
  // 5. stolen PAY key signs a V5-style payment capability with no V6 owner approval
  const v5 = await w.v5pay({ credId: 'k1-phone' });
  denial('05', 'stolen PAY key without a V6 owner approval', !v5.ok && v5.error?.code === 'V6_PAYMENT_APPROVAL_REQUIRED', v5.ok ? 'ACCEPTED' : v5.error?.code);
  // 6. local process / foreign web origin asks the fingerprint gate to sign
  const g1 = await fetch(`${GATE_ORIGIN}/`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  const g2 = await fetch(`${GATE_ORIGIN}/`, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://evil.localhost:8080' }, body: '{}' });
  denial('06', 'fingerprint gate called without / with a foreign Origin', g1.status === 403 && g2.status === 403, `no Origin -> HTTP ${g1.status}, foreign Origin -> HTTP ${g2.status}`);
  await thief.close();
} catch (e) { attacks.push({ id: 'error', refused: false, detail: e.code ?? e.message }); ev('FAIL', 'attack denials: ' + (e.code ?? e.message)); }

// ================================================================== Workflow B
// --only-workflow-a: the PIN-fallback test (owner answers Windows Hello with a PIN and does NOT touch the sensor at the
// gate); no incident, no email, no freeze
if (flag('--only-workflow-a')) { results.workflowB = { skipped: 'ONLY_WORKFLOW_A' }; ev('INFO', 'Workflow B skipped (--only-workflow-a): no alert is sent'); }
else try {
  ev('STEP', 'Workflow B: a burst from k1-phone (simulated stolen key) triggers a Risk Engine incident and a security alert');
  for (let i = 0; i < 4; i++) { await w.pay({ credId: 'k1-phone', amountYocto: (10n ** 22n).toString() }); await w.advance(60_000); }
  const row = w.notify.outbox().filter((o) => o.kind === 'INCIDENT' && o.locator).at(-1);
  const ds = w.notify.deliveryStatus(row.id);
  results.alert = { transport: transport.kind, outboxState: row.state, api: ds.api, inbox: ds.inbox, lastError: row.last_error ?? null, gmailLog: transport.log ?? null };
  ev('MAIL', `alert ${row.state} via ${transport.kind}: api=${ds.api}, inbox=${ds.inbox}`);
  if (ATTACKS) { // 7. a mail scanner / link preview fetches the Emergency Freeze link: nothing changes, nothing freezes
    // same digest scope as showcase clip 05: Root head, holds, console proposals and the locator's own state
    const digest = () => sha(JSON.stringify({ head: w.root.state.head, holds: w.root.state.v5.holds, props: [...consoleObj.proposals.values()].map((p) => p.state), loc: w.notify.locators.resolve(row.locator), frozen: w.frozen() }));
    const before = digest(); const codes = [];
    for (let i = 0; i < 6; i++) codes.push((await consoleObj.handle({ method: i % 2 ? 'HEAD' : 'GET', path: `/e/${row.locator}`, headers: { host: new URL(ORIGIN).host, 'user-agent': 'SafeLinks/1.0' } })).status);
    const after = digest();
    // the visits must actually reach the real page (2xx), otherwise "nothing changed" would prove nothing
    denial('07', '6 scanner GET/HEAD visits of the Emergency Freeze link', codes.every((c) => c >= 200 && c < 300) && before === after && !w.frozen(), `HTTP ${codes.join(',')}; state digest ${before.slice(0, 12)}… -> ${after.slice(0, 12)}…, frozen=${w.frozen()}`);
  }
  ev('STEP', `Open the Emergency Freeze link from the email (or ${ORIGIN}/e/${row.locator}), sign in with Windows Hello, review, type the phrase, approve${fpOnly.length ? ' and touch the sensor' : ''}.`);
  for (let i = 0; !w.frozen(); i++) { if (i > 1800) throw Object.assign(new Error('owner did not freeze within 15 min'), { code: 'FREEZE_NOT_DONE' }); await sleep(500); }
  const hold = Object.values(w.root.state.v5.holds).find((x) => x.reason === emergencyReason(row.incident) && x.status === 'ACTIVE');
  ev('OK', `FROZEN by the owner: hold ${hold?.holdId} (${hold?.class})`);
  const p = await w.pay({ credId: 'k1-phone' }); ev(p.ok ? 'DENY' : 'OK', 'new payment while frozen: ' + (p.ok ? 'ACCEPTED (unexpected)' : p.error.code));
  await w.advance(30 * 60_000, 5 * 60_000);
  const frozenStates = w.vault.v5payments().map((x) => x.state);
  ev('INFO', 'Vault payment states after 30 min frozen: ' + JSON.stringify(frozenStates));
  const v = await verifyWorld6(w);
  ev(v.ok ? 'OK' : 'DENY', `independent V6 verifier: ok=${v.ok}, owner approvals=${v.v6.ownerApprovals.checked}, emergency freezes=${v.v6.emergency.freezes}`);
  results.workflowB = { frozen: true, holdId: hold?.holdId, holdClass: hold?.class, paymentWhileFrozen: p.ok ? 'ACCEPTED' : p.error.code, statesAfter30Min: frozenStates, verifierOk: v.ok,
    settledWhileFrozen: w.vault.v5payments().filter((x) => x.state === 'SETTLED' && Number(x.settled_at ?? 0) > Number(hold?.createdAt ?? Infinity)).length };
  ev('STEP', 'Recovery: approve HOLD_RELEASE on the bridge page' + (fpOnly.length ? ' and touch the sensor' : ''));
  const rel = await w.cmd('HOLD_RELEASE', { holdId: hold.holdId, holdDigest: w.holdDigest(hold.holdId) }, ['k2-laptop']);
  results.recovery = { ok: rel.ok, error: rel.error?.code ?? null, frozenAfter: w.frozen() };
  ev(rel.ok ? 'OK' : 'DENY', `HOLD_RELEASE: ${rel.ok ? 'accepted' : rel.error.code}; frozen now ${w.frozen()}`);
} catch (e) { results.workflowB = { ...(results.workflowB ?? {}), error: e.code ?? e.message }; ev('FAIL', 'Workflow B: ' + (e.code ?? e.message)); }

// ------------------------------------------------------------------ evidence
if (rec) { rec.stdin.write('q'); await new Promise((r) => rec.on('close', r)); }
const gateLog = wbg?.log ?? [];
const gatedApprovals = gateLog.filter((x) => x.purpose !== 'SENSOR_CHECK' && x.purpose !== 'ENROLL_GATE_KEY');
// labels derived from what actually happened, per factor
const gatedOk = fpOnly.length > 0 && gatedApprovals.length > 0 && gatedApprovals.every((x) => x.ok);
const labels = ['MOCK LEDGER', 'REAL DEVICE AUTH (Windows Hello WebAuthn)', 'WINDOWS HELLO UV: PIN FALLBACK POSSIBLE (WebAuthn UV cannot tell fingerprint from PIN)'];
labels.push(gatedOk ? `FINGERPRINT_ONLY_LOCALLY_VERIFIED for ${gatedApprovals.length} gated approvals (WinBio MATCH + ${wbg?.kind ?? 'gate'} key signature; not hardware attestation)` : 'FINGERPRINT ONLY NOT PROVEN');
if (helper && helper.endsWith('.mjs')) labels.unshift('EMULATED FINGERPRINT HELPER (test fixture: no sensor, no real fingerprint; selftest only)');
labels.push(results.alert?.api === 'GMAIL_API_ACCEPTED' ? 'REAL GMAIL (API accepted; inbox receipt NOT verified until the owner confirms)' : 'REAL GMAIL: NOT RUN');
if (ATTACKS) labels.push(`ATTACK DENIALS: ${attacks.filter((a) => a.refused).length}/${attacks.length} refused (attacker side SIMULATED; interface-level only)`);
const summary = { runner: 'scripts/v6/real-device.mjs', startedAt: stamp, labels, ...(ATTACKS ? { attacks } : {}), gateProbe, sensorCheck, gateEnrollment, gateLog, refusedSyncablePasskeys: [...realAuth.refused, ...(activeAuth !== realAuth ? activeAuth.refused : [])], webauthnCeremonies: [...realAuth.ceremonies, ...(activeAuth !== realAuth ? activeAuth.ceremonies : [])], results,
  ownerReportedModalities: 'ASK THE OWNER: WebAuthn cannot tell which Windows Hello modality was used',
  git: (() => { try { return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO }).toString().trim(); } catch { return null; } })() };
writeFileSync(join(OUT, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
writeFileSync(join(OUT, 'trace.jsonl'), events.map((e) => JSON.stringify(e)).join('\n') + '\n');
const files = readdirSync(OUT).filter((f) => f !== 'SHA256SUMS' && statSync(join(OUT, f)).isFile());
writeFileSync(join(OUT, 'SHA256SUMS'), files.sort().map((f) => `${sha(readFileSync(join(OUT, f)))}  ${f}`).join('\n') + '\n');
ev('DONE', 'evidence: ' + shown(OUT));
gateSrv.close(); await h.close(); await bridge.close(); process.exit(0);
