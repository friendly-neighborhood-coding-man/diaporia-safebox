#!/usr/bin/env node
// SELF-TEST of the real-device runner's plumbing (bridge, console forwarding, enrollment, Workflow A/B waits) using
// Chromium's VIRTUAL authenticator as the "owner" and an automated clicker. Everything this produces is SIMULATED
// DEVICE evidence; it exists only to prove scripts/v6/real-device.mjs works before the owner's real run.
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const { chromium } = createRequire(import.meta.url)('playwright');
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const PORT = Number(process.argv[2] ?? 47700), ORIGIN = `http://localhost:${PORT}`, OUT = process.argv[3];
const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', join(REPO, 'scripts/v6/real-device.mjs'), '--port', String(PORT), ...(OUT ? ['--out', OUT] : []), ...process.argv.slice(4)], { stdio: ['ignore', 'pipe', 'inherit'] });
let log = ''; const seen = (re) => re.exec(log);
child.stdout.on('data', (d) => { log += d; process.stdout.write('[runner] ' + d); });
const until = async (re, ms = 120000) => { const t = Date.now(); while (!seen(re)) { if (Date.now() - t > ms) throw new Error('timeout waiting for ' + re); await new Promise((r) => setTimeout(r, 200)); } return seen(re); };
const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP localhost 127.0.0.1'] });
const ctx = await browser.newContext();
const page = await ctx.newPage(); const cdp = await ctx.newCDPSession(page);
await cdp.send('WebAuthn.enable');
// SELFTEST_SYNCABLE=1: the virtual authenticator behaves like a syncing password manager (backup-eligible), to exercise the refusal path
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, ...(process.env.SELFTEST_SYNCABLE === '1' ? { defaultBackupEligibility: true } : {}) } });
// --demo: the runner prints the bridge link redacted and writes it to --bridge-url-file (default .demo-bridge-url)
let bridgeUrl;
if (process.argv.includes('--demo')) {
  await until(/Open the bridge link .*#t=<per-run secret, redacted>/);
  const i = process.argv.indexOf('--bridge-url-file');
  bridgeUrl = (await import('node:fs')).readFileSync(i > 0 ? resolve(process.argv[i + 1]) : join(REPO, '.demo-bridge-url'), 'utf8').trim();
  if (/#t=[0-9a-f]+/.exec(log.replace(bridgeUrl, ''))?.[0] && log.includes(bridgeUrl.split('#')[1])) throw new Error('bridge secret leaked to the terminal');
} else bridgeUrl = (await until(/Open (http:\/\/localhost:\d+\/bridge#t=[0-9a-f]+)/))[1];
await page.goto(bridgeUrl);
let clicks = 0; let stop = false;
(async () => { while (!stop) { try { const b = await page.$('#go'); if (b) { await b.click(); clicks++; await page.waitForTimeout(400); } } catch {} await page.waitForTimeout(150); } })();
const m = await until(/Open the Emergency Freeze link from the email \(or (http:\/\/localhost:\d+\/e\/l[0-9a-f]{32})\)/, 300000);
const p2 = await ctx.newPage(); // same context: the virtual authenticator holds the k2-laptop credential the runner enrolled
// virtual authenticators are per tab: copy the credential the runner enrolled (k2-laptop) into the console tab's own one
const cdp2 = await ctx.newCDPSession(p2); await cdp2.send('WebAuthn.enable');
const { authenticatorId: a2 } = await cdp2.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
for (const c of (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials) await cdp2.send('WebAuthn.addCredential', { authenticatorId: a2, credential: c });
await p2.goto(m[1]); await p2.fill('#cred', 'k2-laptop'); await p2.click('#signin');
await p2.waitForSelector('#freeze:not([hidden])', { timeout: 30000 }).catch(async (e) => { console.log('[selftest] page text: ' + (await p2.textContent('body')).slice(0, 1500)); throw e; });
await p2.fill('#confirm', 'FREEZE EVERYTHING'); await p2.click('#go');
await p2.waitForFunction(() => document.getElementById('freezeOut').textContent.length > 0, null, { timeout: 30000 });
console.log('[selftest] bridge card: ' + await page.textContent('#log').catch(() => '')); console.log('[selftest] console: ' + await p2.textContent('#freezeOut'));
// hand the (now higher) signature counter back to the bridge tab, as one real authenticator would have it
await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
for (const c of (await cdp2.send('WebAuthn.getCredentials', { authenticatorId: a2 })).credentials) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: c });
await until(/DONE\s+evidence/, 300000);
stop = true; await new Promise((r) => setTimeout(r, 800)); console.log(`[selftest] bridge approvals clicked: ${clicks}`);
await browser.close();
process.exit(0);
