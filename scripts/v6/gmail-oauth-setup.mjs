#!/usr/bin/env node
// Operator-only: obtain a Gmail OAuth refresh token for the SafeBox alert sender with EXACTLY the gmail.send scope.
//
//   node scripts/v6/gmail-oauth-setup.mjs --client <client_secret.json> --sender <sender@gmail.com> --out <path OUTSIDE the repo>
//
// * <client_secret.json> is the "Desktop app" OAuth client downloaded from Google Cloud Console (APIs & Services >
//   Credentials). It is read locally and never copied into the repository.
// * Uses the loopback redirect (http://127.0.0.1:<port>) with PKCE (S256) and a random state; you sign in to Google in
//   your own browser and approve "Send email on your behalf". Nothing else is requested.
// * The resulting {client_id, client_secret, refresh_token, sender} is written with mode 0600 to --out, which must be
//   outside the repository. The token is never printed. The granted scope is checked to be exactly gmail.send.
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, realpathSync, existsSync } from 'node:fs';
import { dirname, resolve, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { GMAIL_SEND_SCOPE, writeGmailCredentialFile } from '../../src/v6/notify/gmail.mjs';

const arg = (k) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : null; };
const clientPath = arg('--client'), sender = arg('--sender'), out = arg('--out');
if (!clientPath || !sender || !out) { console.error('usage: --client <client_secret.json> --sender <address> --out <file outside the repo>'); process.exit(2); }
const repo = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
const outAbs = resolve(out); const outDir = realpathSync(dirname(outAbs));
const rel = relative(repo, outDir);
if (!rel.startsWith('..') && !isAbsolute(rel)) { console.error('refusing to write credentials inside the repository: ' + outAbs); process.exit(2); }
if (existsSync(outAbs)) { console.error('refusing to overwrite an existing credentials file: ' + outAbs); process.exit(2); }
const cj = JSON.parse(readFileSync(clientPath, 'utf8')); const c = cj.installed ?? cj.web ?? cj;
if (!c.client_id || !c.client_secret) { console.error('client file has no client_id/client_secret'); process.exit(2); }

const verifier = randomBytes(32).toString('base64url'); const challenge = createHash('sha256').update(verifier).digest('base64url'); const state = randomBytes(16).toString('hex');
const srv = createServer(); await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
const redirect = `http://127.0.0.1:${srv.address().port}`;
const auth = new URL('https://accounts.google.com/o/oauth2/v2/auth');
for (const [k, v] of Object.entries({ client_id: c.client_id, redirect_uri: redirect, response_type: 'code', scope: GMAIL_SEND_SCOPE, access_type: 'offline', prompt: 'consent',
  code_challenge: challenge, code_challenge_method: 'S256', state, login_hint: sender })) auth.searchParams.set(k, v);
// open the consent page in the operator's own default browser (Windows: start; macOS: open; Linux: xdg-open)
try { const u = auth.toString(); const [cmd, args] = process.platform === 'win32' ? ['cmd', ['/c', 'start', '""', u.replace(/&/g, '^&')]] : [process.platform === 'darwin' ? 'open' : 'xdg-open', [u]];
  spawn(cmd, args, { stdio: 'ignore', detached: true }).unref(); } catch { /* fall back to the printed URL */ }
console.log('\nOpen this URL in your browser, sign in as ' + sender + ' and allow ONLY "Send email on your behalf":\n\n' + auth.toString() + '\n\nWaiting on ' + redirect + ' ...');

const code = await new Promise((ok, fail) => {
  const t = setTimeout(() => fail(new Error('timed out after 10 minutes')), 600_000);
  srv.on('request', (req, res) => {
    const u = new URL(req.url, redirect);
    if (u.pathname !== '/') { res.writeHead(404).end(); return; }
    const done = (msg) => { res.writeHead(200, { 'content-type': 'text/plain' }).end(msg + '\nYou can close this tab.'); };
    if (u.searchParams.get('state') !== state) { done('state mismatch: ignored'); return; }
    clearTimeout(t);
    if (u.searchParams.get('error')) { done('authorization refused: ' + u.searchParams.get('error')); fail(new Error(u.searchParams.get('error'))); return; }
    done('SafeBox received the authorization code.'); ok(u.searchParams.get('code'));
  });
});
srv.close();
const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: c.client_id, client_secret: c.client_secret, redirect_uri: redirect, code_verifier: verifier }).toString() });
const j = await r.json();
if (r.status !== 200 || !j.refresh_token) { console.error('token exchange failed: HTTP ' + r.status + ' ' + (j.error ?? '')); process.exit(1); }
const scopes = String(j.scope ?? '').split(/\s+/).filter(Boolean);
if (scopes.length !== 1 || scopes[0] !== GMAIL_SEND_SCOPE) { console.error('granted scope is not exactly gmail.send (' + scopes.join(' ') + '); refusing to store it'); process.exit(1); }
// CodeQL js/file-system-race: the existsSync check above is only an early, friendly refusal. writeGmailCredentialFile
// is an exclusive create (O_CREAT|O_EXCL, plus O_NOFOLLOW on POSIX), so a file or symlink planted after that check makes
// this fail instead of being overwritten or followed. It also refuses empty / oversized / control-character fields.
try { writeGmailCredentialFile(outAbs, { client_id: c.client_id, client_secret: c.client_secret, refresh_token: j.refresh_token, sender }); }
catch (e) { console.error('refusing to write credentials: ' + (e.code ?? e.message) + ' at ' + outAbs); process.exit(2); }
console.log('Stored gmail.send credentials (refresh token not shown) at ' + outAbs);
