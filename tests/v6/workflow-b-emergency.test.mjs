// Workflow B: Gmail/outbox incident alert -> navigation-only Emergency Freeze link -> trusted SafeBox Owner Console ->
// independent owner sign-in -> canonical incident + GLOBAL scope from trusted state -> explicit confirm + fresh device
// approval (fingerprint gate for fingerprint-only creds) -> single-use exact FREEZE -> Root + Vault hold -> Vault refuses
// settlement -> recovery through the unchanged V5 hold-release rules. Adversarial cases from the mission section 5.
import test from 'node:test';
import assert from 'node:assert/strict';
import { incidentWorld, client, consoleForWorld, stateDigest, CONFIRM_PHRASE, ok, MIN, H } from './helpers6.mjs';
import { verifyWorld6 } from '../../src/v6/supervisor/verifier.mjs';
import { emergencyReason } from '../../src/v6/emergency/console.mjs';

test('B-honest: link -> sign-in -> canonical incident -> exact FREEZE -> Root and Vault frozen -> settlement refused -> verifier clean -> recovery', async () => {
  const { w, incidentId, locator, outboxId } = await incidentWorld();
  assert.match(locator, /^l[0-9a-f]{32}$/);
  const body = w.notify.messageBody(outboxId);
  assert.ok(body.includes(`https://safebox.local/e/${locator}`));
  assert.ok(!/approve|token|sig=|key=/i.test(body.split('\n').filter(l => l.includes('http')).join('\n')), 'link line carries no authority');
  const c = consoleForWorld(w); const k = client(c);
  const page = await k.get('/e/' + locator);
  assert.equal(page.status, 200); assert.equal(page.headers['cache-control'], 'no-store'); assert.ok(!page.body.includes(incidentId), 'static page embeds no incident data');
  ok({ ok: (await k.login(w, 'k2-laptop')).ok });
  const inc = (await k.get('/api/incident?locator=' + locator)).json;
  assert.equal(inc.incident.incidentId, incidentId); assert.equal(inc.freeze.rootFrozen, false); assert.equal(inc.freezeScope.kind, 'GLOBAL');
  const { pr, cf } = await k.freeze(w, 'k2-laptop', { locator });
  assert.equal(pr.gateRequired, true); assert.equal(pr.action.body.reason, emergencyReason(incidentId)); assert.equal(pr.scope, 'GLOBAL');
  assert.equal(cf.ok, true, JSON.stringify(cf.error)); assert.equal(cf.rootFrozen, true); assert.equal(cf.vaultFrozen, true); assert.equal(cf.holdClass, 'PROVISIONAL_HOLD');
  const r = await w.pay({ credId: 'k1-phone' }); assert.equal(r.ok, false); assert.equal(r.error.code, 'FREEZE_ACTIVE');
  await w.advance(30 * MIN);
  assert.ok(w.vault.v5payments().filter(p => p.cred_id === 'k1-phone').every(p => p.state !== 'SETTLED' || p.settled_at < Date.parse(pr.action.issuedAt)), 'nothing settles while frozen');
  const v = await verifyWorld6(w); assert.equal(v.ok, true, JSON.stringify(v.v6)); assert.equal(v.v6.emergency.freezes, 1);
  // recovery: the hold's own (still valid) issuer releases it through direct entry (V5 provenance rule, fingerprint gate)
  ok({ ok: (await k.login(w, 'k2-laptop')).ok });
  const rel = await k.command(w, 'HOLD_RELEASE', { holdId: cf.holdId }, [{ cl: k, credId: 'k2-laptop' }]);
  assert.equal(rel.ok, true, JSON.stringify(rel.error)); assert.equal(rel.freeze.rootFrozen, false);
  assert.equal(w.frozen(), false);
  ok(await w.pay({ credId: 'k2-laptop' }));
});

test('B-scanner: GET / HEAD / preview / scanner visits of the link and the API change NO state and consume nothing', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c);
  const before = stateDigest(w, c);
  for (const p of ['/e/' + locator, '/e/' + locator + '?utm=x', '/e/not-a-locator', '/', '/app', '/api/incident?locator=' + locator, '/api/status', '/api/freeze/confirm', '/robots.txt'])
    for (const m of ['GET', 'HEAD']) await c.handle({ method: m, path: p, headers: { 'user-agent': 'SafeLinks-Scanner/1.0' } });
  assert.equal(stateDigest(w, c), before);
  assert.equal(w.notify.locators.resolve(locator).ok, true, 'locator is never consumed');
  assert.equal(w.frozen(), false);
  const bad = await k.get('/api/incident?locator=' + locator); assert.equal(bad.status, 401); // nothing without an owner session
  const pg = await k.get('/e/zzz'); assert.ok(pg.body.includes('not a valid SafeBox link'));
});

test('B-email: the email (or a forwarded copy) cannot freeze, approve or sign in: the locator alone authorizes nothing', async () => {
  const { w, locator, incidentId } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c);
  assert.equal((await k.post('/api/freeze/prepare', { locator })).error.code, 'NOT_AUTHENTICATED');
  assert.equal((await k.post('/api/freeze/confirm', { proposalId: locator, confirm: CONFIRM_PHRASE })).error.code, 'NOT_AUTHENTICATED');
  assert.equal((await k.post('/api/login/finish', { loginId: locator })).error.code, 'LOGIN_UNKNOWN');
  // forwarded mail: the recipient has the link but no enrolled device (an unknown authenticator) -> cannot sign in
  const st = await k.post('/api/login/start', { credId: 'k2-laptop' });
  const { SoftAuthenticator } = await import('../../src/v3/webauthn/soft-authenticator.mjs');
  const mallory = new SoftAuthenticator({ label: 'mallory' });
  const fake = mallory.assert({ rpId: w.owner.rp.rpId, origin: w.owner.rp.origin, challenge: Buffer.from(st.challengeHex, 'hex') });
  assert.match((await k.post('/api/login/finish', { loginId: st.loginId, webauthn: fake })).error.code, /WEBAUTHN_CREDENTIAL_MISMATCH/);
  assert.equal(w.frozen(), false); assert.ok(incidentId);
});

test('B-csrf: POSTs need the exact Origin, JSON, the session cookie and the CSRF token (cross-site form / missing token fail before any effect)', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c);
  assert.equal((await k.login(w, 'k2-laptop')).ok, true);
  const before = stateDigest(w, c);
  const cases = [
    [{ origin: 'https://evil.example' }, 'ORIGIN_REJECTED'], [{ origin: '' }, 'ORIGIN_REJECTED'], [{ origin: 'https://safebox.local.evil.example' }, 'ORIGIN_REJECTED'],
    [{ 'sec-fetch-site': 'cross-site' }, 'CROSS_SITE_REQUEST'], [{ 'content-type': 'application/x-www-form-urlencoded' }, 'CONTENT_TYPE_NOT_JSON'],
    [{ 'x-safebox-csrf': 'f'.repeat(64) }, 'CSRF_TOKEN_INVALID'], [{ cookie: '' }, 'NOT_AUTHENTICATED'],
  ];
  for (const [h, code] of cases) { const r = JSON.parse((await k.raw('POST', '/api/freeze/prepare', { locator }, h)).body); assert.equal(r.error.code, code, JSON.stringify(h)); }
  assert.equal(JSON.parse((await k.raw('POST', '/api/freeze/prepare', 'locator=' + locator)).body).error.code, 'BODY_NOT_JSON');
  assert.equal((await c.handle({ method: 'PUT', path: '/api/freeze/prepare', headers: {} })).status, 405);
  assert.equal(stateDigest(w, c), before);
});

test('B-phishing: an assertion made on a look-alike origin, or for another RP, is refused; the link origin is only the owner-signed one', async () => {
  const { w } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c);
  assert.match((await k.login(w, 'k2-laptop', { origin: 'https://safebox-login.example' })).error.code, /WEBAUTHN_ORIGIN_MISMATCH/);
  assert.match((await k.login(w, 'k2-laptop', { rpId: 'safebox-login.example' })).error.code, /WEBAUTHN_RPID_MISMATCH/);
  assert.match((await k.login(w, 'k2-laptop', { uv: false })).error.code, /WEBAUTHN_NO_USER_VERIFICATION/);
  assert.equal(w.notify.emergencyOrigin, w.owner.policy6.emergency.origin);
  assert.throws(() => consoleForWorld(w, { origin: 'javascript:alert(1)' }), /CONSOLE_ORIGIN_INVALID/);
});

test('B-replay: login, proposal, approval and Root challenge are all single-use', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c);
  const st = await k.post('/api/login/start', { credId: 'k2-laptop' });
  const as = w.owner.loginAssertion('k2-laptop', st.challengeHex);
  assert.equal((await k.post('/api/login/finish', { loginId: st.loginId, ...as })).ok, true);
  assert.equal((await k.post('/api/login/finish', { loginId: st.loginId, ...as })).error.code, 'LOGIN_ALREADY_USED');
  const st2 = await k.post('/api/login/start', { credId: 'k2-laptop' });
  assert.match((await k.post('/api/login/finish', { loginId: st2.loginId, ...as })).error.code, /WEBAUTHN_CHALLENGE_MISMATCH/, 'old assertion for a new login');
  assert.equal((await k.login(w, 'k2-laptop')).ok, true);
  const { pr, ap, cf } = await k.freeze(w, 'k2-laptop', { locator });
  assert.equal(cf.ok, true);
  assert.equal((await k.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm: CONFIRM_PHRASE, approval: ap })).error.code, 'PROPOSAL_ALREADY_USED');
  const pr2 = await k.post('/api/freeze/prepare', { locator });
  assert.equal((await k.post('/api/freeze/confirm', { proposalId: pr2.proposalId, confirm: CONFIRM_PHRASE, approval: ap })).error.code, 'APPROVAL_NOT_FOR_PREPARED_COMMAND');
  const raw = await w.submit({ action: pr.action, approvals: [ap] }); assert.equal(raw.ok, false); assert.match(raw.error.code, /CHALLENGE_ALREADY_CONSUMED|ACTION_REPLAY|HOLD_EXISTS|ALREADY/);
});

test('B-wrong-incident: unknown / malformed / mismatched incidents are refused; the reason is fixed by the console, not the client', async () => {
  const { w, locator, incidentId } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
  assert.equal((await k.post('/api/freeze/prepare', { incidentId: 'inc-' + 'ab'.repeat(12) })).error.code, 'INCIDENT_UNKNOWN');
  assert.equal((await k.post('/api/freeze/prepare', { incidentId: 'x; DROP TABLE' })).error.code, 'INCIDENT_ID_FORMAT');
  assert.equal((await k.post('/api/freeze/prepare', { incidentId: 'inc-' + 'ab'.repeat(12), locator })).error.code, 'LOCATOR_INCIDENT_MISMATCH');
  assert.equal((await k.post('/api/freeze/prepare', { locator: 'l' + '0'.repeat(32) })).error.code, 'LOCATOR_UNKNOWN');
  const pr = await k.post('/api/freeze/prepare', { incidentId, reason: 'attacker text', scope: 'CREDENTIAL' });
  assert.equal(pr.action.body.reason, emergencyReason(incidentId)); assert.equal(pr.scope, 'GLOBAL');
  assert.equal((await k.post('/api/command/prepare', { type: 'FREEZE', body: { reason: emergencyReason('inc-' + 'cd'.repeat(12)) } })).error.code, 'USE_EMERGENCY_FREEZE_FLOW');
});

test('B-substitution: a compromised console/page that alters the action or statement is caught by the device (and by Root)', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
  const pr = await k.post('/api/freeze/prepare', { locator });
  // page swaps the shown text / action body (e.g. a HOLD on a different scope): the device rebuilds from its own Root replica
  const swapped = { ...pr, action: { ...pr.action, body: { ...pr.action.body, reason: 'benign' } } };
  assert.equal(w.owner.approvePrepared(w.root.state, swapped, 'k2-laptop', { at: w.now() }), null);
  assert.equal(w.owner.gateErrors.at(-1).code, 'PREPARED_GRANT_MISMATCH');
  const st = { ...pr, command: { ...pr.command, financialScope: 'none' } };
  assert.equal(w.owner.approvePrepared(w.root.state, st, 'k2-laptop', { at: w.now() }), null);
  assert.equal(w.owner.gateErrors.at(-1).code, 'PREPARED_COMMAND_MISMATCH');
  // a device that signs a tampered statement is refused by the console (not the prepared command) and by Root
  const bad = w.owner.approvePrepared(w.root.state, pr, 'k2-laptop', { at: w.now(), tamper: (s) => ({ ...s, affectedResources: ['credential:k1-phone'] }) });
  assert.equal((await k.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm: CONFIRM_PHRASE, approval: bad })).error.code, 'APPROVAL_NOT_FOR_PREPARED_COMMAND');
  // approval from a DIFFERENT credential for this proposal
  const k1 = client(c); await k1.login(w, 'k1-phone'); const pr1 = await k1.post('/api/freeze/prepare', { locator });
  const ap1 = w.owner.approvePrepared(w.root.state, pr1, 'k1-phone', { at: w.now() });
  assert.equal((await k.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm: CONFIRM_PHRASE, approval: ap1 })).error.code, 'APPROVAL_WRONG_CREDENTIAL');
  // session B cannot confirm session A's proposal
  assert.equal((await k1.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm: CONFIRM_PHRASE, approval: ap1 })).error.code, 'PROPOSAL_NOT_FOR_THIS_SESSION');
  assert.equal(w.frozen(), false);
});

test('B-fingerprint: no gate / PIN only / no match / lockout / timeout / unsupported sensor -> no FREEZE, and never a silent PIN substitute', async () => {
  for (const outcome of ['PIN_ONLY', 'NO_MATCH', 'LOCKOUT', 'TIMEOUT', 'CANCELLED']) {
    const { w, locator } = await incidentWorld();
    const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
    w.gates['k2-laptop'].next(outcome);
    const { ap } = await k.freeze(w, 'k2-laptop', { locator });
    assert.equal(ap, null, outcome); assert.equal(w.frozen(), false);
  }
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
  const { pr, cf } = await k.freeze(w, 'k2-laptop', { locator, approve: { noGate: true } }); // a client that skips the gate
  assert.match(cf.error.code, /ROOT_REJECTED:FINGERPRINT_GATE_REQUIRED/); assert.equal(w.frozen(), false);
  assert.equal(c.proposals.get(pr.proposalId).state, 'REJECTED');
  const { w: w2, locator: l2 } = await incidentWorld({ noGateDevice: ['k2-laptop'] }); // sensor absent: fail closed
  const k2 = client(consoleForWorld(w2)); await k2.login(w2, 'k2-laptop');
  const r2 = await k2.freeze(w2, 'k2-laptop', { locator: l2 });
  assert.equal(r2.ap, null); assert.equal(w2.owner.gateErrors.at(-1).code, 'FINGERPRINT_ONLY_UNSUPPORTED');
  // the UV-only phone (PIN fallback possible) can still freeze: assurance is per credential and reported as such
  const k1 = client(consoleForWorld(w2)); await k1.login(w2, 'k1-phone');
  const r1 = await k1.freeze(w2, 'k1-phone', { locator: l2 }); assert.equal(r1.cf.ok, true); assert.equal(r1.pr.gateRequired, false);
});

test('B-confirm/expiry/epoch: no confirm phrase -> nothing; expired proposal; session dies on Epoch or credential change', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
  const pr = await k.post('/api/freeze/prepare', { locator });
  const ap = w.owner.approvePrepared(w.root.state, pr, 'k2-laptop', { at: w.now() });
  for (const confirm of [undefined, '', 'yes', 'freeze everything', true]) assert.equal((await k.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm, approval: ap })).error.code, 'EXPLICIT_CONFIRMATION_REQUIRED');
  assert.equal(w.frozen(), false); assert.equal(c.proposals.get(pr.proposalId).state, 'PREPARED');
  await w.advance(3 * MIN);
  assert.equal((await k.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm: CONFIRM_PHRASE, approval: ap })).error.code, 'PROPOSAL_EXPIRED');
  await w.advance(10 * MIN);
  assert.equal((await k.post('/api/freeze/prepare', { locator })).error.code, 'SESSION_EXPIRED');
  // suspension of the signed-in credential ends its session
  await k.login(w, 'k2-laptop');
  ok(await w.cmd('SUSPEND', { credId: 'k2-laptop', reason: 'lost laptop' }, ['k1-phone']));
  assert.equal((await k.post('/api/freeze/prepare', { locator })).error.code, 'SESSION_CREDENTIAL_OR_EPOCH_CHANGED');
});

test('B-unfreeze/recovery: release needs every valid party (non-party refused); unsupported command types refused; Root decides quorum', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k2 = client(c); await k2.login(w, 'k2-laptop');
  const { cf } = await k2.freeze(w, 'k2-laptop', { locator }); assert.equal(cf.ok, true);
  const k1 = client(c); await k1.login(w, 'k1-phone');
  const r = await k1.command(w, 'HOLD_RELEASE', { holdId: cf.holdId }, [{ cl: k1, credId: 'k1-phone' }]);
  assert.match(r.error.code, /ROOT_REJECTED:(RELEASE_NEEDS_EVERY_VALID_PARTY|RELEASE_SIGNER_NOT_A_PARTY)/);
  for (const type of ['ROTATE', 'ENROLL', 'PURPOSE_UPDATE', 'RECOVERY_COMPLETE', 'UNFREEZE', 'DELEGATION_GRANT']) assert.equal((await k1.post('/api/command/prepare', { type, body: {} })).error.code, 'COMMAND_NOT_AVAILABLE_HERE', type);
  assert.equal(w.frozen(), true);
  // a bundle is single-use too
  const rel = await k2.command(w, 'HOLD_RELEASE', { holdId: cf.holdId }, [{ cl: k2, credId: 'k2-laptop' }]); assert.equal(rel.ok, true);
  assert.equal(w.frozen(), false);
});

test('B-forged freeze: a FREEZE naming an incident the Risk Engine never opened is flagged by the independent verifier', async () => {
  const { w } = await incidentWorld();
  ok(await w.cmd('FREEZE', { freezeId: 'ef-forged', reason: emergencyReason('inc-' + 'ee'.repeat(12)), source: 'owner' }, ['k1-phone']));
  ok(await w.cmd('FREEZE', { freezeId: 'ef-malformed', reason: 'EMERGENCY_FREEZE incident=please-click-here', source: 'owner' }, ['k2-laptop']));
  const v = await verifyWorld6(w);
  assert.equal(v.ok, false);
  assert.deepEqual(v.v6.emergency.violations.map(x => x.code).sort(), ['EMERGENCY_FREEZE_REASON_MALFORMED', 'EMERGENCY_FREEZE_UNKNOWN_INCIDENT']);
});

test('B-restart/outage: the hold survives Root and Vault restarts; console sessions do not (re-authentication required)', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
  const { cf } = await k.freeze(w, 'k2-laptop', { locator }); assert.equal(cf.ok, true);
  w.restartRoot(); w.restartVault(); await w.pump();
  assert.equal(w.frozen(), true);
  const r = await w.pay({ credId: 'k1-phone' }); assert.equal(r.error.code, 'FREEZE_ACTIVE');
  const c2 = consoleForWorld(w); const kk = client(c2); kk.cookie = k.cookie; kk.csrf = k.csrf;
  assert.equal((await kk.post('/api/freeze/prepare', { locator })).error.code, 'NOT_AUTHENTICATED');
});

test('B-concurrency: two confirms of one proposal race -> exactly one submission', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c); await k.login(w, 'k2-laptop');
  const pr = await k.post('/api/freeze/prepare', { locator });
  const ap = w.owner.approvePrepared(w.root.state, pr, 'k2-laptop', { at: w.now() });
  const body = { proposalId: pr.proposalId, confirm: CONFIRM_PHRASE, approval: ap };
  const rs = await Promise.all([k.post('/api/freeze/confirm', body), k.post('/api/freeze/confirm', body), k.post('/api/freeze/confirm', body)]);
  assert.equal(rs.filter(r => r.ok).length, 1); assert.ok(rs.filter(r => !r.ok).every(r => r.error.code === 'PROPOSAL_ALREADY_USED'));
});

test('B-http: the real HTTP listener serves the page with no-store and refuses cross-origin POSTs', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w, { origin: 'http://127.0.0.1:1' });
  const srv = await c.listen({ port: 0 }); const port = srv.address().port;
  try {
    const g = await fetch(`http://127.0.0.1:${port}/e/${locator}`); assert.equal(g.status, 200); assert.equal(g.headers.get('cache-control'), 'no-store');
    assert.match(g.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    const p = await fetch(`http://127.0.0.1:${port}/api/login/start`, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: '{"credId":"k2-laptop"}' });
    assert.equal(p.status, 403); assert.equal((await p.json()).error.code, 'ORIGIN_REJECTED');
  } finally { srv.close(); }
});
