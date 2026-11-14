// V6 hardening P1.6 (issue #14): availability of the Owner Console under an unauthenticated request flood.
// Attacker capability: any local process (it can forge the Origin header) or a page the console's origin serves can call
// POST /api/login/start without a session, as fast as it likes, for the owner's own credential id.
// Invariants: console memory stays bounded (pending logins, audit log); the owner can still log in right after the
// flood (their login is started and finished within seconds); the flood changes no security state.
import test from 'node:test';
import assert from 'node:assert/strict';
import { incidentWorld, consoleForWorld, client } from './helpers6.mjs';

test('P1.6-login-flood: 20 000 unauthenticated login starts keep console memory bounded and the owner can still log in', async () => {
  const { w } = await incidentWorld();
  const c = consoleForWorld(w); const attacker = client(c);
  const seq = w.root.state.seq;
  for (let i = 0; i < 20_000; i++) await attacker.raw('POST', '/api/login/start', { credId: 'k2-laptop' });
  assert.ok(c.logins.size <= 1024, `pending logins grew to ${c.logins.size}`);
  assert.ok(c.audit.length <= 5000, `audit log grew to ${c.audit.length}`);
  // the owner, right after (and with the flood still in the pending table), logs in normally
  const owner = client(c);
  const r = await owner.login(w, 'k2-laptop'); assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(w.root.state.seq, seq);
});

test('P1.6-login-race: a flood running BETWEEN the owner\'s login start and finish cannot evict the owner\'s pending login below the cap', async () => {
  const { w } = await incidentWorld();
  const c = consoleForWorld(w); const attacker = client(c); const owner = client(c);
  const st = await owner.post('/api/login/start', { credId: 'k2-laptop' }); assert.equal(st.ok, true);
  for (let i = 0; i < 1000; i++) await attacker.raw('POST', '/api/login/start', { credId: 'k2-laptop' });
  const fin = await owner.post('/api/login/finish', { loginId: st.loginId, ...w.owner.loginAssertion('k2-laptop', st.challengeHex) });
  assert.equal(fin.ok, true, 'owner login evicted by fewer than cap requests: ' + JSON.stringify(fin.error));
});

test('P1.6-residual: more than PENDING_LOGINS_MAX starts between the owner\'s start and finish evict the owner\'s pending login (fails closed; the owner retries)', async () => {
  const { PENDING_LOGINS_MAX } = await import('../../src/v6/emergency/console.mjs');
  const { w } = await incidentWorld();
  const c = consoleForWorld(w); const attacker = client(c); const owner = client(c);
  const st = await owner.post('/api/login/start', { credId: 'k2-laptop' });
  for (let i = 0; i < PENDING_LOGINS_MAX + 10; i++) await attacker.raw('POST', '/api/login/start', { credId: 'k2-laptop' });
  const fin = await owner.post('/api/login/finish', { loginId: st.loginId, ...w.owner.loginAssertion('k2-laptop', st.challengeHex) });
  assert.equal(fin.ok, false); assert.equal(fin.error.code, 'LOGIN_UNKNOWN');
  assert.equal((await owner.login(w, 'k2-laptop')).ok, true, 'a fresh login after the burst works');
});
