// V6 hardening P1.8 (issue #14): loopback / browser hardening of the Owner Console.
// Attacker capabilities: (a) a web page the owner visits that DNS-rebinds its own hostname to 127.0.0.1 (same-origin
// for the attacker's hostname, so it can send any request and read responses, but carries the attacker's Host/Origin and
// none of the console's host-scoped cookies); (b) arbitrary request bodies, paths, methods and headers (input fuzzing),
// with or without an owner session.
// Invariants: a request whose Host is not the console's own host is refused before routing; no fuzzed request reaches
// an unhandled exception (generic code ERROR) or changes any security state (Root, Vault, notify, console proposals).
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { connect } from 'node:net';
import { incidentWorld, consoleForWorld, client, ok } from './helpers6.mjs';
import { stateDigest } from './helpers6.mjs';

const get = (port, path, host) => new Promise((resolve, reject) => {
  const r = request({ host: '127.0.0.1', port, path, method: 'GET', headers: { host } }, (res) => { let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, body: b })); });
  r.on('error', reject); r.end();
});

test('P1.8-rebinding: the console refuses requests whose Host is not its own (DNS rebinding), and still serves its own host', async () => {
  const { w, locator } = await incidentWorld();
  const port = 47900 + Math.floor(Math.random() * 90);
  const c = consoleForWorld(w, { origin: `http://localhost:${port}` });
  const srv = await c.listen({ port });
  try {
    for (const host of [`rebind.attacker.example:${port}`, `attacker.example`, `localhost.attacker.example:${port}`, `127.0.0.1:${port + 1}`]) {
      const r = await get(port, '/e/' + locator, host);
      assert.equal(r.status, 421, `Host "${host}" was served: ${r.status}`);
    }
    // no Host at all (HTTP/1.0 from a raw socket; Node's client would fill one in)
    const raw = await new Promise((resolve) => { const sk = connect(port, '127.0.0.1', () => sk.write(`GET /e/${locator} HTTP/1.0\r\n\r\n`)); let b = ''; sk.on('data', (d) => { b += d; }); sk.on('end', () => resolve(b)); sk.on('error', () => resolve(b)); });
    assert.match(raw.split('\r\n')[0], / 421 /, 'a request without Host was served: ' + raw.split('\r\n')[0]);
    const okr = await get(port, '/e/' + locator, `localhost:${port}`);
    assert.equal(okr.status, 200);
    const loop = await get(port, '/e/' + locator, `127.0.0.1:${port}`);
    assert.equal(loop.status, 200, 'the loopback address of a localhost console is the same host');
  } finally { srv.close(); }
});

// deterministic PRNG (mulberry32) so a failing case is reproducible from its seed
const rng = (seed) => () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const WEIRD = () => [null, true, 0, -1, 1e308, NaN, '', 'x'.repeat(70_000), '\u0000', '\ud800', '../../etc', '<script>', '__proto__', { __proto__: { admin: true } }, [], [[]], { a: { b: { c: {} } } }, '0'.repeat(64), 'A'.repeat(86)];
function mutate(r, v, depth = 0) {
  const W = WEIRD();
  if (depth > 3 || v === null || typeof v !== 'object') return r() < 0.5 ? W[Math.floor(r() * W.length)] : v;
  const out = Array.isArray(v) ? [...v] : { ...v }; const keys = Object.keys(out);
  const k = keys.length ? keys[Math.floor(r() * keys.length)] : 'x';
  const op = r();
  if (op < 0.25) delete out[k]; else if (op < 0.5) out['extra' + Math.floor(r() * 9)] = W[Math.floor(r() * W.length)];
  else if (op < 0.75) out[k] = W[Math.floor(r() * W.length)]; else out[k] = mutate(r, out[k], depth + 1);
  return out;
}

test('P1.8-fuzz: 1500 fuzzed console requests (no session, and with a real owner session) never hit an unhandled exception or change security state', async () => {
  const { w, locator } = await incidentWorld();
  const c = consoleForWorld(w); const k = client(c);
  ok({ ok: (await k.login(w, 'k2-laptop')).ok });
  // valid shapes to start from (what the page would send)
  const pr = await k.post('/api/freeze/prepare', { locator }); assert.equal(pr.ok, true);
  const ap = w.owner.approvePrepared(w.root.state, pr, 'k2-laptop', { at: w.now(), noGate: true });
  const seeds = [
    ['/api/login/start', { credId: 'k2-laptop' }], ['/api/login/finish', { loginId: 'l'.repeat(32), webauthn: {} }],
    ['/api/freeze/prepare', { locator }], ['/api/freeze/confirm', { proposalId: pr.proposalId, confirm: pr.confirmPhrase, approval: { ...ap, gate: { statement: {}, sig: '' } } }],
    ['/api/command/prepare', { type: 'HOLD_RELEASE', body: { holdId: 'h', holdDigest: '0'.repeat(64) } }], ['/api/command/challenge', { bundleId: 'b' }],
    ['/api/command/sign', { bundleId: 'b', approval: ap }], ['/api/command/submit', { bundleId: 'b' }], ['/api/logout', {}],
  ];
  const before = stateDigest(w, null); const seqBefore = w.root.state.seq;
  const r = rng(1414); const unhandled = []; const accepted = [];
  for (let i = 0; i < 1500; i++) {
    const [path, body] = seeds[Math.floor(r() * seeds.length)];
    const withSession = r() < 0.6 && path !== '/api/logout';
    const fuzzBody = r() < 0.1 ? ['', '{', '[]', 'null', '"x"', '{"a":' + '['.repeat(5000)][Math.floor(r() * 7)] : JSON.stringify(mutate(r, body));
    const headers = withSession ? { origin: c.origin, 'content-type': 'application/json', cookie: k.cookie, 'x-safebox-csrf': k.csrf } : { origin: c.origin, 'content-type': 'application/json' };
    if (r() < 0.1) headers['content-type'] = ['text/plain', 'application/jsonx', ''][Math.floor(r() * 3)];
    const method = r() < 0.05 ? ['PUT', 'DELETE', 'GET', 'TRACE'][Math.floor(r() * 4)] : 'POST';
    const p = r() < 0.05 ? path + ['/', '?x=1', '/../x', '%00'][Math.floor(r() * 4)] : path;
    let out;
    try { out = await c.handle({ method, path: p, headers, body: fuzzBody }); } catch (e) { unhandled.push({ i, path, thrown: String(e?.message ?? e).slice(0, 80) }); continue; }
    const j = (() => { try { return JSON.parse(out.body); } catch { return null; } })();
    if (out.status >= 500 || j?.error?.code === 'ERROR') unhandled.push({ i, path, status: out.status, detail: j?.error?.detail });
    if (out.status === 200 && /freeze\/confirm|command\/(sign|submit)/.test(path)) accepted.push({ i, path });
  }
  assert.deepEqual(unhandled.slice(0, 5), [], `${unhandled.length} requests reached an unhandled exception`);
  assert.deepEqual(accepted, [], 'a fuzzed approval was accepted');
  assert.equal(w.root.state.seq, seqBefore, 'Root changed under fuzzing');
  assert.equal(stateDigest(w, null), before, 'Vault/notify state changed under fuzzing');
});
