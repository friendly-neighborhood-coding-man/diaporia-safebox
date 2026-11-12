// WP3: durable, atomic single-use reservation across OS processes sharing one SQLite file.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { makeWorld, signMandate, proposal, ownerAuthorize, asAuthz, NEAR } from '../support/harness.mjs';

const CHILD = fileURLToPath(new URL('../support/race-child.mjs', import.meta.url));
function runChild(args) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ['--no-warnings', CHILD, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', d => out += d); p.stderr.on('data', d => err += d);
    p.on('close', code => code === 0 ? resolve(JSON.parse(out)) : reject(new Error(err)));
  });
}
function authorizedIntents(n, { maxTotal = 3n * NEAR } = {}) {
  const w = makeWorld();
  const svc = w.open();
  const m = signMandate(w.owners.owner_alice, { maxTotal, maxPer: NEAR });
  svc.registerMandate({ mandate: m.statement, signature: m.signature });
  const ids = [];
  for (let k = 0; k < n; k++) {
    const p = svc.propose(proposal());
    svc.authorize(p.intentId, asAuthz(ownerAuthorize(w.owners.owner_alice, svc.authorizationRequest(p.intentId), w.now())));
    ids.push(p.intentId);
  }
  // Child processes use the wall clock; make the shared row usable by them.
  return { w, svc, ids };
}

test('8 processes racing on one capability: exactly one reservation', async () => {
  const { w, svc, ids } = authorizedIntents(1);
  svc.store.close();
  const startAt = String(Date.now() + 400);
  const results = (await Promise.all(Array.from({ length: 8 }, () => runChild([w.dbPath, startAt, (100n * NEAR).toString(), ids[0]])))).flat();
  assert.equal(results.filter(r => r.ok).length, 1, JSON.stringify(results));
  assert.ok(results.filter(r => !r.ok).every(r => r.code === 'STATE_CONFLICT'));
  const s2 = w.open();
  assert.equal(s2.store.get(ids[0]).state, 'RESERVED');
  assert.equal(s2.store.journal(ids[0]).filter(j => j.to_state === 'RESERVED').length, 1);
  assert.ok(s2.store.verifyJournalChain().ok);
});

test('cumulative mandate ceiling holds under multi-process contention (5 x 1 NEAR, cap 3 NEAR)', async () => {
  const { w, svc, ids } = authorizedIntents(5, { maxTotal: 3n * NEAR });
  svc.store.close();
  const startAt = String(Date.now() + 400);
  // Every process tries every intent; the 3 NEAR ceiling (as signed in the mandate) is applied inside the write lock.
  const results = (await Promise.all(Array.from({ length: 5 }, () => runChild([w.dbPath, startAt, (3n * NEAR).toString(), ...ids])))).flat();
  const ok = results.filter(r => r.ok);
  assert.equal(ok.length, 3, JSON.stringify(results));
  assert.equal(new Set(ok.map(r => r.id)).size, 3);
  const s2 = w.open();
  assert.equal(s2.store.getMandate('m_alice').reserved_total, (3n * NEAR).toString());
});

test('journal is append-only and hash chained', () => {
  const { svc } = authorizedIntents(1);
  assert.throws(() => svc.store.db.exec("UPDATE journal SET actor='x'"), /append-only/);
  assert.throws(() => svc.store.db.exec('DELETE FROM journal'), /append-only/);
  assert.ok(svc.store.verifyJournalChain().ok);
});
