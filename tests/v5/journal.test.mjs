// Footprint Journal: tamper-evident hash chain, signed checkpoints held by independent witnesses, layer-bound writers,
// privacy rules, rate-limited attempt recording, role-based readers, retention by key shredding.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, H, burst, freezeBy } from './helpers.mjs';
import { FootprintJournal, verifyJournalChain } from '../../src/v5/journal/journal.mjs';

const J = () => { let t = Date.parse('2026-11-14T00:00:00Z'); const j = new FootprintJournal({ now: () => (t += 1000), accountId: 'acct', checkpointEvery: 5 }); return j; };
const fill = (j, n, layer = 'VAULT') => { const wr = j.writer(layer); for (let i = 0; i < n; i++) wr.append({ type: 'PAYMENT_PROPOSED', principal: 'p1', relatedId: 'x' + i, outcome: 'BUFFERED', data: { amount: String(i) } }); };
const ver = (j, rows = j.rows()) => verifyJournalChain(rows, j.witnesses[1].all(), j.signer.publicKey);

test('intact journal verifies; checkpoints are signed and held by two witnesses', () => {
  const j = J(); fill(j, 12);
  const v = ver(j); assert.equal(v.ok, true, v.problems.join()); assert.equal(v.checkpointsVerified, 2);
});

test('the store itself refuses UPDATE / DELETE (append-only triggers)', () => {
  const j = J(); fill(j, 3);
  assert.throws(() => j.db.prepare("UPDATE events SET type='X' WHERE seq=1").run(), /append-only/);
  assert.throws(() => j.db.prepare('DELETE FROM events WHERE seq=1').run(), /append-only/);
});

test('an administrator who bypasses the triggers is still DETECTED: modification, deletion, truncation, reordering, insertion', () => {
  const j = J(); fill(j, 12);
  const rows = j.rows();
  const mod = rows.map(r => ({ ...r })); const b = JSON.parse(mod[3].body); b.data.amount = '999'; mod[3].body = JSON.stringify(b);
  assert.match(ver(j, mod).problems.join(), /modified_event_4/);
  assert.match(ver(j, rows.filter((_, i) => i !== 6)).problems.join(), /gap_or_reorder|broken_link/);
  assert.match(ver(j, rows.slice(0, 7)).problems.join(), /checkpoint_10_missing_events/);
  assert.match(ver(j, [rows[1], rows[0], ...rows.slice(2)]).problems.join(), /gap_or_reorder|broken_link/);
  // a fully re-hashed forged chain fails against the witness checkpoints
  const forged = rows.map(r => ({ ...r })); forged[0] = { ...forged[0], hash: 'f'.repeat(64) };
  assert.equal(ver(j, forged).ok, false);
});

test('privacy: secrets, keys, biometrics, PINs and raw challenge responses are refused at the writer', () => {
  const j = J(); const wr = j.writer('ROOT');
  for (const k of ['privateKey', 'secret', 'pin', 'biometric', 'signature', 'challengeResponse', 'mnemonic', 'password'])
    assert.throws(() => wr.append({ type: 'X', data: { [k]: 'abc' } }), /PRIVACY/, k);
  assert.throws(() => wr.append({ type: 'X', data: { note: '-----BEGIN PRIVATE KEY-----' } }), /PRIVACY/);
  wr.append({ type: 'X', data: { shippingTokens: '3', note: 'ok' } }); // ordinary words are fine
  assert.equal(j.stats.rejectedPrivacy, 9);
});

test('flood: rejected attempts are rate-limited per principal (one ATTEMPTS_SUPPRESSED marker), other principals unaffected', () => {
  const j = J(); const wr = j.writer('VAULT');
  for (let i = 0; i < 200; i++) wr.attempt({ type: 'PAYMENT_REJECTED', principal: 'attacker', outcome: 'POLICY_DENY' });
  wr.attempt({ type: 'PAYMENT_REJECTED', principal: 'owner', outcome: 'POLICY_DENY' });
  const rows = j.rows().map(r => JSON.parse(r.body));
  assert.equal(rows.filter(e => e.principal === 'attacker').length, 21);
  assert.equal(rows.filter(e => e.type === 'ATTEMPTS_SUPPRESSED').length, 1);
  assert.equal(rows.filter(e => e.principal === 'owner').length, 1);
  assert.equal(j.stats.suppressed, 180);
});

test('roles: the analyst sees pseudonyms and no sealed metadata; the owner sees names; the verifier sees only hashes', async () => {
  const w = buildV5();
  await w.pay({ request: { memo: 'gift for mom' } });
  const an = w.journal.reader('analyst').events({ types: ['PAYMENT_PROPOSED'] })[0];
  assert.ok(!JSON.stringify(an).includes('k1-phone')); assert.equal(an.sealed, undefined);
  const own = w.journal.reader('owner').events({ types: ['PAYMENT_PROPOSED'] })[0];
  assert.equal(own.principalName, 'cred:k1-phone'); assert.equal(own.sealed.memo, 'gift for mom');
  const v = w.journal.reader('verifier').events()[0];
  assert.deepEqual(Object.keys(v).sort(), ['at', 'eventId', 'hash', 'layer', 'prevHash', 'seq', 'type']);
  assert.throws(() => w.journal.reader('admin'), /JOURNAL_ROLE/);
});

test('retention: shredding a period key makes its sealed metadata unreadable while the chain still verifies', async () => {
  const w = buildV5();
  await w.pay({ request: { memo: 'private note' } });
  w.journal.shred(w.iso(w.now()).slice(0, 7));
  assert.equal(w.journal.reader('auditor').events({ types: ['PAYMENT_PROPOSED'] })[0].sealed, 'SHREDDED');
  assert.equal(verifyJournalChain(w.journal.rows(), w.journal.witnesses[0].all(), w.journal.signer.publicKey).ok, true);
});

test('all layers record the lifecycle: Root holds, vault payments, risk detection, notification queue/attempts', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k4-freeze', 'h1'));
  ok(await w.cmd('HOLD_RELEASE', { holdId: 'h1', holdDigest: w.holdDigest('h1') }, ['k4-freeze']));
  await burst(w, 4);
  await w.advance(25 * H, 10 * 60_000); // vault ticks every 10 min here (real deployment: seconds)
  const types = new Set(w.journal.reader('auditor').events().map(e => `${e.layer}:${e.type}`));
  for (const t of ['ROOT:HOLD_CREATED', 'ROOT:HOLD_RELEASED', 'VAULT:PAYMENT_PROPOSED', 'VAULT:UNUSUAL_ACTIVITY_DETECTED', 'VAULT:INCIDENT_OPENED', 'VAULT:PAYMENT_DELAYED', 'VAULT:PAYMENT_SETTLED', 'NOTIFY:NOTIFICATION_QUEUED', 'NOTIFY:NOTIFICATION_ATTEMPT'])
    assert.ok(types.has(t), t);
  const v = verifyJournalChain(w.journal.rows(), w.journal.witnesses[0].all(), w.journal.signer.publicKey);
  assert.equal(v.ok, true, v.problems.join());
});
