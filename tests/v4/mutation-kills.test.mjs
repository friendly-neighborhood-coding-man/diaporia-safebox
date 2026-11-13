// Targeted tests added after mutation testing (docs/evidence/v4/mutations.json, first run): each pins one check that
// an earlier, broader test exercised only through an overlapping guard (quorum / action nonce / service pre-check).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV4 } from '../../src/v4/world.mjs';
import { openCaseV4, evidence4 as E, openGov, govVote, govTally } from '../../src/v4/recovery/sim.mjs';
import { intentDigest, INTENT_FIELDS, verifyIntentApproval } from '../../src/v4/intent/intent.mjs';
import { V4_DOMAINS, signDigestWith } from '../../src/v4/common/v4.mjs';
import { H, ok, deny, cs } from './helpers.mjs';

const MAJ = ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'];
const resignK3 = (w, ap) => { ap.sig = signDigestWith(w.owner.dev('k3-root-hw').signer, V4_DOMAINS.INTENT, intentDigest(ap.intent)); return ap; };
const code = (fn) => { try { fn(); return null; } catch (e) { return e.code ?? e.message; } };

test('INTENT EQUALITY: a validly signed approval for a different intent (fresh grant, full quorum) => INTENT_MISMATCH', async () => {
  const w = buildV4();
  for (const f of INTENT_FIELDS) {
    if (f === 'rootSeq' || f === 'screenDigest') continue; // rootSeq: older allowed if authority unchanged; screenDigest: screen-evidence rules
    const a = w.owner.action(w.view(), 'REVOKE', { credId: 'k4-freeze', reason: 'device lost' });
    const aps = w.owner.authorize(w.root.state, a, ['k1-phone', 'k3-root-hw']);
    const x = aps[1]; const v = x.intent[f];
    x.intent[f] = Array.isArray(v) ? [...v, 'ff'.repeat(32)] : (typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) ? 'cd'.repeat(32) : v + 'x');
    deny(await w.submit({ action: a, approvals: [aps[0], resignK3(w, x)] }), 'INTENT_MISMATCH');
  }
});

test('CHALLENGE SINGLE USE: the same grant cannot be verified twice against one state (independent of the action nonce)', async () => {
  const w = buildV4();
  const a = w.owner.action(w.view(), 'REVOKE', { credId: 'k4-freeze', reason: 'x' });
  const [ap] = w.owner.authorize(w.root.state, a, ['k3-root-hw']);
  const s = structuredClone(w.root.state);
  assert.equal(code(() => verifyIntentApproval(s, a, ap, s.creds['k3-root-hw'], w.now())), null);
  assert.equal(code(() => verifyIntentApproval(s, a, ap, s.creds['k3-root-hw'], w.now())), 'CHALLENGE_ALREADY_CONSUMED');
});

test('ORC DIGEST BINDING: an ORC authorization recorded for another case digest never reconstitutes', async () => {
  const w = buildV4();
  ok((await openCaseV4(w, { lost: MAJ, full: true })).r);
  ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  ok(await E.consent(w, 'k1-phone'));
  for (const g of ['g1', 'g2', 'g3']) ok(await E.guardian(w, g));
  for (const ch of Object.keys(w.root.state.channels)) ok(await E.ack(w, ch));
  ok(await E.orcAuthorize(w));
  await w.advance(73 * H - (w.now() - cs(w).openedAt), H);
  const real = cs(w).v4.ownerAuth.caseDigest;
  // defence in depth: corrupt the recorded binding (a replan already clears ownerAuth, so this models any future path
  // that changes the case digest without clearing it)
  w.root.state.case.v4.ownerAuth.caseDigest = 'ee'.repeat(32);
  const r = await w.recovery.tryComplete(w.root.state); await w.pump();
  assert.equal(r.ok, false); assert.equal(r.code, 'OWNER_AUTHORIZATION_REQUIRED');
  w.root.state.case.v4.ownerAuth.caseDigest = real;
  const r2 = await w.recovery.tryComplete(w.root.state); await w.pump();
  assert.equal(r2.ok, true, JSON.stringify(r2));
});

test('GOV SECURITY DELAY: a direct GOV_CASE_EXECUTE before executeAfter is refused by the Root itself', async () => {
  const w = buildV4();
  ok((await openGov(w, { accused: ['g1'] })).r);
  const g = () => w.root.state.v4.gcase;
  for (const v of g().electorate) ok(await govVote(w, v));
  ok(await govTally(w)); assert.equal(g().state, 'APPROVED');
  deny(await w.submitRaw('GOV_CASE_EXECUTE', { gcaseId: g().gcaseId, gcaseDigest: g().digest }, { intended: false }), 'GOV_SECURITY_DELAY_OPEN');
  await w.advance(g().executeAfter - w.now() - 2 * H, H);
  deny(await w.submitRaw('GOV_CASE_EXECUTE', { gcaseId: g().gcaseId, gcaseDigest: g().digest }, { intended: false }), 'GOV_SECURITY_DELAY_OPEN');
});
