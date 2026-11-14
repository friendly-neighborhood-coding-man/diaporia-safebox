// Kill tests for mutations that survived the first V5 mutation run (docs/evidence/v5/mutations.json): each test pins a
// check that the main suites exercised only indirectly.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, T0, ok, deny, H, GLOBAL, release, rapidRequest, rapidVote, rapidActivate, burst } from './helpers.mjs';
import { buildCommand, commandDigest } from '../../src/v5/root/command.mjs';
import { V5_DOMAINS, newSigner5 } from '../../src/v5/common/v5.mjs';
import * as V5 from '../../src/v5/root/chain.mjs';
import { multiOwnerWorld } from '../../src/v5/kit.mjs';

const noApc = { authOpts: { apc: false } }; // the owner signs on the phone WITHOUT its protected-confirmation prompt (UV only)

test('CONFIRMED_OWNER_HOLD release needs a trusted confirmation; UV-only signers are refused', async () => {
  const w = buildV5();
  ok(await w.cmd('HOLD_CREATE', { holdId: 'ch-1', class: 'CONFIRMED_OWNER_HOLD', scope: GLOBAL, reason: 'travel lock', durationMs: String(24 * H) }, ['k2-laptop', 'k4-freeze']));
  assert.equal(w.frozen(), true);
  deny(await release(w, ['k2-laptop', 'k4-freeze'], 'ch-1', noApc), 'TRUSTED_CONFIRMATION_REQUIRED');
  assert.equal(w.frozen(), true);
  ok(await release(w, ['k2-laptop', 'k4-freeze'], 'ch-1'));
  assert.equal(w.frozen(), false);
});

test('VERIFIED_INCIDENT_FREEZE release with quorum + repair certificate still needs a trusted confirmation (multi-admin: all passkeys)', async () => {
  const w = buildV5({ ownerWorld: multiOwnerWorld({ t0: T0 }) });
  ok(await w.supervisorFreeze('inc-1'));
  const cert = () => ({ repair: w.owner.repairCert({ freezeId: 'inc-1', verdict: 'REPAIRED', exactReplay: 'DENIED_FOR_INVARIANT', mutations: 'ALL_DENIED', regression: 'PASS', legitimate: 'PASS', candidate: 'fix-1' }) });
  const r = await release(w, ['alice-admin', 'bob-admin'], 'inc-1', { attestation: cert, ...noApc });
  deny(r, 'TRUSTED_CONFIRMATION_REQUIRED');
  assert.equal(w.frozen(), true);
  ok(await release(w, ['alice-admin', 'bob-admin'], 'inc-1', { attestation: cert }));
  assert.equal(w.frozen(), false);
});

test('a consumed challenge grant cannot be reused, even inside a fresh action carrying the same approval', async () => {
  const w = buildV5();
  const a = w.action('FREEZE', { freezeId: 'f-1', reason: 'x', source: 'owner' });
  const aps = w.owner.authorize5(w.root.state, a, ['k4-freeze'], { at: w.now() });
  ok(await w.submit({ action: a, approvals: aps }));
  ok(await w.submit({ action: w.action('HOLD_RELEASE', { holdId: 'f-1', holdDigest: w.holdDigest('f-1') }), approvals: w.owner.authorize5(w.root.state, w.action('HOLD_RELEASE', { holdId: 'f-1', holdDigest: w.holdDigest('f-1') }), ['k4-freeze'], { at: w.now() }) }).then(() => ({ ok: true })));
  const again = await w.submit({ action: a, approvals: aps });
  assert.equal(again.ok, false);
  assert.match(again.error.code, /CHALLENGE_ALREADY_CONSUMED|NONCE|REPLAY|ACTION_REPLAYED/);
});

test('a Rapid-Use grant for k1 never removes anomaly delays of another flow (k2)', async () => {
  const w = buildV5();
  await burst(w, 4);
  ok(await rapidRequest(w, 'k1-phone', { incidentId: w.vault.incidents()[0].incident_id }));
  ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  const k2 = await burst(w, 6, { credId: 'k2-laptop' });
  assert.ok(k2.some(r => r.ok && r.result.anomaly === 'ANOMALY_PAYMENT_DELAY'), 'k2 burst must still be delayed');
  assert.equal(w.vault.v5payments().filter(p => p.cred_id === 'k2-laptop' && p.rapid_grant).length, 0);
});

test('F-V5-04: a forged approval with an otherwise invalid body gets the AUTHENTICATION error, never a business-rule error', async () => {
  const w = buildV5(); const forger = newSigner5('x');
  const body = { delegationId: 'dlg-f', delegateKey: forger.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: '1', cumulativeMaxYocto: '1', maxUses: '100000', expiresAt: '2030-01-01T00:00:00.000Z', revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] };
  const a = w.action('DELEGATION_GRANT', body); const s = V5.projectState(w.root.state, w.now());
  const grant = w.challenge.issue({ accountId: s.accountId, chainId: s.chainId, actionType: a.type, actionDigestHex: V5.actionDigest(a).toString('hex'), credId: 'k3-root-hw' });
  const { statement } = buildCommand(s, a, grant.statement, s.creds['k3-root-hw']);
  const r = await w.submit({ action: a, approvals: [{ credId: 'k3-root-hw', command: statement, grant, sig: forger.signDigest(V5_DOMAINS.COMMAND, commandDigest(statement)) }] });
  assert.equal(r.ok, false);
  assert.doesNotMatch(r.error.code, /DELEGATION_/, 'business rule leaked before authentication: ' + r.error.code);
  assert.match(r.error.code, /SIGNATURE|APPROVAL/);
});
