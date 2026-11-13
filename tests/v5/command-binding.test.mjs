// Mission 1: every authority-bearing V5 operation is bound to one canonical Command Statement; V4 operations inside V5
// must carry V4 AuthorizationIntents; bare action-digest approvals are never accepted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, GLOBAL, freezeBy } from './helpers.mjs';
import { COMMAND_FIELDS, commandDigest } from '../../src/v5/root/command.mjs';
import { projectState } from '../../src/v5/root/chain.mjs';

const freezeAction = (w, id = 'f1') => w.action('FREEZE', { freezeId: id, reason: 'x', source: 'owner' });

test('statement binds every required field (protocol, account, chain, credential, role, command, params, Purpose, matrix, epoch, root state, resources, limits, nonce, expiry, usage, level)', async () => {
  const w = buildV5();
  const a = freezeAction(w);
  const ap = w.owner.approveCommand(w.root.state, a, 'k1-phone', { at: w.now() });
  for (const k of ['protocol', 'accountId', 'chainId', 'credId', 'role', 'commandType', 'actionDigest', 'paramsDigest', 'purposeId', 'purposeVersion', 'matrixVersion', 'epoch', 'rootSeq',
    'authorityDigest', 'affectedResources', 'caseRef', 'financialScope', 'operationId', 'usageLimit', 'requiredLevel', 'challengeNonce', 'issuedAt', 'expiresAt']) assert.ok(COMMAND_FIELDS.includes(k), k);
  assert.equal(ap.command.commandType, 'FREEZE');
  assert.equal(ap.command.usageLimit, '1');
  assert.equal(ap.command.credId, 'k1-phone');
  ok(await w.submit({ action: a, approvals: [ap] }));
});

for (const field of ['accountId', 'chainId', 'credId', 'role', 'commandType', 'actionDigest', 'paramsDigest', 'purposeVersion', 'matrixVersion', 'epoch', 'authorityDigest', 'affectedResources', 'financialScope', 'requiredLevel', 'expiresAt', 'usageLimit'])
  test(`a signed statement with a modified ${field} is rejected`, async () => {
    const w = buildV5();
    const a = freezeAction(w);
    const ap = w.owner.approveCommand(w.root.state, a, 'k1-phone', { at: w.now(), tamper: (st) => { st[field] = Array.isArray(st[field]) ? [...st[field], 'x'] : field === 'usageLimit' ? '2' : field === 'requiredLevel' ? 'NONE' : String(st[field]) + 'x'; } });
    deny(await w.submit({ action: a, approvals: [ap] }), 'COMMAND_|GRANT|CHALLENGE|EXPIRE|ROLE|CREDENTIAL|BAD');
  });

test('cross-command substitution: an approval for FREEZE cannot authorize HOLD_RELEASE / CONTEST / RAPID approve', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k2-laptop', 'h2'));
  ok(await freezeBy(w, 'k1-phone', 'h1'));
  const a = freezeAction(w, 'f9');
  const ap = w.owner.approveCommand(w.root.state, a, 'k2-laptop', { at: w.now() });
  const rel = w.action('HOLD_RELEASE', { holdId: 'h2', holdDigest: w.holdDigest('h2') });
  deny(await w.submit({ action: rel, approvals: [ap] }), 'GRANT|COMMAND_MISMATCH|ACTION');
  const con = w.action('CONTEST_PROTECTIVE_HOLD', { contestId: 'c1', holdIds: ['h1'], suspectCredId: 'k1-phone', reason: 'x' });
  deny(await w.submit({ action: con, approvals: [ap, w.owner.approveCommand(w.root.state, a, 'orc-1', { at: w.now() })] }), 'GRANT|COMMAND_MISMATCH|ACTION');
  assert.equal(w.frozen(), true);
});

test('replay: the same approved request cannot be applied twice (nonce + one-time challenge)', async () => {
  const w = buildV5();
  const a = freezeAction(w);
  const req = { action: a, approvals: [w.owner.approveCommand(w.root.state, a, 'k1-phone', { at: w.now() })] };
  ok(await w.submit(req));
  deny(await w.submit(req), 'ACTION_REPLAY|CHALLENGE');
  // re-wrapped in a fresh action header: the statement still names the old action digest and a used challenge
  const a2 = freezeAction(w, 'f2');
  deny(await w.submit({ action: a2, approvals: req.approvals }), 'GRANT|COMMAND|CHALLENGE|ACTION');
});

test('stale authority: an approval built before another transition fails (authority digest / root state binding)', async () => {
  const w = buildV5();
  const a = w.action('HOLD_CREATE', { holdId: 'm1', class: 'PROVISIONAL_HOLD', scope: { kind: 'MERCHANT', target: 'merchant-a.mock' }, reason: 'x', durationMs: String(H) });
  const ap = w.owner.approveCommand(w.root.state, a, 'k2-laptop', { at: w.now() });
  ok(await freezeBy(w, 'k1-phone', 'h1'));                  // the authority state changes in between
  deny(await w.submit({ action: a, approvals: [ap] }), 'COMMAND_MISMATCH');
});

test('expired grant / statement is rejected', async () => {
  const w = buildV5();
  const a = freezeAction(w);
  const ap = w.owner.approveCommand(w.root.state, a, 'k1-phone', { at: w.now() });
  w.clock.advance(5 * 60_000);
  deny(await w.submit({ action: a, approvals: [ap] }), 'EXPIRED|CHALLENGE|GRANT');
});

test('V5 commands refuse V4 intents and bare action-digest approvals; V4 operations refuse bare approvals', async () => {
  const w = buildV5();
  const a = freezeAction(w);
  deny(await w.submit({ action: a, approvals: w.owner.authorize4(w.root.state, a, ['k1-phone']) }), 'COMMAND_FIELDS|COMMAND');
  deny(await w.submit({ action: a, approvals: w.owner.approvals(a, ['k1-phone']) }), 'COMMAND');
  const r = w.action('REVOKE', { credId: 'k4-freeze', reason: 'lost' });
  deny(await w.submit({ action: r, approvals: w.owner.approvals(r, ['k2-laptop', 'k3-root-hw']) }), 'AUTHORIZATION_INTENT_REQUIRED');
  deny(await w.submit({ action: w.action('UNFREEZE', {}) }), 'USE_HOLD_RELEASE');
});

test('approval signed by one credential presented as another credential is rejected', async () => {
  const w = buildV5();
  const a = freezeAction(w);
  const ap = w.owner.approveCommand(w.root.state, a, 'k1-phone', { at: w.now() });
  deny(await w.submit({ action: a, approvals: [{ ...ap, credId: 'k4-freeze' }] }), 'GRANT|COMMAND|CREDENTIAL|SIGNATURE');
});

test('trusted-confirmation commands: DELEGATION_GRANT from a software-only key is refused, from protected confirmation accepted', async () => {
  const w = buildV5();
  const k = w.owner.newDelegate('d1');
  const body = { delegationId: 'd1', delegateKey: k.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: '20000000000000000000000',
    cumulativeMaxYocto: '100000000000000000000000', maxUses: '10', expiresAt: w.iso(w.now() + 2 * 86_400_000), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] };
  deny(await w.cmd('DELEGATION_GRANT', body, ['k2-laptop']), 'TRUSTED_CONFIRMATION_REQUIRED');
  ok(await w.cmd('DELEGATION_GRANT', body, ['k1-phone']));
  assert.equal(w.root.state.v5.delegations.d1.status, 'ACTIVE');
});

test('the deterministic device summary names the command, resources and limits', async () => {
  const w = buildV5();
  let shown = null;
  const a = w.action('HOLD_CREATE', { holdId: 'm1', class: 'PROVISIONAL_HOLD', scope: { kind: 'MERCHANT', target: 'merchant-b.mock' }, reason: 'x', durationMs: String(H) });
  w.owner.approveCommand(w.root.state, a, 'k1-phone', { at: w.now(), decide: (_p, text) => { shown = text; return true; } });
  assert.match(shown, /HOLD_CREATE/); assert.match(shown, /merchant-b\.mock/);
});
