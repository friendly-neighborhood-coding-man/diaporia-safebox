// V6 hardening P0.2 (issue #14): a compromised Owner Console (its page AND its in-process proposal list are attacker
// controlled) must not obtain a fingerprint-gate attestation for anything other than the exact command the owner's
// side rebuilt from its OWN Root replica, and the gate window must show that rebuilt command (not the console's text).
// Attacker capability: serve any page and any JSON from the console origin; add, alter or relabel console proposals.
// Not in scope here: the WebAuthn UV assertion itself (a page on the RP origin can always obtain one; see residuals).
import test from 'node:test';
import assert from 'node:assert/strict';
import { incidentWorld, consoleForWorld, client, ok } from './helpers6.mjs';
import { SimulatedFingerprintGate } from '../../src/v6/device/biometric.mjs';
import { consoleGate } from '../../src/v6/device/gate-service.mjs';
import { commandDigest } from '../../src/v5/root/command.mjs';

class RecordingGate extends SimulatedFingerprintGate {
  constructor(o) { super(o); this.shown = []; }
  attest(o) { this.shown.push(o.display ?? null); return super.attest(o); }
}
async function setup() {
  const g = new RecordingGate({ credId: 'k2-laptop' });
  const { w, locator, incidentId } = await incidentWorld({ gates: { 'k2-laptop': g } });
  const c = consoleForWorld(w); const k = client(c);
  ok({ ok: (await k.login(w, 'k2-laptop')).ok });
  const svc = { consoleObj: c, rootState: () => w.root.state, gates: w.gates, now: w.now };
  return { w, c, k, g, svc, locator, incidentId };
}
/** What the console page sends to the local gate service (the new page sends the prepared object; the old one only digests). */
const req = (p) => ({ subject: 'COMMAND', credId: p.command.credId, accountId: p.command.accountId, chainId: p.command.chainId, boundDigestHex: p.digestHex,
  challengeNonce: p.grant.statement.challengeNonce, action: p.action, grant: p.grant, command: p.command });

test('P0.2-display: the gate window shows the command rebuilt from Root (type, scope, hold), not a digest prefix', async () => {
  const { w, k, g, svc, locator } = await setup();
  const pr = await k.post('/api/freeze/prepare', { locator });
  const gate = consoleGate(svc, req(pr));
  const shown = g.shown.at(-1);
  assert.ok(shown && /FREEZE/.test(shown) && /Scope: GLOBAL/.test(shown), 'gate window showed: ' + JSON.stringify(shown));
  // the honest path still works end to end
  const ap = { ...w.owner.approvePrepared(w.root.state, pr, 'k2-laptop', { at: w.now(), noGate: true }), gate };
  const cf = await k.post('/api/freeze/confirm', { proposalId: pr.proposalId, confirm: pr.confirmPhrase, approval: ap });
  assert.equal(cf.ok, true, JSON.stringify(cf.error)); assert.equal(cf.rootFrozen, true);
});

test('P0.2-substitution: a console that shows FREEZE but asks the gate for a HOLD_RELEASE gets a window that says HOLD_RELEASE', async () => {
  const { w, k, g, svc, locator } = await setup();
  const fr = await k.freeze(w, 'k2-laptop', { locator }); assert.equal(fr.cf.ok, true);
  // the attacker now wants the freeze released; it prepares HOLD_RELEASE and keeps the page saying "FREEZE"
  const cp = await k.post('/api/command/prepare', { type: 'HOLD_RELEASE', body: { holdId: fr.cf.holdId } });
  const ch = await k.post('/api/command/challenge', { bundleId: cp.bundleId });
  const before = g.shown.length;
  try { consoleGate(svc, req(ch)); } catch {}
  const shown = g.shown.slice(before).at(-1);
  assert.ok(shown && /HOLD_RELEASE|Releases hold/.test(shown) && !/^FREEZE/m.test(shown), 'gate window showed: ' + JSON.stringify(shown));
});

test('P0.2-forged: commands the Root would not produce are refused before any fingerprint prompt', async () => {
  const { w, c, k, g, svc, locator } = await setup();
  const pr = await k.post('/api/freeze/prepare', { locator });
  const forge = (mut) => { const p = structuredClone(pr); mut(p); p.digestHex = commandDigest(p.command).toString('hex');
    // compromised console: its own proposal list holds the forged command as PREPARED
    c.proposals.set('fp-forged-' + Math.random(), { pid: 'x', kind: 'FREEZE', state: 'PREPARED', command: p.command, grant: p.grant, action: p.action }); return p; };
  const cases = [
    ['wrong epoch', (p) => { p.command.epoch = String(Number(p.command.epoch) + 1); }],
    ['wrong summary digest', (p) => { p.command.summaryDigest = 'ab'.repeat(32); }],
    ['wrong financial scope', (p) => { p.command.financialScope = 'NONE'; }],
    ['future rootSeq', (p) => { p.command.rootSeq = String(Number(w.root.state.seq) + 50); }],
    ['action swapped (other incident reason)', (p) => { p.action = { ...p.action, body: { ...p.action.body, reason: 'EMERGENCY_FREEZE incident inc-' + 'ee'.repeat(12) } }; }],
    ['grant forged by the console', (p) => { p.grant = { ...p.grant, sig: 'A'.repeat(86) }; }],
    ['grant for another credential', (p) => { p.grant = { ...p.grant, statement: { ...p.grant.statement, credId: 'k1-phone' } }; }],
  ];
  for (const [name, mut] of cases) {
    const before = g.shown.length;
    assert.throws(() => consoleGate(svc, req(forge(mut))), (e) => /^PREPARED_|^GATE_/.test(e.code), name);
    assert.equal(g.shown.length, before, name + ': the owner was prompted for a forged command');
    // the same forgery without the optional digest/nonce echo must still be refused by the review itself
    const { boundDigestHex, challengeNonce, ...bare } = req(forge(mut));
    assert.throws(() => consoleGate(svc, bare), (e) => /^PREPARED_|^GATE_/.test(e.code), name + ' (no digest echo)');
    assert.equal(g.shown.length, before, name + ' (no digest echo): the owner was prompted for a forged command');
  }
});

test('P0.2-format: a digest-only gate request (no prepared object) is refused', async () => {
  const { k, svc, locator } = await setup();
  const pr = await k.post('/api/freeze/prepare', { locator });
  const { action, grant, command, ...digestOnly } = req(pr);
  assert.throws(() => consoleGate(svc, digestOnly), (e) => /GATE_REQUEST/.test(e.code));
});

test('P0.2-display (device route): a HOLD_RELEASE approved on the device shows the rebuilt command on the gate window, not a digest prefix', async () => {
  const { w, k, g, locator } = await setup();
  const fr = await k.freeze(w, 'k2-laptop', { locator }); assert.equal(fr.cf.ok, true);
  const before = g.shown.length;
  const rel = await w.cmd('HOLD_RELEASE', { holdId: fr.cf.holdId, holdDigest: w.holdDigest(fr.cf.holdId) }, ['k2-laptop']);
  assert.equal(rel.ok, true, JSON.stringify(rel.error));
  const shown = g.shown.slice(before).at(-1);
  assert.ok(shown && /HOLD_RELEASE/.test(shown) && /Account:/.test(shown), 'gate window showed: ' + JSON.stringify(shown));
});
