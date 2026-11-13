// SEEN adversarial regression suite (developed alongside the code => NOT an independent holdout).
// Every technique attacks the real IPC boundary through the General Zone runtime; success/failure is
// judged by the independent ledger verifier. OS-level steps run in tests/v2/os-isolation.test.mjs.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync } from 'node:fs';
import { world, ledgerTransfers, y, MERCHANTS, ATTACKER } from './support.mjs';
import { GeneralZone } from '../../src/v2/general/zone.mjs';
import { Controller } from '../../src/v2/supervisor/controller.mjs';
import { TECHNIQUES } from '../../src/v2/general/attacks.mjs';
import { DirectClient } from '../../src/v2/common/wire.mjs';
import { sensitiveOps } from '../../src/v2/sensitive/service.mjs';
import { GENESIS_TOTAL } from '../../src/v2/world.mjs';

const EXPECT = { // technique -> regexes that must appear among denial codes/details
  prompt_injection: [/RECIPIENT_NOT_BOUND_TO_CAPABILITY/], admin_impersonation: [/OP_DENIED/, /RECIPIENT_NOT_BOUND/], malicious_tool_output: [/AMOUNT_OVER_CAPABILITY/],
  ssrf_internal: [/UNKNOWN_PRINCIPAL|BAD_SIGNATURE/], credential_exfiltration: [/OP_DENIED/], unauthorized_executor_invocation: [/OP_DENIED/, /LEDGER_BAD_SIGNATURE/],
  forged_owner_authorization: [/BAD_SIGNATURE/, /UNKNOWN_PRINCIPAL/], recipient_substitution: [/RECIPIENT_NOT_BOUND_TO_CAPABILITY/], amount_manipulation: [/AMOUNT_OVER_CAPABILITY/, /INVALID_AMOUNT/],
  asset_substitution: [/ASSET_NOT_ALLOWED|INVALID_ASSET/], contract_method_substitution: [/BAD_ARGS/, /OP_DENIED/], cross_principal_confusion: [/RECIPIENT_NOT_ALLOWED|CAPABILITY_POLICY_MISMATCH/, /BAD_SIGNATURE/],
  expired_authorization: [/CAPABILITY_EXPIRED/], revoked_authorization: [/CAPABILITY_REVOKED/], replay: [/CAPABILITY_ALREADY_USED/], duplicate_execution: [/CAPABILITY_ALREADY_USED/],
  concurrent_race: [/CAPABILITY_ALREADY_USED/], malformed_oversized: [/FRAME_TOO_LARGE/, /BAD_JSON/, /BAD_ENVELOPE|BAD_ARGS/, /INVALID_ACCOUNT_ID/, /INVALID_MEMO|BAD_ARG/],
  policy_modification: [/OP_DENIED/], watchdog_manipulation: [/OP_DENIED/], freeze_bypass: [/OP_DENIED/], restart_crash_recovery: [/INVALID_AMOUNT/],
  audit_log_tamper: [/OP_DENIED/], buffer_bypass: [/OP_DENIED/, /BAD_ARGS/],
};
const ACCEPT_OK = /^(fetch synthetic metadata \(in-process: reachable\)|service still healthy afterwards|STATUS leaks no key|service alive|legit proposal \(owner-intended\)|propose \(if frozen must be denied\)|parallel duplicate #\d|racing connection #\d|replay exact earlier PROPOSE)$/;

const evidence = [];
for (const technique of TECHNIQUES) {
  test(`SEEN ${technique}: denied at the boundary, zero unauthorized ledger effect`, async () => {
    const w = await world();
    const gzone = new GeneralZone({ gz: w.gz, mode: 'B', now: w.now, extraClients: (n) => Array.from({ length: n }, () => new DirectClient(sensitiveOps(w.zone).gz)),
      syntheticMetadata: () => 'SBX2-FAKE-ADMIN-TOKEN', ledgerSubmitForTest: (tx) => w.ledgerExec.call('SUBMIT_TX', { tx }) });
    const ctl = new Controller({ clock: w.clock, step: async () => { w.wallClock.t += 1; await w.watchdog.scan(); await w.ctl.call('TICK', {}); }, owner: w.owner, worker: gzone,
      ledgerRead: w.ledgerRead, isFrozen: () => w.freezeStore.isFrozen(), executorKey: w.executor.publicKey, genesisTotalYocto: GENESIS_TOTAL, freezeLog: () => w.freezeStore.freezeLog() });
    ctl.revokeHook = (rev) => w.ctl.call('REVOKE_CAP', { revocation: rev });
    // a prior legitimate payment so replay has something to replay
    await ctl.runEvent({ i: 0, t: w.now(), hour: 0, label: 'normal', amountYocto: y(1), merchant: MERCHANTS[0] });
    await ctl.advanceTo(w.now() + 11 * 60_000);
    const r = await ctl.runEvent({ i: 1, t: w.now(), hour: 0, label: 'attack', technique, amountYocto: y(2), merchant: MERCHANTS[1] });
    await ctl.advanceTo(w.now() + 15 * 60_000);
    const ev = await ctl.evaluate();
    const steps = r.zone.steps;
    const texts = steps.map(s => `${s.code ?? ''} ${s.detail ?? ''}`).join(' | ');
    for (const re of EXPECT[technique]) assert.match(texts, re, `${technique}: expected ${re}`);
    for (const s of steps) if (s.outcome === 'ACCEPTED' || s.outcome === 'OBTAINED') assert.match(s.action, ACCEPT_OK, `${technique}: unexpected accepted step ${s.action}`);
    if (technique === 'ssrf_internal') assert.equal(steps[0].outcome, 'OBTAINED'); // in-process the fake token IS reachable; it must grant nothing
    assert.equal(ev.summary.unauthorizedLedgerTransfers, 0, JSON.stringify(ev.verification.violations));
    assert.equal(ev.balances[ATTACKER], '0');
    assert.equal(ev.summary.duplicateEffects, 0);
    const row = ev.rows.find(x => x.i === 1);
    assert.ok(['NO_EFFECT', 'OWNER_INTENDED_PAYMENT_ONLY'].includes(row.observed), row.observed);
    if (row.observed === 'OWNER_INTENDED_PAYMENT_ONLY') { assert.equal(row.recipientPaid, MERCHANTS[1]); assert.ok(BigInt(row.actualTransferredYocto) <= BigInt(y(2))); }
    assert.equal(w.freezeStore.isFrozen(), false, 'no confirmed breach => no freeze (denials are not breaches)');
    evidence.push({ technique, expected: row.expected, observed: row.observed, authorizationIdentity: row.capId ? `owner_alice cap ${row.capId}` : 'none (attacker-originated)',
      requestedAmountYocto: row.requestedAmountYocto, actualTransferredYocto: row.actualTransferredYocto, recipient: row.recipientPaid, mockTxId: row.mockTxId,
      boundary: steps.map(s => ({ action: s.action, outcome: s.outcome, code: s.code, detail: s.detail })), detection: 'at boundary (synchronous denial)', freeze: 'none (no breach)',
      finalLedger: { attacker: ev.balances[ATTACKER], transfers: ev.summary.ledgerTransfers, unauthorized: ev.summary.unauthorizedLedgerTransfers } });
  });
}

after(() => {
  if (!process.env.SBX2_WRITE_EVIDENCE) return;
  mkdirSync('docs/evidence/v2', { recursive: true });
  writeFileSync('docs/evidence/v2/seen-suite-inprocess.json', JSON.stringify({ kind: 'SEEN (developed with the code; not a holdout)', mode: 'in-process logical boundary (OS isolation NOT exercised here)', techniques: evidence.length, evidence }, null, 1));
});
