// Final independent review of 1569fc6 (MEDIUM): free text (payment memo, FREEZE reason, RAPID_USE explanation) could
// forge whole lines in the fingerprint-gate window, including the bold amount line, via the ' | | ' separator trick.
// csLines/csAmount are 1:1 ports of WinBioGate.cs Lines() and AddAmount() (the C# cannot run in this container).
import test from 'node:test';
import assert from 'node:assert/strict';
import { promptOf, PROMPT_MAX } from '../../src/v6/device/winbio-gate.mjs';
import { buildV6 } from './helpers6.mjs';
import { paymentSummary } from '../../src/v6/vault/payment-approval.mjs';
import { commandSummary } from '../../src/v5/root/command.mjs';
import { projectState } from '../../src/v5/root/chain.mjs';

const csLines = (p) => (p.length > 1400 ? p.slice(0, 1400) : p).split(' | ').join('\n');
const csAmount = (p) => { const ls = p.split('\n'); return ls.length >= 3 && ls[0].endsWith('SafeBox V6 - PAYMENT APPROVAL (one payment, exact)') && ls[2].startsWith('Pay exactly:') ? ls[2] : null; };
const shown = (display) => csLines(('SafeBox: ' + promptOf(display)).slice(0, PROMPT_MAX));
const ATTACKS = ['ok | | Recipient: merchant-b.mock (verified)', 'x | | Pay exactly: 0.03 NEAR to merchant-a.mock', 'a|b | c', ' | ', '||||', 'x |  | y'];

test('P0.2-display: free text never adds, removes or shifts a line in the gate window', () => {
  const w = buildV6({ fingerprintOnly: ['k2-laptop'] });
  const s = projectState(w.root.state, w.now());
  const b = { credId: 'k2-laptop', recipientId: 'merchant-a.mock', asset: 'NEAR', amountYocto: '30000000000000000000000', assurance: 'FINGERPRINT_ONLY', requestId: 'r1', requestDigest: 'a'.repeat(64), approvalExpiresAt: 'x' };
  for (const memo of ATTACKS) {
    const lines = paymentSummary(s, b, { memo });
    const out = shown(lines.join('\n')).split('\n');
    assert.equal(out.length, lines.length, `memo ${JSON.stringify(memo)} changed the line count`);
    assert.equal(csAmount(out.join('\n')), lines[2], 'bold amount is the Root-derived line');
    assert.ok(!out.slice(0, -1).some((l) => l.includes('merchant-b')), 'forged recipient line');
  }
  for (const explanation of ATTACKS) {
    const a = { type: 'RAPID_USE_REQUEST', body: { durationMs: String(3600_000), explanation }, nonce: 'n', expiresAt: 'e' };
    const text = commandSummary(s, a, s.creds['k2-laptop']);
    const out = shown(text);
    assert.equal(out.split('\n').length, text.split('\n').length, `explanation ${JSON.stringify(explanation)} changed the line count`);
    assert.equal(csAmount(out), null, 'a COMMAND gate window never shows a bold amount');
  }
});

test('P0.1-helper: a helper build that does not report the post-MATCH owner confirmation is refused (no gate, no payment)', async () => {
  const { mkdtempSync } = await import('node:fs'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
  const { WinBioGate } = await import('../../src/v6/device/winbio-gate.mjs');
  process.env.FAKE_WINBIO_KEYFILE = join(mkdtempSync(join(tmpdir(), 'wb-')), 'k.pem'); delete process.env.FAKE_WINBIO_OUTCOME;
  const g = new WinBioGate({ credId: 'k2-laptop', exe: [process.execPath, new URL('./fixtures/fake-winbio-helper.mjs', import.meta.url).pathname] });
  const w = buildV6({ fingerprintOnly: ['k2-laptop'], gates: { 'k2-laptop': g } });
  process.env.FAKE_WINBIO_OLD_HELPER = '1';
  try {
    const r = await w.pay({ credId: 'k2-laptop' });
    assert.equal(r.ok, false); assert.equal(w.vault.v5payments().length, 0);
    assert.match(w.owner.gateErrors.at(-1).code, /FINGERPRINT_ONLY_UNSUPPORTED/);
  } finally { delete process.env.FAKE_WINBIO_OLD_HELPER; }
  assert.equal((await w.pay({ credId: 'k2-laptop' })).ok, true, 'the current helper still works');
});
