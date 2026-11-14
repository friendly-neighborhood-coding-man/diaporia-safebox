// The REAL-gate wrapper (WinBioGate) against a fixture that emulates the Windows helper's JSON contract with a software
// key: the wrapper's statements must verify in Root / Vault exactly like the simulated gate's, and every non-MATCH
// sensor outcome must fail closed. (The physical WinBio path itself can only be tested on the owner's laptop.)
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WinBioGate } from '../../src/v6/device/winbio-gate.mjs';
import { buildV6, ok, deny } from './helpers6.mjs';

const FIX = fileURLToPath(new URL('./fixtures/fake-winbio-helper.mjs', import.meta.url));
const setup = () => { process.env.FAKE_WINBIO_KEYFILE = join(mkdtempSync(join(tmpdir(), 'wb-')), 'k.pem'); delete process.env.FAKE_WINBIO_OUTCOME;
  return new WinBioGate({ credId: 'k2-laptop', exe: [process.execPath, FIX] }); };

test('WinBioGate (emulated helper): genesis enrollment PoP, payment gate and FREEZE gate verify in Root/Vault', async () => {
  const g = setup();
  const w = buildV6({ fingerprintOnly: ['k2-laptop'], gates: { 'k2-laptop': g } });
  assert.equal(w.root.state.v6.gateKeys['k2-laptop'].kind, 'WINBIO_SOFTWARE_KEY');
  ok(await w.pay({ credId: 'k2-laptop' }));
  assert.equal(w.vault.v6evidence()[0].level, 'LOCAL_FINGERPRINT_GATE_PASSED');
  ok(await w.cmd('FREEZE', { freezeId: 'f1', reason: 'test', source: 'owner' }, ['k2-laptop']));
});

test('WinBioGate: NO_MATCH / TIMEOUT / LOCKOUT / unsupported -> no gate, no payment (fail closed)', async () => {
  const g = setup();
  const w = buildV6({ fingerprintOnly: ['k2-laptop'], gates: { 'k2-laptop': g } });
  for (const code of ['BIOMETRIC_NO_MATCH', 'BIOMETRIC_TIMEOUT', 'BIOMETRIC_LOCKOUT', 'FINGERPRINT_ONLY_UNSUPPORTED', 'WEIRD_HELPER_CODE']) {
    process.env.FAKE_WINBIO_OUTCOME = code;
    const r = await w.pay({ credId: 'k2-laptop' }); assert.equal(r.ok, false, code);
    assert.equal(w.owner.gateErrors.at(-1).code, code === 'WEIRD_HELPER_CODE' ? 'FINGERPRINT_ONLY_UNSUPPORTED' : code);
  }
  delete process.env.FAKE_WINBIO_OUTCOME;
  assert.equal(w.vault.v5payments().length, 0);
  const missing = new WinBioGate({ credId: 'k2-laptop', exe: join(tmpdir(), 'no-such-helper.exe') });
  assert.throws(() => missing.attest({ accountId: 'a', chainId: 'c', subject: 'PAYMENT', boundDigestHex: '0'.repeat(64), challengeNonce: '0'.repeat(64), at: 0 }), /FINGERPRINT_ONLY_UNSUPPORTED/);
});
