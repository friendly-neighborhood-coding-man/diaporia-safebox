// The JS contract model must agree with the shared vectors that the Rust contract tests also run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SafeBoxPaymentContractModel } from '../../src/v1/sim/contract-model.mjs';

const V = JSON.parse(readFileSync(new URL('../vectors/contract-vectors.json', import.meta.url), 'utf8'));
const model = () => new SafeBoxPaymentContractModel({ contractId: V.contractId, ownerId: V.ownerId, ownerPrincipalId: V.ownerPrincipalId,
  ownerAuthKey: V.ownerAuthKey, executorId: V.executorId, maxPaymentYocto: V.maxPaymentYocto });

for (const c of V.cases) {
  test(`contract vector: ${c.name} -> ${c.expect}`, () => {
    const m = model();
    const args = Buffer.from(JSON.stringify({ intent: c.intent, authorization: c.authorization, signature: c.signature }));
    const run = () => m.call('execute_payment', args, { predecessor: c.predecessor, attachedDeposit: 0n, blockTimestampMs: c.blockTimestampMs, balance: BigInt(V.contractBalanceYocto) });
    if (c.expect === 'OK') {
      const r = run();
      assert.equal(r.transfers.length, 1);
      assert.equal(r.transfers[0].to, 'merchant.testnet');
      assert.throws(run, /ERR_NONCE_USED/); // on-chain one-use
    } else assert.throws(run, new RegExp(c.expect));
  });
}

test('vectors contain no private key material', () => {
  const text = readFileSync(new URL('../vectors/contract-vectors.json', import.meta.url), 'utf8');
  assert.doesNotMatch(text, /private|secret|pkcs8/i);
});
