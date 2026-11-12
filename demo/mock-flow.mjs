import { MockSafeBox } from '../src/mock/contract.mjs';

const safe = new MockSafeBox();
const prepared = safe.prepare({
  principalId: 'demo_owner', action: 'MOCK_TRANSFER', recipientId: 'merchant.testnet',
  asset: 'TEST_NEAR', amountAtomic: '1000000000000000000000000',
  expiresAt: new Date(Date.now() + 5 * 60_000).toISOString()
});
console.log('PREPARED', {id: prepared.id, digest: prepared.digest});
safe.recordMockApproval(prepared.id, {principalId:'demo_owner', digest:prepared.digest});
for (const changed of [{recipientId:'attacker.testnet'}, {amountAtomic:'2000000000000000000000000'}]) {
  try { safe.executeOnce(prepared.id, {...prepared.intent, ...changed}); }
  catch (err) { console.log('BLOCKED', err.message); }
}
console.log('EXECUTED', safe.executeOnce(prepared.id, prepared.intent).result);
try { safe.executeOnce(prepared.id, prepared.intent); }
catch (err) { console.log('REPLAY_BLOCKED', err.message); }
console.log('MOCK_EFFECTS', safe.mockEffects.length);
console.log('NOTE: No real authentication, keys, payment, network or NEAR transactions.');
