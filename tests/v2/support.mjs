import { buildWorld, MERCHANTS, ATTACKER } from '../../src/v2/world.mjs';
import { y } from '../../src/v2/common/amounts.mjs';
export { MERCHANTS, ATTACKER, y };

export async function world(opts = {}) {
  const w = buildWorld(opts);
  await w.loadPolicies();
  await w.watchdog.scan(); // first heartbeat
  return w;
}
/** Owner issues a capability and the (honest) agent proposes exactly it. */
export async function legitPropose(w, { recipientId = MERCHANTS[0], amount = y(1), principalId = 'owner_alice', memo = 'buy test item' } = {}) {
  const { cap, signed } = w.owner.issueCapability({ principalId, recipientId, maxAmountYocto: amount, taskRef: 'task_' + Math.random().toString(36).slice(2, 10) });
  const r = await w.gz.call('PROPOSE', { capability: signed, recipientId, amountYocto: amount, asset: 'NEAR', memo });
  return { cap, signed, ...r };
}
export async function ledgerTransfers(w) { return w.ledgerRead.call('TRANSFERS', { sinceSeq: '0' }); }
export async function codeOf(p) { try { await p; return 'OK'; } catch (e) { return e.code; } }
