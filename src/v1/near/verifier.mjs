// WP5 — Independent verification of on-chain outcome from NEAR RPC evidence
// (EXPERIMENTAL_tx_status result shape). RPC submission success alone is never sufficient.
import { ACTIONS, CONTRACT_METHOD } from '../intent.mjs';
import { explorerUrl } from './config.mjs';

const isFailure = (st) => st && typeof st === 'object' && 'Failure' in st;
const isSuccess = (st) => st && typeof st === 'object' && ('SuccessValue' in st || 'SuccessReceiptId' in st);
const FINAL_OK = new Set(['FINAL']);

function transfersIn(receipt) {
  const acts = receipt?.receipt?.Action?.actions ?? [];
  return acts.filter(a => a && typeof a === 'object' && a.Transfer).map(a => BigInt(a.Transfer.deposit));
}

/**
 * @returns {{verdict:'CONFIRMED'|'FAILED'|'PENDING'|'MISMATCH', checks:object[], effect:object, evidence:object}}
 */
export function verifyTxOutcome({ sealed, row, status, nowIso, expectedArgsB64 }) {
  const i = sealed.intent;
  const checks = [];
  const check = (name, ok, info) => { checks.push({ name, ok: !!ok, ...(info ? { info } : {}) }); return !!ok; };
  const tx = status?.transaction ?? {};
  const evidence = {
    network: 'testnet', txHash: row.tx_hash, explorerUrl: explorerUrl(row.tx_hash),
    signerId: tx.signer_id, receiverId: tx.receiver_id, finalExecutionStatus: status?.final_execution_status ?? null,
    verifiedAt: nowIso,
  };
  let structural = true;
  structural &= check('tx_hash_matches', tx.hash === row.tx_hash);
  structural &= check('signer_matches', tx.signer_id === i.signerAccountId);
  structural &= check('signer_key_matches', tx.public_key === row.signer_public_key);
  structural &= check('signer_nonce_matches', String(tx.nonce) === row.signer_nonce);
  structural &= check('receiver_matches', tx.receiver_id === i.receiverId);
  const acts = Array.isArray(tx.actions) ? tx.actions : [];
  structural &= check('single_action', acts.length === 1);
  if (i.action === ACTIONS.NATIVE) {
    structural &= check('action_is_transfer', acts[0]?.Transfer && BigInt(acts[0].Transfer.deposit) === BigInt(i.amountYocto));
  } else {
    const fc = acts[0]?.FunctionCall;
    structural &= check('action_is_execute_payment', fc && fc.method_name === CONTRACT_METHOD &&
      fc.args === expectedArgsB64 && BigInt(fc.deposit) === 0n && String(fc.gas) === i.gas);
  }
  if (!structural) return { verdict: 'MISMATCH', checks, effect: { kind: 'UNVERIFIED' }, evidence };

  const finalized = FINAL_OK.has(status.final_execution_status);
  check('finalized', finalized, status.final_execution_status);
  if (!finalized) return { verdict: 'PENDING', checks, effect: { kind: 'PENDING' }, evidence };

  // Index receipts and outcomes.
  const outcomes = new Map((status.receipts_outcome ?? []).map(o => [o.id, o.outcome]));
  const receipts = (status.receipts ?? []).filter(r => r.predecessor_id !== 'system'); // exclude gas refunds
  const payer = i.action === ACTIONS.NATIVE ? i.signerAccountId : i.receiverId;
  const valueTransfers = receipts.flatMap(r => transfersIn(r).map(amount => ({ r, amount })))
    .filter(t => t.amount > 0n);
  const toRecipient = valueTransfers.filter(t => t.r.predecessor_id === payer && t.r.receiver_id === i.recipientId);
  const unexpected = valueTransfers.filter(t => !(t.r.predecessor_id === payer && t.r.receiver_id === i.recipientId));
  check('no_unexpected_value_transfers', unexpected.length === 0, unexpected.map(t => `${t.r.predecessor_id}->${t.r.receiver_id}:${t.amount}`));
  const succeeded = toRecipient.filter(t => isSuccess(outcomes.get(t.r.receipt_id)?.status));
  const transferred = succeeded.reduce((s, t) => s + t.amount, 0n);
  check('recipient_receipt_success', succeeded.length === 1, `${succeeded.length} successful transfer receipt(s)`);
  check('amount_exact', transferred === BigInt(i.amountYocto), transferred.toString());

  if (i.action === ACTIONS.CONTRACT) {
    const logs = (status.receipts_outcome ?? []).filter(o => o.outcome?.executor_id === i.receiverId).flatMap(o => o.outcome.logs ?? []);
    const ev = logs.map(l => { try { return l.startsWith('EVENT_JSON:') ? JSON.parse(l.slice(11)) : null; } catch { return null; } })
      .find(e => e?.standard === 'diaporia_safebox' && e?.event === 'payment_executed');
    const d = ev?.data?.[0];
    check('contract_event_matches', d && d.intent_id === i.intentId && d.nonce === i.nonce && d.recipient === i.recipientId && d.amount === i.amountYocto);
  }
  const overallOk = isSuccess(status.status) && !(status.receipts_outcome ?? []).some(o => isFailure(o.outcome?.status));
  check('overall_status_success', overallOk);

  evidence.recipient = i.recipientId;
  evidence.transferredYocto = transferred.toString();
  if (overallOk && checks.every(c => c.ok)) {
    return { verdict: 'CONFIRMED', checks, effect: { kind: 'TRANSFER', to: i.recipientId, amountYocto: transferred.toString() }, evidence };
  }
  if (transferred === 0n && unexpected.length === 0) {
    return { verdict: 'FAILED', checks, effect: { kind: 'NONE', reason: 'execution failed on chain; no value reached the recipient' }, evidence };
  }
  return { verdict: 'MISMATCH', checks, effect: { kind: 'ANOMALOUS', transferredYocto: transferred.toString() }, evidence };
}
