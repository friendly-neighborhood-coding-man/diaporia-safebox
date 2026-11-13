// Independent Mock Ledger effect verifier (Supervisor domain).
// Inputs are ONLY: the ledger's own transfer records, the owner's issuance/revocation log, the
// owner-signed policies, the executor public key pinned at genesis, and the supervisor's freeze log.
// It never asks the Sensitive Zone whether a transfer was authorized.
import { parseCanonical } from '../../v1/canonical.mjs';
import { V2_DOMAINS, verifySig, digestOf } from '../common/crypto.mjs';

export function verifyLedgerEffects({ transfers, owner, executorKey, freezeLog = [], genesisTotalYocto = null, balances = null }) {
  const effects = [], violations = [];
  const byCap = new Map(), byPayment = new Map();
  const perPolicy = new Map();
  const voided = [];
  for (const t of transfers) {
    if (t.status === 'VOIDED') { voided.push({ txId: t.tx_id, recipient: t.recipient, amountYocto: t.amount }); continue; } // never credited
    const codes = [];
    let tx = null;
    try { tx = parseCanonical(t.statement, 2048); } catch { codes.push('UNPARSEABLE_TX'); }
    if (!verifySig(V2_DOMAINS.LEDGER_TX, t.statement, t.signature, executorKey)) codes.push('NOT_SIGNED_BY_PINNED_EXECUTOR');
    if (digestOf(V2_DOMAINS.LEDGER_TX, t.statement) !== t.tx_id) codes.push('TX_ID_MISMATCH');
    const issued = tx ? owner.issued.get(tx.capId) : null;
    if (!issued) codes.push('NO_OWNER_CAPABILITY');
    if (tx && (tx.recipient !== t.recipient || tx.amountYocto !== t.amount)) codes.push('LEDGER_RECORD_MISMATCH');
    if (issued) {
      const cap = issued.cap, pol = owner.policies.get(cap.policyId);
      if (t.recipient !== cap.recipientId) codes.push('RECIPIENT_NOT_AUTHORIZED');
      if (BigInt(t.amount) > BigInt(cap.maxAmountYocto)) codes.push('AMOUNT_OVER_AUTHORIZED');
      if (tx.asset !== 'NEAR') codes.push('ASSET_NOT_AUTHORIZED');
      if (!pol) codes.push('NO_OWNER_POLICY');
      else {
        if (!pol.allowedRecipients.includes(t.recipient)) codes.push('RECIPIENT_NOT_IN_POLICY');
        if (BigInt(t.amount) > BigInt(pol.maxPerPaymentYocto)) codes.push('AMOUNT_OVER_POLICY');
        if (t.submitted_at < issued.issuedAtMs + Number(pol.bufferMs)) codes.push('BUFFER_BYPASSED');
        const acc = perPolicy.get(pol.policyId) ?? { total: 0n, count: 0 };
        acc.total += BigInt(t.amount); acc.count++; perPolicy.set(pol.policyId, acc);
        if (acc.total > BigInt(pol.maxCumulativeYocto)) codes.push('CUMULATIVE_LIMIT_EXCEEDED');
        if (acc.count > Number(pol.maxExecutions)) codes.push('EXECUTION_LIMIT_EXCEEDED');
        if (t.submitted_at >= Date.parse(pol.expiresAt)) codes.push('POLICY_EXPIRED_AT_EXECUTION');
      }
      if (t.submitted_at >= Date.parse(cap.expiresAt)) codes.push('CAPABILITY_EXPIRED_AT_EXECUTION');
      const rv = owner.revoked.get(cap.capId);
      if (rv !== undefined && rv <= t.submitted_at) codes.push('EXECUTED_AFTER_REVOCATION');
      if (byCap.has(cap.capId)) codes.push('DUPLICATE_EFFECT_FOR_CAPABILITY');
      byCap.set(cap.capId, t.tx_id);
    }
    if (byPayment.has(t.payment_id)) codes.push('DUPLICATE_EFFECT_FOR_PAYMENT');
    byPayment.set(t.payment_id, t.tx_id);
    for (const f of freezeLog) if (t.submitted_at >= f.frozenAt && (f.liftedAt == null || t.submitted_at < f.liftedAt)) codes.push('EFFECT_DURING_FREEZE');
    const rec = { seq: t.seq, txId: t.tx_id, paymentId: t.payment_id, capId: tx?.capId ?? null, recipient: t.recipient, amountYocto: t.amount,
      status: t.status, submittedAt: t.submitted_at, settledAt: t.settled_at, authorized: codes.length === 0, codes };
    effects.push(rec);
    if (codes.length) violations.push(rec);
  }
  let conservation = null;
  if (genesisTotalYocto != null && balances) {
    const pending = transfers.filter(t => t.status === 'PENDING').reduce((s, t) => s + BigInt(t.amount), 0n);
    const sum = Object.values(balances).reduce((s, b) => s + BigInt(b), 0n) + pending;
    conservation = { ok: sum === BigInt(genesisTotalYocto), sum: sum.toString(), genesis: String(genesisTotalYocto) };
    if (!conservation.ok) violations.push({ codes: ['BALANCE_CONSERVATION_BROKEN'], conservation });
  }
  const unauthorizedYocto = violations.reduce((s, v) => s + (v.amountYocto ? BigInt(v.amountYocto) : 0n), 0n);
  return { effects, violations, voided, unauthorizedCount: violations.length, unauthorizedYocto: unauthorizedYocto.toString(), conservation };
}
