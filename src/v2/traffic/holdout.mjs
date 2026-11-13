// Independent EVALUATION set generator (not used for patch selection).
// Cases are drawn from a combinatorial grammar of owner-side setups x attacker-side mutations, with a seed that
// is fixed only AFTER the evaluated revision is frozen (seed = sha256 of the frozen commit id). Written by the same
// author as the system (limitation: not an externally authored holdout).
import { makeRng } from '../common/rng.mjs';
import { AMOUNT_DISTRIBUTION } from '../common/amounts.mjs';
import { V2_DOMAINS, newSigner } from '../common/crypto.mjs';

const MERCHANTS = ['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock'];
const OWNER_SETUPS = ['genuine', 'genuine', 'genuine', 'expired', 'revoked', 'future_issued', 'ttl_too_long', 'unknown_policy', 'bob_policy', 'bob_signed_for_alice', 'used_before'];
const MUTATIONS = {
  none: { benign: true }, amount_lower: { benign: true }, memo_unicode: { benign: true }, memo_max: { benign: true }, memo_empty: { benign: true },
  recipient_attacker: {}, recipient_other_merchant: {}, recipient_lookalike_unicode: {}, recipient_upper: {}, recipient_trailing_dot: {}, recipient_suffix: {}, recipient_bob_shop: {},
  amount_plus_one: {}, amount_double: {}, amount_u128max: {}, amount_leading_zero: {}, amount_space: {}, amount_negative: {}, amount_float: {},
  asset_lower: {}, asset_other: {},
  cap_field_tamper_recipient: {}, cap_field_tamper_amount: {}, cap_field_tamper_expiry: {}, cap_noncanonical_order: {}, cap_whitespace: {},
  sig_flip_char: {}, sig_truncate: {}, sig_from_other_cap: {}, cap_resigned_attacker: {},
  dup_json_keys_recipient: {}, extra_arg: {}, missing_arg: {}, number_amount: {}, array_recipient: {},
  op_lowercase: {}, op_trailing_space: {}, double_submit_then_redirect: {}, parallel_x5: {},
};
export const HOLDOUT_MUTATIONS = Object.keys(MUTATIONS);

export function generateHoldout({ seed, n }) {
  const rng = makeRng('holdout:' + seed);
  return Array.from({ length: n }, (_, i) => {
    const mutation = rng.pick(HOLDOUT_MUTATIONS);
    const ownerSetup = MUTATIONS[mutation].benign ? rng.pick(['genuine', 'genuine', 'genuine', 'expired', 'revoked']) : rng.pick(OWNER_SETUPS);
    return { id: `H${String(i).padStart(4, '0')}`, ownerSetup, mutation, amountYocto: rng.weighted(AMOUNT_DISTRIBUTION), merchant: rng.pick(MERCHANTS),
      // owner intent: a payment is legitimately expected ONLY for a genuine, live owner capability with a benign mutation
      legitimateExpected: ownerSetup === 'genuine' && !!MUTATIONS[mutation].benign };
  });
}

const iso = (t) => new Date(t).toISOString();
/** Supervisor side: the owner signs whatever genuine statements the case needs (all synthetic). */
export function ownerPrepare(c, owner, now, revoke) {
  const base = { recipientId: c.merchant, maxAmountYocto: c.amountYocto, taskRef: 'hold_' + c.id.toLowerCase() };
  let issued;
  switch (c.ownerSetup) {
    case 'expired': issued = owner.issueCapability({ ...base, issuedAt: now - 50 * 60_000, ttlMs: 30 * 60_000 }); break;
    case 'future_issued': issued = owner.issueCapability({ ...base, issuedAt: now + 3600_000, ttlMs: 30 * 60_000 }); break;
    case 'ttl_too_long': issued = owner.issueCapability({ ...base, ttlMs: 3 * 3600_000 }); break;
    case 'unknown_policy': issued = owner.issueCapability({ ...base, policyId: 'pol_nonexistent' }); break;
    case 'bob_policy': issued = owner.issueCapability({ ...base, policyId: 'pol_bob_1' }); break;
    case 'bob_signed_for_alice': {
      const cap = { v: 'safebox.v2.cap', capId: crypto.randomUUID(), principalId: 'owner_alice', policyId: 'pol_alice_1', recipientId: c.merchant, asset: 'NEAR',
        maxAmountYocto: c.amountYocto, taskRef: base.taskRef, issuedAt: iso(now), expiresAt: iso(now + 1800_000) };
      issued = { cap, signed: owner.signers.owner_bob.sign(V2_DOMAINS.CAPABILITY, cap) }; break; // NOT recorded as an alice issuance
    }
    default: issued = owner.issueCapability(base);
  }
  const other = owner.issueCapability({ ...base, taskRef: base.taskRef + 'x' }); // a second genuine cap (for signature swaps)
  if (c.ownerSetup === 'revoked') revoke?.(owner.revoke('owner_alice', issued.cap.capId));
  return { cap: issued.cap, signed: issued.signed, other: other.signed, usedBefore: c.ownerSetup === 'used_before' };
}

const reorder = (statement, rev = true) => { const o = JSON.parse(statement); const keys = Object.keys(o).sort(); if (rev) keys.reverse(); return JSON.stringify(Object.fromEntries(keys.map(k => [k, o[k]]))); };
const canon = (o) => JSON.stringify(Object.fromEntries(Object.keys(o).sort().map(k => [k, o[k]])));

/** General Zone side (compromised): applies the mutation and drives the real boundary. */
export async function attackerExecute(c, prep, gz) {
  const cap = prep.cap; const steps = [];
  const req = { capability: prep.signed, recipientId: cap.recipientId, amountYocto: cap.maxAmountYocto, asset: 'NEAR', memo: 'holdout ' + c.id };
  const send = async (label, args, op = 'PROPOSE') => { const r = await gz.request(op, args); steps.push({ action: label, outcome: r.ok ? 'ACCEPTED' : 'DENIED', code: r.ok ? r.result.state : r.error.code, detail: r.ok ? undefined : r.error.detail }); return r; };
  if (prep.usedBefore) await send('owner-intended first use', { ...req });
  const tamper = (k, v) => { const o = JSON.parse(prep.signed.statement); o[k] = v; return { statement: canon(o), signature: prep.signed.signature }; };
  const m = c.mutation;
  const amt = BigInt(cap.maxAmountYocto);
  const variants = {
    none: () => send('as owner intended', req),
    amount_lower: () => send('lower amount', { ...req, amountYocto: (amt - 1n).toString() }),
    memo_unicode: () => send('unicode memo', { ...req, memo: 'café ☕ order' }),
    memo_max: () => send('max memo', { ...req, memo: 'm'.repeat(280) }),
    memo_empty: () => send('empty memo', { ...req, memo: '' }),
    recipient_attacker: () => send('recipient attacker', { ...req, recipientId: 'attacker.mock' }),
    recipient_other_merchant: () => send('other merchant', { ...req, recipientId: MERCHANTS.find(x => x !== cap.recipientId) }),
    recipient_lookalike_unicode: () => send('cyrillic a', { ...req, recipientId: cap.recipientId.replace('a', 'а') }),
    recipient_upper: () => send('uppercase', { ...req, recipientId: cap.recipientId.toUpperCase() }),
    recipient_trailing_dot: () => send('trailing dot', { ...req, recipientId: cap.recipientId + '.' }),
    recipient_suffix: () => send('suffix', { ...req, recipientId: cap.recipientId.replace('.mock', '-x.mock') }),
    recipient_bob_shop: () => send('bob-shop', { ...req, recipientId: 'bob-shop.mock' }),
    amount_plus_one: () => send('+1 yocto', { ...req, amountYocto: (amt + 1n).toString() }),
    amount_double: () => send('x2', { ...req, amountYocto: (amt * 2n).toString() }),
    amount_u128max: () => send('u128 max', { ...req, amountYocto: ((1n << 128n) - 1n).toString() }),
    amount_leading_zero: () => send('leading zero', { ...req, amountYocto: '0' + cap.maxAmountYocto }),
    amount_space: () => send('space', { ...req, amountYocto: cap.maxAmountYocto + ' ' }),
    amount_negative: () => send('negative', { ...req, amountYocto: '-' + cap.maxAmountYocto }),
    amount_float: () => send('float', { ...req, amountYocto: '0.03e24' }),
    asset_lower: () => send('asset near', { ...req, asset: 'near' }),
    asset_other: () => send('asset USDT', { ...req, asset: 'USDT' }),
    cap_field_tamper_recipient: () => send('tampered cap recipient', { ...req, capability: tamper('recipientId', 'attacker.mock'), recipientId: 'attacker.mock' }),
    cap_field_tamper_amount: () => send('tampered cap amount', { ...req, capability: tamper('maxAmountYocto', '60000000000000000000000'), amountYocto: '60000000000000000000000' }),
    cap_field_tamper_expiry: () => send('tampered cap expiry', { ...req, capability: tamper('expiresAt', '2027-01-01T00:00:00.000Z') }),
    cap_noncanonical_order: () => send('non-canonical order', { ...req, capability: { statement: reorder(prep.signed.statement), signature: prep.signed.signature } }),
    cap_whitespace: () => send('whitespace', { ...req, capability: { statement: prep.signed.statement.replace(',', ', '), signature: prep.signed.signature } }),
    sig_flip_char: () => { const s = prep.signed.signature; const ch = s[10] === 'A' ? 'B' : 'A'; return send('flipped sig char', { ...req, capability: { statement: prep.signed.statement, signature: s.slice(0, 10) + ch + s.slice(11) } }); },
    sig_truncate: () => send('truncated sig', { ...req, capability: { statement: prep.signed.statement, signature: prep.signed.signature.slice(0, 40) } }),
    sig_from_other_cap: () => send('signature of another cap', { ...req, capability: { statement: prep.signed.statement, signature: prep.other.signature } }),
    cap_resigned_attacker: () => { const evil = newSigner('evil'); return send('re-signed by attacker', { ...req, capability: { statement: prep.signed.statement, signature: evil.sign(V2_DOMAINS.CAPABILITY, JSON.parse(prep.signed.statement)).signature } }); },
    dup_json_keys_recipient: async () => { const line = JSON.stringify({ op: 'PROPOSE', rid: 'dup1', args: req }).replace(`"recipientId":"${cap.recipientId}"`, `"recipientId":"${cap.recipientId}","recipientId":"attacker.mock"`);
      const r = await gz.raw(line, 'dup1'); steps.push({ action: 'duplicate JSON key', outcome: r.ok ? 'ACCEPTED' : 'DENIED', code: r.ok ? r.result.state : r.error.code, detail: r.error?.detail }); },
    extra_arg: () => send('extra arg', { ...req, priority: 'high' }),
    missing_arg: () => { const { memo, ...rest } = req; return send('missing memo', rest); },
    number_amount: () => send('number amount', { ...req, amountYocto: 1e22 }),
    array_recipient: () => send('array recipient', { ...req, recipientId: [cap.recipientId, 'attacker.mock'] }),
    op_lowercase: () => send('op lowercase', req, 'propose'),
    op_trailing_space: () => send('op trailing space', req, 'PROPOSE '),
    double_submit_then_redirect: async () => { await send('first (as intended)', req); await send('second redirect', { ...req, recipientId: 'attacker.mock' }); },
    parallel_x5: async () => { await Promise.all(Array.from({ length: 5 }, (_, k) => send('parallel ' + k, req))); },
  };
  await variants[m]();
  return steps;
}
