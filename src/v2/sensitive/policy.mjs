// Deterministic policy decision point (OPA-style: pure function of explicit input facts,
// separate from application code). Deny by default: ALLOW only if every rule explicitly passes.
// Every failing rule is reported so decisions are explainable and auditable.

/**
 * @param {object} f facts
 *   f.policy, f.cap (verified capability), f.req {recipientId, asset, amountYocto},
 *   f.now (ms), f.usage {committedYocto, pendingCount, pendingExposureYocto, executions},
 *   f.capUsed (bool), f.capRevoked (bool), f.control {level}, f.flaw (drill-only injected flaw or null)
 */
export function evaluatePayment(f) {
  const deny = [];
  const rule = (ok, code) => { if (ok !== true) deny.push(code); };
  const p = f.policy, c = f.cap, r = f.req;
  rule(!!p, 'NO_ACTIVE_POLICY');
  rule(!!c, 'NO_CAPABILITY');
  if (!p || !c) return { decision: 'DENY', deny };
  rule(f.control?.level !== 'FROZEN', 'FREEZE_ACTIVE');
  rule(c.principalId === p.principalId, 'CROSS_PRINCIPAL_CAPABILITY');
  rule(c.policyId === p.policyId, 'CAPABILITY_POLICY_MISMATCH');
  rule(f.now >= Date.parse(p.validFrom) && f.now < Date.parse(p.expiresAt), 'POLICY_NOT_ACTIVE');
  rule(f.now >= Date.parse(c.issuedAt) - 60_000, 'CAPABILITY_FROM_FUTURE');
  rule(f.now < Date.parse(c.expiresAt), 'CAPABILITY_EXPIRED');
  rule(Date.parse(c.expiresAt) - Date.parse(c.issuedAt) <= Number(p.maxCapabilityTtlMs), 'CAPABILITY_TTL_TOO_LONG');
  rule(f.capRevoked === false, 'CAPABILITY_REVOKED');
  rule(f.capUsed === false, 'CAPABILITY_ALREADY_USED');
  rule(r.asset === 'NEAR' && c.asset === 'NEAR' && p.asset === 'NEAR', 'ASSET_NOT_ALLOWED');
  if (f.flaw !== 'SKIP_RECIPIENT_BINDING') { // drill-only injected flaw (never enabled outside containment drills)
    rule(r.recipientId === c.recipientId, 'RECIPIENT_NOT_BOUND_TO_CAPABILITY');
    rule(p.allowedRecipients.includes(r.recipientId), 'RECIPIENT_NOT_ALLOWED');
  }
  let amt;
  try { amt = BigInt(r.amountYocto); } catch { amt = -1n; }
  rule(amt > 0n, 'INVALID_AMOUNT');
  rule(amt <= BigInt(c.maxAmountYocto), 'AMOUNT_OVER_CAPABILITY');
  rule(amt <= BigInt(p.maxPerPaymentYocto), 'AMOUNT_OVER_PER_PAYMENT_LIMIT');
  const u = f.usage;
  rule(BigInt(u.committedYocto) + amt <= BigInt(p.maxCumulativeYocto), 'CUMULATIVE_LIMIT');
  rule(u.pendingCount + 1 <= Number(p.maxPendingCount), 'PENDING_COUNT_LIMIT');
  rule(BigInt(u.pendingExposureYocto) + amt <= BigInt(p.maxPendingExposureYocto), 'PENDING_EXPOSURE_LIMIT');
  rule(u.executions + u.pendingCount + 1 <= Number(p.maxExecutions), 'EXECUTION_COUNT_LIMIT');
  return deny.length ? { decision: 'DENY', deny } : { decision: 'ALLOW', deny: [] };
}

/** Final release-time re-check (authoritative state at release, not at proposal). */
export function evaluateRelease(f) {
  const deny = [];
  const rule = (ok, code) => { if (ok !== true) deny.push(code); };
  rule(f.control?.level === 'NONE', f.control?.level === 'FROZEN' ? 'FREEZE_ACTIVE' : 'HOLD_ACTIVE');
  rule(f.leaseFresh === true, 'WATCHDOG_LEASE_STALE');
  rule(!!f.policy && f.policyDigest === f.row.policy_digest, 'POLICY_CHANGED_OR_MISSING');
  if (f.policy) rule(f.now >= Date.parse(f.policy.validFrom) && f.now < Date.parse(f.policy.expiresAt), 'POLICY_NOT_ACTIVE');
  rule(f.now >= f.row.release_at, 'BUFFER_NOT_ELAPSED');
  rule(f.capRevoked === false, 'CAPABILITY_REVOKED');
  rule(f.now < f.row.cap_expires_at, 'CAPABILITY_EXPIRED');
  if (f.policy) rule(f.executions + 1 <= Number(f.policy.maxExecutions), 'EXECUTION_COUNT_LIMIT');
  return deny.length ? { decision: 'DENY', deny } : { decision: 'ALLOW', deny: [] };
}
