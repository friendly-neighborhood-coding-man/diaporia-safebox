// Purpose Capsule: the owner's canonical, signed statement of what this SafeBox is FOR. It is the root of every
// spending decision. The AI may change its plans; it can never amend the capsule, because amendments need the
// governance quorum of the authority matrix (K1+K2+K3 by default) and immutable fields can never change at all.
import { fail, exactFields, id, uint, isoMs, deepFreeze, clone, digestHex, V3_DOMAINS } from '../common/canon.mjs';

export const CAPSULE_V = 'safebox.v3.purpose';
export const IMMUTABLE_FIELDS = Object.freeze(['purposeId', 'accountId', 'principalId', 'statement', 'asset', 'allowedOperations']);
const ACCOUNT_RE = /^[a-z0-9][a-z0-9-]{1,40}\.mock$/;
const FIELDS = ['v', 'purposeId', 'accountId', 'principalId', 'version', 'policyEpoch', 'statement', 'allowedOperations', 'asset',
  'recipients', 'products', 'exactProductsOnly', 'perPaymentMaxYocto', 'cumulativeLimitYocto', 'dailyLimitYocto', 'maxCapabilityTtlMs', 'validFrom', 'expiresAt'];

export function parseCapsule(c) {
  exactFields(c, FIELDS, [], 'CAPSULE_FIELDS');
  if (c.v !== CAPSULE_V) fail('CAPSULE_VERSION_UNSUPPORTED');
  id(c.purposeId, 'purposeId'); id(c.principalId, 'principalId');
  if (!ACCOUNT_RE.test(c.accountId)) fail('CAPSULE_ACCOUNT');
  uint(c.version, 'version'); uint(c.policyEpoch, 'policyEpoch');
  if (c.version === '0' || c.policyEpoch === '0') fail('CAPSULE_VERSION');
  if (typeof c.statement !== 'string' || c.statement.length < 8 || c.statement.length > 400) fail('CAPSULE_STATEMENT');
  if (!Array.isArray(c.allowedOperations) || !c.allowedOperations.length || c.allowedOperations.some(o => o !== 'PAY')) fail('CAPSULE_OPERATIONS');
  if (c.asset !== 'NEAR') fail('CAPSULE_ASSET');
  if (!Array.isArray(c.recipients) || c.recipients.length < 1 || c.recipients.length > 32 || c.recipients.some(r => !ACCOUNT_RE.test(r)) || new Set(c.recipients).size !== c.recipients.length) fail('CAPSULE_RECIPIENTS');
  if (!Array.isArray(c.products) || c.products.length > 64) fail('CAPSULE_PRODUCTS');
  const skus = new Set();
  for (const p of c.products) {
    exactFields(p, ['sku', 'recipientId', 'amountYocto'], [], 'CAPSULE_PRODUCT');
    id(p.sku, 'sku'); if (skus.has(p.sku)) fail('CAPSULE_PRODUCT_DUP'); skus.add(p.sku);
    if (!c.recipients.includes(p.recipientId)) fail('CAPSULE_PRODUCT_RECIPIENT');
    if (uint(p.amountYocto, 'amountYocto') === 0n) fail('CAPSULE_PRODUCT_AMOUNT');
  }
  if (!['true', 'false'].includes(c.exactProductsOnly)) fail('CAPSULE_EXACT_FLAG');
  if (c.exactProductsOnly === 'true' && !c.products.length) fail('CAPSULE_EXACT_WITHOUT_PRODUCTS');
  const per = uint(c.perPaymentMaxYocto, 'perPaymentMaxYocto'), cum = uint(c.cumulativeLimitYocto, 'cumulativeLimitYocto'), day = uint(c.dailyLimitYocto, 'dailyLimitYocto');
  if (per === 0n || per > day || day > cum) fail('CAPSULE_LIMITS_INCONSISTENT');
  for (const p of c.products) if (BigInt(p.amountYocto) > per) fail('CAPSULE_PRODUCT_OVER_LIMIT');
  const ttl = uint(c.maxCapabilityTtlMs, 'maxCapabilityTtlMs'); if (ttl < 60_000n || ttl > 7n * 86_400_000n) fail('CAPSULE_TTL');
  if (isoMs(c.expiresAt, 'expiresAt') <= isoMs(c.validFrom, 'validFrom')) fail('CAPSULE_WINDOW');
  return deepFreeze(clone(c));
}
export const capsuleDigest = (c) => digestHex(V3_DOMAINS.CAPSULE, c);

export function amendmentViolations(oldC, newC) {
  const v = [];
  for (const f of IMMUTABLE_FIELDS) if (JSON.stringify(oldC[f]) !== JSON.stringify(newC[f])) v.push(`IMMUTABLE_${f}`);
  if (BigInt(newC.version) !== BigInt(oldC.version) + 1n) v.push('VERSION_NOT_SEQUENTIAL');
  if (BigInt(newC.policyEpoch) < BigInt(oldC.policyEpoch)) v.push('POLICY_EPOCH_ROLLBACK');
  return v;
}

/**
 * Purpose constraints for one payment request (independent of who signed it).
 * spent: {cumulativeYocto, last24hYocto}. Returns list of violated constraints (empty = within purpose).
 */
export function purposeViolations(c, { operation, recipientId, asset, amountYocto, sku, now, capExpiresAt, capIssuedAt }, spent) {
  const v = [];
  if (!c.allowedOperations.includes(operation)) v.push('OPERATION_NOT_IN_PURPOSE');
  if (asset !== c.asset) v.push('ASSET_NOT_IN_PURPOSE');
  if (!c.recipients.includes(recipientId)) v.push('RECIPIENT_NOT_IN_PURPOSE');
  const amt = BigInt(amountYocto);
  if (amt <= 0n) v.push('AMOUNT_INVALID');
  if (amt > BigInt(c.perPaymentMaxYocto)) v.push('OVER_PER_PAYMENT_LIMIT');
  if (BigInt(spent.cumulativeYocto) + amt > BigInt(c.cumulativeLimitYocto)) v.push('OVER_CUMULATIVE_LIMIT');
  if (BigInt(spent.last24hYocto) + amt > BigInt(c.dailyLimitYocto)) v.push('OVER_DAILY_LIMIT');
  if (sku) {
    const p = c.products.find(x => x.sku === sku);
    if (!p) v.push('PRODUCT_NOT_IN_PURPOSE');
    else { if (p.recipientId !== recipientId) v.push('PRODUCT_RECIPIENT_MISMATCH'); if (p.amountYocto !== String(amountYocto)) v.push('PRODUCT_AMOUNT_NOT_EXACT'); }
  } else if (c.exactProductsOnly === 'true') v.push('PRODUCT_REQUIRED');
  if (now < Date.parse(c.validFrom) || now >= Date.parse(c.expiresAt)) v.push('PURPOSE_NOT_ACTIVE');
  if (capExpiresAt > Date.parse(c.expiresAt)) v.push('CAPABILITY_OUTLIVES_PURPOSE');
  if (capExpiresAt - capIssuedAt > Number(c.maxCapabilityTtlMs)) v.push('CAPABILITY_TTL_TOO_LONG');
  return v;
}
