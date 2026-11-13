// Owner-signed V2 statements: payment policy, task capability, capability revocation, unfreeze.
// Parsers are strict (exact field sets, canonical round-trip, printable ASCII only).
import { fail, requireExactFields, atomicAmount, isoMillis, simpleId, uuidV4 } from '../../v1/canonical.mjs';
import { rawFromKeyId } from '../../v1/authz.mjs';
import { V2_DOMAINS, openSigned, digestOf } from '../common/crypto.mjs';
import { MOCK_ACCOUNT_RE } from '../mock-ledger/ledger.mjs';

export const POLICY_V = 'safebox.v2.policy';
export const CAP_V = 'safebox.v2.cap';
export const REVOKE_V = 'safebox.v2.revoke-cap';
export const UNFREEZE_V = 'safebox.v2.unfreeze';

export function mockAccount(v, field) { if (typeof v !== 'string' || !MOCK_ACCOUNT_RE.test(v)) fail('INVALID_ACCOUNT_ID', field); return v; }
const posInt = (v, field, max = 1e12) => { if (typeof v !== 'string' || !/^[1-9][0-9]{0,12}$/.test(v) || Number(v) > max) fail('INVALID_NUMBER', field); return Number(v); };

const POLICY_FIELDS = ['v', 'policyId', 'principalId', 'ownerKey', 'asset', 'allowedRecipients', 'maxPerPaymentYocto',
  'maxCumulativeYocto', 'maxPendingCount', 'maxPendingExposureYocto', 'maxExecutions', 'bufferMs', 'maxCapabilityTtlMs', 'validFrom', 'expiresAt'];

export function parsePolicy(obj) {
  requireExactFields(obj, POLICY_FIELDS);
  if (obj.v !== POLICY_V) fail('UNSUPPORTED_VERSION');
  simpleId(obj.policyId, 'policyId'); simpleId(obj.principalId, 'principalId'); rawFromKeyId(obj.ownerKey);
  if (obj.asset !== 'NEAR') fail('UNSUPPORTED_ASSET');
  if (!Array.isArray(obj.allowedRecipients) || obj.allowedRecipients.length < 1 || obj.allowedRecipients.length > 64) fail('POLICY_RECIPIENTS');
  obj.allowedRecipients.forEach(r => mockAccount(r, 'allowedRecipients'));
  if (new Set(obj.allowedRecipients).size !== obj.allowedRecipients.length) fail('POLICY_RECIPIENTS');
  for (const f of ['maxPerPaymentYocto', 'maxCumulativeYocto', 'maxPendingExposureYocto']) atomicAmount(obj[f], f);
  for (const f of ['maxPendingCount', 'maxExecutions', 'bufferMs', 'maxCapabilityTtlMs']) posInt(obj[f], f);
  isoMillis(obj.validFrom, 'validFrom'); isoMillis(obj.expiresAt, 'expiresAt');
  if (Date.parse(obj.expiresAt) <= Date.parse(obj.validFrom)) fail('POLICY_WINDOW');
  if (BigInt(obj.maxPerPaymentYocto) > BigInt(obj.maxCumulativeYocto)) fail('POLICY_INCONSISTENT');
  return Object.freeze({ ...obj, allowedRecipients: Object.freeze([...obj.allowedRecipients]) });
}

export function openPolicy(signed, trustedOwnerKeys, { minBufferMs }) {
  const raw = openSigned(V2_DOMAINS.POLICY, signed, peekKey(signed, trustedOwnerKeys), 8192);
  const p = parsePolicy(raw);
  if (trustedOwnerKeys[p.principalId] !== p.ownerKey) fail('POLICY_KEY_NOT_TRUSTED');
  if (Number(p.bufferMs) < minBufferMs) fail('POLICY_BUFFER_BELOW_FLOOR');
  return { policy: p, digest: digestOf(V2_DOMAINS.POLICY, signed.statement) };
}

// The verifying key is chosen from TRUSTED configuration by the claimed principal; a statement naming
// an unknown principal has no key and fails closed.
function peekKey(signed, trustedOwnerKeys) {
  let principalId;
  try { principalId = JSON.parse(signed.statement).principalId; } catch { fail('INVALID_SIGNED_STATEMENT'); }
  const k = typeof principalId === 'string' && Object.prototype.hasOwnProperty.call(trustedOwnerKeys, principalId) ? trustedOwnerKeys[principalId] : null;
  if (!k) fail('UNKNOWN_PRINCIPAL');
  return k;
}

const CAP_FIELDS = ['v', 'capId', 'principalId', 'policyId', 'recipientId', 'asset', 'maxAmountYocto', 'taskRef', 'issuedAt', 'expiresAt'];
export function openCapability(signed, trustedOwnerKeys) {
  const c = openSigned(V2_DOMAINS.CAPABILITY, signed, peekKey(signed, trustedOwnerKeys), 2048);
  requireExactFields(c, CAP_FIELDS);
  if (c.v !== CAP_V) fail('UNSUPPORTED_VERSION');
  uuidV4(c.capId, 'capId'); simpleId(c.principalId, 'principalId'); simpleId(c.policyId, 'policyId'); simpleId(c.taskRef, 'taskRef');
  mockAccount(c.recipientId, 'recipientId');
  if (c.asset !== 'NEAR') fail('UNSUPPORTED_ASSET');
  atomicAmount(c.maxAmountYocto, 'maxAmountYocto'); isoMillis(c.issuedAt, 'issuedAt'); isoMillis(c.expiresAt, 'expiresAt');
  if (Date.parse(c.expiresAt) <= Date.parse(c.issuedAt)) fail('CAP_WINDOW');
  return Object.freeze({ ...c, digest: digestOf(V2_DOMAINS.CAPABILITY, signed.statement) });
}

const REVOKE_FIELDS = ['v', 'capId', 'principalId', 'issuedAt'];
export function openRevocation(signed, trustedOwnerKeys) {
  const r = openSigned(V2_DOMAINS.REVOKE_CAP, signed, peekKey(signed, trustedOwnerKeys), 1024);
  requireExactFields(r, REVOKE_FIELDS);
  if (r.v !== REVOKE_V) fail('UNSUPPORTED_VERSION');
  uuidV4(r.capId, 'capId'); isoMillis(r.issuedAt, 'issuedAt');
  return r;
}

const UNFREEZE_FIELDS = ['v', 'target', 'frozenAt', 'reviewRef', 'issuedAt'];
export function openUnfreeze(signed, operatorKey) {
  const u = openSigned(V2_DOMAINS.UNFREEZE, signed, operatorKey, 1024);
  requireExactFields(u, UNFREEZE_FIELDS);
  if (u.v !== UNFREEZE_V) fail('UNSUPPORTED_VERSION');
  simpleId(u.reviewRef, 'reviewRef'); isoMillis(u.issuedAt, 'issuedAt');
  return u;
}
