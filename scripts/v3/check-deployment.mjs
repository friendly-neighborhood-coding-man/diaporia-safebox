#!/usr/bin/env node
// SafeBox V3 deployment invariant checker (pure, offline). The on-chain vault has no owner/admin/upgrade/withdraw
// method, so a privileged bypass exists only through the ACCOUNT's access keys or a different code hash. This checks a
// `view_access_key_list` + `view_code` snapshot (as JSON) against the invariants:
//   D1 no FullAccess key on the vault account (a FullAccess key could DeployContract / DeleteAccount / Transfer);
//   D2 every FunctionCall key targets the vault itself, lists explicit method names (empty list = ALL methods),
//      and never `new`;
//   D3 the deployed code hash equals the reviewed build hash;
//   D4 the account is not a known-implicit (64-hex) account controlled by a single raw key.
// Usage: node scripts/v3/check-deployment.mjs snapshot.json [--expect-code-hash <base58|hex>]
import { readFileSync } from 'node:fs';

export const PUBLIC_METHODS = ['propose_payment', 'release', 'govern', 'recovery_open', 'recovery_consent', 'recovery_object', 'recovery_withdraw',
  'recovery_guardian', 'recovery_identity', 'recovery_cancel', 'recovery_complete'];

export function checkDeployment(snap, { expectCodeHash = null } = {}) {
  const violations = [];
  const acct = String(snap.accountId ?? '');
  if (/^[0-9a-f]{64}$/.test(acct)) violations.push({ code: 'D4_IMPLICIT_ACCOUNT', detail: acct });
  for (const k of snap.keys ?? []) {
    const p = k.access_key?.permission;
    if (p === 'FullAccess' || p?.FullAccess !== undefined) { violations.push({ code: 'D1_FULL_ACCESS_KEY', detail: k.public_key }); continue; }
    const fc = p?.FunctionCall;
    if (!fc) { violations.push({ code: 'D2_UNKNOWN_PERMISSION', detail: k.public_key }); continue; }
    if (fc.receiver_id !== acct) violations.push({ code: 'D2_FOREIGN_RECEIVER', detail: `${k.public_key} -> ${fc.receiver_id}` });
    if (!Array.isArray(fc.method_names) || fc.method_names.length === 0) violations.push({ code: 'D2_ALL_METHODS', detail: k.public_key });
    for (const m of fc.method_names ?? []) if (!PUBLIC_METHODS.includes(m)) violations.push({ code: 'D2_METHOD_NOT_ALLOWED', detail: `${k.public_key}:${m}` });
  }
  if (expectCodeHash && snap.codeHash !== expectCodeHash) violations.push({ code: 'D3_CODE_HASH_MISMATCH', detail: `${snap.codeHash} != ${expectCodeHash}` });
  if (!expectCodeHash) violations.push({ code: 'D3_NO_EXPECTED_HASH', detail: 'pass --expect-code-hash of the reviewed build' });
  return { ok: violations.length === 0, violations };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const snap = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  const i = process.argv.indexOf('--expect-code-hash');
  const r = checkDeployment(snap, { expectCodeHash: i > 0 ? process.argv[i + 1] : null });
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.ok ? 0 : 1);
}
