// Versioned authority matrix: which ROLES (not which keys) may approve which ACTION, with how many independent
// credentials. Credential identity (credId/public key), role, authorization scope (this matrix) and signing quorum are
// separate concepts. Hard floors below are CODE, not configuration: no matrix amendment can go below them.
import { fail, canon, exactFields, id, digestHex, V3_DOMAINS, deepFreeze, clone } from '../common/canon.mjs';

export const MATRIX_V = 'safebox.v3.matrix';
export const PERSONAL_ROLES = Object.freeze(['DAILY', 'ROOT', 'FREEZE', 'RECOVERY']);
export const MULTI_ROLES = Object.freeze(['ADMIN', 'FREEZE', 'RECOVERY']);
// Pseudo-roles inside a requirement: SELF = the credential that is the subject of the action (rotation proves
// possession of the old key); ANY = any active, non-provisional credential (narrow-scope recovery consent/objection).
const PSEUDO = ['SELF', 'ANY'];

export const ACTIONS = Object.freeze(['PAY', 'AMEND_PURPOSE', 'AMEND_MATRIX', 'FREEZE', 'UNFREEZE', 'ROTATE_DAILY', 'ROTATE_ROOT',
  'ROTATE_FREEZE', 'ROTATE_RECOVERY', 'ROTATE_ADMIN', 'REVOKE', 'REPLACE_VACANT', 'SUSPEND', 'UNSUSPEND', 'RATIFY_BASELINE',
  'RECOVERY_CONSENT', 'RECOVERY_OBJECT', 'RECOVERY_WITHDRAW', 'RECOVERY_CANCEL', 'LOCKDOWN_CANCEL']);

/** Default personal matrix (5 independent credentials: K1/K2 DAILY, K3 ROOT, K4 FREEZE, K5 RECOVERY). */
export function defaultPersonalMatrix() {
  return {
    v: MATRIX_V, profile: 'personal', version: '1', countMode: 'credentials',
    rules: {
      PAY: { anyOf: [{ DAILY: '1' }], uv: '1' },
      AMEND_PURPOSE: { anyOf: [{ DAILY: '2', ROOT: '1' }], uv: '1' },
      AMEND_MATRIX: { anyOf: [{ DAILY: '2', ROOT: '1' }], uv: '1' },
      FREEZE: { anyOf: [{ FREEZE: '1' }, { DAILY: '1' }, { ROOT: '1' }, { RECOVERY: '1' }], uv: '0' },
      UNFREEZE: { anyOf: [{ ROOT: '1', DAILY: '1' }], uv: '1' },
      ROTATE_DAILY: { anyOf: [{ SELF: '1', DAILY: '1' }, { SELF: '1', ROOT: '1' }], uv: '1' },
      ROTATE_ROOT: { anyOf: [{ SELF: '1', DAILY: '2' }], uv: '1' },
      ROTATE_FREEZE: { anyOf: [{ SELF: '1', ROOT: '1' }], uv: '1' },
      ROTATE_RECOVERY: { anyOf: [{ SELF: '1', ROOT: '1', DAILY: '1' }], uv: '1', guardians: 'quorum' },
      ROTATE_ADMIN: { anyOf: [{ SELF: '1', DAILY: '1', ROOT: '1' }], uv: '1' },
      REVOKE: { anyOf: [{ DAILY: '1', ROOT: '1' }, { DAILY: '2' }], uv: '1' },
      REPLACE_VACANT: { anyOf: [{ ROOT: '1', DAILY: '1' }], uv: '1' },
      SUSPEND: { anyOf: [{ ANY: '1' }], uv: '0' },
      UNSUSPEND: { anyOf: [{ SELF: '1', ROOT: '1' }, { SELF: '1', DAILY: '1' }, { DAILY: '2', ROOT: '1' }], uv: '1' },
      RATIFY_BASELINE: { anyOf: [{ DAILY: '2', ROOT: '1' }], uv: '1' },
      RECOVERY_CONSENT: { anyOf: [{ ANY: '1' }], uv: '1' },
      RECOVERY_OBJECT: { anyOf: [{ ANY: '1' }], uv: '0' },
      RECOVERY_WITHDRAW: { anyOf: [{ ANY: '1' }], uv: '1' },
      RECOVERY_CANCEL: { anyOf: [{ ANY: '1' }], uv: '1' },
      LOCKDOWN_CANCEL: { anyOf: [{ ROOT: '1', DAILY: '1' }], uv: '1' },
    },
  };
}

/** Multi-administrator matrix: quorums count DISTINCT HUMAN HOLDERS, not credentials. */
export function defaultMultiAdminMatrix() {
  return {
    v: MATRIX_V, profile: 'multi-admin', version: '1', countMode: 'distinct-holders',
    rules: {
      PAY: { anyOf: [{ ADMIN: '1' }], uv: '1' },
      AMEND_PURPOSE: { anyOf: [{ ADMIN: '3' }], uv: '1' },
      AMEND_MATRIX: { anyOf: [{ ADMIN: '3' }], uv: '1' },
      FREEZE: { anyOf: [{ FREEZE: '1' }, { ADMIN: '1' }, { RECOVERY: '1' }], uv: '0' },
      UNFREEZE: { anyOf: [{ ADMIN: '2' }], uv: '1' },
      ROTATE_ADMIN: { anyOf: [{ SELF: '1', ADMIN: '1' }], uv: '1' },
      ROTATE_FREEZE: { anyOf: [{ SELF: '1', ADMIN: '1' }], uv: '1' },
      ROTATE_RECOVERY: { anyOf: [{ SELF: '1', ADMIN: '2' }], uv: '1', guardians: 'quorum' },
      ROTATE_DAILY: { anyOf: [{ SELF: '1', ADMIN: '1' }], uv: '1' },
      ROTATE_ROOT: { anyOf: [{ SELF: '1', ADMIN: '2' }], uv: '1' },
      REVOKE: { anyOf: [{ ADMIN: '2' }], uv: '1' },
      REPLACE_VACANT: { anyOf: [{ ADMIN: '2' }], uv: '1' },
      SUSPEND: { anyOf: [{ ANY: '1' }], uv: '0' },
      UNSUSPEND: { anyOf: [{ SELF: '1', ADMIN: '1' }, { ADMIN: '2' }], uv: '1' },
      RATIFY_BASELINE: { anyOf: [{ ADMIN: '3' }], uv: '1' },
      RECOVERY_CONSENT: { anyOf: [{ ANY: '1' }], uv: '1' },
      RECOVERY_OBJECT: { anyOf: [{ ANY: '1' }], uv: '0' },
      RECOVERY_WITHDRAW: { anyOf: [{ ANY: '1' }], uv: '1' },
      RECOVERY_CANCEL: { anyOf: [{ ANY: '1' }], uv: '1' },
      LOCKDOWN_CANCEL: { anyOf: [{ ADMIN: '2' }], uv: '1' },
    },
  };
}

const roleCount = (alt, r) => Number(alt[r] ?? '0');
const nonPseudo = (alt) => Object.keys(alt).filter(r => !PSEUDO.includes(r));
const total = (alt) => Object.values(alt).reduce((s, x) => s + Number(x), 0);

/** Hard floors (not amendable). Returns list of violations. */
export function floorViolations(m) {
  const v = [];
  const R = m.rules;
  const roles = m.profile === 'personal' ? PERSONAL_ROLES : MULTI_ROLES;
  const payRole = m.profile === 'personal' ? 'DAILY' : 'ADMIN';
  for (const a of R.PAY.anyOf) for (const r of Object.keys(a)) if (r !== payRole) v.push(`PAY_ROLE_${r}`); // K3/K4/K5 never pay
  for (const act of ['AMEND_PURPOSE', 'AMEND_MATRIX', 'RATIFY_BASELINE']) for (const a of R[act].anyOf) {
    if (a.ANY || a.SELF) v.push(`${act}_PSEUDO`);
    if (m.profile === 'personal' ? !(roleCount(a, 'DAILY') >= 2 && roleCount(a, 'ROOT') >= 1) : !(roleCount(a, 'ADMIN') >= 2)) v.push(`${act}_BELOW_FLOOR`);
    if (roleCount(a, 'RECOVERY') > 0 && total(a) - roleCount(a, 'RECOVERY') < 3) v.push(`${act}_RECOVERY_SUBSTITUTION`);
  }
  for (const a of R.UNFREEZE.anyOf) {
    if (nonPseudo(a).every(r => r === 'FREEZE' || r === 'RECOVERY')) v.push('UNFREEZE_BY_FREEZE_OR_RECOVERY_ONLY'); // K4 has no unilateral unfreeze
    if (total(a) < 2) v.push('UNFREEZE_SINGLE_KEY');
    if (a.ANY) v.push('UNFREEZE_PSEUDO');
  }
  for (const act of ['ROTATE_ROOT', 'ROTATE_RECOVERY', 'REVOKE', 'REPLACE_VACANT', 'LOCKDOWN_CANCEL']) for (const a of R[act].anyOf) if (total(a) < 2) v.push(`${act}_SINGLE_KEY`);
  for (const act of ['RECOVERY_CONSENT', 'RECOVERY_OBJECT', 'RECOVERY_WITHDRAW', 'RECOVERY_CANCEL', 'SUSPEND'])
    for (const a of R[act].anyOf) if (!(a.ANY && Object.keys(a).length === 1 && a.ANY === '1')) v.push(`${act}_SHAPE`); // narrow single-signer scopes stay narrow
  for (const act of ['PAY', 'AMEND_PURPOSE', 'AMEND_MATRIX', 'UNFREEZE', 'ROTATE_ROOT', 'RECOVERY_CONSENT']) if (R[act].uv !== '1') v.push(`${act}_UV_REQUIRED`);
  for (const act of ACTIONS) for (const a of R[act]?.anyOf ?? []) for (const r of Object.keys(a)) if (!roles.includes(r) && !PSEUDO.includes(r)) v.push(`UNKNOWN_ROLE_${r}`);
  return v;
}

export function parseMatrix(m) {
  exactFields(m, ['v', 'profile', 'version', 'countMode', 'rules']);
  if (m.v !== MATRIX_V) fail('MATRIX_VERSION_UNSUPPORTED');
  if (!['personal', 'multi-admin'].includes(m.profile)) fail('MATRIX_PROFILE');
  if (m.countMode !== (m.profile === 'personal' ? 'credentials' : 'distinct-holders')) fail('MATRIX_COUNT_MODE');
  if (!/^[1-9][0-9]{0,5}$/.test(m.version)) fail('MATRIX_VERSION');
  exactFields(m.rules, ACTIONS, [], 'MATRIX_RULES');
  for (const act of ACTIONS) {
    const r = exactFields(m.rules[act], ['anyOf', 'uv'], ['guardians'], 'MATRIX_RULE');
    if (!Array.isArray(r.anyOf) || r.anyOf.length < 1 || r.anyOf.length > 8) fail('MATRIX_RULE', act);
    if (!['0', '1'].includes(r.uv)) fail('MATRIX_RULE_UV', act);
    if ('guardians' in r && r.guardians !== 'quorum') fail('MATRIX_RULE_GUARDIANS', act);
    for (const a of r.anyOf) { if (!a || typeof a !== 'object' || Array.isArray(a) || !Object.keys(a).length) fail('MATRIX_ALT', act); for (const x of Object.values(a)) if (!/^[1-9]$/.test(x)) fail('MATRIX_ALT_COUNT', act); }
  }
  const v = floorViolations(m);
  if (v.length) fail('MATRIX_BELOW_HARD_FLOOR', v.slice(0, 6).join(','));
  return deepFreeze(clone(m));
}
export const matrixDigest = (m) => digestHex(V3_DOMAINS.MATRIX, m);

/** Strengthen-only amendment: every new alternative must dominate at least one old alternative (role-wise >=). */
export function amendmentViolations(oldM, newM, activeRoleCounts) {
  const v = [];
  if (newM.profile !== oldM.profile) v.push('PROFILE_CHANGE');
  if (BigInt(newM.version) !== BigInt(oldM.version) + 1n) v.push('VERSION_NOT_SEQUENTIAL');
  for (const act of ACTIONS) {
    for (const alt of newM.rules[act].anyOf) {
      const dominatesSome = oldM.rules[act].anyOf.some(o => Object.keys(o).every(r => roleCount(alt, r) >= roleCount(o, r)));
      if (!dominatesSome) v.push(`${act}_WEAKENED`);
    }
    if (oldM.rules[act].uv === '1' && newM.rules[act].uv !== '1') v.push(`${act}_UV_WEAKENED`);
    if (oldM.rules[act].guardians && !newM.rules[act].guardians) v.push(`${act}_GUARDIANS_DROPPED`);
    // usability invariant: an amendment must not make an action unsatisfiable with the current credential set
    const satisfiable = newM.rules[act].anyOf.some(alt => nonPseudo(alt).every(r => (activeRoleCounts[r] ?? 0) >= roleCount(alt, r)));
    if (!satisfiable) v.push(`${act}_UNSATISFIABLE`);
  }
  return v;
}
