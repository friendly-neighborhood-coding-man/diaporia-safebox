// SafeBox V3 Purpose Root: deterministic, independently verifiable state machine.
//
// The Root state (purpose capsule, authority matrix, credentials, epoch, freeze/lockdown, recovery case) changes ONLY
// through transitions in a hash chain anchored at a pinned genesis digest. Every transition carries the owner-side
// evidence that authorizes it (WebAuthn assertions, external-key signatures, guardian/identity/registrar statements).
// The same pure function `applyTransition` is run by the Root service (sequencer), by the Execution Vault (its own
// replica) and by the independent verifier: a compromised Root service, Recovery service or executor cannot make the
// other domains accept a transition that the owner's credentials did not authorize.
import { fail, SafeBoxError, canon, exactFields, id, uint, isoMs, iso, digest, digestHex, sha256hex, V3_DOMAINS, clone, edVerifyDigest, edVerifyStatement, ED_PREFIX } from '../common/canon.mjs';
import { parseMatrix, matrixDigest, amendmentViolations as matrixAmendViolations, PERSONAL_ROLES, MULTI_ROLES } from '../authority/matrix.mjs';
import { parseCapsule, capsuleDigest, amendmentViolations as capsuleAmendViolations } from './capsule.mjs';
import { verifyEnrollment, independenceViolations } from '../authority/enroll.mjs';
import { verifyAssertion } from '../webauthn/verify.mjs';

export const ACTION_V = 'safebox.v3.action';
export const TR_V = 'safebox.v3.transition';
export const ZERO = '0'.repeat(64);

export const DEFAULT_CONFIG = Object.freeze({
  windowMs: String(72 * 3600_000),      // protected verification/objection window (<= 72 h)
  minWindowMs: String(3600_000),        // floor for early completion when every channel positively acknowledged
  guardianQuorum: '2',                  // M of N guardians for ordinary recovery
  reconGuardianQuorum: '3',             // stricter quorum for reconstitution (default N of N)
  reconIdentityAttestations: '2',       // distinct identity verifiers for reconstitution
  reconMinSurvivors: '1',               // reconstitution needs >= 1 surviving original credential
  provisionalMs: String(30 * 86_400_000), // recovered credentials cannot consent / ratify for 30 days
  reconCooldownMs: String(30 * 86_400_000),
  caseCooldownMs: String(3600_000),     // anti-spam: one case at a time, 1 h between cases
  maxActionTtlMs: String(96 * 3600_000),
  skewMs: String(300_000),
});
const CONFIG_FIELDS = Object.keys(DEFAULT_CONFIG);
const RECOVERY_STATES = ['LOSS_REPORTED', 'IDENTITY_CHECK', 'RECOVERY_CHALLENGE', 'HOLD', 'INSUFFICIENT_AUTHORITY', 'EMERGENCY_LOCKDOWN', 'RECONSTITUTION', 'RECOVERY_IMPOSSIBLE'];

// ---------------------------------------------------------------- helpers
const rolesOf = (m) => m.profile === 'personal' ? PERSONAL_ROLES : MULTI_ROLES;
const isLive = (c) => c.status === 'active' || c.status === 'suspended';
export const actionDigest = (action) => digest(V3_DOMAINS.ACTION, action);

function parseConfig(c) {
  exactFields(c, CONFIG_FIELDS, [], 'CONFIG_FIELDS');
  const n = Object.fromEntries(CONFIG_FIELDS.map(k => [k, Number(uint(c[k], k))]));
  if (n.windowMs > 72 * 3600_000 || n.windowMs < n.minWindowMs || n.minWindowMs < 600_000) fail('CONFIG_WINDOW');
  if (n.guardianQuorum < 2 || n.reconGuardianQuorum < n.guardianQuorum) fail('CONFIG_GUARDIAN_QUORUM');
  if (n.reconIdentityAttestations < 1 || n.reconMinSurvivors < 1) fail('CONFIG_RECON');
  return c;
}

/** Assigns verified approvers to an alternative's role slots. Returns true if satisfied. */
function satisfies(alt, approvers, { subject, countMode }) {
  const pool = approvers.filter(a => a.credId !== subject);
  const holdersUsed = new Set();
  let ok = true;
  if (alt.SELF) { if (!approvers.some(a => a.credId === subject)) return false; const s = approvers.find(a => a.credId === subject); holdersUsed.add(s.holderId); }
  for (const [role, cntS] of Object.entries(alt)) {
    if (role === 'SELF') continue;
    const need = Number(cntS);
    const cands = pool.filter(a => role === 'ANY' ? a.eligibleAny : a.role === role);
    if (countMode === 'distinct-holders') {
      const hs = [...new Set(cands.map(a => a.holderId))].filter(h => !holdersUsed.has(h));
      if (hs.length < need) ok = false; else hs.slice(0, need).forEach(h => holdersUsed.add(h));
    } else if (cands.length < need) ok = false;
  }
  return ok;
}

/**
 * Verifies approvals for an action under a matrix rule. Fails closed on ANY invalid approval.
 * Returns { approvers, signCounts }.
 */
export function verifyApprovals(state, action, approvals, ruleName, { subject = null, at, allowSuspendedSelf = false, eligibleAny = null } = {}) {
  const rule = state.matrix.rules[ruleName];
  if (!rule) fail('NO_RULE', ruleName);
  if (!Array.isArray(approvals) || approvals.length > 12) fail('APPROVALS_INVALID');
  const dig = actionDigest(action);
  const seen = new Set(); const approvers = []; const signCounts = {};
  for (const ap of approvals) {
    exactFields(ap, ['credId'], ['webauthn', 'sig'], 'APPROVAL_FIELDS');
    if (seen.has(ap.credId)) fail('DUPLICATE_APPROVAL'); seen.add(ap.credId);
    const c = state.creds[ap.credId];
    if (!c) fail('APPROVAL_UNKNOWN_CREDENTIAL');
    const selfSusp = allowSuspendedSelf && ap.credId === subject && c.status === 'suspended';
    if (c.status !== 'active' && !selfSusp) fail('APPROVAL_CREDENTIAL_NOT_ACTIVE', `${ap.credId}:${c.status}`);
    let uv = false;
    if (c.kind === 'passkey') {
      if (!ap.webauthn || 'sig' in ap) fail('APPROVAL_KIND_MISMATCH');
      const r = verifyAssertion(ap.webauthn, { rp: state.rp, expectedChallenge: dig, credential: { ...c.webauthn, signCount: c.signCount }, requireUV: rule.uv === '1' });
      uv = r.uv; signCounts[ap.credId] = r.signCount;
    } else {
      if (typeof ap.sig !== 'string' || 'webauthn' in ap) fail('APPROVAL_KIND_MISMATCH');
      if (!edVerifyDigest(V3_DOMAINS.ACTION, dig, ap.sig, c.publicKey)) fail('APPROVAL_BAD_SIGNATURE', ap.credId);
    }
    const provisional = Number(c.provisionalUntil ?? 0) > at;
    approvers.push({ credId: c.credId, role: c.role, holderId: c.holderId, uv, provisional,
      eligibleAny: (eligibleAny ? eligibleAny(c) : true) && !provisional && c.credId !== subject });
  }
  const ok = rule.anyOf.some(alt => satisfies(alt, approvers, { subject, countMode: state.matrix.countMode }));
  if (!ok) fail('QUORUM_NOT_SATISFIED', ruleName);
  // uv='1': every passkey approval must carry UV (enforced in verifyAssertion) and multi-signer actions need >= 1 UV
  // assertion. Single-signer narrow scopes (recovery consent/withdraw/cancel) may be signed by an external hardware key
  // alone: otherwise K3/K5 hardware keys could never consent and recovery would be impossible (found by the 0..5 sweep).
  const multi = rule.anyOf.every(alt => Object.values(alt).reduce((x, n) => x + Number(n), 0) >= 2);
  if (rule.uv === '1' && multi && !approvers.some(a => a.uv)) fail('USER_VERIFICATION_REQUIRED', ruleName);
  return { approvers: approvers.map(a => a.credId), signCounts, digestHex: dig.toString('hex') };
}

function checkGuardians(state, action, guardianApprovals, need) {
  const dig = actionDigest(action);
  const ok = new Set();
  for (const g of guardianApprovals ?? []) {
    exactFields(g, ['guardianId', 'sig'], [], 'GUARDIAN_APPROVAL_FIELDS');
    const gr = state.guardians[g.guardianId];
    if (!gr || gr.status !== 'active') fail('GUARDIAN_UNKNOWN');
    if (!edVerifyStatement(V3_DOMAINS.GUARDIAN, { actionDigest: dig.toString('hex'), decision: 'APPROVE' }, g.sig, gr.publicKey)) fail('GUARDIAN_BAD_SIGNATURE');
    ok.add(gr.holderId);
  }
  if (ok.size < need) fail('GUARDIAN_QUORUM_NOT_MET');
}

function checkActionHeader(state, action, at) {
  exactFields(action, ['v', 'type', 'accountId', 'chainId', 'epoch', 'matrixVersion', 'purposeVersion', 'nonce', 'issuedAt', 'expiresAt', 'body'], [], 'ACTION_FIELDS');
  if (action.v !== ACTION_V) fail('ACTION_VERSION');
  if (action.accountId !== state.accountId) fail('ACTION_WRONG_ACCOUNT');
  if (action.chainId !== state.chainId) fail('ACTION_WRONG_CHAIN');
  if (action.epoch !== String(state.epoch)) fail('STALE_EPOCH', `action=${action.epoch} current=${state.epoch}`);
  if (action.matrixVersion !== state.matrix.version) fail('STALE_MATRIX_VERSION');
  if (action.purposeVersion !== state.purpose.version) fail('STALE_PURPOSE_VERSION');
  if (typeof action.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(action.nonce)) fail('ACTION_NONCE');
  if (state.usedNonces[action.nonce] !== undefined) fail('ACTION_REPLAY');
  const ia = isoMs(action.issuedAt, 'issuedAt'), ea = isoMs(action.expiresAt, 'expiresAt');
  if (ea <= ia || ea - ia > Number(state.config.maxActionTtlMs)) fail('ACTION_TTL');
  if (ia > at + Number(state.config.skewMs)) fail('ACTION_FROM_FUTURE');
  if (at >= ea) fail('ACTION_EXPIRED');
}

function pinEnrollments(state, enrollments, context, { replacingRoles = null } = {}) {
  if (!Array.isArray(enrollments) || !enrollments.length || enrollments.length > 8) fail('ENROLLMENTS_INVALID');
  const everything = Object.values(state.creds).map(c => c);
  const out = [];
  for (const e of enrollments) {
    const c = verifyEnrollment(e, { accountId: state.accountId, rp: state.rp, context, roles: rolesOf(state.matrix) });
    if (!state.channels[c.channelId]) fail('ENROLLMENT_UNKNOWN_CHANNEL');
    const v = independenceViolations(c, [...everything, ...out]);
    if (v.length) fail('CREDENTIAL_NOT_INDEPENDENT', v.join(','));
    out.push(c);
  }
  if (replacingRoles) {
    const a = [...replacingRoles].sort().join(','), b = out.map(c => c.role).sort().join(',');
    if (a !== b) fail('REPLACEMENT_ROLES_MISMATCH', `${a} vs ${b}`);
  }
  return out;
}

function activeRoleCounts(state) {
  const r = {};
  for (const c of Object.values(state.creds)) if (c.status === 'active') r[c.role] = (r[c.role] ?? 0) + 1;
  return r;
}

// ---------------------------------------------------------------- recovery helpers
export function caseDigestOf(cs) {
  return digestHex(V3_DOMAINS.ACTION, { caseId: cs.caseId, kind: cs.kind, lost: cs.lost, subjectHolderId: cs.subjectHolderId,
    plan: cs.plan.map(c => `${c.credId}|${c.role}|${c.publicKey}`), openedAt: iso(cs.openedAt) });
}
/** Survivors: live, not claimed lost, not provisional (recovered credentials cannot launder further recoveries). */
export function survivors(state, cs, at) {
  return Object.values(state.creds).filter(c => isLive(c) && !cs.lost.includes(c.credId) && !(Number(c.provisionalUntil ?? 0) > at)).map(c => c.credId);
}
/** Loss accounting against the fixed BASELINE (denominator never resets through partial recoveries). */
export function lossAssessment(state, cs, at) {
  const baseline = state.baseline.credIds;
  const lostSet = new Set([...state.lostSinceBaseline, ...cs.lost.filter(x => baseline.includes(x))]);
  // Credentials added by recovery that are now claimed lost also count against the baseline role they replaced.
  for (const x of cs.lost) if (!baseline.includes(x)) lostSet.add('replacement:' + x);
  const ratioNum = lostSet.size, ratioDen = baseline.length;
  const surv = survivors(state, cs, at);
  const survRoles = new Set(surv.map(x => state.creds[x].role));
  const personal = state.matrix.profile === 'personal';
  const critical = personal ? !(survRoles.has('DAILY') || survRoles.has('ROOT')) : !survRoles.has('ADMIN');
  return { lostCount: ratioNum, baseline: ratioDen, overHalf: ratioNum * 2 > ratioDen, critical, survivors: surv };
}

// ---------------------------------------------------------------- genesis
export function genesisState(gen, { pinnedChainId = null } = {}) {
  // gen = { action (type GENESIS), approvals, at }
  const a = gen.action;
  exactFields(a, ['v', 'type', 'accountId', 'nonce', 'issuedAt', 'body'], [], 'GENESIS_FIELDS');
  if (a.v !== ACTION_V || a.type !== 'GENESIS') fail('GENESIS_TYPE');
  const chainId = actionDigest(a).toString('hex');
  if (pinnedChainId && chainId !== pinnedChainId) fail('GENESIS_NOT_PINNED');
  const b = exactFields(a.body, ['rp', 'config', 'matrix', 'capsule', 'channels', 'credentials', 'guardians', 'identityVerifiers', 'registrars', 'serviceKeys'], [], 'GENESIS_BODY');
  exactFields(b.rp, ['rpId', 'origin'], [], 'GENESIS_RP');
  if (!/^[a-z0-9.-]{3,64}$/.test(b.rp.rpId) || b.rp.origin !== 'https://' + b.rp.rpId) fail('GENESIS_RP');
  const matrix = parseMatrix(b.matrix); const capsule = parseCapsule(b.capsule); parseConfig(b.config);
  if (capsule.accountId !== a.accountId) fail('GENESIS_CAPSULE_ACCOUNT');
  const keyMap = (o, code) => { const m = {}; for (const [k, v] of Object.entries(o)) { id(k, code); exactFields(v, ['publicKey', 'holderId'], [], code); if (!v.publicKey.startsWith(ED_PREFIX)) fail(code); id(v.holderId, code); m[k] = { ...v, status: 'active' }; } return m; };
  const state = {
    accountId: a.accountId, chainId, seq: 0, head: ZERO, epoch: 1, lastAt: 0, rp: { ...b.rp }, config: { ...b.config },
    matrix, matrixDigest: matrixDigest(matrix), purpose: capsule, purposeDigest: capsuleDigest(capsule),
    channels: keyMap(b.channels, 'GENESIS_CHANNEL'), guardians: keyMap(b.guardians, 'GENESIS_GUARDIAN'),
    idvs: keyMap(b.identityVerifiers, 'GENESIS_IDV'), registrars: keyMap(b.registrars, 'GENESIS_REGISTRAR'),
    serviceKeys: exactFields({ ...b.serviceKeys }, ['supervisorFreeze', 'supervisorRepair', 'notifier'], [], 'GENESIS_SERVICE_KEYS'),
    creds: {}, baseline: { epoch: 1, credIds: [] }, lostSinceBaseline: [], lastReconstitutionAt: 0,
    freeze: { active: false, freezeId: null, requiresRepair: false, source: null, at: 0 }, lockdown: { active: false, caseId: null },
    case: null, lastCaseClosedAt: 0, caseHistory: [], usedNonces: {}, transitions: 0,
  };
  // guardians must be independent of the owner's credentials and of each other
  const gkeys = Object.values(state.guardians).map(g => g.publicKey);
  if (new Set(gkeys).size !== gkeys.length || new Set(Object.values(state.guardians).map(g => g.holderId)).size !== gkeys.length) fail('GUARDIANS_NOT_INDEPENDENT');
  if (Number(b.config.reconGuardianQuorum) > gkeys.length) fail('CONFIG_GUARDIAN_QUORUM_EXCEEDS_GUARDIANS');
  const creds = pinEnrollments(state, b.credentials, 'genesis:' + a.nonce);
  for (const c of creds) {
    if (state.guardians[c.holderId] || Object.values(state.guardians).some(g => g.holderId === c.holderId || g.publicKey === c.publicKey)) fail('GUARDIAN_IS_CREDENTIAL_HOLDER');
    state.creds[c.credId] = { ...c, status: 'active', epochAdded: 1, provisionalUntil: 0 };
  }
  // high-security personal profile: >= 5 independent credentials with every role present
  const rc = activeRoleCounts(state);
  if (matrix.profile === 'personal' && !(creds.length >= 5 && rc.DAILY >= 2 && rc.ROOT >= 1 && rc.FREEZE >= 1 && rc.RECOVERY >= 1)) fail('PERSONAL_PROFILE_NEEDS_FIVE_INDEPENDENT_CREDENTIALS');
  if (matrix.profile === 'multi-admin' && new Set(creds.filter(c => c.role === 'ADMIN').map(c => c.holderId)).size < 3) fail('MULTI_ADMIN_NEEDS_THREE_HOLDERS');
  for (const r of Object.keys(matrix.rules)) if (!matrix.rules[r].anyOf.some(alt => Object.entries(alt).every(([role, n]) => role === 'SELF' || role === 'ANY' || (rc[role] ?? 0) >= Number(n)))) fail('GENESIS_ACTION_UNSATISFIABLE', r);
  // every enrolled credential approves genesis (possession + consent); passkeys with UV
  const dig = actionDigest(a);
  const signed = new Set();
  for (const ap of gen.approvals ?? []) {
    const c = state.creds[ap.credId]; if (!c || signed.has(ap.credId)) fail('GENESIS_APPROVAL');
    if (c.kind === 'passkey') { const r = verifyAssertion(ap.webauthn, { rp: state.rp, expectedChallenge: dig, credential: { ...c.webauthn, signCount: c.signCount }, requireUV: true }); c.signCount = r.signCount; }
    else if (!edVerifyDigest(V3_DOMAINS.ACTION, dig, ap.sig, c.publicKey)) fail('GENESIS_APPROVAL_SIGNATURE');
    signed.add(ap.credId);
  }
  if (signed.size !== creds.length) fail('GENESIS_NOT_APPROVED_BY_ALL_CREDENTIALS');
  state.baseline = { epoch: 1, credIds: creds.map(c => c.credId) };
  state.usedNonces[a.nonce] = 0;
  state.lastAt = isoMs(gen.at, 'at');
  state.head = sha256hex(Buffer.concat([Buffer.from(V3_DOMAINS.TRANSITION), Buffer.from(ZERO), Buffer.from(canon({ seq: '0', at: gen.at, actionDigest: chainId }))]));
  return state;
}

// ---------------------------------------------------------------- transitions
export function transitionHash(prev, tr) {
  return sha256hex(Buffer.concat([Buffer.from(V3_DOMAINS.TRANSITION), Buffer.from(prev), Buffer.from(canon({ seq: tr.seq, at: tr.at, actionDigest: actionDigest(tr.action).toString('hex'),
    evidence: sha256hex(Buffer.from(canon({ approvals: tr.approvals ?? [], guardianApprovals: tr.guardianApprovals ?? [], attestation: tr.attestation ?? {} }))) }))]));
}

/**
 * Pure state transition. tr = { v, seq, prev, at, action, approvals?, guardianApprovals?, attestation? }.
 * Returns { state: newState, effects: [...] } or throws SafeBoxError (state unchanged).
 */
export function applyTransition(state0, tr) {
  exactFields(tr, ['v', 'seq', 'prev', 'at', 'action'], ['approvals', 'guardianApprovals', 'attestation'], 'TRANSITION_FIELDS');
  if (tr.v !== TR_V) fail('TRANSITION_VERSION');
  if (tr.seq !== String(state0.seq + 1)) fail('TRANSITION_SEQ', `${tr.seq} vs ${state0.seq + 1}`);
  if (tr.prev !== state0.head) fail('TRANSITION_FORK');
  const at = isoMs(tr.at, 'at');
  if (at < state0.lastAt) fail('TRANSITION_TIME_BACKWARDS');
  const s = clone(state0);
  const a = tr.action;
  checkActionHeader(s, a, at);
  const effects = [];
  const H = HANDLERS[a.type];
  if (!H) fail('TRANSITION_TYPE_UNKNOWN', a.type);
  H(s, a, tr, at, effects);
  s.usedNonces[a.nonce] = s.seq + 1;
  s.seq += 1; s.lastAt = at; s.transitions += 1;
  s.head = transitionHash(state0.head, tr);
  return { state: s, effects };
}

function applySignCounts(s, signCounts) { for (const [k, v] of Object.entries(signCounts)) s.creds[k].signCount = v; }
function bumpEpoch(s, effects, why) { s.epoch += 1; effects.push({ type: 'EPOCH', epoch: s.epoch, why }); }
function noCase(s, code = 'RECOVERY_IN_PROGRESS') { if (s.case) fail(code); }
function noLockdown(s) { if (s.lockdown.active) fail('EMERGENCY_LOCKDOWN_ACTIVE'); }
const body = (a, req, opt = []) => exactFields(a.body, req, opt, `BODY_${a.type}`);

const ROTATE_RULE = { DAILY: 'ROTATE_DAILY', ROOT: 'ROTATE_ROOT', FREEZE: 'ROTATE_FREEZE', RECOVERY: 'ROTATE_RECOVERY', ADMIN: 'ROTATE_ADMIN' };

const HANDLERS = {
  AMEND_PURPOSE(s, a, tr, at, fx) {
    noCase(s); noLockdown(s);
    body(a, ['capsule']);
    const r = verifyApprovals(s, a, tr.approvals, 'AMEND_PURPOSE', { at }); applySignCounts(s, r.signCounts);
    const c = parseCapsule(a.body.capsule);
    const v = capsuleAmendViolations(s.purpose, c);
    if (v.length) fail('PURPOSE_AMENDMENT_INVALID', v.join(','));
    s.purpose = c; s.purposeDigest = capsuleDigest(c);
    fx.push({ type: 'PURPOSE_AMENDED', version: c.version, digest: s.purposeDigest, approvers: r.approvers });
  },
  AMEND_MATRIX(s, a, tr, at, fx) {
    noCase(s); noLockdown(s);
    body(a, ['matrix']);
    const r = verifyApprovals(s, a, tr.approvals, 'AMEND_MATRIX', { at }); applySignCounts(s, r.signCounts);
    const m = parseMatrix(a.body.matrix);
    const v = matrixAmendViolations(s.matrix, m, activeRoleCounts(s));
    if (v.length) fail('MATRIX_AMENDMENT_INVALID', v.slice(0, 6).join(','));
    s.matrix = m; s.matrixDigest = matrixDigest(m);
    fx.push({ type: 'MATRIX_AMENDED', version: m.version, approvers: r.approvers });
  },
  FREEZE(s, a, tr, at, fx) {
    body(a, ['freezeId', 'reason', 'source']);
    id(a.body.freezeId, 'freezeId');
    if (typeof a.body.reason !== 'string' || a.body.reason.length > 200) fail('FREEZE_REASON');
    if (a.body.source === 'supervisor') {
      // the independent supervisor may freeze (never unfreeze): signature by its pinned freeze key, no credentials
      exactFields(tr.attestation ?? {}, ['supervisorSig'], [], 'FREEZE_ATTESTATION');
      if (tr.approvals?.length) fail('FREEZE_MIXED_AUTHORITY');
      if (!edVerifyDigest(V3_DOMAINS.SUPERVISOR_FREEZE, actionDigest(a), tr.attestation.supervisorSig, s.serviceKeys.supervisorFreeze)) fail('SUPERVISOR_FREEZE_SIGNATURE');
    } else if (a.body.source === 'owner') {
      const r = verifyApprovals(s, a, tr.approvals, 'FREEZE', { at }); applySignCounts(s, r.signCounts);
    } else fail('FREEZE_SOURCE');
    if (s.freeze.active) { s.freeze.requiresRepair ||= a.body.source === 'supervisor'; fx.push({ type: 'FREEZE_REINFORCED' }); return; }
    s.freeze = { active: true, freezeId: a.body.freezeId, requiresRepair: a.body.source === 'supervisor', source: a.body.source, at };
    fx.push({ type: 'FROZEN', freezeId: a.body.freezeId, source: a.body.source });
  },
  UNFREEZE(s, a, tr, at, fx) {
    body(a, ['freezeId']);
    if (!s.freeze.active) fail('NOT_FROZEN');
    if (a.body.freezeId !== s.freeze.freezeId) fail('UNFREEZE_NOT_BOUND_TO_THIS_FREEZE');
    const r = verifyApprovals(s, a, tr.approvals, 'UNFREEZE', { at }); applySignCounts(s, r.signCounts);
    if (s.freeze.requiresRepair) {
      // a breach freeze lifts only with the supervisor's trusted-replay repair certificate for THIS freeze
      exactFields(tr.attestation ?? {}, ['repair'], [], 'UNFREEZE_ATTESTATION');
      const rp = exactFields(tr.attestation.repair, ['statement', 'sig'], [], 'REPAIR_CERT');
      const st = exactFields(rp.statement, ['freezeId', 'verdict', 'exactReplay', 'mutations', 'regression', 'legitimate', 'candidate'], [], 'REPAIR_STATEMENT');
      if (st.freezeId !== s.freeze.freezeId) fail('REPAIR_CERT_WRONG_FREEZE');
      if (st.verdict !== 'REPAIRED' || st.exactReplay !== 'DENIED_FOR_INVARIANT' || st.mutations !== 'ALL_DENIED' || st.regression !== 'PASS' || st.legitimate !== 'PASS') fail('REPAIR_NOT_COMPLETE');
      if (!edVerifyStatement(V3_DOMAINS.REPAIR, st, rp.sig, s.serviceKeys.supervisorRepair)) fail('REPAIR_CERT_SIGNATURE');
    }
    s.freeze = { active: false, freezeId: null, requiresRepair: false, source: null, at };
    fx.push({ type: 'UNFROZEN', approvers: r.approvers });
  },
  ROTATE(s, a, tr, at, fx) {
    noCase(s); noLockdown(s);
    body(a, ['credId', 'newCredential']);
    const old = s.creds[a.body.credId];
    if (!old || old.status !== 'active') fail('ROTATE_SUBJECT_NOT_ACTIVE');
    const rule = ROTATE_RULE[old.role];
    const r = verifyApprovals(s, a, tr.approvals, rule, { subject: old.credId, at }); applySignCounts(s, r.signCounts);
    if (s.matrix.rules[rule].guardians) checkGuardians(s, a, tr.guardianApprovals, Number(s.config.guardianQuorum));
    const [nc] = pinEnrollments(s, [a.body.newCredential], `${s.accountId}:${a.nonce}`, { replacingRoles: [old.role] });
    old.status = 'retired'; old.retiredAt = at; old.retiredBy = 'rotation';
    s.creds[nc.credId] = { ...nc, status: 'active', epochAdded: s.epoch + 1, provisionalUntil: 0 };
    s.baseline.credIds = s.baseline.credIds.map(x => x === old.credId ? nc.credId : x); // role-preserving rotation keeps the baseline slot
    bumpEpoch(s, fx, `rotate ${old.role}`);
    fx.push({ type: 'ROTATED', role: old.role, from: old.credId, to: nc.credId, approvers: r.approvers });
  },
  REVOKE(s, a, tr, at, fx) {
    noCase(s);
    body(a, ['credId', 'reason']);
    const c = s.creds[a.body.credId];
    if (!c || !isLive(c)) fail('REVOKE_SUBJECT_NOT_LIVE');
    // the subject never counts toward its own revocation quorum
    if ((tr.approvals ?? []).some(x => x.credId === c.credId)) fail('REVOKE_SELF_APPROVAL');
    const r = verifyApprovals(s, a, tr.approvals, 'REVOKE', { subject: c.credId, at });
    applySignCounts(s, r.signCounts);
    c.status = 'revoked'; c.revokedAt = at;
    bumpEpoch(s, fx, 'revoke'); // outstanding capabilities and pending operations of the old epoch die here
    fx.push({ type: 'REVOKED', credId: c.credId, role: c.role, approvers: r.approvers });
  },
  REPLACE_VACANT(s, a, tr, at, fx) {
    noCase(s); noLockdown(s);
    body(a, ['revokedCredId', 'newCredential']);
    const old = s.creds[a.body.revokedCredId];
    if (!old || old.status !== 'revoked' || old.replacedBy) fail('REPLACE_SUBJECT_NOT_REVOKED');
    // ROOT and RECOVERY vacancies are refilled only through the recovery protocol (guardians + identity + window)
    if (['ROOT', 'RECOVERY'].includes(old.role)) fail('VACANCY_REQUIRES_RECOVERY_PROTOCOL');
    const r = verifyApprovals(s, a, tr.approvals, 'REPLACE_VACANT', { at }); applySignCounts(s, r.signCounts);
    const [nc] = pinEnrollments(s, [a.body.newCredential], `${s.accountId}:${a.nonce}`, { replacingRoles: [old.role] });
    old.replacedBy = nc.credId;
    s.creds[nc.credId] = { ...nc, status: 'active', epochAdded: s.epoch + 1, provisionalUntil: 0 };
    s.baseline.credIds = s.baseline.credIds.map(x => x === old.credId ? nc.credId : x);
    bumpEpoch(s, fx, 'replace vacant');
    fx.push({ type: 'REPLACED', role: old.role, from: old.credId, to: nc.credId, approvers: r.approvers });
  },
  SUSPEND(s, a, tr, at, fx) {
    body(a, ['credId']);
    const c = s.creds[a.body.credId];
    if (!c || c.status !== 'active') fail('SUSPEND_SUBJECT_NOT_ACTIVE');
    const r = verifyApprovals(s, a, tr.approvals, 'SUSPEND', { subject: c.credId, at }); applySignCounts(s, r.signCounts);
    c.status = 'suspended'; c.suspendedAt = at;
    fx.push({ type: 'SUSPENDED', credId: c.credId, by: r.approvers });
  },
  UNSUSPEND(s, a, tr, at, fx) {
    body(a, ['credId']);
    const c = s.creds[a.body.credId];
    if (!c || c.status !== 'suspended') fail('UNSUSPEND_SUBJECT_NOT_SUSPENDED');
    if (s.case && s.case.lost.includes(c.credId)) fail('UNSUSPEND_DURING_OWN_RECOVERY');
    const r = verifyApprovals(s, a, tr.approvals, 'UNSUSPEND', { subject: c.credId, at, allowSuspendedSelf: true }); applySignCounts(s, r.signCounts);
    c.status = 'active';
    fx.push({ type: 'UNSUSPENDED', credId: c.credId });
  },
  RATIFY_BASELINE(s, a, tr, at, fx) {
    noCase(s); noLockdown(s);
    body(a, []);
    if (Object.values(s.creds).some(c => isLive(c) && Number(c.provisionalUntil ?? 0) > at)) fail('PROVISIONAL_CREDENTIALS_PRESENT');
    const r = verifyApprovals(s, a, tr.approvals, 'RATIFY_BASELINE', { at }); applySignCounts(s, r.signCounts);
    s.baseline = { epoch: s.epoch, credIds: Object.values(s.creds).filter(c => c.status === 'active').map(c => c.credId) };
    s.lostSinceBaseline = [];
    fx.push({ type: 'BASELINE_RATIFIED', size: s.baseline.credIds.length });
  },

  // ------------------------------------------------ Recovery V0
  RECOVERY_OPEN(s, a, tr, at, fx) {
    // A loss CLAIM: needs no authority and changes no authority. It only starts the protected window and the
    // mandatory notifications. Nothing is revoked, destroyed or reconstituted by a claim.
    body(a, ['caseId', 'kind', 'lost', 'subjectHolderId', 'plan', 'note']);
    if (s.case) fail('RECOVERY_CASE_ALREADY_OPEN');
    if (at < s.lastCaseClosedAt + Number(s.config.caseCooldownMs)) fail('RECOVERY_CASE_COOLDOWN');
    if (tr.approvals?.length) fail('RECOVERY_OPEN_TAKES_NO_APPROVALS');
    id(a.body.caseId, 'caseId'); id(a.body.subjectHolderId, 'subjectHolderId');
    if (typeof a.body.note !== 'string' || a.body.note.length > 200) fail('RECOVERY_NOTE');
    if (!['KEY_LOSS', 'DECEASED', 'MISSING'].includes(a.body.kind)) fail('RECOVERY_KIND');
    if (a.body.kind !== 'KEY_LOSS' && s.matrix.profile === 'personal') fail('EVIDENCE_REVIEW_NOT_SUPPORTED_IN_PERSONAL_PROFILE');
    if (!Array.isArray(a.body.lost) || !a.body.lost.length || new Set(a.body.lost).size !== a.body.lost.length) fail('RECOVERY_LOST_SET');
    for (const x of a.body.lost) { const c = s.creds[x]; if (!c || !isLive(c)) fail('RECOVERY_LOST_NOT_LIVE', x); if (c.holderId !== a.body.subjectHolderId) fail('RECOVERY_LOST_HOLDER_MISMATCH'); }
    if (a.body.kind !== 'KEY_LOSS') {
      const all = Object.values(s.creds).filter(c => isLive(c) && c.holderId === a.body.subjectHolderId).map(c => c.credId).sort();
      if (all.join(',') !== [...a.body.lost].sort().join(',')) fail('EVIDENCE_REVIEW_MUST_COVER_ALL_HOLDER_CREDENTIALS');
    }
    const plan = pinEnrollments(s, a.body.plan, `${s.accountId}:${a.nonce}`);
    const cs = { caseId: a.body.caseId, kind: a.body.kind, lost: [...a.body.lost], subjectHolderId: a.body.subjectHolderId, plan, openedAt: at,
      state: 'LOSS_REPORTED', path: null, confirmed: false, dispatched: [], acks: {}, identity: {}, official: {}, consents: {}, guardians: {}, disputes: [], prior: null, openNonce: a.nonce };
    cs.digest = caseDigestOf(cs);
    s.case = cs;
    fx.push({ type: 'RECOVERY_OPENED', caseId: cs.caseId, lost: cs.lost, notifyAll: Object.keys(s.channels) });
  },
  RECOVERY_DISPATCH(s, a, tr, at, fx) {
    // The Recovery service attests that it notified EVERY enrolled channel (all administrators, the owner of every
    // allegedly lost credential). Root checks the set is complete.
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest', 'channels']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    exactFields(tr.attestation ?? {}, ['notifierSig'], [], 'DISPATCH_ATTESTATION');
    if (!edVerifyDigest(V3_DOMAINS.DISPATCH, actionDigest(a), tr.attestation.notifierSig, s.serviceKeys.notifier)) fail('DISPATCH_SIGNATURE');
    const want = Object.keys(s.channels).sort().join(',');
    if ([...a.body.channels].sort().join(',') !== want) fail('DISPATCH_INCOMPLETE');
    cs.dispatched = [...a.body.channels].sort();
    if (cs.state === 'LOSS_REPORTED') cs.state = 'IDENTITY_CHECK';
    fx.push({ type: 'RECOVERY_NOTIFIED', channels: cs.dispatched.length });
  },
  RECOVERY_ACK(s, a, tr, at, fx) {
    // A channel acknowledgement (signed by the pinned channel key). OBJECTION puts the case on HOLD.
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest', 'channelId', 'decision']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    const ch = s.channels[a.body.channelId]; if (!ch) fail('ACK_UNKNOWN_CHANNEL');
    exactFields(tr.attestation ?? {}, ['channelSig'], [], 'ACK_ATTESTATION');
    if (!edVerifyDigest(V3_DOMAINS.CHANNEL, actionDigest(a), tr.attestation.channelSig, ch.publicKey)) fail('ACK_SIGNATURE');
    if (!['NO_OBJECTION', 'OBJECTION'].includes(a.body.decision)) fail('ACK_DECISION');
    if (a.body.decision === 'OBJECTION') dispute(cs, { by: 'channel:' + a.body.channelId, kind: 'channel', at }, fx);
    else { cs.acks[a.body.channelId] = 'NO_OBJECTION'; fx.push({ type: 'RECOVERY_ACK', channelId: a.body.channelId }); }
  },
  RECOVERY_IDENTITY(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest', 'idvId', 'holderId', 'method', 'result']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    const idv = s.idvs[a.body.idvId]; if (!idv) fail('IDV_UNKNOWN');
    exactFields(tr.attestation ?? {}, ['idvSig'], [], 'IDV_ATTESTATION');
    if (!edVerifyDigest(V3_DOMAINS.IDENTITY, actionDigest(a), tr.attestation.idvSig, idv.publicKey)) fail('IDV_SIGNATURE');
    if (a.body.result !== 'VERIFIED') fail('IDENTITY_NOT_VERIFIED');
    if (!['document-and-liveness', 'in-person', 'video-call-with-document'].includes(a.body.method)) fail('IDV_METHOD');
    const planHolders = [...new Set(cs.plan.map(c => c.holderId))];
    const expected = cs.kind === 'KEY_LOSS' ? [cs.subjectHolderId] : planHolders;
    if (!expected.includes(a.body.holderId)) fail('IDENTITY_WRONG_HOLDER');
    if (cs.dispatched.length === 0) fail('IDENTITY_BEFORE_NOTIFICATION');
    cs.identity[a.body.idvId] = a.body.holderId;
    fx.push({ type: 'RECOVERY_IDENTITY_VERIFIED', idvId: a.body.idvId });
    maybeConfirm(s, cs, at, fx);
  },
  RECOVERY_OFFICIAL(s, a, tr, at, fx) {
    // Deceased / missing administrator: verifiable official document signed by a pinned registrar. A police report is
    // recorded as context but never grants authority or replaces cryptographic authorization.
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest', 'registrarId', 'docType', 'docRef', 'subjectHolderId']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    if (cs.kind === 'KEY_LOSS') fail('OFFICIAL_DOCUMENT_NOT_APPLICABLE');
    const reg = s.registrars[a.body.registrarId]; if (!reg) fail('REGISTRAR_UNKNOWN');
    exactFields(tr.attestation ?? {}, ['registrarSig'], [], 'OFFICIAL_ATTESTATION');
    if (!edVerifyDigest(V3_DOMAINS.OFFICIAL, actionDigest(a), tr.attestation.registrarSig, reg.publicKey)) fail('REGISTRAR_SIGNATURE');
    if (a.body.subjectHolderId !== cs.subjectHolderId) fail('OFFICIAL_WRONG_SUBJECT');
    const accepted = { DECEASED: ['DEATH_CERTIFICATE'], MISSING: ['COURT_DECLARATION_OF_ABSENCE'] }[cs.kind];
    if (!accepted.includes(a.body.docType)) { fx.push({ type: 'OFFICIAL_DOCUMENT_INFORMATIONAL_ONLY', docType: a.body.docType }); return; }
    cs.official[a.body.registrarId] = a.body.docType;
    fx.push({ type: 'OFFICIAL_DOCUMENT_VERIFIED', docType: a.body.docType });
    maybeConfirm(s, cs, at, fx);
  },
  RECOVERY_CONSENT(s, a, tr, at, fx) {
    // Narrow scope: a surviving credential (any role, including K4/K5) consents to THIS case digest only.
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    const surv = survivors(s, cs, at);
    if ((tr.approvals ?? []).length !== 1) fail('CONSENT_ONE_SIGNER');
    if (!surv.includes(tr.approvals[0].credId)) fail('CONSENT_NOT_FROM_ELIGIBLE_SURVIVOR');
    const susp = s.creds[tr.approvals[0].credId].status === 'suspended';
    const r = verifyApprovals(s, a, tr.approvals, 'RECOVERY_CONSENT', { at, subject: susp ? tr.approvals[0].credId : null, allowSuspendedSelf: susp, eligibleAny: (c) => surv.includes(c.credId) });
    applySignCounts(s, r.signCounts);
    cs.consents[r.approvers[0]] = true;
    fx.push({ type: 'RECOVERY_CONSENT', credId: r.approvers[0] });
  },
  RECOVERY_GUARDIAN(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest', 'guardianId', 'decision']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    const g = s.guardians[a.body.guardianId]; if (!g || g.status !== 'active') fail('GUARDIAN_UNKNOWN');
    exactFields(tr.attestation ?? {}, ['guardianSig'], [], 'GUARDIAN_ATTESTATION');
    if (!edVerifyStatement(V3_DOMAINS.GUARDIAN, { actionDigest: actionDigest(a).toString('hex'), decision: a.body.decision }, tr.attestation.guardianSig, g.publicKey)) fail('GUARDIAN_BAD_SIGNATURE');
    if (a.body.decision === 'APPROVE') { cs.guardians[a.body.guardianId] = true; fx.push({ type: 'RECOVERY_GUARDIAN_APPROVED', guardianId: a.body.guardianId }); }
    else if (a.body.decision === 'OBJECT') dispute(cs, { by: 'guardian:' + a.body.guardianId, kind: 'guardian', at }, fx);
    else if (a.body.decision === 'WITHDRAW') withdraw(cs, 'guardian:' + a.body.guardianId, fx);
    else fail('GUARDIAN_DECISION');
  },
  RECOVERY_OBJECT(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    if ((tr.approvals ?? []).length !== 1) fail('OBJECTION_ONE_SIGNER');
    const cid = tr.approvals[0].credId; const c = s.creds[cid];
    if (!c || !isLive(c)) fail('OBJECTION_NOT_FROM_LIVE_CREDENTIAL');
    const r = verifyApprovals(s, a, tr.approvals, 'RECOVERY_OBJECT', { at, subject: c.status === 'suspended' ? cid : null, allowSuspendedSelf: true, eligibleAny: (x) => isLive(x) });
    if (!r.approvers.length) fail('OBJECTION_INVALID');
    applySignCounts(s, r.signCounts);
    // An objection signed by an allegedly LOST credential proves the key is usable by SOMEONE (owner who found it, or
    // a thief). Either way the case cannot proceed silently.
    dispute(cs, { by: 'cred:' + cid, kind: cs.lost.includes(cid) ? 'subject' : 'credential', at }, fx);
  },
  RECOVERY_WITHDRAW(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest', 'channelId'], []);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    if (a.body.channelId !== '-') {
      const ch = s.channels[a.body.channelId]; if (!ch) fail('ACK_UNKNOWN_CHANNEL');
      exactFields(tr.attestation ?? {}, ['channelSig'], [], 'WITHDRAW_ATTESTATION');
      if (!edVerifyDigest(V3_DOMAINS.CHANNEL, actionDigest(a), tr.attestation.channelSig, ch.publicKey)) fail('ACK_SIGNATURE');
      return withdraw(cs, 'channel:' + a.body.channelId, fx);
    }
    if ((tr.approvals ?? []).length !== 1) fail('WITHDRAW_ONE_SIGNER');
    const cid = tr.approvals[0].credId; const c = s.creds[cid];
    if (!c || !isLive(c)) fail('WITHDRAW_NOT_LIVE');
    const r = verifyApprovals(s, a, tr.approvals, 'RECOVERY_WITHDRAW', { at, subject: c.status === 'suspended' ? cid : null, allowSuspendedSelf: true, eligibleAny: (x) => isLive(x) });
    applySignCounts(s, r.signCounts);
    withdraw(cs, 'cred:' + cid, fx);
  },
  RECOVERY_OVERRIDE(s, a, tr, at, fx) {
    // Channel objections (a channel may be compromised) and objections signed by an allegedly lost credential (may be
    // a thief) must not lock the owner out forever. They can be overridden only by the FULL evidence set: every
    // eligible survivor consented to this digest, the reconstitution-strength guardian quorum, verified identity.
    // Objections by surviving credentials or guardians can never be overridden — they must be withdrawn.
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    // F-V3-02 repair: on the RECOVERY path (<= 50 % lost) EVERY surviving credential must consent, and those survivors
    // are a majority of the baseline. That is stronger ownership evidence than one notification channel or a minority of
    // guardians, so channel, claimed-lost-key and MINORITY guardian objections are overridable with the normal guardian
    // quorum (approvals must strictly outnumber guardian objections). Before the repair the reconstitution quorum was
    // required, so one compromised guardian of three (or a stolen channel plus one guardian) vetoed recovery forever,
    // which for a lost ROOT/RECOVERY key meant permanent loss of governance. The reconstitution path is unchanged:
    // there the survivors are a minority, so only channel objections are overridable, with the reconstitution quorum.
    const recoveryPath = cs.path === 'RECOVERY';
    const overridableKind = (d) => d.kind === 'channel' || d.kind === 'subject' || (recoveryPath && d.kind === 'guardian');
    const overridable = cs.disputes.filter(overridableKind);
    if (!overridable.length) fail('NOTHING_TO_OVERRIDE');
    const surv = survivors(s, cs, at);
    if (!surv.length || !surv.every(x => cs.consents[x])) fail('OVERRIDE_NEEDS_ALL_SURVIVOR_CONSENTS');
    const objectingG = new Set(cs.disputes.filter(d => d.kind === 'guardian').map(d => d.by.slice('guardian:'.length)));
    const approving = Object.keys(cs.guardians).filter(g => !objectingG.has(g)).length; // a guardian that objects is not also counted as approving
    if (recoveryPath) {
      if (approving < Number(s.config.guardianQuorum)) fail('OVERRIDE_NEEDS_GUARDIAN_QUORUM');
      if (!(approving > objectingG.size)) fail('OVERRIDE_GUARDIAN_OBJECTIONS_NOT_OUTNUMBERED', `${approving} approve vs ${objectingG.size} object`);
    } else if (approving < Number(s.config.reconGuardianQuorum)) fail('OVERRIDE_NEEDS_RECON_GUARDIAN_QUORUM');
    if (!Object.keys(cs.identity).length) fail('OVERRIDE_NEEDS_IDENTITY');
    // F-V3-01 repair: an objection signed by an allegedly lost key is evidence too. It may be overridden (thief case)
    // only when the consenting survivors strictly OUTNUMBER the distinct objecting "lost" keys. Otherwise one stolen
    // key + a colluding guardian/IDV quorum could claim the real owner's keys lost and override the owner's objections.
    const subjectObjectors = new Set(cs.disputes.filter(d => d.kind === 'subject').map(d => d.by));
    if (subjectObjectors.size && cs.path !== 'RECOVERY') fail('OVERRIDE_NOT_ALLOWED_IN_RECONSTITUTION', 'survivors are a minority; a claimed-lost key objecting cannot be outvoted');
    if (subjectObjectors.size && !(surv.length > subjectObjectors.size)) fail('OVERRIDE_OUTNUMBERED_BY_OBJECTING_KEYS', `${surv.length} survivors vs ${subjectObjectors.size} objecting keys`);
    cs.disputes = cs.disputes.filter(d => !overridableKind(d));
    cs.overrides = (cs.overrides ?? 0) + overridable.length;
    if (!cs.disputes.length && cs.state === 'HOLD') { cs.state = cs.prior; cs.prior = null; }
    fx.push({ type: 'RECOVERY_DISPUTES_OVERRIDDEN', count: overridable.length });
  },
  RECOVERY_REPLAN(s, a, tr, at, fx) {
    // Only for a confirmed reconstitution case whose plan does not cover the full credential set. Requires the guardian
    // quorum; resets the window and all collected evidence (no last-minute key substitution).
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest', 'plan']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    if (cs.state !== 'EMERGENCY_LOCKDOWN') fail('REPLAN_ONLY_IN_LOCKDOWN');
    checkGuardians(s, a, tr.guardianApprovals, Number(s.config.guardianQuorum));
    cs.plan = pinEnrollments(s, a.body.plan, `${s.accountId}:${a.nonce}`);
    cs.openedAt = at; cs.consents = {}; cs.guardians = {}; cs.identity = {}; cs.acks = {}; cs.dispatched = []; cs.confirmed = false;
    cs.state = 'LOSS_REPORTED'; cs.replans = (cs.replans ?? 0) + 1;
    cs.digest = caseDigestOf(cs);
    fx.push({ type: 'RECOVERY_REPLANNED', caseId: cs.caseId, notifyAll: Object.keys(s.channels) });
  },
  RECOVERY_CANCEL(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId']);
    if (a.body.caseId !== cs.caseId) fail('RECOVERY_CASE_MISMATCH');
    if (s.lockdown.active) {
      // leaving an emergency lockdown is an authority decision: the matrix LOCKDOWN_CANCEL quorum (non-provisional)
      const r = verifyApprovals(s, a, tr.approvals, 'LOCKDOWN_CANCEL', { at }); applySignCounts(s, r.signCounts);
      s.lockdown = { active: false, caseId: null };
    } else {
      // a surviving (not allegedly lost) credential cancels a false or mistaken claim
      const surv = survivors(s, cs, at);
      if ((tr.approvals ?? []).length !== 1 || !surv.includes(tr.approvals[0].credId)) fail('CANCEL_NOT_FROM_SURVIVOR');
      const susp = s.creds[tr.approvals[0].credId].status === 'suspended';
      const r = verifyApprovals(s, a, tr.approvals, 'RECOVERY_CANCEL', { at, subject: susp ? tr.approvals[0].credId : null, allowSuspendedSelf: susp, eligibleAny: (c) => surv.includes(c.credId) });
      applySignCounts(s, r.signCounts);
    }
    closeCase(s, cs, 'CANCELLED', at, fx);
  },
  RECOVERY_COMPLETE(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    if (cs.state === 'HOLD') fail('RECOVERY_ON_HOLD');
    if (cs.state !== 'RECOVERY_CHALLENGE') fail('RECOVERY_NOT_IN_CHALLENGE', cs.state);
    const la = lossAssessment(s, cs, at);
    if (la.overHalf || la.critical) fail('INSUFFICIENT_AUTHORITY');
    requireCommon(s, cs, at, { guardianNeed: Number(s.config.guardianQuorum), idNeed: 1, early: true });
    // replace exactly the lost credentials (same roles), preserve purpose, assets and history
    const lostRoles = cs.lost.map(x => s.creds[x].role);
    const planRoles = cs.plan.map(c => c.role);
    if ([...lostRoles].sort().join(',') !== [...planRoles].sort().join(',')) fail('REPLACEMENT_ROLES_MISMATCH');
    for (const x of cs.lost) { s.creds[x].status = 'retired'; s.creds[x].retiredAt = at; s.creds[x].retiredBy = 'recovery:' + cs.caseId; }
    for (const c of cs.plan) s.creds[c.credId] = { ...c, status: 'active', epochAdded: s.epoch + 1, provisionalUntil: at + Number(s.config.provisionalMs) };
    s.lostSinceBaseline = [...new Set([...s.lostSinceBaseline, ...cs.lost.filter(x => s.baseline.credIds.includes(x))])];
    bumpEpoch(s, fx, 'recovery');
    closeCase(s, cs, 'RECOVERED', at, fx);
  },
  RECONSTITUTE(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    body(a, ['caseId', 'caseDigest']);
    if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
    if (cs.state === 'HOLD') fail('RECOVERY_ON_HOLD');
    if (cs.state !== 'RECONSTITUTION') fail('NOT_IN_RECONSTITUTION', cs.state);
    if (at < s.lastReconstitutionAt + Number(s.config.reconCooldownMs) && s.lastReconstitutionAt) fail('RECONSTITUTION_COOLDOWN');
    requireCommon(s, cs, at, { guardianNeed: Number(s.config.reconGuardianQuorum), idNeed: Number(s.config.reconIdentityAttestations), early: false });
    const la = lossAssessment(s, cs, at);
    if (la.survivors.length < Number(s.config.reconMinSurvivors)) fail('RECOVERY_IMPOSSIBLE_NO_SURVIVOR');
    // F-V3-01 hardening: the subject holder's own channels must positively acknowledge (majority), so a reconstitution
    // cannot be driven through while the owner is silent unless the attacker ALSO controls most of the owner's channels.
    const subjCh = Object.keys(s.channels).filter(c => s.channels[c].holderId === cs.subjectHolderId);
    const acked = subjCh.filter(c => cs.acks[c] === 'NO_OBJECTION').length;
    if (subjCh.length && acked * 2 <= subjCh.length) fail('RECONSTITUTION_NEEDS_OWNER_CHANNEL_ACKS', `${acked}/${subjCh.length}`);
    // retire the WHOLE old authorization environment; assets, purpose and audit history are preserved
    for (const c of Object.values(s.creds)) if (isLive(c)) { c.status = 'retired'; c.retiredAt = at; c.retiredBy = 'reconstitution:' + cs.caseId; }
    for (const c of cs.plan) s.creds[c.credId] = { ...c, status: 'active', epochAdded: s.epoch + 1, provisionalUntil: 0 };
    s.baseline = { epoch: s.epoch + 1, credIds: cs.plan.map(c => c.credId) };
    s.lostSinceBaseline = []; s.lastReconstitutionAt = at;
    s.lockdown = { active: false, caseId: null };
    bumpEpoch(s, fx, 'reconstitution');
    closeCase(s, cs, 'NEW_EPOCH', at, fx);
  },
};

function dispute(cs, d, fx) {
  if (!cs.disputes.some(x => x.by === d.by)) cs.disputes.push(d);
  if (cs.state !== 'HOLD') { cs.prior = cs.state; cs.state = 'HOLD'; }
  fx.push({ type: 'RECOVERY_DISPUTED', by: d.by, kind: d.kind, state: 'HOLD' });
}
function withdraw(cs, by, fx) {
  const n = cs.disputes.length; cs.disputes = cs.disputes.filter(d => d.by !== by);
  if (n === cs.disputes.length) fail('NO_SUCH_OBJECTION');
  if (!cs.disputes.length && cs.state === 'HOLD') { cs.state = cs.prior; cs.prior = null; }
  fx.push({ type: 'RECOVERY_OBJECTION_WITHDRAWN', by });
}
function closeCase(s, cs, outcome, at, fx) {
  s.caseHistory.push({ caseId: cs.caseId, kind: cs.kind, lost: cs.lost, outcome, openedAt: cs.openedAt, closedAt: at, overrides: cs.overrides ?? 0 });
  s.case = null; s.lastCaseClosedAt = at;
  fx.push({ type: 'RECOVERY_CLOSED', caseId: cs.caseId, outcome });
}

/** Loss is CONFIRMED by independent evidence (identity verification / official document), never by the claim. */
function maybeConfirm(s, cs, at, fx) {
  if (cs.confirmed) return;
  if (!Object.keys(cs.identity).length) return;
  if (cs.kind !== 'KEY_LOSS' && !Object.keys(cs.official).length) return;
  cs.confirmed = true;
  const la = lossAssessment(s, cs, at);
  const target = (cs.state === 'HOLD') ? 'prior' : 'state';
  const set = (st) => { if (target === 'prior') cs.prior = st; else cs.state = st; };
  if (la.overHalf || la.critical) {
    fx.push({ type: 'INSUFFICIENT_AUTHORITY', lost: la.lostCount, baseline: la.baseline, critical: la.critical });
    s.lockdown = { active: true, caseId: cs.caseId };
    cs.path = 'RECONSTITUTION';
    if (la.survivors.length < Number(s.config.reconMinSurvivors)) { set('RECOVERY_IMPOSSIBLE'); fx.push({ type: 'RECOVERY_IMPOSSIBLE', reason: 'no surviving original credential; SafeBox will not invent a bypass' }); return; }
    const fullRoles = s.baseline.credIds.map(x => s.creds[x]?.role).sort().join(',');
    const planRoles = cs.plan.map(c => c.role).sort().join(',');
    set(planRoles === fullRoles ? 'RECONSTITUTION' : 'EMERGENCY_LOCKDOWN');
    fx.push({ type: 'EMERGENCY_LOCKDOWN', caseId: cs.caseId, planComplete: planRoles === fullRoles });
  } else { cs.path = 'RECOVERY'; set('RECOVERY_CHALLENGE'); fx.push({ type: 'RECOVERY_CHALLENGE', caseId: cs.caseId }); }
}

function requireCommon(s, cs, at, { guardianNeed, idNeed, early }) {
  if (cs.disputes.length) fail('RECOVERY_DISPUTED');
  if (!cs.confirmed) fail('LOSS_NOT_CONFIRMED');
  if (cs.dispatched.join(',') !== Object.keys(s.channels).sort().join(',')) fail('NOTIFICATIONS_INCOMPLETE');
  if (new Set(Object.keys(cs.identity)).size < idNeed) fail('IDENTITY_EVIDENCE_INSUFFICIENT');
  if (cs.kind !== 'KEY_LOSS' && !Object.keys(cs.official).length) fail('OFFICIAL_EVIDENCE_REQUIRED');
  const surv = survivors(s, cs, at);
  const missing = surv.filter(x => !cs.consents[x]);
  if (missing.length) fail('SURVIVOR_CONSENT_MISSING', missing.join(','));
  const gh = new Set(Object.keys(cs.guardians).map(g => s.guardians[g].holderId));
  if (gh.size < guardianNeed) fail('GUARDIAN_QUORUM_NOT_MET');
  // the timer never approves anything by itself: all evidence above is required in every case
  const full = at >= cs.openedAt + Number(s.config.windowMs);
  const allAcked = Object.keys(s.channels).every(c => cs.acks[c] === 'NO_OBJECTION');
  const earlyOk = early && allAcked && at >= cs.openedAt + Number(s.config.minWindowMs);
  if (!full && !earlyOk) fail('OBJECTION_WINDOW_OPEN');
}

/** Replays a full chain from a pinned genesis. Used by every independent domain. */
export function replayChain(genesis, transitions, { pinnedChainId }) {
  let st = genesisState(genesis, { pinnedChainId });
  const log = [];
  for (const tr of transitions) { const r = applyTransition(st, tr); st = r.state; log.push({ seq: tr.seq, type: tr.action.type, effects: r.effects }); }
  return { state: st, log };
}

/** Compact public view (no evidence) used by the vault/verifier to bind capabilities. */
export function rootView(st) {
  return { accountId: st.accountId, chainId: st.chainId, seq: st.seq, head: st.head, epoch: st.epoch, matrixVersion: st.matrix.version, purposeVersion: st.purpose.version,
    purposeDigest: st.purposeDigest, freeze: st.freeze, lockdown: st.lockdown, caseState: st.case?.state ?? null, caseId: st.case?.caseId ?? null };
}

export { SafeBoxError };
