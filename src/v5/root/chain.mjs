// SafeBox V5 Purpose Root state machine = the V4 Root (every V4 handler and invariant reused unchanged) plus:
//   * Universal command binding: no credential approval in V5 may be a bare V3 action-digest signature. V4 operations
//     keep the V4 AuthorizationIntent; every V5 operation uses the V5 Command Statement (role, principal, affected
//     resources, financial scope, usage count, required confirmation level made explicit).
//   * Protective-hold protocol (holds.mjs): independent, accountable hold records with severity classes, single-signer
//     budgets and expiry, independent confirmation for long-duration holds, provenance-correct release.
//   * CONTEST_PROTECTIVE_HOLD: the owner's independent escape path (ORC + an uncompromised owner credential, which may be
//     suspended) contests holds placed by a suspected credential, revokes it, and releases ONLY what that credential alone imposed.
//   * Delegated payment capabilities (bounded autonomous execution), incident review, and Rapid-Use Mode
//     (REQUEST / APPROVE / ACTIVATE / REVOKE / EXPIRE) with distinct-principal quorum and a hard 24 h lifetime.
import { fail, exactFields, id, uint, isoMs, iso, canon, clone, V3_DOMAINS, edVerifyDigest, edVerifyStatement } from '../../v3/common/canon.mjs';
import * as V3 from '../../v3/root/chain.mjs';
import * as V4 from '../../v4/root/chain.mjs';
import { verifyAssertion } from '../../v3/webauthn/verify.mjs';
import { signDigest5With, PROTOCOL5, V5_DOMAINS, d5, d5hex, verifyObj5, verifyDigest5, H, D } from '../common/v5.mjs';
import { verifyCommand, TRUSTED_LEVELS } from './command.mjs';
import { normalizeHolds, holdEffective, holdDigest, issuerUsage, chargeIssuer, pushHistory, assertScope, credentialParties, partyValid, HOLD_CLASSES, EVIDENCE_CLASSES, publicHold, effectiveHolds } from './holds.mjs';

const { checkActionHeader, transitionHash, bumpEpoch, noCase, isLive, actionDigest, satisfies, ZERO } = V3;
export { actionDigest };
export const ACTION_V = V3.ACTION_V;
export const TR_V = 'safebox.v5.transition';
export const EXT5_V = 'safebox.v5.genesis-ext';

export const V5_DEFAULT_CONFIG = Object.freeze({
  provisionalMaxMs: String(24 * H),       // PROVISIONAL_HOLD: one signer, expires unless independently confirmed
  quarantineMaxMs: String(72 * H),        // TARGETED_QUARANTINE: one signer, one resource
  issuerBudgetMs: String(96 * H),         // single-signer restriction time per issuer per 30 days
  maxActiveHoldsPerIssuer: '3',
  confirmedReviewMs: String(30 * D),      // CONFIRMED_OWNER_HOLD review deadline (a deadline never auto-releases)
  rapidMaxMs: String(24 * H),             // hard ceiling, never renews
  rapidApprovalWindowMs: String(1 * H),
  rapidRequestsPerCred24h: '3',
  rapidActivationsPer7d: '3',
  delegationMaxTtlMs: String(7 * D),
  delegationMaxUses: '500',
  // V5.1 (P2): owner-signed maximum settlement horizon. A payment authorization (capability / delegated operation) must be
  // CONSUMED before its own expiresAt (submission deadline); once consumed and reserved, the vault may settle it no later
  // than issuedAt + settlementHorizonMs. Every owner device and the ORC sign this value in the genesis extension; no
  // delay, review or Rapid-Use can move a payment past it (the vault and the verifier enforce it independently).
  settlementHorizonMs: String(26 * H),
});
const CFG5 = Object.keys(V5_DEFAULT_CONFIG);
/** Predefined deterministic Risk-Policy-Engine rules that may END a Rapid-Use grant (they can never start or extend one). */
export const ENGINE_RAPID_RULES = Object.freeze(['R1_SCOPE_EXPLOIT', 'R2_CREDENTIAL_RESTRICTED', 'R3_VELOCITY_CEILING']);
const OWNER_ROLES_PERSONAL = new Set(['DAILY', 'ROOT', 'RECOVERY']);

function parseV5Config(c) {
  exactFields(c, CFG5, [], 'V5_CONFIG_FIELDS');
  const n = Object.fromEntries(CFG5.map(k => [k, Number(uint(c[k], k))]));
  if (n.provisionalMaxMs > 48 * H || n.quarantineMaxMs > 7 * D || n.provisionalMaxMs < H) fail('V5_CONFIG_HOLD_DURATIONS');
  if (n.rapidMaxMs > 24 * H || n.rapidMaxMs < 600_000) fail('V5_CONFIG_RAPID_MAX_24H');
  if (n.issuerBudgetMs < n.provisionalMaxMs) fail('V5_CONFIG_ISSUER_BUDGET');
  if (n.settlementHorizonMs < H || n.settlementHorizonMs > 72 * H) fail('V5_CONFIG_SETTLEMENT_HORIZON', 'between 1 h and 72 h');
  return { ...c };
}

// ------------------------------------------------------------------ genesis
export function genesisState(gen, { pinnedChainId = null } = {}) {
  exactFields(gen, ['v4', 'ext'], [], 'GENESIS5_FIELDS');
  const st = V4.genesisState(gen.v4, {});
  const e = exactFields(gen.ext, ['action', 'approvals'], [], 'GENESIS5_EXT_FIELDS');
  const a = exactFields(e.action, ['v', 'v4ChainId', 'accountId', 'nonce', 'issuedAt', 'body'], [], 'GENESIS5_EXT_ACTION');
  if (a.v !== EXT5_V || a.v4ChainId !== st.chainId || a.accountId !== st.accountId) fail('GENESIS5_EXT_BINDING');
  const b = exactFields(a.body, ['config', 'riskEngine', 'contacts'], [], 'GENESIS5_EXT_BODY');
  const config = parseV5Config(b.config);
  exactFields(b.riskEngine, ['id', 'publicKey'], [], 'GENESIS5_RISK_ENGINE');
  const holders = new Set(Object.values(st.creds).map(c => c.holderId));
  const contacts = {};
  // verified security-notification contacts: the Root stores only digests; the notifier attests the verification
  for (const [holderId, list] of Object.entries(b.contacts)) {
    if (!holders.has(holderId)) fail('CONTACT_HOLDER_NOT_KEY_HOLDER', holderId);
    if (!Array.isArray(list) || !list.length || list.length > 4) fail('CONTACTS_SHAPE');
    contacts[holderId] = list.map(x => {
      exactFields(x, ['contactRef', 'verifiedAt', 'sig'], [], 'CONTACT_FIELDS');
      if (!/^[0-9a-f]{64}$/.test(x.contactRef)) fail('CONTACT_REF');
      if (!verifyObj5(V5_DOMAINS.CONTACT, { accountId: st.accountId, holderId, contactRef: x.contactRef, verifiedAt: x.verifiedAt }, x.sig, st.serviceKeys.notifier)) fail('CONTACT_NOT_VERIFIED', holderId);
      return { contactRef: x.contactRef, verifiedAt: x.verifiedAt };
    });
  }
  for (const h of holders) if (!contacts[h]) fail('KEY_HOLDER_WITHOUT_VERIFIED_CONTACT', h);
  const extDigest = d5(V5_DOMAINS.GENESIS_EXT, a);
  const signed = new Set();
  for (const ap of e.approvals ?? []) {
    if (!ap || signed.has(ap.credId)) fail('GENESIS5_APPROVAL');
    const c = st.creds[ap.credId];
    if (c && c.kind === 'passkey') { const r = verifyAssertion(ap.webauthn, { rp: st.rp, expectedChallenge: extDigest, credential: { ...c.webauthn, signCount: c.signCount }, requireUV: true }); c.signCount = r.signCount; }
    else if (c) { if (!verifyDigest5(V5_DOMAINS.GENESIS_EXT, extDigest, ap.sig, c.publicKey)) fail('GENESIS5_SIGNATURE', ap.credId); }
    else if (st.v4.orcs[ap.credId]) { if (!verifyDigest5(V5_DOMAINS.GENESIS_EXT, extDigest, ap.sig, st.v4.orcs[ap.credId].publicKey)) fail('GENESIS5_ORC_SIGNATURE'); }
    else fail('GENESIS5_APPROVAL_UNKNOWN');
    signed.add(ap.credId);
  }
  if (signed.size !== Object.keys(st.creds).length + Object.keys(st.v4.orcs).length) fail('GENESIS5_NOT_APPROVED_BY_ALL');
  const chainId = d5hex(V5_DOMAINS.GENESIS, { v4ChainId: st.chainId, ext: extDigest.toString('hex') });
  if (pinnedChainId && chainId !== pinnedChainId) fail('GENESIS_NOT_PINNED');
  st.v4ChainId = st.chainId; st.chainId = chainId;
  st.usedNonces[a.nonce] = 0;
  st.v5 = { protocol: PROTOCOL5, config, riskEngine: { ...b.riskEngine }, contacts, holds: {}, issuerLog: {}, delegations: {}, incidentReviews: {},
    rapid: { requests: {}, grants: {}, requestLog: {}, activations: [] }, contests: [] };
  return st;
}

// ------------------------------------------------------------------ helpers
const body = (a, req, opt = []) => exactFields(a.body, req, opt, `BODY_${a.type}`);
const roleSetOf = (s, rule) => new Set(s.matrix.rules[rule].anyOf.filter(alt => Object.keys(alt).length === 1 && Object.values(alt)[0] === '1').map(alt => Object.keys(alt)[0]));
const multi = (s) => s.matrix.profile !== 'personal';
/** Eligible human owner principals: personal -> the single owner; multi -> distinct holders of LIVE ADMIN credentials (suspension never shrinks N). */
export function ownerPrincipals(s) {
  if (!multi(s)) return [...new Set(Object.values(s.creds).filter(c => isLive(c)).map(c => c.holderId))];
  return [...new Set(Object.values(s.creds).filter(c => isLive(c) && c.role === 'ADMIN').map(c => c.holderId))].sort();
}
export const rapidQuorum = (n) => Math.max(2, Math.ceil(n / 2));
function approvalsArr(tr, min, max, code) { const aps = tr.approvals ?? []; if (!Array.isArray(aps) || aps.length < min || aps.length > max) fail(code); const ids = aps.map(x => x?.credId); if (new Set(ids).size !== ids.length) fail('DUPLICATE_APPROVAL'); return aps; }
function noEvidenceBut(tr, allowed) { for (const k of ['approvals', 'guardianApprovals', 'attestation']) if (!allowed.includes(k) && tr[k] !== undefined && !(Array.isArray(tr[k]) && !tr[k].length)) fail('UNEXPECTED_EVIDENCE', k); }
function partyRef(p) { return p.isOrc ? { kind: 'orc', ref: p.credId, role: 'ORC', holder: p.holderId } : { kind: 'credential', ref: p.credId, role: p.role, holder: p.holderId }; }

function newHold(s, at, { holdId, cls, scope, reason, issuers, evidenceClass, authDigest, expiresAt, reinforces = null, levels = [] }) {
  id(holdId, 'holdId');
  if (s.v5.holds[holdId]) fail('HOLD_ID_IN_USE');
  if (typeof reason !== 'string' || reason.length > 200) fail('HOLD_REASON');
  const h = { holdId, class: cls, scope: { kind: scope.kind, target: scope.target }, reason, issuers, evidenceClass, createdAt: String(at), authDigest,
    escalation: cls, status: 'ACTIVE', expiresAt: expiresAt === null ? null : String(expiresAt), reviewAt: cls === 'CONFIRMED_OWNER_HOLD' ? String(at + Number(s.v5.config.confirmedReviewMs)) : null,
    confirmers: [], levels, reinforces, releaseConditions: releaseConditionsOf(cls), history: [] };
  pushHistory(h, at, 'CREATED', issuers.map(i => `${i.kind}:${i.ref}`).join('+'), `${cls} ${scope.kind}:${scope.target}`);
  s.v5.holds[holdId] = h;
  return h;
}
function releaseConditionsOf(cls) {
  return {
    TARGETED_QUARANTINE: ['expires at expiresAt (max 72 h)', 'every valid issuer/confirmer signs HOLD_RELEASE', 'every issuer/confirmer revoked or retired', 'CONTEST_PROTECTIVE_HOLD revokes its sole issuer'],
    PROVISIONAL_HOLD: ['expires at expiresAt (max 24 h) unless independently confirmed', 'every valid issuer/confirmer signs HOLD_RELEASE', 'every issuer/confirmer revoked or retired', 'CONTEST_PROTECTIVE_HOLD revokes its sole issuer'],
    CONFIRMED_OWNER_HOLD: ['never expires; review deadline only', 'every valid issuer/confirmer signs HOLD_RELEASE (trusted confirmation)', 'every issuer/confirmer revoked or retired'],
    VERIFIED_INCIDENT_FREEZE: ['UNFREEZE owner quorum AND the supervisor trusted-replay repair certificate for this hold; never by timer, contest or revocation'],
  }[cls];
}

/** Verifies V5 command approvals; returns parties. Fails closed on any invalid approval. */
function commandParties(s, a, aps, at, { allowSuspended = false } = {}) {
  return aps.map(ap => { const r = verifyCommand(s, a, ap, at, { allowSuspended }); return { ...r.party, level: r.level, digest: r.digestHex }; });
}
const anyTrusted = (ps) => ps.some(p => TRUSTED_LEVELS.has(p.level));

// ------------------------------------------------------------------ V5 handlers
const HANDLERS5 = {
  HOLD_CREATE(s, a, tr, at, fx) {
    body(a, ['holdId', 'class', 'scope', 'reason', 'durationMs'], ['reinforces']);
    const b = a.body;
    if (!HOLD_CLASSES.includes(b.class)) fail('HOLD_CLASS');
    assertScope(s, b.scope);
    const dur = Number(uint(b.durationMs, 'durationMs'));
    if (b.reinforces !== undefined && !s.v5.holds[b.reinforces]) fail('HOLD_REINFORCES_UNKNOWN');
    if (b.class === 'VERIFIED_INCIDENT_FREEZE') {
      // only the independent supervisor (trusted replay evidence), global, no expiry; never credentials
      noEvidenceBut(tr, ['attestation']);
      exactFields(tr.attestation ?? {}, ['supervisorSig'], [], 'HOLD_ATTESTATION');
      if (!edVerifyDigest(V3_DOMAINS.SUPERVISOR_FREEZE, actionDigest(a), tr.attestation.supervisorSig, s.serviceKeys.supervisorFreeze)) fail('SUPERVISOR_FREEZE_SIGNATURE');
      if (b.scope.kind !== 'GLOBAL') fail('INCIDENT_FREEZE_IS_GLOBAL');
      newHold(s, at, { holdId: b.holdId, cls: b.class, scope: b.scope, reason: b.reason, issuers: [{ kind: 'supervisor', ref: 'supervisorFreeze', role: 'SUPERVISOR', holder: 'supervisor' }],
        evidenceClass: EVIDENCE_CLASSES.SUPERVISOR, authDigest: actionDigest(a).toString('hex'), expiresAt: null, reinforces: b.reinforces ?? null });
      fx.push({ type: 'HOLD_CREATED', holdId: b.holdId, cls: b.class, scope: 'GLOBAL:*' });
      return;
    }
    noEvidenceBut(tr, ['approvals']);
    if (b.class === 'CONFIRMED_OWNER_HOLD') {
      const ps = commandParties(s, a, approvalsArr(tr, 2, 4, 'CONFIRMED_HOLD_NEEDS_TWO'), at);
      requireIndependent(s, ps, 'CONFIRMED_OWNER_HOLD');
      const h = newHold(s, at, { holdId: b.holdId, cls: b.class, scope: b.scope, reason: b.reason, issuers: ps.map(partyRef), evidenceClass: EVIDENCE_CLASSES.CONFIRMED,
        authDigest: ps.map(p => p.digest).join(','), expiresAt: null, reinforces: b.reinforces ?? null, levels: ps.map(p => p.level) });
      fx.push({ type: 'HOLD_CREATED', holdId: h.holdId, cls: h.class, scope: `${b.scope.kind}:${b.scope.target}`, issuers: ps.map(p => p.credId) });
      return;
    }
    // single-signer protective classes: one eligible signer, narrowly bounded in time and budget
    const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'HOLD_ONE_SIGNER'), at);
    singleSignerHold(s, a, at, fx, p, { holdId: b.holdId, cls: b.class, scope: b.scope, reason: b.reason, dur, reinforces: b.reinforces ?? null });
  },
  /** V4-compatible FREEZE: an owner FREEZE is a PROVISIONAL_HOLD (global, 24 h unless confirmed); a supervisor FREEZE is a VERIFIED_INCIDENT_FREEZE. */
  FREEZE(s, a, tr, at, fx) {
    body(a, ['freezeId', 'reason', 'source']);
    const cls = a.body.source === 'supervisor' ? 'VERIFIED_INCIDENT_FREEZE' : a.body.source === 'owner' ? 'PROVISIONAL_HOLD' : fail('FREEZE_SOURCE');
    const shim = { ...a, body: { holdId: a.body.freezeId, class: cls, scope: { kind: 'GLOBAL', target: '*' }, reason: a.body.reason, durationMs: s.v5.config.provisionalMaxMs } };
    if (cls === 'VERIFIED_INCIDENT_FREEZE') {
      noEvidenceBut(tr, ['attestation']);
      exactFields(tr.attestation ?? {}, ['supervisorSig'], [], 'FREEZE_ATTESTATION');
      if (!edVerifyDigest(V3_DOMAINS.SUPERVISOR_FREEZE, actionDigest(a), tr.attestation.supervisorSig, s.serviceKeys.supervisorFreeze)) fail('SUPERVISOR_FREEZE_SIGNATURE');
      newHold(s, at, { holdId: a.body.freezeId, cls, scope: shim.body.scope, reason: a.body.reason, issuers: [{ kind: 'supervisor', ref: 'supervisorFreeze', role: 'SUPERVISOR', holder: 'supervisor' }],
        evidenceClass: EVIDENCE_CLASSES.SUPERVISOR, authDigest: actionDigest(a).toString('hex'), expiresAt: null });
      fx.push({ type: 'HOLD_CREATED', holdId: a.body.freezeId, cls, scope: 'GLOBAL:*' });
      return;
    }
    noEvidenceBut(tr, ['approvals']);
    const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'HOLD_ONE_SIGNER'), at);
    singleSignerHold(s, a, at, fx, p, { holdId: a.body.freezeId, cls, scope: shim.body.scope, reason: a.body.reason, dur: Number(s.v5.config.provisionalMaxMs), reinforces: null });
  },
  /** SUSPEND = TARGETED_QUARANTINE of one credential (72 h max unless independently confirmed). Reinforcement is allowed. */
  SUSPEND(s, a, tr, at, fx) {
    body(a, ['credId'], ['holdId', 'reason']);
    const c = s.creds[a.body.credId]; if (!c || !isLive(c)) fail('SUSPEND_SUBJECT_NOT_LIVE');
    noEvidenceBut(tr, ['approvals']);
    const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'HOLD_ONE_SIGNER'), at);
    singleSignerHold(s, a, at, fx, p, { holdId: a.body.holdId ?? ('q-' + a.nonce.slice(0, 16)), cls: 'TARGETED_QUARANTINE', scope: { kind: 'CREDENTIAL', target: c.credId },
      reason: a.body.reason ?? 'suspend credential', dur: Number(s.v5.config.quarantineMaxMs), reinforces: null });
  },
  HOLD_CONFIRM(s, a, tr, at, fx) {
    body(a, ['holdId', 'holdDigest']);
    const h = s.v5.holds[a.body.holdId]; if (!h || !holdEffective(h, at)) fail('HOLD_NOT_ACTIVE');
    if (a.body.holdDigest !== holdDigest(s, h)) fail('HOLD_DIGEST_MISMATCH');
    if (h.class === 'VERIFIED_INCIDENT_FREEZE') fail('INCIDENT_FREEZE_NEEDS_NO_CONFIRMATION');
    noEvidenceBut(tr, ['approvals']);
    const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'CONFIRM_ONE_SIGNER'), at);
    if ([...h.issuers, ...h.confirmers].some(x => x.ref === p.credId)) fail('CONFIRMER_NOT_INDEPENDENT', 'an issuer or existing confirmer cannot confirm again');
    if (!p.isOrc && !eligibleFor(s, p, 'FREEZE', h.scope)) fail('CONFIRMER_ROLE_NOT_ELIGIBLE', p.role);
    h.confirmers.push({ ...partyRef(p), at: String(at), level: p.level, digest: p.digest });
    pushHistory(h, at, 'CONFIRMED', `${p.isOrc ? 'orc' : 'credential'}:${p.credId}`, p.level);
    // escalation: two independent parties of distinct roles with >= 1 trusted confirmation -> CONFIRMED_OWNER_HOLD
    const parties = [...h.issuers, ...h.confirmers].filter(x => x.kind !== 'supervisor');
    const roles = new Set(parties.map(x => x.role));
    const trusted = [...(h.levels ?? []), ...h.confirmers.map(x => x.level)].some(l => TRUSTED_LEVELS.has(l));
    if (h.class !== 'CONFIRMED_OWNER_HOLD' && parties.length >= 2 && roles.size >= 2 && trusted) {
      h.class = 'CONFIRMED_OWNER_HOLD'; h.expiresAt = null; h.reviewAt = String(at + Number(s.v5.config.confirmedReviewMs)); h.evidenceClass = EVIDENCE_CLASSES.CONFIRMED;
      h.releaseConditions = releaseConditionsOf(h.class);
      pushHistory(h, at, 'ESCALATED', 'protocol', 'CONFIRMED_OWNER_HOLD'); fx.push({ type: 'HOLD_ESCALATED', holdId: h.holdId, cls: h.class });
    }
    fx.push({ type: 'HOLD_CONFIRMED', holdId: h.holdId, by: p.credId, cls: h.class });
  },
  HOLD_RELEASE(s, a, tr, at, fx) {
    body(a, ['holdId', 'holdDigest']);
    const h = s.v5.holds[a.body.holdId]; if (!h || h.status !== 'ACTIVE') fail('HOLD_NOT_ACTIVE');
    if (a.body.holdDigest !== holdDigest(s, h)) fail('HOLD_DIGEST_MISMATCH');
    if (h.class === 'VERIFIED_INCIDENT_FREEZE') {
      // owner UNFREEZE quorum (command-bound) AND the supervisor repair certificate bound to THIS hold
      noEvidenceBut(tr, ['approvals', 'attestation']);
      const ps = commandParties(s, a, approvalsArr(tr, 2, 6, 'APPROVALS_INVALID'), at);
      const approvers = ps.filter(p => !p.isOrc).map(p => ({ credId: p.credId, role: p.role, holderId: p.holderId, uv: true, provisional: Number(p.provisionalUntil ?? 0) > at, eligibleAny: true }));
      if (!s.matrix.rules.UNFREEZE.anyOf.some(alt => satisfies(alt, approvers, { subject: null, countMode: s.matrix.countMode }))) fail('QUORUM_NOT_SATISFIED', 'UNFREEZE');
      if (!anyTrusted(ps)) fail('TRUSTED_CONFIRMATION_REQUIRED', 'release of a verified incident freeze');
      exactFields(tr.attestation ?? {}, ['repair'], [], 'RELEASE_ATTESTATION');
      const rp = exactFields(tr.attestation.repair, ['statement', 'sig'], [], 'REPAIR_CERT');
      const st = exactFields(rp.statement, ['freezeId', 'verdict', 'exactReplay', 'mutations', 'regression', 'legitimate', 'candidate'], [], 'REPAIR_STATEMENT');
      if (st.freezeId !== h.holdId) fail('REPAIR_CERT_WRONG_FREEZE');
      if (st.verdict !== 'REPAIRED' || st.exactReplay !== 'DENIED_FOR_INVARIANT' || st.mutations !== 'ALL_DENIED' || st.regression !== 'PASS' || st.legitimate !== 'PASS') fail('REPAIR_NOT_COMPLETE');
      if (!edVerifyStatement(V3_DOMAINS.REPAIR, st, rp.sig, s.serviceKeys.supervisorRepair)) fail('REPAIR_CERT_SIGNATURE');
      h.status = 'RELEASED'; pushHistory(h, at, 'RELEASED', ps.map(p => p.credId).join('+'), 'repair certificate ' + st.candidate);
      fx.push({ type: 'HOLD_RELEASED', holdId: h.holdId, reason: 'owner quorum + trusted repair certificate', parties: ps.map(p => p.credId) });
      return;
    }
    // provenance-correct release: EVERY still-valid party that placed or confirmed this hold must sign the release
    noEvidenceBut(tr, ['approvals']);
    const ps = commandParties(s, a, approvalsArr(tr, 1, 6, 'APPROVALS_INVALID'), at, { allowSuspended: true });
    const signed = new Set(ps.map(p => p.credId));
    const missing = credentialParties(h).filter(p => partyValid(s, p) && !signed.has(p.ref));
    if (missing.length) fail('RELEASE_NEEDS_EVERY_VALID_PARTY', missing.map(p => p.ref).join(','));
    if (ps.some(p => !credentialParties(h).some(x => x.ref === p.credId))) fail('RELEASE_SIGNER_NOT_A_PARTY');
    if (h.class === 'CONFIRMED_OWNER_HOLD' && !anyTrusted(ps)) fail('TRUSTED_CONFIRMATION_REQUIRED', 'release of a confirmed hold');
    h.status = 'RELEASED'; pushHistory(h, at, 'RELEASED', ps.map(p => p.credId).join('+'));
    fx.push({ type: 'HOLD_RELEASED', holdId: h.holdId, reason: 'released by its parties', parties: ps.map(p => p.credId) });
  },
  /** UNSUSPEND releases ONLY the quarantine holds on that credential whose every valid party signs. */
  UNSUSPEND(s, a, tr, at, fx) {
    body(a, ['credId']);
    const c = s.creds[a.body.credId]; if (!c || c.status !== 'suspended') fail('UNSUSPEND_SUBJECT_NOT_SUSPENDED');
    noEvidenceBut(tr, ['approvals']);
    const ps = commandParties(s, a, approvalsArr(tr, 1, 6, 'APPROVALS_INVALID'), at, { allowSuspended: true });
    const signed = new Set(ps.map(p => p.credId));
    const released = [];
    for (const h of Object.values(s.v5.holds)) {
      if (!holdEffective(h, at) || h.scope.kind !== 'CREDENTIAL' || h.scope.target !== c.credId || h.class === 'VERIFIED_INCIDENT_FREEZE') continue;
      const need = credentialParties(h).filter(p => partyValid(s, p));
      if (need.every(p => signed.has(p.ref))) { h.status = 'RELEASED'; pushHistory(h, at, 'RELEASED', [...signed].join('+'), 'UNSUSPEND'); released.push(h.holdId); }
    }
    if (!released.length) fail('UNSUSPEND_NO_RELEASABLE_HOLD', 'each quarantine must be released by every valid party that placed it');
    fx.push({ type: 'HOLDS_RELEASED_BY_UNSUSPEND', credId: c.credId, holds: released });
  },
  HOLD_EXPIRE(s, a, tr, at, fx) {
    body(a, ['holdId']); noEvidenceBut(tr, []);
    const h = s.v5.holds[a.body.holdId]; if (!h) fail('HOLD_UNKNOWN');
    if (h.status === 'ACTIVE' && (h.expiresAt === null || at < Number(h.expiresAt))) fail('HOLD_NOT_EXPIRED');
    fx.push({ type: 'HOLD_HOUSEKEEPING', holdId: h.holdId, status: h.status });
  },
  CONTEST_PROTECTIVE_HOLD(s, a, tr, at, fx) {
    body(a, ['contestId', 'holdIds', 'suspectCredId', 'reason']);
    const b = a.body; id(b.contestId, 'contestId');
    noCase(s, 'RECOVERY_CASE_OPEN'); if (s.v4.gcase) fail('GOVERNANCE_CASE_OPEN');
    if (s.v5.contests.some(c => c.contestId === b.contestId)) fail('CONTEST_ID_REUSED');
    if (typeof b.reason !== 'string' || b.reason.length > 200) fail('CONTEST_REASON');
    const suspect = s.creds[b.suspectCredId]; if (!suspect || !isLive(suspect)) fail('CONTEST_SUSPECT_NOT_LIVE');
    if (!Array.isArray(b.holdIds) || !b.holdIds.length || b.holdIds.length > 16 || new Set(b.holdIds).size !== b.holdIds.length) fail('CONTEST_HOLD_SET');
    for (const hid of b.holdIds) {
      const h = s.v5.holds[hid]; if (!h || !holdEffective(h, at)) fail('CONTEST_HOLD_NOT_ACTIVE', hid);
      if (h.class === 'VERIFIED_INCIDENT_FREEZE') fail('CONTEST_CANNOT_BYPASS_VERIFIED_INCIDENT_FREEZE');
      if (!h.issuers.some(i => i.ref === suspect.credId)) fail('CONTEST_HOLD_NOT_ATTRIBUTABLE_TO_SUSPECT', hid);
    }
    noEvidenceBut(tr, ['approvals']);
    // independent owner path: a suspended (never revoked) surviving key may authenticate for THIS operation only
    const ps = commandParties(s, a, approvalsArr(tr, 2, 4, 'CONTEST_APPROVALS'), at, { allowSuspended: true });
    if (ps.some(p => p.credId === suspect.credId)) fail('CONTEST_SIGNED_BY_SUSPECT');
    if (multi(s)) {
      const hs = new Set(ps.filter(p => !p.isOrc && p.role === 'ADMIN' && p.holderId !== suspect.holderId).map(p => p.holderId));
      if (hs.size < 2) fail('CONTEST_NEEDS_TWO_OTHER_OWNERS');
    } else {
      if (!ps.some(p => p.isOrc)) fail('CONTEST_NEEDS_ORC');
      if (!ps.some(p => !p.isOrc && OWNER_ROLES_PERSONAL.has(p.role) && Number(p.provisionalUntil ?? 0) <= at)) fail('CONTEST_NEEDS_INDEPENDENT_OWNER_CREDENTIAL');
    }
    if (!anyTrusted(ps)) fail('TRUSTED_CONFIRMATION_REQUIRED', 'contest');
    // effect 1: revoke the suspected credential (epoch bump kills its capabilities and pending payments)
    suspect.status = 'revoked'; suspect.revokedAt = at; suspect.revokedBy = 'contest:' + b.contestId;
    bumpEpoch(s, fx, 'contest revocation');
    fx.push({ type: 'REVOKED', credId: suspect.credId, role: suspect.role, approvers: ps.map(p => p.credId), via: 'CONTEST_PROTECTIVE_HOLD' });
    // effect 2: release ONLY holds whose every credential party is now invalid; anything else keeps restricting
    const released = [], kept = [];
    for (const hid of b.holdIds) {
      const h = s.v5.holds[hid];
      const others = credentialParties(h).filter(p => partyValid(s, p));
      if (!others.length) { h.status = 'RELEASED_BY_CONTEST'; pushHistory(h, at, 'RELEASED_BY_CONTEST', ps.map(p => p.credId).join('+'), b.contestId); released.push(hid); }
      else { pushHistory(h, at, 'CONTEST_REJECTED_OTHER_PARTIES', ps.map(p => p.credId).join('+'), others.map(p => p.ref).join(',')); kept.push(hid); }
    }
    s.v5.contests.push({ contestId: b.contestId, at: String(at), suspect: suspect.credId, by: ps.map(p => p.credId), released, kept });
    fx.push({ type: 'CONTEST_RESOLVED', contestId: b.contestId, suspect: suspect.credId, released, kept });
  },
  INCIDENT_REVIEW(s, a, tr, at, fx) {
    body(a, ['incidentId', 'credId', 'verdict', 'evidenceDigest']);
    const b = a.body; id(b.incidentId, 'incidentId');
    if (!['LEGITIMATE', 'FRAUD'].includes(b.verdict)) fail('INCIDENT_VERDICT');
    if (!/^[0-9a-f]{64}$/.test(b.evidenceDigest)) fail('INCIDENT_EVIDENCE_DIGEST');
    if (!s.creds[b.credId]) fail('INCIDENT_UNKNOWN_CREDENTIAL');
    if (s.v5.incidentReviews[b.incidentId]) fail('INCIDENT_ALREADY_REVIEWED');
    noEvidenceBut(tr, ['approvals']);
    const ps = commandParties(s, a, approvalsArr(tr, 1, 3, 'INCIDENT_APPROVALS'), at);
    // the reviewed flow's own credential can never vouch for itself (a thief would simply declare itself legitimate)
    if (ps.some(p => p.credId === b.credId)) fail('INCIDENT_REVIEW_BY_AFFECTED_CREDENTIAL');
    if (b.verdict === 'LEGITIMATE') {
      if (!anyTrusted(ps)) fail('TRUSTED_CONFIRMATION_REQUIRED', 'LEGITIMATE verdict releases delayed payments');
      if (multi(s)) { const hs = new Set(ps.filter(p => p.role === 'ADMIN').map(p => p.holderId)); if (hs.size < rapidQuorum(ownerPrincipals(s).length)) fail('INCIDENT_LEGITIMATE_NEEDS_OWNER_QUORUM'); }
      else if (!ps.some(p => p.isOrc || OWNER_ROLES_PERSONAL.has(p.role))) fail('INCIDENT_REVIEWER_ROLE');
    }
    s.v5.incidentReviews[b.incidentId] = { verdict: b.verdict, credId: b.credId, by: ps.map(p => p.credId), at: String(at), evidenceDigest: b.evidenceDigest };
    fx.push({ type: 'INCIDENT_REVIEWED', incidentId: b.incidentId, credId: b.credId, verdict: b.verdict, by: ps.map(p => p.credId) });
  },

  // ---------------------------------------------- delegated execution (bounded autonomous payments)
  DELEGATION_GRANT(s, a, tr, at, fx) {
    body(a, ['delegationId', 'delegateKey', 'operation', 'recipients', 'assets', 'perOpMaxYocto', 'cumulativeMaxYocto', 'maxUses', 'expiresAt', 'revokeOn']);
    const b = a.body; id(b.delegationId, 'delegationId');
    if (s.v5.delegations[b.delegationId]) fail('DELEGATION_ID_IN_USE');
    if (b.operation !== 'PAY') fail('DELEGATION_OPERATION');
    if (typeof b.delegateKey !== 'string' || !b.delegateKey.startsWith('ed25519:')) fail('DELEGATE_KEY');
    if (!Array.isArray(b.recipients) || !b.recipients.length || b.recipients.some(r => !s.purpose.recipients.includes(r))) fail('DELEGATION_RECIPIENT_NOT_IN_PURPOSE');
    if (!Array.isArray(b.assets) || b.assets.length !== 1 || b.assets[0] !== s.purpose.asset) fail('DELEGATION_ASSET_NOT_IN_PURPOSE');
    const per = uint(b.perOpMaxYocto, 'perOpMaxYocto'), cum = uint(b.cumulativeMaxYocto, 'cumulativeMaxYocto'), uses = Number(uint(b.maxUses, 'maxUses'));
    if (per <= 0n || per > BigInt(s.purpose.perPaymentMaxYocto)) fail('DELEGATION_PER_OP_EXCEEDS_PURPOSE');
    if (cum < per || cum > BigInt(s.purpose.cumulativeLimitYocto)) fail('DELEGATION_CUMULATIVE_EXCEEDS_PURPOSE');
    if (uses < 1 || uses > Number(s.v5.config.delegationMaxUses)) fail('DELEGATION_MAX_USES');
    const exp = isoMs(b.expiresAt, 'expiresAt');
    if (exp <= at || exp - at > Number(s.v5.config.delegationMaxTtlMs) || exp > Date.parse(s.purpose.expiresAt)) fail('DELEGATION_EXPIRY');
    if (canon(b.revokeOn) !== canon(['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'])) fail('DELEGATION_REVOKE_CONDITIONS', 'all three conditions are mandatory');
    noEvidenceBut(tr, ['approvals']);
    const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'DELEGATION_ONE_SIGNER'), at);
    if (p.isOrc || !roleSetOf(s, 'PAY').has(p.role)) fail('DELEGATION_ISSUER_NOT_PAYMENT_ROLE');
    s.v5.delegations[b.delegationId] = { delegationId: b.delegationId, delegateKey: b.delegateKey, issuerCredId: p.credId, recipients: [...b.recipients], asset: s.purpose.asset,
      perOpMaxYocto: b.perOpMaxYocto, cumulativeMaxYocto: b.cumulativeMaxYocto, maxUses: b.maxUses, expiresAt: String(exp), epoch: String(s.epoch), purposeVersion: s.purpose.version,
      matrixVersion: s.matrix.version, status: 'ACTIVE', grantedAt: String(at), digest: p.digest };
    fx.push({ type: 'DELEGATION_GRANTED', delegationId: b.delegationId, issuer: p.credId });
  },
  DELEGATION_REVOKE(s, a, tr, at, fx) {
    body(a, ['delegationId']);
    const d = s.v5.delegations[a.body.delegationId]; if (!d || d.status !== 'ACTIVE') fail('DELEGATION_NOT_ACTIVE');
    noEvidenceBut(tr, ['approvals']);
    const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'DELEGATION_ONE_SIGNER'), at, { allowSuspended: true });
    d.status = 'REVOKED'; d.endedAt = String(at); d.endedBy = p.credId;
    fx.push({ type: 'DELEGATION_REVOKED', delegationId: d.delegationId, by: p.credId });
  },

  // ---------------------------------------------- Rapid-Use Mode
  RAPID_USE_REQUEST(s, a, tr, at, fx) {
    body(a, ['requestId', 'scope', 'delayException', 'durationMs', 'explanation', 'incidentId']);
    const b = a.body; id(b.requestId, 'requestId');
    if (s.v5.rapid.requests[b.requestId]) fail('RAPID_REQUEST_ID_REUSED', 'a new window always needs a fresh request');
    const x = exactFields(b.scope, ['credIds', 'delegationIds', 'recipients', 'asset', 'purposeId', 'purposeVersion', 'perPaymentMaxYocto', 'dailyLimitYocto', 'cumulativeLimitYocto', 'sessionCapYocto'], [], 'RAPID_SCOPE');
    // P3: the scope restates the CURRENT financial boundaries exactly; nothing can be enlarged
    if (x.purposeId !== s.purpose.purposeId || x.purposeVersion !== s.purpose.version) fail('RAPID_SCOPE_PURPOSE_MISMATCH');
    if (x.asset !== s.purpose.asset) fail('RAPID_SCOPE_ASSET');
    if (x.perPaymentMaxYocto !== s.purpose.perPaymentMaxYocto || x.dailyLimitYocto !== s.purpose.dailyLimitYocto || x.cumulativeLimitYocto !== s.purpose.cumulativeLimitYocto) fail('RAPID_SCOPE_LIMITS_MUST_EQUAL_PURPOSE');
    if (!Array.isArray(x.recipients) || !x.recipients.length || new Set(x.recipients).size !== x.recipients.length || x.recipients.some(r => !s.purpose.recipients.includes(r))) fail('RAPID_SCOPE_RECIPIENT_NOT_IN_PURPOSE');
    if (!Array.isArray(x.credIds) || !Array.isArray(x.delegationIds) || !(x.credIds.length + x.delegationIds.length) || x.credIds.length > 4 || x.delegationIds.length > 4) fail('RAPID_SCOPE_FLOWS');
    for (const c of x.credIds) { const cr = s.creds[c]; if (!cr || cr.status !== 'active' || !roleSetOf(s, 'PAY').has(cr.role)) fail('RAPID_SCOPE_CREDENTIAL', c); }
    for (const dId of x.delegationIds) if (s.v5.delegations[dId]?.status !== 'ACTIVE') fail('RAPID_SCOPE_DELEGATION', dId);
    if (x.sessionCapYocto !== '-' && (uint(x.sessionCapYocto, 'sessionCapYocto') <= 0n || BigInt(x.sessionCapYocto) > BigInt(s.purpose.cumulativeLimitYocto))) fail('RAPID_SESSION_CAP');
    if (b.delayException !== 'REMOVE_ANOMALY_DELAY') fail('RAPID_DELAY_EXCEPTION', 'only the anomaly-induced delay can be removed');
    const dur = Number(uint(b.durationMs, 'durationMs'));
    if (dur < 600_000 || dur > Number(s.v5.config.rapidMaxMs)) fail('RAPID_DURATION_MAX_24H');
    if (typeof b.explanation !== 'string' || b.explanation.length < 4 || b.explanation.length > 200) fail('RAPID_EXPLANATION');
    if (b.incidentId !== '-') id(b.incidentId, 'incidentId');
    noEvidenceBut(tr, ['approvals']);
    const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'RAPID_REQUEST_ONE_SIGNER'), at);
    // abuse controls are per requesting credential, so a thief's key cannot exhaust the owner's other keys' capacity
    const log = (s.v5.rapid.requestLog[p.credId] ?? []).filter(t => Number(t) > at - D);
    if (log.length >= Number(s.v5.config.rapidRequestsPerCred24h)) fail('RAPID_REQUEST_RATE_LIMIT');
    if (Object.values(s.v5.rapid.requests).some(q => q.status === 'PENDING' && q.requestedBy === p.credId)) fail('RAPID_REQUEST_ALREADY_PENDING');
    s.v5.rapid.requestLog[p.credId] = [...log, String(at)];
    const q = { requestId: b.requestId, scope: clone(x), delayException: b.delayException, durationMs: String(dur), explanation: b.explanation, incidentId: b.incidentId,
      requestedBy: p.credId, requestedAt: String(at), approveBy: String(at + Number(s.v5.config.rapidApprovalWindowMs)), epoch: String(s.epoch), nonce: a.nonce, votes: {}, rejections: {}, status: 'PENDING' };
    q.digest = rapidRequestDigest(s, q);
    s.v5.rapid.requests[b.requestId] = q;
    fx.push({ type: 'RAPID_USE_REQUESTED', requestId: q.requestId, requestDigest: q.digest, by: p.credId, notifyAll: true });
  },
  RAPID_USE_APPROVE(s, a, tr, at, fx) {
    body(a, ['requestId', 'requestDigest', 'decision']);
    const q = s.v5.rapid.requests[a.body.requestId]; if (!q || q.status !== 'PENDING') fail('RAPID_REQUEST_NOT_PENDING');
    if (a.body.requestDigest !== q.digest) fail('RAPID_REQUEST_DIGEST_MISMATCH');
    if (at >= Number(q.approveBy)) fail('RAPID_REQUEST_APPROVAL_WINDOW_CLOSED');
    if (!['APPROVE', 'REJECT'].includes(a.body.decision)) fail('RAPID_DECISION');
    noEvidenceBut(tr, ['approvals']);
    // one voter per transition; a suspended / revoked / provisional credential can never supply a vote
    const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'RAPID_ONE_VOTER_PER_TRANSITION'), at);
    const key = voteKey(s, q, p);
    if (a.body.decision === 'REJECT') { q.rejections[key] = { credId: p.credId, at: String(at) }; fx.push({ type: 'RAPID_USE_VOTE', requestId: q.requestId, voter: key, decision: 'REJECT' }); return; }
    if (q.votes[key]) fail('RAPID_DUPLICATE_PRINCIPAL_VOTE', 'several keys of one human are one vote');
    q.votes[key] = { credId: p.credId, holderId: p.holderId, level: p.level, at: String(at), digest: p.digest };
    fx.push({ type: 'RAPID_USE_VOTE', requestId: q.requestId, voter: key, decision: 'APPROVE', level: p.level });
  },
  RAPID_USE_ACTIVATE(s, a, tr, at, fx) {
    body(a, ['requestId', 'requestDigest']); noEvidenceBut(tr, []);
    const q = s.v5.rapid.requests[a.body.requestId]; if (!q || q.status !== 'PENDING') fail('RAPID_REQUEST_NOT_PENDING');
    if (a.body.requestDigest !== q.digest) fail('RAPID_REQUEST_DIGEST_MISMATCH');
    if (at >= Number(q.approveBy)) fail('RAPID_REQUEST_APPROVAL_WINDOW_CLOSED');
    if (q.epoch !== String(s.epoch)) fail('RAPID_REQUEST_STALE_EPOCH');
    const qr = quorumStatus(s, q, at);
    if (!qr.met) fail('RAPID_QUORUM_NOT_MET', qr.detail);
    for (const c of q.scope.credIds) if (s.creds[c]?.status !== 'active') fail('RAPID_SCOPE_CREDENTIAL_RESTRICTED', c);
    for (const g of Object.values(s.v5.rapid.grants)) if (g.status === 'ACTIVE' && g.scope.credIds.some(c => q.scope.credIds.includes(c))) fail('RAPID_GRANT_ALREADY_ACTIVE_FOR_FLOW');
    const recent = s.v5.rapid.activations.filter(t => Number(t) > at - 7 * D);
    if (recent.length >= Number(s.v5.config.rapidActivationsPer7d)) fail('RAPID_ACTIVATION_RATE_LIMIT');
    s.v5.rapid.activations = [...recent, String(at)];
    q.status = 'ACTIVATED';
    const g = { grantId: q.requestId, requestDigest: q.digest, scope: clone(q.scope), delayException: q.delayException, activatedAt: String(at), expiresAt: String(at + Number(q.durationMs)),
      epoch: String(s.epoch), purposeVersion: s.purpose.version, approvers: qr.voters, status: 'ACTIVE', explanation: q.explanation, incidentId: q.incidentId };
    s.v5.rapid.grants[g.grantId] = g;
    fx.push({ type: 'RAPID_USE_ACTIVATED', grantId: g.grantId, expiresAt: iso(Number(g.expiresAt)), approvers: g.approvers, credIds: g.scope.credIds, notifyAll: true });
  },
  /** "End Rapid-Use Mode": an approving owner, the holder of a covered flow, the ORC, or a predefined Risk-Engine rule. */
  RAPID_USE_REVOKE(s, a, tr, at, fx) {
    body(a, ['grantId', 'reason']);
    const g = s.v5.rapid.grants[a.body.grantId]; if (!g || g.status !== 'ACTIVE') fail('RAPID_GRANT_NOT_ACTIVE');
    if (typeof a.body.reason !== 'string' || a.body.reason.length > 200) fail('RAPID_REVOKE_REASON');
    let by;
    if (tr.attestation) {
      noEvidenceBut(tr, ['attestation']);
      exactFields(tr.attestation, ['engineSig', 'ruleId', 'evidenceDigest'], [], 'ENGINE_ATTESTATION');
      if (!ENGINE_RAPID_RULES.includes(tr.attestation.ruleId)) fail('ENGINE_RULE_NOT_PREDEFINED');
      if (!verifyObj5(V5_DOMAINS.RISK_ENGINE, { kind: 'RAPID_USE_REVOKE', actionDigest: actionDigest(a).toString('hex'), ruleId: tr.attestation.ruleId, evidenceDigest: tr.attestation.evidenceDigest }, tr.attestation.engineSig, s.v5.riskEngine.publicKey)) fail('ENGINE_SIGNATURE');
      by = 'risk-engine:' + tr.attestation.ruleId;
    } else {
      noEvidenceBut(tr, ['approvals']);
      const [p] = commandParties(s, a, approvalsArr(tr, 1, 1, 'RAPID_REVOKE_ONE_SIGNER'), at, { allowSuspended: true });
      const approverCreds = new Set(Object.values(g.approvers).map(v => v.credId)), approverHolders = new Set(Object.values(g.approvers).map(v => v.holderId));
      const flowHolders = new Set(g.scope.credIds.map(c => s.creds[c]?.holderId));
      const ok = multi(s) ? (approverHolders.has(p.holderId) || flowHolders.has(p.holderId))
        : (p.isOrc || approverCreds.has(p.credId) || g.scope.credIds.includes(p.credId));
      if (!ok) fail('RAPID_REVOKE_NOT_ENTITLED', 'only an approving owner, the covered flow\'s holder, the ORC (personal) or a predefined engine rule');
      by = p.credId;
    }
    g.status = 'REVOKED'; g.endedAt = String(at); g.endedBy = by;
    fx.push({ type: 'RAPID_USE_REVOKED', grantId: g.grantId, by, reason: a.body.reason });
  },
  RAPID_USE_EXPIRE(s, a, tr, at, fx) {
    body(a, ['grantId']); noEvidenceBut(tr, []);
    const g = s.v5.rapid.grants[a.body.grantId]; if (!g) fail('RAPID_GRANT_UNKNOWN');
    if (g.status === 'ACTIVE' && at < Number(g.expiresAt)) fail('RAPID_GRANT_NOT_EXPIRED');
    fx.push({ type: 'RAPID_USE_HOUSEKEEPING', grantId: g.grantId, status: g.status });
  },
};

function singleSignerHold(s, a, at, fx, p, { holdId, cls, scope, reason, dur, reinforces }) {
  if (!['TARGETED_QUARANTINE', 'PROVISIONAL_HOLD'].includes(cls)) fail('HOLD_CLASS_NEEDS_INDEPENDENT_AUTHORITY', cls);
  if (cls === 'TARGETED_QUARANTINE' && scope.kind === 'GLOBAL') fail('QUARANTINE_MUST_BE_TARGETED');
  if (!p.isOrc && !eligibleFor(s, p, cls === 'TARGETED_QUARANTINE' && scope.kind === 'CREDENTIAL' ? 'SUSPEND' : 'FREEZE', scope)) fail('HOLD_ISSUER_ROLE_NOT_ELIGIBLE', p.role);
  const max = Number(cls === 'PROVISIONAL_HOLD' ? s.v5.config.provisionalMaxMs : s.v5.config.quarantineMaxMs);
  if (!(dur >= 60_000 && dur <= max)) fail('HOLD_DURATION', `max ${max / H} h for ${cls}`);
  // anti-amplification: the same issuer cannot stack identical holds; per-issuer active-count and 30-day budget
  if (Object.values(s.v5.holds).some(h => holdEffective(h, at) && h.scope.kind === scope.kind && h.scope.target === scope.target && h.issuers.some(i => i.ref === p.credId))) fail('HOLD_DUPLICATE_BY_SAME_ISSUER');
  const u = issuerUsage(s, p.credId, at);
  if (u.active >= Number(s.v5.config.maxActiveHoldsPerIssuer)) fail('HOLD_ISSUER_ACTIVE_LIMIT');
  if (u.ms + dur > Number(s.v5.config.issuerBudgetMs)) fail('HOLD_ISSUER_BUDGET_EXHAUSTED', `${Math.round(u.ms / H)} h used of ${Number(s.v5.config.issuerBudgetMs) / H} h / 30 d`);
  chargeIssuer(s, p.credId, at, dur);
  const h = newHold(s, at, { holdId, cls, scope, reason, issuers: [partyRef(p)], evidenceClass: EVIDENCE_CLASSES.OWNER, authDigest: p.digest, expiresAt: at + dur, reinforces, levels: [p.level] });
  fx.push({ type: 'HOLD_CREATED', holdId: h.holdId, cls, scope: `${scope.kind}:${scope.target}`, issuers: [p.credId], expiresAt: iso(Number(h.expiresAt)) });
}
function eligibleFor(s, p, rule, scope) {
  if (rule === 'SUSPEND') return true; // SUSPEND rule is ANY: any active credential may quarantine one credential
  return roleSetOf(s, 'FREEZE').has(p.role);
}
function requireIndependent(s, ps, what) {
  const roles = new Set(ps.map(p => p.isOrc ? 'ORC' : p.role));
  if (roles.size < 2) fail('INDEPENDENT_AUTHORITY_REQUIRED', `${what}: two distinct owner roles (or ORC + one)`);
  if (multi(s) && new Set(ps.map(p => p.holderId)).size < 2) fail('INDEPENDENT_AUTHORITY_REQUIRED', `${what}: two distinct owners`);
  if (!anyTrusted(ps)) fail('TRUSTED_CONFIRMATION_REQUIRED', what);
}
function voteKey(s, q, p) {
  if (multi(s)) {
    if (p.isOrc || p.role !== 'ADMIN') fail('RAPID_VOTER_NOT_OWNER_PRINCIPAL', p.role);
    if (!ownerPrincipals(s).includes(p.holderId)) fail('RAPID_VOTER_NOT_ENROLLED_OWNER');
    return 'owner:' + p.holderId;
  }
  // personal: an enhanced single-owner ceremony = the ORC + one separately protected owner credential that is not a covered flow
  if (p.isOrc) return 'factor:orc';
  if (!OWNER_ROLES_PERSONAL.has(p.role)) fail('RAPID_FACTOR_ROLE', p.role);
  if (q.scope.credIds.includes(p.credId)) fail('RAPID_FACTOR_IS_AFFECTED_CREDENTIAL', 'the bursting credential cannot vouch for itself');
  return 'factor:owner-credential';
}
/** Re-evaluated at activation: votes of credentials that have since become suspended / revoked / provisional no longer count. */
export function quorumStatus(s, q, at) {
  const valid = {};
  for (const [k, v] of Object.entries(q.votes)) {
    if (k === 'factor:orc') { if (s.v4.orcs[v.credId]?.status === 'active') valid[k] = v; continue; }
    const c = s.creds[v.credId];
    if (c && c.status === 'active' && !(Number(c.provisionalUntil ?? 0) > at)) valid[k] = v;
  }
  if (multi(s)) {
    const n = ownerPrincipals(s).length, need = rapidQuorum(n), have = Object.keys(valid).length;
    return { met: have >= need && n >= 2, detail: `${have}/${need} distinct owners (N=${n})`, voters: valid };
  }
  const met = !!valid['factor:orc'] && !!valid['factor:owner-credential'];
  return { met, detail: met ? 'ORC + owner credential' : 'needs the ORC AND a separate owner credential (not the covered flow)', voters: valid };
}
export const rapidRequestDigest = (s, q) => d5hex(V5_DOMAINS.RAPID_REQUEST, { chainId: s.chainId, requestId: q.requestId, scope: q.scope, delayException: q.delayException, durationMs: q.durationMs,
  explanation: q.explanation, incidentId: q.incidentId, requestedBy: q.requestedBy, requestedAt: q.requestedAt, epoch: q.epoch, nonce: q.nonce });

/** Rapid-Use grants / requests / delegations end deterministically on time, epoch, Purpose and credential restriction. */
function normalizeRapid(s, at, fx) {
  for (const q of Object.values(s.v5.rapid.requests)) if (q.status === 'PENDING' && (at >= Number(q.approveBy) || q.epoch !== String(s.epoch))) { q.status = 'EXPIRED'; fx.push({ type: 'RAPID_USE_REQUEST_EXPIRED', requestId: q.requestId }); }
  for (const g of Object.values(s.v5.rapid.grants)) {
    if (g.status !== 'ACTIVE') continue;
    let why = null;
    if (at >= Number(g.expiresAt)) why = 'EXPIRED';
    else if (g.epoch !== String(s.epoch)) why = 'ENDED_EPOCH_CHANGE';
    else if (g.purposeVersion !== s.purpose.version) why = 'ENDED_PURPOSE_CHANGE';
    else if (g.scope.credIds.some(c => s.creds[c]?.status !== 'active')) why = 'ENDED_CREDENTIAL_RESTRICTED';
    if (why) { g.status = why; g.endedAt = String(Math.min(at, Number(g.expiresAt))); fx.push({ type: why === 'EXPIRED' ? 'RAPID_USE_EXPIRED' : 'RAPID_USE_ENDED', grantId: g.grantId, reason: why }); }
  }
  for (const d of Object.values(s.v5.delegations)) {
    if (d.status !== 'ACTIVE') continue;
    const iss = s.creds[d.issuerCredId];
    let why = null;
    if (at >= Number(d.expiresAt)) why = 'EXPIRED';
    else if (d.epoch !== String(s.epoch)) why = 'ENDED_EPOCH_CHANGE';
    else if (d.purposeVersion !== s.purpose.version) why = 'ENDED_PURPOSE_CHANGE';
    else if (!iss || !isLive(iss)) why = 'ENDED_ISSUER_REVOKED';
    if (why) { d.status = why; d.endedAt = String(at); fx.push({ type: 'DELEGATION_ENDED', delegationId: d.delegationId, reason: why }); }
  }
}

// ------------------------------------------------------------------ transition
const V4_FORBIDDEN = new Set(['UNFREEZE']); // replaced by HOLD_RELEASE (provenance-correct)
export const ACTION_TYPES = Object.freeze([...new Set([...V4.ACTION_TYPES.filter(t => !V4_FORBIDDEN.has(t)), ...Object.keys(HANDLERS5)])]);
export const V5_COMMANDS = Object.freeze(Object.keys(HANDLERS5));

/** Projection of the Root state at time `at` (what every domain derives; owner devices build approvals against it). */
export function projectState(state0, at) { const s = clone(state0); const fx = []; normalizeHolds(s, at, fx); normalizeRapid(s, at, fx); return s; }

export function applyTransition(state0, tr) {
  if (state0.v5?.protocol !== PROTOCOL5) fail('PROTOCOL_MISMATCH');
  exactFields(tr, ['v', 'seq', 'prev', 'at', 'action'], ['approvals', 'guardianApprovals', 'attestation'], 'TRANSITION_FIELDS');
  if (tr.v !== TR_V) fail('TRANSITION_VERSION');
  if (tr.seq !== String(state0.seq + 1)) fail('TRANSITION_SEQ', `${tr.seq} vs ${state0.seq + 1}`);
  if (tr.prev !== state0.head) fail('TRANSITION_FORK');
  const at = isoMs(tr.at, 'at');
  if (at < state0.lastAt) fail('TRANSITION_TIME_BACKWARDS');
  const a = tr.action;
  if (V4_FORBIDDEN.has(a?.type)) fail('USE_HOLD_RELEASE', 'V5 releases protective holds individually (HOLD_RELEASE)');
  const pre = []; const s = clone(state0);
  normalizeHolds(s, at, pre); normalizeRapid(s, at, pre);
  let out, fx;
  if (HANDLERS5[a?.type]) {
    checkActionHeader(s, a, at);
    // F-V5-04: authenticate every approval BEFORE any command-specific validation, so an unauthenticated submitter
    // learns nothing about policy (it gets the authentication error, never a business-rule error). Runs on a scratch
    // copy (verification consumes challenges); the handler re-verifies and applies status rules on the real state.
    if (Array.isArray(tr.approvals) && tr.approvals.length) { const probe = clone(s); for (const ap of tr.approvals.slice(0, 8)) verifyCommand(probe, a, ap, at, { allowSuspended: true }); }
    fx = [];
    s.v5tx = { levels: [] };
    HANDLERS5[a.type](s, a, tr, at, fx);
    if (s.v5tx.levels.length) fx.push({ type: 'CONFIRMATION_ASSURANCE', levels: s.v5tx.levels.map(x => `${x.credId}:${x.level}`) });
    delete s.v5tx;
    s.usedNonces[a.nonce] = s.seq + 1;
    s.seq += 1; s.lastAt = at; s.transitions += 1;
    s.head = transitionHash(state0.head, tr);
    out = s;
  } else {
    // V4 operation: universal command binding = every credential approval must be a V4 AuthorizationIntent
    if ((tr.approvals ?? []).some(ap => !ap || typeof ap !== 'object' || !('intent' in ap))) fail('AUTHORIZATION_INTENT_REQUIRED', `${a?.type}: V5 accepts no bare action-digest approval`);
    const r = V4.applyTransition(s, { ...tr, v: V4.TR_V });
    out = r.state; fx = r.effects;
    out.head = transitionHash(state0.head, tr); // the chain commits to the transition AS STORED (V5 envelope)
  }
  const post = [];
  normalizeHolds(out, at, post); normalizeRapid(out, at, post);
  return { state: out, effects: [...pre, ...fx, ...post] };
}

export function replayChain(genesis, transitions, { pinnedChainId }) {
  let st = genesisState(genesis, { pinnedChainId }); const log = [];
  for (const tr of transitions) { const r = applyTransition(st, tr); st = r.state; log.push({ seq: tr.seq, type: tr.action.type, effects: r.effects }); }
  return { state: st, log };
}
export function rootView(st) {
  return { ...V4.rootView(st), protocol5: PROTOCOL5, holds: effectiveHolds(st, st.lastAt).map(publicHold),
    rapidGrants: Object.values(st.v5.rapid.grants).filter(g => g.status === 'ACTIVE').map(g => ({ grantId: g.grantId, expiresAt: iso(Number(g.expiresAt)), credIds: g.scope.credIds })) };
}
export { transitionHash, holdDigest, publicHold, effectiveHolds };
