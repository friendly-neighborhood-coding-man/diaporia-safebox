// SafeBox V4 Purpose Root state machine. It is the V3 Root (every V3 invariant and handler is reused unchanged unless
// listed below) plus:
//   * AuthorizationIntent approvals for every high-risk action (one-time 256-bit challenge, Root-time validity,
//     exact display/action binding, confirmation-assurance levels; trusted confirmation for CRITICAL actions).
//   * R-1 closure: silence is never consent. A reconstitution needs an explicit Owner Recovery Credential (ORC)
//     authorization bound to the exact case and replacement set, recorded BEFORE the 72 h deadline; an unapproved case
//     terminates at the deadline without moving authority; failed claims impose a 12 h re-attempt cooldown keyed on the
//     subject (not the case id), a 30-day claim budget, burned replacement keys and a bounded lockdown budget.
//   * R-3 closure: GUARDIAN_EMERGENCY_REPLACE / IDENTITY_VERIFIER_EMERGENCY_REPLACE governance cases: owner quorum of
//     two distinct owner roles (independent of guardians/IDVs), independent precommitted evidence (adjudicator verdict
//     quorum, cryptographic equivocation proof, self-signed withdrawal, or on-chain liveness timeout), exclusion of
//     verified members, a non-empty electorate voting unanimously by confidential sealed ballots, a notified security
//     delay, and an atomic 1:1 replacement that keeps the quorum floor.
import { fail, exactFields, id, uint, isoMs, iso, canon, clone, V3_DOMAINS, edVerifyDigest, edVerifyStatement, sha256hex as sha3hex } from '../../v3/common/canon.mjs';
import * as V3 from '../../v3/root/chain.mjs';
import { verifyAssertion } from '../../v3/webauthn/verify.mjs';
import { PROTOCOL, V4_DOMAINS, d4, d4hex, keyDigest, verifyObj, verifyDigest } from '../common/v4.mjs';
import { verifyIntentApproval, TRUSTED_LEVELS, LEVELS } from '../intent/intent.mjs';
import { verifyBallotEligibility, commitmentOf } from '../ballot/ballot.mjs';

const { HANDLERS: H3, checkActionHeader, verifyApprovals, checkGuardians, applySignCounts, bumpEpoch, noCase, noLockdown, closeCase, isLive, actionDigest, transitionHash, caseDigestOf, ZERO } = V3;
export { actionDigest, survivors, lossAssessment, caseDigestOf, ACTION_V } from '../../v3/root/chain.mjs';

export const TR_V = 'safebox.v4.transition';
export const EXT_V = 'safebox.v4.genesis-ext';
export const VERDICT_V = 'safebox.v4.verdict';
export const WITHDRAWAL_V = 'safebox.v4.withdrawal';
const H = 3600_000, D = 86_400_000;
export const V4_DEFAULT_CONFIG = Object.freeze({
  challengeTtlMs: '120000',              // authentication-challenge lifetime (separate from every recovery timer)
  reattemptCooldownMs: String(12 * H),   // after an unapproved / cancelled claim, per subject holder
  completionGraceMs: String(7 * D),      // an owner-authorized case must complete within deadline + grace
  maxFailedClaims30d: '3',               // claim budget per subject holder (ORC-attested opens are exempt)
  lockdownBudgetMs: String(96 * H),      // total claim-triggered lockdown time per 30 days
  adjudicatorQuorum: '2',                // distinct adjudicator verdicts needed to establish compromise / misconduct
  govVoteMs: String(72 * H),             // confidential vote window of a governance case
  govDelayMs: String(24 * H),            // notified security delay between approval and execution
  unavailabilityMs: String(30 * D),      // unanswered liveness challenge before a participant counts as unavailable
});
const CFG_FIELDS = Object.keys(V4_DEFAULT_CONFIG);

/** High-risk actions: approvals MUST be AuthorizationIntents. Protective actions (FREEZE, SUSPEND, OBJECT) may use either form. */
export const INTENT_REQUIRED = new Set(['AMEND_PURPOSE', 'AMEND_MATRIX', 'UNFREEZE', 'ROTATE', 'REVOKE', 'REPLACE_VACANT', 'UNSUSPEND', 'RATIFY_BASELINE',
  'RECOVERY_CONSENT', 'RECOVERY_WITHDRAW', 'RECOVERY_CANCEL', 'RECOVERY_OWNER_AUTHORIZE', 'RECOVERY_ORC_CANCEL', 'RECOVERY_OPEN', 'ORC_REPLACE', 'GOV_CASE_OPEN', 'GOV_CASE_CANCEL', 'GUARDIAN_ROTATE']);
/** CRITICAL actions additionally need >= 1 approval through a trusted confirmation path (hardware display / protected confirmation). */
export const CRITICAL = new Set(['AMEND_PURPOSE', 'AMEND_MATRIX', 'ROTATE', 'REPLACE_VACANT', 'RATIFY_BASELINE', 'RECOVERY_OWNER_AUTHORIZE', 'ORC_REPLACE', 'GOV_CASE_OPEN', 'GUARDIAN_ROTATE']);
const FAILED_OUTCOMES = new Set(['CANCELLED', 'EXPIRED_UNAPPROVED']);
const PROCEDURES = ['GUARDIAN_EMERGENCY_REPLACE', 'IDENTITY_VERIFIER_EMERGENCY_REPLACE'];
const GROUNDS = ['COMPROMISE', 'MISCONDUCT', 'UNAVAILABLE', 'WITHDRAWAL'];
const OWNER_QUORUM_ROLES = new Set(['DAILY', 'ROOT', 'RECOVERY', 'ORC']);

// ------------------------------------------------------------------ approval delegate (registered for state.protocol)
function delegate({ state, action, approval, credential, rule, at }) {
  if ('intent' in approval) return verifyIntentApproval(state, action, approval, credential, at, { requireUV: rule.uv === '1' || credential.kind === 'passkey' });
  if (INTENT_REQUIRED.has(action.type)) fail('AUTHORIZATION_INTENT_REQUIRED', action.type);
  // protective low-risk scopes: V3 action-digest approval
  exactFields(approval, ['credId'], ['webauthn', 'sig'], 'APPROVAL_FIELDS');
  const dig = actionDigest(action);
  if (credential.kind === 'passkey') {
    if (!approval.webauthn || 'sig' in approval) fail('APPROVAL_KIND_MISMATCH');
    const r = verifyAssertion(approval.webauthn, { rp: state.rp, expectedChallenge: dig, credential: { ...credential.webauthn, signCount: credential.signCount }, requireUV: rule.uv === '1' });
    return { uv: r.uv, signCount: r.signCount };
  }
  if (typeof approval.sig !== 'string' || 'webauthn' in approval) fail('APPROVAL_KIND_MISMATCH');
  if (!edVerifyDigest(V3_DOMAINS.ACTION, dig, approval.sig, credential.publicKey)) fail('APPROVAL_BAD_SIGNATURE', approval.credId);
  return { uv: false };
}
V3.registerApprovalVerifier(PROTOCOL, delegate);

/** ORC approval: an independent, pre-enrolled hardware credential with a trusted display. Never a V3 credential. */
function verifyOrcApproval(s, a, ap, at) {
  const o = s.v4.orcs[ap?.credId];
  if (!o || o.status !== 'active') fail('ORC_UNKNOWN_OR_INACTIVE');
  const r = verifyIntentApproval(s, a, ap, { kind: 'ed25519', publicKey: o.publicKey }, at);
  if (!TRUSTED_LEVELS.has(r.level)) fail('ORC_REQUIRES_TRUSTED_DISPLAY');
  return r;
}

/** Emergency owner quorum: >= 2 DISTINCT owner roles among DAILY / ROOT / RECOVERY / ORC (FREEZE excluded), via intents. */
function verifyOwnerQuorum(s, a, approvals, at) {
  if (s.matrix.profile !== 'personal') fail('EMERGENCY_PROCEDURE_PERSONAL_PROFILE_ONLY');
  if (!Array.isArray(approvals) || approvals.length < 2 || approvals.length > 6) fail('EMERGENCY_OWNER_QUORUM_SHAPE');
  const seen = new Set(), roles = new Set(), who = [];
  // F-V4-03 (fresh campaign B_r3 on 69d5f08): one-signature SUSPENDs by stolen keys could strip the owner of every
  // second role, so the guardian majority blocking the recovery could never be replaced. With an ORC approval in the
  // same quorum (the independent owner anchor), a SUSPENDED (never revoked / retired) owner credential may supply the
  // second role; without the ORC, suspended credentials never count.
  const withOrc = approvals.some(ap => ap && typeof ap.credId === 'string' && s.v4.orcs[ap.credId]);
  for (const ap of approvals) {
    if (!ap || typeof ap.credId !== 'string' || seen.has(ap.credId)) fail('DUPLICATE_APPROVAL'); seen.add(ap.credId);
    if (s.v4.orcs[ap.credId]) { verifyOrcApproval(s, a, ap, at); roles.add('ORC'); who.push(ap.credId); continue; }
    const c = s.creds[ap.credId];
    if (!c || !(c.status === 'active' || (withOrc && c.status === 'suspended'))) fail('APPROVAL_CREDENTIAL_NOT_ACTIVE', ap.credId);
    if (!OWNER_QUORUM_ROLES.has(c.role)) fail('ROLE_NOT_IN_EMERGENCY_OWNER_QUORUM', c.role);
    if (Number(c.provisionalUntil ?? 0) > at) fail('PROVISIONAL_CREDENTIAL');
    const r = verifyIntentApproval(s, a, ap, c, at, { requireUV: true });
    if (r.signCount !== null && r.signCount !== undefined) c.signCount = r.signCount;
    roles.add(c.role); who.push(c.credId);
  }
  if (roles.size < 2) fail('EMERGENCY_OWNER_QUORUM_NOT_MET', 'two distinct owner roles (DAILY/ROOT/RECOVERY/ORC) are required');
  return who;
}

// ------------------------------------------------------------------ genesis
function parseV4Config(c) {
  exactFields(c, CFG_FIELDS, [], 'V4_CONFIG_FIELDS');
  const n = Object.fromEntries(CFG_FIELDS.map(k => [k, Number(uint(c[k], k))]));
  if (n.challengeTtlMs < 30_000 || n.challengeTtlMs > 300_000) fail('V4_CONFIG_CHALLENGE_TTL');
  if (n.reattemptCooldownMs < 12 * H) fail('V4_CONFIG_REATTEMPT_COOLDOWN_BELOW_12H');
  if (n.completionGraceMs < H || n.completionGraceMs > 30 * D) fail('V4_CONFIG_GRACE');
  if (n.maxFailedClaims30d < 1 || n.maxFailedClaims30d > 20) fail('V4_CONFIG_CLAIM_BUDGET');
  if (n.adjudicatorQuorum < 1) fail('V4_CONFIG_ADJUDICATOR_QUORUM');
  if (n.govVoteMs < H || n.govDelayMs < H || n.unavailabilityMs < 7 * D) fail('V4_CONFIG_GOV');
  return { ...c };
}

export function genesisState(gen, { pinnedChainId = null } = {}) {
  exactFields(gen, ['v3', 'ext'], [], 'GENESIS4_FIELDS');
  const st = V3.genesisState(gen.v3, {});
  const e = exactFields(gen.ext, ['action', 'approvals'], [], 'GENESIS_EXT_FIELDS');
  const a = exactFields(e.action, ['v', 'v3ChainId', 'accountId', 'nonce', 'issuedAt', 'body'], [], 'GENESIS_EXT_ACTION');
  if (a.v !== EXT_V || a.v3ChainId !== st.chainId || a.accountId !== st.accountId) fail('GENESIS_EXT_BINDING');
  const b = exactFields(a.body, ['config', 'orcs', 'displays', 'confirmers', 'adjudicators', 'tally', 'challengeIssuer'], [], 'GENESIS_EXT_BODY');
  const config = parseV4Config(b.config);
  const extDigest = d4(V4_DOMAINS.GENESIS_EXT, a);
  const ownerHolders = new Set(Object.values(st.creds).map(c => c.holderId));
  const allKeys = new Set([...Object.values(st.creds).map(c => c.publicKey), ...Object.values(st.guardians).map(g => g.publicKey), ...Object.values(st.idvs).map(g => g.publicKey),
    ...Object.values(st.registrars).map(g => g.publicKey), ...Object.values(st.serviceKeys), ...Object.values(st.channels).map(c => c.publicKey)]);
  const addKey = (k, code) => { if (allKeys.has(k)) fail(code); allKeys.add(k); };
  const orcs = {};
  for (const [oid, o] of Object.entries(exactFields(b.orcs, Object.keys(b.orcs), [], 'GENESIS_ORCS'))) {
    id(oid, 'orcId'); exactFields(o, ['publicKey', 'holderId'], [], 'GENESIS_ORC');
    if (st.creds[oid]) fail('ORC_ID_COLLIDES_WITH_CREDENTIAL');
    if (!ownerHolders.has(o.holderId)) fail('ORC_HOLDER_NOT_OWNER');
    addKey(o.publicKey, 'ORC_KEY_NOT_INDEPENDENT');
    orcs[oid] = { publicKey: o.publicKey, holderId: o.holderId, status: 'active', addedAt: '0' };
  }
  if (!Object.keys(orcs).length) fail('V4_NEEDS_OWNER_RECOVERY_CREDENTIAL');
  const displays = {};
  for (const [cid, v] of Object.entries(b.displays)) { const c = st.creds[cid]; if (!c || c.kind !== 'ed25519' || v !== 'TRUSTED_DISPLAY') fail('GENESIS_DISPLAY'); displays[cid] = v; }
  for (const oid of Object.keys(orcs)) displays[oid] = 'TRUSTED_DISPLAY';
  const confirmers = {};
  for (const [cid, v] of Object.entries(b.confirmers)) {
    const c = st.creds[cid]; if (!c || c.kind !== 'passkey') fail('GENESIS_CONFIRMER');
    exactFields(v, ['publicKey', 'pop'], [], 'GENESIS_CONFIRMER');
    if (!verifyObj(V4_DOMAINS.CONFIRM_POP, { accountId: st.accountId, v3ChainId: st.chainId, credId: cid, publicKey: v.publicKey }, v.pop, v.publicKey)) fail('CONFIRMER_POP_INVALID');
    addKey(v.publicKey, 'CONFIRMER_KEY_NOT_INDEPENDENT'); confirmers[cid] = { publicKey: v.publicKey };
  }
  const participantHolders = new Set([...Object.values(st.guardians).map(g => g.holderId), ...Object.values(st.idvs).map(g => g.holderId)]);
  const adjudicators = {};
  for (const [aid, v] of Object.entries(b.adjudicators)) {
    id(aid, 'adjudicatorId'); exactFields(v, ['publicKey', 'holderId'], [], 'GENESIS_ADJUDICATOR');
    if (ownerHolders.has(v.holderId) || participantHolders.has(v.holderId)) fail('ADJUDICATOR_NOT_INDEPENDENT');
    addKey(v.publicKey, 'ADJUDICATOR_KEY_NOT_INDEPENDENT'); participantHolders.add(v.holderId);
    adjudicators[aid] = { ...v, status: 'active' };
  }
  if (Number(config.adjudicatorQuorum) > Object.keys(adjudicators).length) fail('V4_CONFIG_ADJUDICATOR_QUORUM_EXCEEDS_ADJUDICATORS');
  exactFields(b.tally, ['id', 'publicKey', 'sigKey'], [], 'GENESIS_TALLY'); addKey(b.tally.sigKey, 'TALLY_KEY_NOT_INDEPENDENT');
  exactFields(b.challengeIssuer, ['id', 'publicKey'], [], 'GENESIS_CHALLENGE_ISSUER'); addKey(b.challengeIssuer.publicKey, 'ISSUER_KEY_NOT_INDEPENDENT');
  // guardian and identity-verifier ids share one namespace (ballot voter ids); holders are distinct and never the owner
  const gi = [...Object.keys(st.guardians), ...Object.keys(st.idvs)]; if (new Set(gi).size !== gi.length) fail('PARTICIPANT_IDS_NOT_DISTINCT');
  const gh = [...Object.values(st.guardians), ...Object.values(st.idvs)].map(x => x.holderId);
  if (new Set(gh).size !== gh.length || gh.some(h => ownerHolders.has(h))) fail('PARTICIPANTS_NOT_INDEPENDENT');
  // every credential and every ORC approves the extension (possession + consent), passkeys with UV
  const signed = new Set();
  for (const ap of e.approvals ?? []) {
    if (!ap || signed.has(ap.credId)) fail('GENESIS_EXT_APPROVAL');
    const c = st.creds[ap.credId];
    if (c && c.kind === 'passkey') { const r = verifyAssertion(ap.webauthn, { rp: st.rp, expectedChallenge: extDigest, credential: { ...c.webauthn, signCount: c.signCount }, requireUV: true }); c.signCount = r.signCount; }
    else if (c) { if (!verifyDigest(V4_DOMAINS.GENESIS_EXT, extDigest, ap.sig, c.publicKey)) fail('GENESIS_EXT_SIGNATURE', ap.credId); }
    else if (orcs[ap.credId]) { if (!verifyDigest(V4_DOMAINS.ORC_POP, extDigest, ap.sig, orcs[ap.credId].publicKey)) fail('GENESIS_ORC_POP', ap.credId); }
    else fail('GENESIS_EXT_APPROVAL_UNKNOWN');
    signed.add(ap.credId);
  }
  if (signed.size !== Object.keys(st.creds).length + Object.keys(orcs).length) fail('GENESIS_EXT_NOT_APPROVED_BY_ALL');
  const chainId = d4hex(V4_DOMAINS.GENESIS, { v3ChainId: st.chainId, ext: extDigest.toString('hex') });
  if (pinnedChainId && chainId !== pinnedChainId) fail('GENESIS_NOT_PINNED');
  st.v3ChainId = st.chainId; st.chainId = chainId; st.protocol = PROTOCOL;
  st.head = sha3hex(Buffer.concat([Buffer.from(V3_DOMAINS.TRANSITION), Buffer.from(ZERO), Buffer.from(canon({ seq: '0', at: gen.v3.at, actionDigest: chainId }))]));
  st.usedNonces[a.nonce] = 0;
  st.v4 = { config, orcs, displays, confirmers, adjudicators, tally: { ...b.tally }, challengeIssuer: { ...b.challengeIssuer },
    usedChallenges: {}, screenDigests: {}, claims: [], burnedPlanKeys: {}, lockdowns: [], gcase: null, gcaseHistory: [], disqualified: {}, retired: {}, removedIdvs: {}, liveness: {}, suspendedBy: {}, freezeHolds: [] };
  return st;
}

// ------------------------------------------------------------------ transitions
const body = (a, req, opt = []) => exactFields(a.body, req, opt, `BODY_${a.type}`);
const caseMatch = (s, a) => { const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE'); if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH'); return cs; };
export function caseDigestV4(s, cs) {
  return d4hex(V4_DOMAINS.CASE, { chainId: s.chainId, v3: caseDigestOf(cs), openNonce: cs.v4.openNonce, planMeta: cs.v4.planMeta, deadline: iso(cs.v4.deadline), replans: String(cs.replans ?? 0) });
}
const gcaseDigestOf = (s, g) => d4hex(V4_DOMAINS.GOV_CASE, { chainId: s.chainId, gcaseId: g.gcaseId, procedure: g.procedure, accused: g.accused, ground: g.ground,
  replacements: g.replacements.map(r => `${r.id}|${r.holderId}|${r.publicKey}`), electorate: g.electorate, openedAt: iso(g.openedAt), openNonce: g.openNonce });
const allParticipantKeys = (s) => new Set([...Object.values(s.creds).map(c => c.publicKey), ...Object.values(s.guardians).map(g => g.publicKey), ...Object.values(s.idvs).map(g => g.publicKey),
  ...Object.values(s.v4.removedIdvs).map(g => g.publicKey), ...Object.values(s.v4.adjudicators).map(g => g.publicKey), ...Object.values(s.v4.orcs).map(o => o.publicKey),
  s.v4.tally.sigKey, s.v4.challengeIssuer.publicKey, ...Object.values(s.registrars).map(g => g.publicKey), ...Object.values(s.channels).map(c => c.publicKey)]);
const allHolders = (s) => new Set([...Object.values(s.creds).map(c => c.holderId), ...Object.values(s.guardians).map(g => g.holderId), ...Object.values(s.idvs).map(g => g.holderId),
  ...Object.values(s.v4.removedIdvs).map(g => g.holderId), ...Object.values(s.v4.adjudicators).map(g => g.holderId), ...Object.values(s.v4.orcs).map(o => o.holderId)]);

function parsePlanMeta(s, pm, plan) {
  if (pm === undefined) return {};
  if (!pm || typeof pm !== 'object' || Array.isArray(pm)) fail('PLAN_META');
  const out = {};
  for (const [cid, m] of Object.entries(pm)) {
    const p = plan.find(x => x.credId === cid); if (!p) fail('PLAN_META_UNKNOWN_CREDENTIAL');
    exactFields(m, ['display'], ['confirmer'], 'PLAN_META_ENTRY');
    if (!['TRUSTED_DISPLAY', 'NONE'].includes(m.display) || (m.display === 'TRUSTED_DISPLAY' && p.kind !== 'ed25519')) fail('PLAN_META_DISPLAY');
    const e = { display: m.display };
    if (m.confirmer) {
      if (p.kind !== 'passkey') fail('PLAN_META_CONFIRMER_KIND');
      exactFields(m.confirmer, ['publicKey', 'pop'], [], 'PLAN_META_CONFIRMER');
      if (!verifyObj(V4_DOMAINS.CONFIRM_POP, { accountId: s.accountId, v3ChainId: s.v3ChainId, credId: cid, publicKey: m.confirmer.publicKey }, m.confirmer.pop, m.confirmer.publicKey)) fail('CONFIRMER_POP_INVALID');
      if (allParticipantKeys(s).has(m.confirmer.publicKey)) fail('CONFIRMER_KEY_NOT_INDEPENDENT');
      e.confirmer = { publicKey: m.confirmer.publicKey, pop: m.confirmer.pop };
    }
    out[cid] = e;
  }
  return out;
}
function installPlanMeta(s, cs) {
  for (const [cid, m] of Object.entries(cs.v4.planMeta)) {
    if (m.display === 'TRUSTED_DISPLAY') s.v4.displays[cid] = 'TRUSTED_DISPLAY';
    if (m.confirmer) s.v4.confirmers[cid] = { publicKey: m.confirmer.publicKey };
  }
}
const lockdownUsed30d = (s, at) => s.v4.lockdowns.filter(l => (l.end ?? at) > at - 30 * D).reduce((t, l) => t + ((l.end ?? at) - Math.max(l.start, at - 30 * D)), 0);

const HANDLERS4 = {
  // ---------------------------------------------- R-1: claims, owner authorization, expiry
  RECOVERY_OPEN(s, a, tr, at, fx) {
    body(a, ['caseId', 'kind', 'lost', 'subjectHolderId', 'plan', 'note'], ['planMeta']);
    let ownerAttested = false;
    if (tr.approvals?.length) { if (tr.approvals.length !== 1) fail('RECOVERY_OPEN_ATTESTATION_ONE_ORC'); verifyOrcApproval(s, a, tr.approvals[0], at); ownerAttested = true; }
    if (s.v4.gcase) fail('GOVERNANCE_CASE_OPEN');
    const subj = String(a.body.subjectHolderId);
    const fails = s.v4.claims.filter(c => c.subjectHolderId === subj && FAILED_OUTCOMES.has(c.outcome));
    const last = fails.at(-1);
    if (!ownerAttested && last && at < last.closedAt + Number(s.v4.config.reattemptCooldownMs))
      fail('RECOVERY_REATTEMPT_COOLDOWN', `${Math.ceil((last.closedAt + Number(s.v4.config.reattemptCooldownMs) - at) / 60_000)} min left (keyed on subject, not case id)`);
    if (!ownerAttested && fails.filter(c => c.closedAt > at - 30 * D).length >= Number(s.v4.config.maxFailedClaims30d)) fail('RECOVERY_CLAIM_BUDGET_EXHAUSTED', 'an ORC-attested open is still possible');
    const { planMeta, ...b3 } = a.body;
    H3.RECOVERY_OPEN(s, { ...a, body: b3 }, { ...tr, approvals: undefined }, at, fx);
    const cs = s.case;
    for (const p of cs.plan) if (s.v4.burnedPlanKeys[keyDigest(p.publicKey)]) fail('PLAN_KEY_PREVIOUSLY_REJECTED', p.credId);
    cs.v4 = { openNonce: a.nonce, ownerAttested, planMeta: parsePlanMeta(s, planMeta, cs.plan), ownerAuth: null, consentLevels: {}, deadline: at + Number(s.config.windowMs) };
    cs.digest = caseDigestV4(s, cs);
    fx.push({ type: 'RECOVERY_DEADLINE', caseId: cs.caseId, deadline: iso(cs.v4.deadline), ownerAttested });
  },
  RECOVERY_CONSENT(s, a, tr, at, fx) {
    if (!suspendedSurvivorConsent(s, a, tr, at, fx)) H3.RECOVERY_CONSENT(s, a, tr, at, fx);
    const lv = s.v4.tx.levels.at(-1); if (lv) s.case.v4.consentLevels[lv.credId] = lv.level;
  },
  RECOVERY_REPLAN(s, a, tr, at, fx) {
    H3.RECOVERY_REPLAN(s, a, tr, at, fx);
    const cs = s.case;
    for (const p of cs.plan) if (s.v4.burnedPlanKeys[keyDigest(p.publicKey)]) fail('PLAN_KEY_PREVIOUSLY_REJECTED', p.credId);
    cs.v4 = { ...cs.v4, planMeta: {}, ownerAuth: null, consentLevels: {}, deadline: at + Number(s.config.windowMs) };
    cs.digest = caseDigestV4(s, cs);
  },
  RECOVERY_OWNER_AUTHORIZE(s, a, tr, at, fx) {
    body(a, ['caseId', 'caseDigest', 'orcId']);
    const cs = caseMatch(s, a);
    if (!cs.dispatched.length) fail('OWNER_AUTHORIZATION_BEFORE_NOTIFICATION');
    if (at >= cs.v4.deadline) fail('OWNER_AUTHORIZATION_AFTER_DEADLINE');
    if ((tr.approvals ?? []).length !== 1 || tr.approvals[0].credId !== a.body.orcId) fail('OWNER_AUTHORIZATION_ONE_ORC');
    if (tr.guardianApprovals || tr.attestation) fail('OWNER_AUTHORIZATION_MIXED_EVIDENCE');
    const r = verifyOrcApproval(s, a, tr.approvals[0], at);
    cs.v4.ownerAuth = { orcId: a.body.orcId, at, caseDigest: cs.digest, intent: r.intentDigestHex, level: r.level };
    fx.push({ type: 'OWNER_AUTHORIZED', caseId: cs.caseId, orcId: a.body.orcId, level: r.level });
  },
  RECOVERY_COMPLETE(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    if (at >= cs.v4.deadline + Number(s.v4.config.completionGraceMs)) fail('RECOVERY_CASE_EXPIRED');
    const trusted = Object.values(cs.v4.consentLevels).some(l => TRUSTED_LEVELS.has(l)) || (cs.v4.ownerAuth?.caseDigest === cs.digest);
    if (!trusted) fail('NO_TRUSTED_CONFIRMATION_IN_CASE', 'at least one consent through a trusted display / protected confirmation, or ORC authorization');
    H3.RECOVERY_COMPLETE(s, a, tr, at, fx);
    installPlanMeta(s, cs);
    liftProtectiveActionsOfLost(s, cs.lost, fx, at);
  },
  RECONSTITUTE(s, a, tr, at, fx) {
    const cs = s.case; if (!cs) fail('NO_RECOVERY_CASE');
    // INV-V4-01 / INV-V4-02: the 72 h window, guardians, identity verifiers, channel acks and survivor consents are all
    // necessary, but none of them is owner intent. Only an ORC authorization bound to THIS case digest (exact plan) is.
    if (!cs.v4.ownerAuth || cs.v4.ownerAuth.caseDigest !== cs.digest) fail('OWNER_AUTHORIZATION_REQUIRED', 'silence, acknowledgements and elapsed time never authorize a reconstitution');
    if (at >= cs.v4.deadline + Number(s.v4.config.completionGraceMs)) fail('RECOVERY_CASE_EXPIRED');
    H3.RECONSTITUTE(s, a, tr, at, fx);
    installPlanMeta(s, cs);
    liftProtectiveActionsOfLost(s, cs.lost, fx, at);
  },
  RECOVERY_EXPIRE(s, a, tr, at, fx) {
    body(a, ['caseId', 'caseDigest']);
    if (tr.approvals?.length || tr.guardianApprovals || tr.attestation) fail('EXPIRE_TAKES_NO_EVIDENCE');
    const cs = caseMatch(s, a);
    const st = cs.state === 'HOLD' ? cs.prior : cs.state;
    const majority = cs.path === 'RECONSTITUTION' || ['EMERGENCY_LOCKDOWN', 'RECONSTITUTION', 'RECOVERY_IMPOSSIBLE'].includes(st);
    const hardEnd = cs.v4.deadline + Number(s.v4.config.completionGraceMs);
    const unapprovedMajority = at >= cs.v4.deadline && !cs.v4.ownerAuth;
    const unapprovedAny = at >= cs.v4.deadline && (cs.state === 'HOLD' || st !== 'RECOVERY_CHALLENGE') && !cs.v4.ownerAuth; // never confirmed / objected (HOLD) / impossible
    if (!(at >= hardEnd || (majority && unapprovedMajority) || unapprovedAny)) fail('RECOVERY_NOT_EXPIRED');
    if (s.lockdown.active && s.lockdown.caseId === cs.caseId) s.lockdown = { active: false, caseId: null };
    fx.push({ type: 'RECOVERY_EXPIRED', caseId: cs.caseId, reason: cs.v4.ownerAuth ? 'not completed within grace' : 'no affirmative owner authorization by the deadline' });
    closeCase(s, cs, 'EXPIRED_UNAPPROVED', at, fx);
  },
  RECOVERY_ORC_CANCEL(s, a, tr, at, fx) {
    body(a, ['caseId', 'caseDigest']);
    const cs = caseMatch(s, a);
    if ((tr.approvals ?? []).length !== 1) fail('ORC_CANCEL_ONE_ORC');
    verifyOrcApproval(s, a, tr.approvals[0], at);
    if (s.lockdown.active && s.lockdown.caseId === cs.caseId) s.lockdown = { active: false, caseId: null };
    closeCase(s, cs, 'CANCELLED', at, fx);
  },
  ORC_REPLACE(s, a, tr, at, fx) {
    noCase(s); noLockdown(s); if (s.v4.gcase) fail('GOVERNANCE_CASE_OPEN');
    body(a, ['orcId', 'newOrc']);
    const r = verifyApprovals(s, a, tr.approvals, 'AMEND_MATRIX', { at }); applySignCounts(s, r.signCounts);
    checkGuardians(s, a, tr.guardianApprovals, Number(s.config.guardianQuorum));
    const n = exactFields(a.body.newOrc, ['id', 'publicKey', 'holderId', 'pop'], [], 'NEW_ORC');
    id(n.id, 'orcId'); if (s.creds[n.id] || s.v4.orcs[n.id]) fail('ORC_ID_IN_USE');
    if (!Object.values(s.creds).some(c => c.holderId === n.holderId)) fail('ORC_HOLDER_NOT_OWNER');
    if (allParticipantKeys(s).has(n.publicKey)) fail('ORC_KEY_NOT_INDEPENDENT');
    if (!verifyObj(V4_DOMAINS.ORC_POP, { accountId: s.accountId, chainId: s.chainId, id: n.id, publicKey: n.publicKey, nonce: a.nonce }, n.pop, n.publicKey)) fail('ORC_POP_INVALID');
    if (a.body.orcId !== '-') { const o = s.v4.orcs[a.body.orcId]; if (!o || o.status !== 'active') fail('ORC_SUBJECT_NOT_ACTIVE'); o.status = 'retired'; o.retiredAt = String(at); }
    s.v4.orcs[n.id] = { publicKey: n.publicKey, holderId: n.holderId, status: 'active', addedAt: String(at) }; s.v4.displays[n.id] = 'TRUSTED_DISPLAY';
    bumpEpoch(s, fx, 'orc replace');
    fx.push({ type: 'ORC_REPLACED', from: a.body.orcId, to: n.id, approvers: r.approvers });
  },
  ROTATE(s, a, tr, at, fx) {
    if (s.v4.gcase) fail('GOVERNANCE_CASE_OPEN');
    const old = s.creds[a.body?.credId];
    H3.ROTATE(s, a, tr, at, fx);
    const nc = Object.values(s.creds).find(c => c.status === 'active' && c.epochAdded === s.epoch && c.role === old.role && c.credId === a.body.newCredential.credId);
    if (nc && s.v4.displays[old.credId] && nc.kind === 'ed25519') s.v4.displays[nc.credId] = s.v4.displays[old.credId]; // same hardware model replaced
  },

  // ---------------------------------------------- R-3: governance (participant) cases
  // F-V4-01: protective actions are recorded with their approvers, so that a recovery which revokes those approvers
  // (a completed, owner-confirmed case) also undoes the suspensions / owner-source freeze they alone imposed.
  SUSPEND(s, a, tr, at, fx) {
    H3.SUSPEND(s, a, tr, at, fx);
    s.v4.suspendedBy[a.body.credId] = (tr.approvals ?? []).map(x => x.credId).sort();
  },
  UNSUSPEND(s, a, tr, at, fx) { H3.UNSUSPEND(s, a, tr, at, fx); delete s.v4.suspendedBy[a.body.credId]; },
  FREEZE(s, a, tr, at, fx) {
    // every FREEZE, including a reinforcement of an existing freeze, is an independent hold with its own provenance
    // (review of 780e676: a deliberate K2 reinforcement must survive the revocation of the K1 that froze first)
    H3.FREEZE(s, a, tr, at, fx);
    const by = a.body.source === 'owner' ? (tr.approvals ?? []).map(x => x.credId).sort() : ['source:' + a.body.source];
    s.v4.freezeHolds.push({ freezeId: a.body.freezeId, by, at: String(at) });
  },
  UNFREEZE(s, a, tr, at, fx) { H3.UNFREEZE(s, a, tr, at, fx); s.v4.freezeHolds = []; },
  GOV_CASE_OPEN(s, a, tr, at, fx) {
    body(a, ['gcaseId', 'procedure', 'accused', 'ground', 'evidence', 'replacements']);
    noCase(s, 'RECOVERY_CASE_OPEN'); noLockdown(s);
    if (s.v4.gcase) fail('GOVERNANCE_CASE_ALREADY_OPEN');
    const b = a.body; id(b.gcaseId, 'gcaseId');
    if (s.v4.gcaseHistory.some(g => g.gcaseId === b.gcaseId)) fail('GCASE_ID_REUSED');
    if (!PROCEDURES.includes(b.procedure)) fail('GOV_PROCEDURE');
    if (!GROUNDS.includes(b.ground)) fail('GOV_GROUND');
    if (tr.guardianApprovals || tr.attestation) fail('GOV_OPEN_MIXED_EVIDENCE');
    const owners = verifyOwnerQuorum(s, a, tr.approvals, at);
    const guardianProc = b.procedure === 'GUARDIAN_EMERGENCY_REPLACE';
    const pool = guardianProc ? Object.fromEntries(Object.entries(s.guardians).filter(([, g]) => g.status === 'active')) : { ...s.idvs };
    if (!Array.isArray(b.accused) || !b.accused.length || new Set(b.accused).size !== b.accused.length) fail('GOV_ACCUSED_SET');
    for (const x of b.accused) if (!pool[x]) fail('GOV_ACCUSED_NOT_ACTIVE_MEMBER', x);
    // independent, precommitted evidence per accused member (an accusation alone proves nothing)
    if (!Array.isArray(b.evidence) || b.evidence.length > 16) fail('GOV_EVIDENCE');
    for (const x of b.accused) proveGround(s, b, x, pool[x], guardianProc ? 'guardian' : 'idv', at);
    // replacements: 1:1, possession-proven, independent of every existing key and holder
    if (!Array.isArray(b.replacements) || b.replacements.length !== b.accused.length) fail('REMOVAL_WITHOUT_REPLACEMENT', 'replacement must be atomic and 1:1');
    const keys = allParticipantKeys(s), holders = allHolders(s), ids = new Set([...Object.keys(s.guardians), ...Object.keys(s.idvs), ...Object.keys(s.v4.removedIdvs), ...Object.keys(s.v4.adjudicators), ...Object.keys(s.creds), ...Object.keys(s.v4.orcs)]);
    const reps = [];
    for (const r of b.replacements) {
      exactFields(r, ['id', 'holderId', 'publicKey', 'pop'], [], 'GOV_REPLACEMENT'); id(r.id, 'replacementId'); id(r.holderId, 'replacementHolder');
      if (ids.has(r.id)) fail('REPLACEMENT_ID_IN_USE'); ids.add(r.id);
      if (keys.has(r.publicKey)) fail('REPLACEMENT_KEY_NOT_INDEPENDENT'); keys.add(r.publicKey);
      if (holders.has(r.holderId)) fail('REPLACEMENT_HOLDER_NOT_INDEPENDENT'); holders.add(r.holderId);
      if (!verifyObj(V4_DOMAINS.PARTICIPANT_POP, { accountId: s.accountId, chainId: s.chainId, gcaseId: b.gcaseId, id: r.id, holderId: r.holderId, publicKey: r.publicKey }, r.pop, r.publicKey)) fail('REPLACEMENT_POP_INVALID', r.id);
      reps.push({ id: r.id, holderId: r.holderId, publicKey: r.publicKey });
    }
    // electorate: every active guardian and identity verifier, minus the accused, minus anyone previously disqualified
    const electorate = [...Object.keys(s.guardians).filter(g => s.guardians[g].status === 'active'), ...Object.keys(s.idvs)]
      .filter(v => !b.accused.includes(v) && !s.v4.disqualified[v]).sort();
    if (!electorate.length) fail('EMERGENCY_ELECTORATE_EMPTY', 'unanimous consent of the empty set is never valid; the condition is reported, authority unchanged');
    const g = { gcaseId: b.gcaseId, procedure: b.procedure, accused: [...b.accused], ground: b.ground, replacements: reps, electorate, ballots: {}, openedAt: at,
      voteDeadline: at + Number(s.v4.config.govVoteMs), executeAfter: null, state: 'VOTING', dispatched: [], openNonce: a.nonce, owners };
    g.digest = gcaseDigestOf(s, g);
    s.v4.gcase = g;
    fx.push({ type: 'GOV_CASE_OPENED', gcaseId: g.gcaseId, procedure: g.procedure, accused: g.accused, electorate: String(electorate.length), notifyAll: Object.keys(s.channels) });
  },
  GOV_DISPATCH(s, a, tr, at, fx) {
    const g = gcaseMatch(s, a); body(a, ['gcaseId', 'gcaseDigest', 'channels']);
    exactFields(tr.attestation ?? {}, ['notifierSig'], [], 'DISPATCH_ATTESTATION');
    if (!edVerifyDigest(V3_DOMAINS.DISPATCH, actionDigest(a), tr.attestation.notifierSig, s.serviceKeys.notifier)) fail('DISPATCH_SIGNATURE');
    if ([...a.body.channels].sort().join(',') !== Object.keys(s.channels).sort().join(',')) fail('DISPATCH_INCOMPLETE');
    g.dispatched = [...a.body.channels].sort();
    fx.push({ type: 'GOV_NOTIFIED', channels: g.dispatched.length });
  },
  GOV_BALLOT(s, a, tr, at, fx) {
    const g = gcaseMatch(s, a); body(a, ['gcaseId', 'gcaseDigest', 'voterId', 'commitment', 'sealed']);
    if (tr.approvals?.length || tr.guardianApprovals) fail('BALLOT_MIXED_EVIDENCE');
    if (g.state !== 'VOTING' || at >= g.voteDeadline) fail('BALLOT_VOTING_CLOSED');
    const v = a.body.voterId;
    if (!g.electorate.includes(v)) fail('BALLOT_VOTER_NOT_ELIGIBLE', v);
    if (g.ballots[v]) fail('BALLOT_DUPLICATE_VOTE');
    if (!/^[0-9a-f]{64}$/.test(a.body.commitment)) fail('BALLOT_COMMITMENT');
    const sealed = exactFields(a.body.sealed, ['epk', 'iv', 'ct'], [], 'BALLOT_SEALED');
    if (!/^[A-Za-z0-9_-]{43}$/.test(sealed.epk) || !/^[A-Za-z0-9_-]{16}$/.test(sealed.iv) || !/^[A-Za-z0-9_-]{40,400}$/.test(sealed.ct)) fail('BALLOT_SEALED_FORMAT');
    const pub = (s.guardians[v]?.status === 'active' ? s.guardians[v].publicKey : null) ?? s.idvs[v]?.publicKey;
    exactFields(tr.attestation ?? {}, ['voterSig'], [], 'BALLOT_ATTESTATION');
    if (!pub || !verifyBallotEligibility(a.body, tr.attestation.voterSig, pub)) fail('BALLOT_ELIGIBILITY_SIGNATURE');
    g.ballots[v] = { gcaseId: g.gcaseId, gcaseDigest: g.digest, voterId: v, commitment: a.body.commitment, sealed: { ...sealed } };
    fx.push({ type: 'GOV_BALLOT_RECORDED', gcaseId: g.gcaseId, ballots: String(Object.keys(g.ballots).length), electorate: String(g.electorate.length) });
  },
  GOV_TALLY(s, a, tr, at, fx) {
    const g = gcaseMatch(s, a); body(a, ['gcaseId', 'gcaseDigest', 'result', 'ballots', 'electorate', 'openings']);
    if (g.state !== 'VOTING') fail('TALLY_NOT_VOTING');
    exactFields(tr.attestation ?? {}, ['tallySig'], [], 'TALLY_ATTESTATION');
    if (!verifyObj(V4_DOMAINS.TALLY, a.body, tr.attestation.tallySig, s.v4.tally.sigKey)) fail('TALLY_SIGNATURE');
    const nb = Object.keys(g.ballots).length;
    if (a.body.ballots !== String(nb) || a.body.electorate !== String(g.electorate.length)) fail('TALLY_COUNTS_MISMATCH');
    if (a.body.result === 'APPROVED') {
      // verifiable without trusting the tally: every eligible voter voted and every commitment opens to APPROVE
      if (!g.electorate.length || !g.electorate.every(v => g.ballots[v])) fail('TALLY_APPROVAL_INCOMPLETE');
      if (!Array.isArray(a.body.openings) || a.body.openings.length !== g.electorate.length) fail('TALLY_OPENINGS_MISSING');
      const seen = new Set();
      for (const o of a.body.openings) {
        exactFields(o, ['voterId', 'choice', 'salt'], [], 'TALLY_OPENING');
        if (seen.has(o.voterId) || !g.ballots[o.voterId]) fail('TALLY_OPENING_VOTER'); seen.add(o.voterId);
        if (o.choice !== 'APPROVE') fail('TALLY_APPROVAL_NOT_UNANIMOUS');
        if (commitmentOf({ gcaseDigest: g.digest, voterId: o.voterId, choice: o.choice, salt: o.salt }) !== g.ballots[o.voterId].commitment) fail('TALLY_OPENING_MISMATCH', o.voterId);
      }
      g.state = 'APPROVED'; g.approvedAt = at; g.executeAfter = at + Number(s.v4.config.govDelayMs);
      fx.push({ type: 'GOV_APPROVED', gcaseId: g.gcaseId, executeAfter: iso(g.executeAfter) });
    } else if (a.body.result === 'REJECTED') {
      if (a.body.openings.length) fail('TALLY_REJECTION_MUST_NOT_REVEAL_BALLOTS');
      if (!(g.electorate.every(v => g.ballots[v]) || at >= g.voteDeadline)) fail('TALLY_PREMATURE');
      closeGcase(s, g, 'REJECTED', at, fx);
    } else fail('TALLY_RESULT');
  },
  GOV_EXPIRE(s, a, tr, at, fx) {
    const g = gcaseMatch(s, a); body(a, ['gcaseId', 'gcaseDigest']);
    if (tr.approvals?.length || tr.attestation || tr.guardianApprovals) fail('EXPIRE_TAKES_NO_EVIDENCE');
    const ok = (g.state === 'VOTING' && at >= g.voteDeadline) || (g.state === 'APPROVED' && at >= g.executeAfter + Number(s.v4.config.completionGraceMs));
    if (!ok) fail('GOV_NOT_EXPIRED');
    closeGcase(s, g, 'EXPIRED', at, fx);
  },
  GOV_CASE_CANCEL(s, a, tr, at, fx) {
    const g = gcaseMatch(s, a); body(a, ['gcaseId', 'gcaseDigest']);
    if ((tr.approvals ?? []).length === 1 && s.v4.orcs[tr.approvals[0].credId]) verifyOrcApproval(s, a, tr.approvals[0], at);
    else verifyOwnerQuorum(s, a, tr.approvals, at);
    closeGcase(s, g, 'CANCELLED', at, fx);
  },
  GOV_CASE_EXECUTE(s, a, tr, at, fx) {
    const g = gcaseMatch(s, a); body(a, ['gcaseId', 'gcaseDigest']);
    if (tr.approvals?.length || tr.attestation || tr.guardianApprovals) fail('EXECUTE_TAKES_NO_EVIDENCE');
    if (g.state !== 'APPROVED') fail('GOV_NOT_APPROVED', g.state);
    if (at < g.executeAfter) fail('GOV_SECURITY_DELAY_OPEN');
    if (g.dispatched.join(',') !== Object.keys(s.channels).sort().join(',')) fail('GOV_NOTIFICATIONS_INCOMPLETE');
    noCase(s, 'RECOVERY_CASE_OPEN'); noLockdown(s);
    const guardianProc = g.procedure === 'GUARDIAN_EMERGENCY_REPLACE';
    const before = guardianProc ? Object.values(s.guardians).filter(x => x.status === 'active').length : Object.keys(s.idvs).length;
    g.accused.forEach((x, i) => {
      const r = g.replacements[i];
      if (guardianProc) { if (s.guardians[x]?.status !== 'active') fail('GOV_ACCUSED_NO_LONGER_ACTIVE'); s.guardians[x].status = 'removed'; s.guardians[r.id] = { publicKey: r.publicKey, holderId: r.holderId, status: 'active' }; }
      else { if (!s.idvs[x]) fail('GOV_ACCUSED_NO_LONGER_ACTIVE'); s.v4.removedIdvs[x] = { ...s.idvs[x], removedAt: String(at) }; delete s.idvs[x]; s.idvs[r.id] = { publicKey: r.publicKey, holderId: r.holderId, status: 'active' }; }
      if (g.ground === 'COMPROMISE' || g.ground === 'MISCONDUCT') s.v4.disqualified[x] = { ground: g.ground, gcaseId: g.gcaseId, at: String(at) };
      else s.v4.retired[x] = { ground: g.ground, gcaseId: g.gcaseId, at: String(at) };
    });
    const after = guardianProc ? Object.values(s.guardians).filter(x => x.status === 'active').length : Object.keys(s.idvs).length;
    if (after !== before) fail('QUORUM_FLOOR_CHANGED');
    if (guardianProc && Number(s.config.reconGuardianQuorum) > after) fail('GUARDIAN_QUORUM_BELOW_FLOOR');
    if (!guardianProc && Number(s.config.reconIdentityAttestations) > after) fail('IDV_QUORUM_BELOW_FLOOR');
    bumpEpoch(s, fx, 'participant replacement');
    fx.push({ type: 'GOV_EXECUTED', gcaseId: g.gcaseId, removed: g.accused, added: g.replacements.map(r => r.id) });
    closeGcase(s, g, 'EXECUTED', at, fx);
  },
  PARTICIPANT_LIVENESS_PING(s, a, tr, at, fx) {
    body(a, ['participantId']);
    const pid = a.body.participantId; if (!(s.guardians[pid]?.status === 'active' || s.idvs[pid])) fail('LIVENESS_UNKNOWN_PARTICIPANT');
    exactFields(tr.attestation ?? {}, ['notifierSig'], [], 'LIVENESS_ATTESTATION');
    if (!edVerifyDigest(V3_DOMAINS.DISPATCH, actionDigest(a), tr.attestation.notifierSig, s.serviceKeys.notifier)) fail('LIVENESS_SIGNATURE');
    const lv = s.v4.liveness[pid];
    if (lv && Number(lv.pingAt) > Number(lv.pongAt)) fail('LIVENESS_PING_PENDING'); // an open ping is never reset (no extension games)
    s.v4.liveness[pid] = { pingAt: String(at), pongAt: lv?.pongAt ?? '0' };
    fx.push({ type: 'LIVENESS_PING', participantId: pid });
  },
  PARTICIPANT_LIVENESS_PONG(s, a, tr, at, fx) {
    body(a, ['participantId']);
    const pid = a.body.participantId; const pub = s.guardians[pid]?.status === 'active' ? s.guardians[pid].publicKey : s.idvs[pid]?.publicKey;
    if (!pub) fail('LIVENESS_UNKNOWN_PARTICIPANT');
    exactFields(tr.attestation ?? {}, ['participantSig'], [], 'LIVENESS_ATTESTATION');
    if (!verifyDigest(V4_DOMAINS.LIVENESS, actionDigest(a), tr.attestation.participantSig, pub)) fail('LIVENESS_SIGNATURE');
    s.v4.liveness[pid] = { pingAt: s.v4.liveness[pid]?.pingAt ?? '0', pongAt: String(at) };
    fx.push({ type: 'LIVENESS_PONG', participantId: pid });
  },
  GUARDIAN_ROTATE(s, a, tr, at, fx) {
    // ordinary rotation / voluntary withdrawal: the outgoing guardian consents, the owner governance quorum approves
    noCase(s); noLockdown(s); if (s.v4.gcase) fail('GOVERNANCE_CASE_OPEN');
    body(a, ['guardianId', 'replacement', 'ground']);
    if (!['ROTATION', 'WITHDRAWAL'].includes(a.body.ground)) fail('GUARDIAN_ROTATE_GROUND');
    const gid = a.body.guardianId, g = s.guardians[gid]; if (!g || g.status !== 'active') fail('GUARDIAN_UNKNOWN');
    const r = verifyApprovals(s, a, tr.approvals, 'AMEND_MATRIX', { at }); applySignCounts(s, r.signCounts);
    exactFields(tr.attestation ?? {}, ['withdrawalSig'], [], 'GUARDIAN_ROTATE_ATTESTATION');
    if (!verifyDigest(V4_DOMAINS.WITHDRAWAL, actionDigest(a), tr.attestation.withdrawalSig, g.publicKey)) fail('GUARDIAN_WITHDRAWAL_SIGNATURE');
    const rep = exactFields(a.body.replacement, ['id', 'holderId', 'publicKey', 'pop'], [], 'GOV_REPLACEMENT');
    id(rep.id, 'replacementId');
    if (s.guardians[rep.id] || s.idvs[rep.id] || s.creds[rep.id]) fail('REPLACEMENT_ID_IN_USE');
    if (allParticipantKeys(s).has(rep.publicKey)) fail('REPLACEMENT_KEY_NOT_INDEPENDENT');
    if (allHolders(s).has(rep.holderId)) fail('REPLACEMENT_HOLDER_NOT_INDEPENDENT');
    if (!verifyObj(V4_DOMAINS.PARTICIPANT_POP, { accountId: s.accountId, chainId: s.chainId, gcaseId: '-', id: rep.id, holderId: rep.holderId, publicKey: rep.publicKey }, rep.pop, rep.publicKey)) fail('REPLACEMENT_POP_INVALID');
    g.status = 'retired'; s.guardians[rep.id] = { publicKey: rep.publicKey, holderId: rep.holderId, status: 'active' };
    s.v4.retired[gid] = { ground: a.body.ground, gcaseId: '-', at: String(at) };
    bumpEpoch(s, fx, 'guardian rotation');
    fx.push({ type: 'GUARDIAN_ROTATED', from: gid, to: rep.id });
  },
};

/**
 * F-V4-01: V3 lets a SUSPENDED survivor consent (allowSuspendedSelf), but its quorum counting excludes the subject, so
 * that consent never counted: any single stolen key could suspend every other key and make the owner's recovery
 * impossible. Here a suspended survivor's own single-signer consent counts, verified exactly like any consent
 * (AuthorizationIntent, UV, one-time challenge, confirmation level). Returns false when the V3 path applies.
 */
function suspendedSurvivorConsent(s, a, tr, at, fx) {
  const cs = s.case; const aps = tr.approvals ?? [];
  if (!cs || aps.length !== 1 || tr.guardianApprovals || tr.attestation) return false;
  const c = s.creds[aps[0]?.credId];
  if (!c || c.status !== 'suspended' || !V3.survivors(s, cs, at).includes(c.credId)) return false;
  body(a, ['caseId', 'caseDigest']);
  if (a.body.caseId !== cs.caseId || a.body.caseDigest !== cs.digest) fail('RECOVERY_CASE_MISMATCH');
  if (!('intent' in aps[0])) fail('AUTHORIZATION_INTENT_REQUIRED', a.type);
  const r = verifyIntentApproval(s, a, aps[0], c, at, { requireUV: true });
  if (r.signCount !== null && r.signCount !== undefined) c.signCount = r.signCount;
  cs.consents[c.credId] = true;
  fx.push({ type: 'RECOVERY_CONSENT', credId: c.credId, suspended: true });
  return true;
}
/** F-V4-01: suspensions and an owner-source freeze imposed only by credentials this completed recovery revokes are lifted. */
function liftProtectiveActionsOfLost(s, lost, fx, at) {
  const L = new Set(lost);
  for (const [cid, by] of Object.entries(s.v4.suspendedBy)) {
    const c = s.creds[cid];
    if (c && c.status === 'suspended' && by.length && by.every(x => L.has(x))) { c.status = 'active'; delete c.suspendedAt; fx.push({ type: 'SUSPENSION_LIFTED', credId: cid, by }); }
    if (!c || c.status !== 'suspended') delete s.v4.suspendedBy[cid];
  }
  // freeze: drop the holds attributable ONLY to revoked keys; lift the freeze only when no other hold remains, it is an
  // owner-source freeze, and it is not a supervisor breach freeze (which lifts only with its trusted repair certificate)
  if (!s.freeze.active) return;
  const before = s.v4.freezeHolds.length;
  const dropped = s.v4.freezeHolds.filter(h => h.by.length && h.by.every(x => L.has(x)));
  s.v4.freezeHolds = s.v4.freezeHolds.filter(h => !dropped.includes(h));
  for (const h of dropped) fx.push({ type: 'FREEZE_HOLD_DROPPED', freezeId: h.freezeId, by: h.by });
  if (before && dropped.length && !s.v4.freezeHolds.length && s.freeze.source === 'owner' && !s.freeze.requiresRepair) {
    fx.push({ type: 'FREEZE_LIFTED', freezeId: s.freeze.freezeId, by: dropped.flatMap(h => h.by) });
    s.freeze = { active: false, freezeId: null, requiresRepair: false, source: null, at };
  }
}
function gcaseMatch(s, a) { const g = s.v4.gcase; if (!g) fail('NO_GOVERNANCE_CASE'); if (a.body?.gcaseId !== g.gcaseId || a.body?.gcaseDigest !== g.digest) fail('GOVERNANCE_CASE_MISMATCH'); return g; }
function closeGcase(s, g, outcome, at, fx) {
  s.v4.gcaseHistory.push({ gcaseId: g.gcaseId, procedure: g.procedure, accused: g.accused, ground: g.ground, outcome, openedAt: g.openedAt, closedAt: at, ballots: Object.keys(g.ballots).length, electorate: g.electorate.length });
  s.v4.gcase = null;
  fx.push({ type: 'GOV_CASE_CLOSED', gcaseId: g.gcaseId, outcome });
}

/** Precommitted evidence rules. Returns nothing; fails if the accusation is not independently established. */
function proveGround(s, b, x, member, kind, at) {
  const ev = b.evidence.filter(e => e && e.subjectId === x);
  if (b.ground === 'UNAVAILABLE') {
    const lv = s.v4.liveness[x];
    if (!lv || !(Number(lv.pingAt) > Number(lv.pongAt)) || at - Number(lv.pingAt) < Number(s.v4.config.unavailabilityMs)) fail('UNAVAILABILITY_NOT_ESTABLISHED', x);
    return;
  }
  if (b.ground === 'WITHDRAWAL') {
    const w = ev.find(e => e.kind === 'WITHDRAWAL');
    if (!w) fail('WITHDRAWAL_NOT_SIGNED', x);
    exactFields(w, ['kind', 'subjectId', 'sig'], [], 'WITHDRAWAL_EVIDENCE');
    if (!verifyObj(V4_DOMAINS.WITHDRAWAL, { v: WITHDRAWAL_V, accountId: s.accountId, chainId: s.chainId, gcaseId: b.gcaseId, subjectId: x, subjectKey: member.publicKey }, w.sig, member.publicKey)) fail('WITHDRAWAL_SIGNATURE', x);
    return;
  }
  // COMPROMISE: a cryptographic equivocation proof by the member's own key, or the adjudicator quorum.
  if (b.ground === 'COMPROMISE' && kind === 'guardian') {
    const q = ev.find(e => e.kind === 'EQUIVOCATION');
    if (q) {
      exactFields(q, ['kind', 'subjectId', 'actionDigest', 'sigApprove', 'sigObject'], [], 'EQUIVOCATION_EVIDENCE');
      if (!/^[0-9a-f]{64}$/.test(q.actionDigest)) fail('EQUIVOCATION_DIGEST');
      const okA = edVerifyStatement(V3_DOMAINS.GUARDIAN, { actionDigest: q.actionDigest, decision: 'APPROVE' }, q.sigApprove, member.publicKey);
      const okO = edVerifyStatement(V3_DOMAINS.GUARDIAN, { actionDigest: q.actionDigest, decision: 'OBJECT' }, q.sigObject, member.publicKey);
      if (okA && okO) return;
      fail('EQUIVOCATION_PROOF_INVALID', x);
    }
  }
  const finding = b.ground === 'COMPROMISE' ? 'COMPROMISED' : 'MISCONDUCT';
  const ok = new Set();
  for (const e of ev.filter(e => e.kind === 'VERDICT')) {
    exactFields(e, ['kind', 'subjectId', 'adjudicatorId', 'statement', 'sig'], [], 'VERDICT_EVIDENCE');
    const adj = s.v4.adjudicators[e.adjudicatorId]; if (!adj || adj.status !== 'active') fail('VERDICT_UNKNOWN_ADJUDICATOR');
    const st = exactFields(e.statement, ['v', 'accountId', 'chainId', 'subjectKind', 'subjectId', 'subjectKey', 'finding', 'evidenceRef', 'issuedAt', 'expiresAt'], [], 'VERDICT_STATEMENT');
    if (st.v !== VERDICT_V || st.accountId !== s.accountId || st.chainId !== s.chainId) fail('VERDICT_WRONG_ACCOUNT');
    if (st.subjectKind !== kind || st.subjectId !== x || st.subjectKey !== member.publicKey) fail('VERDICT_WRONG_SUBJECT', x);
    if (st.finding !== finding) fail('VERDICT_WRONG_FINDING', st.finding);
    const ia = isoMs(st.issuedAt, 'issuedAt'), ea = isoMs(st.expiresAt, 'expiresAt');
    if (ia > at + Number(s.config.skewMs) || at >= ea || ea - ia > 30 * D) fail('VERDICT_NOT_CURRENT');
    if (!verifyObj(V4_DOMAINS.VERDICT, st, e.sig, adj.publicKey)) fail('VERDICT_SIGNATURE', e.adjudicatorId);
    ok.add(adj.holderId);
  }
  if (ok.size < Number(s.v4.config.adjudicatorQuorum)) fail('ACCUSATION_NOT_ESTABLISHED', `${x}: ${ok.size}/${s.v4.config.adjudicatorQuorum} independent verdicts`);
}

const V3_PASSTHROUGH = new Set(['AMEND_PURPOSE', 'AMEND_MATRIX', 'REVOKE', 'REPLACE_VACANT', 'RATIFY_BASELINE',
  'RECOVERY_DISPATCH', 'RECOVERY_ACK', 'RECOVERY_IDENTITY', 'RECOVERY_OFFICIAL', 'RECOVERY_GUARDIAN', 'RECOVERY_OBJECT', 'RECOVERY_WITHDRAW', 'RECOVERY_OVERRIDE', 'RECOVERY_CANCEL']);
export const ACTION_TYPES = Object.freeze([...V3_PASSTHROUGH, ...Object.keys(HANDLERS4)]);

/** Pure V4 transition. Same envelope rules as V3 plus the V4 post-conditions and bookkeeping. */
export function applyTransition(state0, tr) {
  if (state0.protocol !== PROTOCOL) fail('PROTOCOL_MISMATCH');
  exactFields(tr, ['v', 'seq', 'prev', 'at', 'action'], ['approvals', 'guardianApprovals', 'attestation'], 'TRANSITION_FIELDS');
  if (tr.v !== TR_V) fail('TRANSITION_VERSION');
  if (tr.seq !== String(state0.seq + 1)) fail('TRANSITION_SEQ', `${tr.seq} vs ${state0.seq + 1}`);
  if (tr.prev !== state0.head) fail('TRANSITION_FORK');
  const at = isoMs(tr.at, 'at');
  if (at < state0.lastAt) fail('TRANSITION_TIME_BACKWARDS');
  const s = clone(state0); const a = tr.action;
  checkActionHeader(s, a, at);
  const own4 = typeof a.type === 'string' && Object.hasOwn(HANDLERS4, a.type) ? HANDLERS4[a.type] : null;
  const own3 = typeof a.type === 'string' && V3_PASSTHROUGH.has(a.type) && Object.hasOwn(H3, a.type) ? H3[a.type] : null;
  const Hd = own4 ?? own3;
  if (!Hd) fail('TRANSITION_TYPE_UNKNOWN', a.type);
  const fx = [];
  const prevCase = s.case ? { caseId: s.case.caseId, subjectHolderId: s.case.subjectHolderId, planKeys: s.case.plan.map(p => p.publicKey) } : null;
  const hadLockdown = s.lockdown.active;
  s.v4.tx = { levels: [] };
  Hd(s, a, tr, at, fx);
  if (CRITICAL.has(a.type) && !s.v4.tx.levels.some(x => TRUSTED_LEVELS.has(x.level))) fail('TRUSTED_CONFIRMATION_REQUIRED', `${a.type}: software-only confirmation is lower assurance and not accepted`);
  if (s.v4.tx.levels.length) fx.push({ type: 'CONFIRMATION_ASSURANCE', levels: s.v4.tx.levels.map(x => `${x.credId}:${x.level}`) });
  delete s.v4.tx;
  // lockdown budget: repeated false claims cannot keep the owner's payments locked indefinitely
  if (!hadLockdown && s.lockdown.active) {
    const attested = s.case?.v4?.ownerAttested;
    if (!attested && lockdownUsed30d(s, at) >= Number(s.v4.config.lockdownBudgetMs)) {
      s.lockdown = { active: false, caseId: null };
      for (let i = fx.length - 1; i >= 0; i--) if (fx[i].type === 'EMERGENCY_LOCKDOWN') fx.splice(i, 1);
      fx.push({ type: 'LOCKDOWN_BUDGET_EXHAUSTED', note: 'case continues without lockdown; reconstitution still needs ORC authorization' });
    } else s.v4.lockdowns.push({ caseId: s.lockdown.caseId, start: at, end: null });
  }
  if (hadLockdown && !s.lockdown.active) { const l = s.v4.lockdowns.at(-1); if (l && l.end === null) l.end = at; }
  if (prevCase && s.case?.caseId !== prevCase.caseId) {
    const h = s.caseHistory.at(-1);
    s.v4.claims.push({ caseId: prevCase.caseId, subjectHolderId: prevCase.subjectHolderId, outcome: h.outcome, closedAt: at });
    if (FAILED_OUTCOMES.has(h.outcome)) for (const k of prevCase.planKeys) s.v4.burnedPlanKeys[keyDigest(k)] = prevCase.caseId;
  }
  s.usedNonces[a.nonce] = s.seq + 1;
  s.seq += 1; s.lastAt = at; s.transitions += 1;
  s.head = transitionHash(state0.head, tr);
  return { state: s, effects: fx };
}

export function replayChain(genesis, transitions, { pinnedChainId }) {
  let st = genesisState(genesis, { pinnedChainId }); const log = [];
  for (const tr of transitions) { const r = applyTransition(st, tr); st = r.state; log.push({ seq: tr.seq, type: tr.action.type, effects: r.effects }); }
  return { state: st, log };
}
export function rootView(st) {
  return { ...V3.rootView(st), protocol: st.protocol,
    caseDeadline: st.case?.v4 ? iso(st.case.v4.deadline) : null, ownerAuthorized: !!st.case?.v4?.ownerAuth,
    gcaseId: st.v4.gcase?.gcaseId ?? null, gcaseState: st.v4.gcase?.state ?? null };
}
export { transitionHash, LEVELS };
