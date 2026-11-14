// V5 Command Statement: the canonical object a credential (or the ORC) signs for ANY V5 authority-bearing command.
// It extends the V4 AuthorizationIntent (which already binds protocol, account, chain, Purpose, matrix, action digest,
// parameter digest, Epoch, Root sequence + authority-state digest, case, new keys, summary, issuer, 256-bit one-time
// challenge, session and lifetime) with the fields V4 left implicit: signing credential ROLE and principal, the exact
// AFFECTED RESOURCES, the FINANCIAL SCOPE (recipients, assets, limits), the permitted USAGE COUNT, the REQUIRED
// CONFIRMATION LEVEL and the action's own expiry. The Root rebuilds the expected statement from its own state + the
// submitted action + the challenge grant and requires byte-for-byte canonical equality.
import { fail, exactFields, isoMs, canon, iso } from '../../v3/common/canon.mjs';
import { verifyAssertion } from '../../v3/webauthn/verify.mjs';
import { actionDigest } from '../../v3/root/chain.mjs';
import { GRANT_V, GRANT_FIELDS, LEVELS, TRUSTED_LEVELS, authorityDigest } from '../../v4/intent/intent.mjs';
import { V4_DOMAINS, verifyObj } from '../../v4/common/v4.mjs';
import { PROTOCOL5, V5_DOMAINS, d5, d5hex, verifyDigest5 } from '../common/v5.mjs';
import { scopeKey } from './holds.mjs';

export const COMMAND_V = 'safebox.v5.command';
export const COMMAND_FIELDS = ['v', 'protocol', 'accountId', 'chainId', 'credId', 'role', 'principal', 'commandType', 'actionDigest', 'paramsDigest', 'purposeId', 'purposeVersion',
  'matrixVersion', 'epoch', 'rootSeq', 'authorityDigest', 'affectedResources', 'caseRef', 'financialScope', 'operationId', 'usageLimit', 'requiredLevel', 'summaryDigest',
  'issuer', 'challengeNonce', 'sessionId', 'issuedAt', 'notBefore', 'expiresAt', 'actionExpiresAt'];

/** Confirmation level each V5 command requires. TRUSTED = trusted display or protected confirmation (simulated). */
// ANY_UV: user verification on any enrolled authenticator. TRUSTED: EVERY signer of this command must use a trusted
// confirmation path (protected confirmation / trusted display); the ORC is its own offline factor and is exempt.
// ONE_TRUSTED: multi-signer commands whose handler requires at least one trusted confirmation among the signers.
export const REQUIRED_LEVEL = Object.freeze({
  FREEZE: 'ANY_UV', HOLD_CREATE: 'ANY_UV', SUSPEND: 'ANY_UV', HOLD_CONFIRM: 'ANY_UV', RECOVERY_OBJECT: 'ANY_UV', INCIDENT_REVIEW_FRAUD: 'ANY_UV',
  HOLD_RELEASE: 'ANY_UV', UNSUSPEND: 'ANY_UV', // release of CONFIRMED holds / incident freezes: the handler requires a trusted signer
  CONTEST_PROTECTIVE_HOLD: 'ONE_TRUSTED', INCIDENT_REVIEW_LEGITIMATE: 'ONE_TRUSTED',
  DELEGATION_GRANT: 'TRUSTED', DELEGATION_REVOKE: 'ANY_UV',
  RAPID_USE_REQUEST: 'ANY_UV', RAPID_USE_APPROVE: 'TRUSTED', RAPID_USE_REVOKE: 'ANY_UV',
});
export const requiredLevelOf = (a) => a.type === 'INCIDENT_REVIEW' ? REQUIRED_LEVEL['INCIDENT_REVIEW_' + (a.body?.verdict === 'LEGITIMATE' ? 'LEGITIMATE' : 'FRAUD')] : (REQUIRED_LEVEL[a.type] ?? 'TRUSTED');

/** V5 authority-state digest: the V4 digest plus every effective hold and the Rapid-Use grant set. */
export function authorityDigest5(s) {
  // the state is already normalized to the transition time (holds.normalizeHolds), so status alone is authoritative
  return d5hex(V5_DOMAINS.AUTH_STATE, { v4: authorityDigest(s), holds: Object.values(s.v5.holds).filter(h => h.status === 'ACTIVE').map(h => `${h.holdId}|${h.class}|${scopeKey(h.scope)}`).sort(),
    grants: Object.values(s.v5.rapid.grants).filter(g => g.status === 'ACTIVE').map(g => `${g.grantId}|${g.expiresAt}`).sort(),
    delegations: Object.values(s.v5.delegations).filter(d => d.status === 'ACTIVE').map(d => d.delegationId).sort() });
}

/** Exact resources a command acts on (bound into the statement, shown on the device). */
export function affectedResources(s, a) {
  const b = a.body ?? {}; const r = [];
  const add = (x) => r.push(String(x));
  switch (a.type) {
    case 'HOLD_CREATE': add(`scope:${b.scope?.kind}:${b.scope?.target}`); add(`class:${b.class}`); break;
    case 'SUSPEND': case 'UNSUSPEND': add(`credential:${b.credId}`); break;
    case 'HOLD_CONFIRM': case 'HOLD_RELEASE': { const h = s.v5.holds[b.holdId]; add(`hold:${b.holdId}`); if (h) add(`scope:${h.scope.kind}:${h.scope.target}`); break; }
    case 'CONTEST_PROTECTIVE_HOLD': for (const x of b.holdIds ?? []) add(`hold:${x}`); add(`revoke:${b.suspectCredId}`); break;
    case 'INCIDENT_REVIEW': add(`incident:${b.incidentId}`); add(`flow:${b.credId}`); add(`verdict:${b.verdict}`); break;
    case 'DELEGATION_GRANT': add(`delegation:${b.delegationId}`); add(`delegate-key:${b.delegateKey}`); break;
    case 'DELEGATION_REVOKE': add(`delegation:${b.delegationId}`); break;
    case 'RAPID_USE_REQUEST': for (const c of b.scope?.credIds ?? []) add(`credential:${c}`); for (const c of b.scope?.delegationIds ?? []) add(`delegation:${c}`); break;
    case 'RAPID_USE_APPROVE': { const q = s.v5.rapid.requests[b.requestId]; add(`rapid-request:${b.requestId}`); for (const c of q?.scope.credIds ?? []) add(`credential:${c}`); break; }
    case 'RAPID_USE_REVOKE': add(`rapid-grant:${b.grantId}`); break;
    case 'RECOVERY_OBJECT': add(`case:${b.caseId}`); break;
    default: add(`action:${a.type}`);
  }
  return r;
}
/** Financial scope a command touches. Rapid-Use and delegations bind the exact, UNCHANGED Purpose limits. */
export function financialScope(s, a) {
  const b = a.body ?? {};
  if (a.type === 'RAPID_USE_REQUEST' && b.scope) { const x = b.scope; return `recipients=${[...(x.recipients ?? [])].join('|')};asset=${x.asset};perPayment=${x.perPaymentMaxYocto};daily=${x.dailyLimitYocto};cumulative=${x.cumulativeLimitYocto};sessionCap=${x.sessionCapYocto}`; }
  if (a.type === 'RAPID_USE_APPROVE') { const q = s.v5.rapid.requests[b.requestId]; return q ? financialScope(s, { type: 'RAPID_USE_REQUEST', body: { scope: q.scope } }) : '-'; }
  if (a.type === 'DELEGATION_GRANT') return `recipients=${[...(b.recipients ?? [])].join('|')};assets=${[...(b.assets ?? [])].join('|')};perOp=${b.perOpMaxYocto};cumulative=${b.cumulativeMaxYocto};maxUses=${b.maxUses}`;
  return '-';
}
export const caseRefOf = (a) => String(a.body?.caseId ?? a.body?.requestId ?? a.body?.grantId ?? a.body?.incidentId ?? a.body?.holdId ?? '-');

/** Deterministic, Root-derived summary (what the trusted display / protected confirmation shows). */
export function commandSummary(s, a, cred) {
  const lines = [`SafeBox V5 - ${a.type}`, `Account: ${s.accountId}`, `Signing credential: ${cred.credId} (${cred.role})`];
  for (const r of affectedResources(s, a)) lines.push(`Affects: ${r}`);
  const f = financialScope(s, a); if (f !== '-') lines.push(`Financial scope (unchanged Purpose limits): ${f}`);
  if (a.type === 'RAPID_USE_REQUEST') lines.push(`Duration: ${Number(a.body.durationMs) / 60_000} min (max 24 h, never renews)`, `Explanation: ${String(a.body.explanation).replace(/[^\x20-\x7e]/g, '?').slice(0, 120)}`);
  if (a.type === 'RAPID_USE_APPROVE') { const q = s.v5.rapid.requests[a.body.requestId]; if (q) lines.push(`Duration: ${Number(q.durationMs) / 60_000} min`, `Explanation: ${String(q.explanation).replace(/[^\x20-\x7e]/g, '?')}`, `Decision: ${a.body.decision}`); }
  lines.push('Purpose, recipients and spending limits are NOT changed by this command.', `This approval authorizes exactly this ${a.type} once and nothing else.`);
  return lines.join('\n');
}

export function buildCommand(s, a, g, cred, { rootSeq = s.seq } = {}) {
  const text = commandSummary(s, a, cred);
  return { text, statement: {
    v: COMMAND_V, protocol: PROTOCOL5, accountId: s.accountId, chainId: s.chainId, credId: cred.credId, role: cred.role, principal: cred.holderId,
    commandType: a.type, actionDigest: actionDigest(a).toString('hex'), paramsDigest: d5hex(V5_DOMAINS.COMMAND, { params: a.body ?? {} }),
    purposeId: s.purpose.purposeId, purposeVersion: s.purpose.version, matrixVersion: s.matrix.version, epoch: String(s.epoch), rootSeq: String(rootSeq),
    authorityDigest: authorityDigest5(s), affectedResources: affectedResources(s, a), caseRef: caseRefOf(a), financialScope: financialScope(s, a),
    operationId: a.nonce, usageLimit: '1', requiredLevel: requiredLevelOf(a), summaryDigest: d5hex(V5_DOMAINS.SUMMARY, { text: text.split('\n') }),
    issuer: g.issuer, challengeNonce: g.challengeNonce, sessionId: g.sessionId, issuedAt: g.issuedAt, notBefore: g.notBefore, expiresAt: g.expiresAt, actionExpiresAt: a.expiresAt,
  } };
}
export const commandDigest = (st) => d5(V5_DOMAINS.COMMAND, st);

/**
 * Resolve the signing party: an owner credential (any live status — callers decide whether a suspended key may act)
 * or an ORC. Returns { credId, role, holderId, kind, publicKey?, webauthn?, signCount?, isOrc }.
 */
export function partyOf(s, credId) {
  if (s.v4.orcs[credId]) { const o = s.v4.orcs[credId]; if (o.status !== 'active') fail('ORC_UNKNOWN_OR_INACTIVE'); return { credId, role: 'ORC', holderId: o.holderId, kind: 'ed25519', publicKey: o.publicKey, isOrc: true }; }
  const c = s.creds[credId]; if (!c) fail('APPROVAL_UNKNOWN_CREDENTIAL', credId);
  return { ...c, isOrc: false };
}

/**
 * Verifies ONE V5 command approval {credId, command, grant, webauthn|sig, apc?}. Consumes the one-time challenge in the
 * transition-local state. Returns { level, digestHex, party }.
 */
export function verifyCommand(s, a, ap, at, { allowSuspended = false } = {}) {
  exactFields(ap, ['credId', 'command', 'grant'], ['webauthn', 'sig', 'apc'], 'COMMAND_APPROVAL_FIELDS');
  const party = partyOf(s, ap.credId);
  if (!party.isOrc) {
    if (!(party.status === 'active' || (allowSuspended && party.status === 'suspended'))) fail('APPROVAL_CREDENTIAL_NOT_ACTIVE', `${party.credId}:${party.status}`);
    if (Number(party.provisionalUntil ?? 0) > at && !allowSuspended) fail('PROVISIONAL_CREDENTIAL');
  }
  // 1. challenge grant (V4 challenge service): genuine, bound to account / chain / action / credential, in window by ROOT time
  const gr = exactFields(ap.grant, ['statement', 'sig'], [], 'GRANT_FIELDS');
  const g = exactFields(gr.statement, GRANT_FIELDS, [], 'GRANT_STATEMENT_FIELDS');
  if (g.v !== GRANT_V || g.issuer !== s.v4.challengeIssuer.id) fail('CHALLENGE_ISSUER');
  if (!verifyObj(V4_DOMAINS.CHALLENGE, g, gr.sig, s.v4.challengeIssuer.publicKey)) fail('CHALLENGE_SIGNATURE');
  if (g.accountId !== s.accountId || g.chainId !== s.chainId) fail('CHALLENGE_WRONG_ACCOUNT');
  if (g.actionDigest !== actionDigest(a).toString('hex') || g.actionType !== a.type) fail('CHALLENGE_NOT_FOR_THIS_ACTION');
  if (g.credId !== ap.credId) fail('CHALLENGE_NOT_FOR_THIS_CREDENTIAL');
  if (!/^[0-9a-f]{64}$/.test(g.challengeNonce)) fail('CHALLENGE_NONCE_FORMAT');
  const ia = isoMs(g.issuedAt, 'issuedAt'), nb = isoMs(g.notBefore, 'notBefore'), ea = isoMs(g.expiresAt, 'expiresAt');
  if (!(ia <= nb && nb < ea) || ea - ia > Number(s.v4.config.challengeTtlMs)) fail('CHALLENGE_LIFETIME');
  if (ia > at + Number(s.config.skewMs)) fail('CHALLENGE_FROM_FUTURE');
  if (at < nb) fail('CHALLENGE_NOT_YET_VALID');
  if (at >= ea) fail('CHALLENGE_EXPIRED');
  if (s.v4.usedChallenges[g.challengeNonce] !== undefined) fail('CHALLENGE_ALREADY_CONSUMED');
  // 2. exact statement equality
  const st = exactFields(ap.command, COMMAND_FIELDS, [], 'COMMAND_FIELDS');
  if (typeof st.rootSeq !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(st.rootSeq) || Number(st.rootSeq) > s.seq) fail('COMMAND_ROOT_SEQ');
  const { statement: expected, text } = buildCommand(s, a, g, party, { rootSeq: st.rootSeq });
  if (canon(st) !== canon(expected)) fail('COMMAND_MISMATCH', COMMAND_FIELDS.filter(k => canon(st[k] ?? '') !== canon(expected[k] ?? '')).join(','));
  const dig = commandDigest(st);
  // 3. the credential signed THIS statement digest (passkey with UV, or Ed25519 hardware key)
  let level = LEVELS.SOFTWARE;
  if (party.kind === 'passkey') {
    if (!ap.webauthn || 'sig' in ap) fail('APPROVAL_KIND_MISMATCH');
    const r = verifyAssertion(ap.webauthn, { rp: s.rp, expectedChallenge: dig, credential: { ...party.webauthn, signCount: party.signCount }, requireUV: true });
    s.creds[party.credId].signCount = r.signCount;
  } else {
    if (typeof ap.sig !== 'string' || 'webauthn' in ap) fail('APPROVAL_KIND_MISMATCH');
    if (!verifyDigest5(V5_DOMAINS.COMMAND, dig, ap.sig, party.publicKey)) fail('APPROVAL_BAD_SIGNATURE', ap.credId);
    if (s.v4.displays[ap.credId] === 'TRUSTED_DISPLAY') level = LEVELS.TRUSTED_DISPLAY;
  }
  if ('apc' in ap) {
    const conf = s.v4.confirmers[ap.credId]; if (!conf) fail('NO_PROTECTED_CONFIRMATION_KEY_ENROLLED');
    const x = exactFields(ap.apc, ['sig'], [], 'APC_FIELDS');
    if (!verifyObj(V4_DOMAINS.CONFIRM, { prompt: text.split('\n'), extraData: dig.toString('hex') }, x.sig, conf.publicKey)) fail('PROTECTED_CONFIRMATION_INVALID');
    level = LEVELS.PROTECTED_CONFIRMATION;
  }
  if (st.requiredLevel === 'TRUSTED' && !party.isOrc && !TRUSTED_LEVELS.has(level)) fail('TRUSTED_CONFIRMATION_REQUIRED', `${a.type}: ${level}`);
  // 4. atomic single use (usageLimit '1'): the challenge nonce is consumed with the transition
  s.v4.usedChallenges[g.challengeNonce] = String(s.seq + 1);
  (s.v5tx ??= { levels: [] }).levels.push({ credId: ap.credId, level, digest: dig.toString('hex') });
  return { level, digestHex: dig.toString('hex'), party };
}
export { TRUSTED_LEVELS, LEVELS, iso };
