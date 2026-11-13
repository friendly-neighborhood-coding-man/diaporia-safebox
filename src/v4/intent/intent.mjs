// AuthorizationIntent: the canonical object an owner credential signs for a HIGH-RISK action.
// It binds protocol, account, chain, Purpose id/version, matrix version, action type, the exact action digest and a
// parameter digest, Epoch, Root sequence + authority-state digest (anti-stale), recovery case id, new-credential key
// digests, the digest of the deterministic authorization summary, the challenge issuer, a 256-bit one-time challenge
// nonce, a session id and UTC issue / not-before / expiry times. The Root REBUILDS the expected intent from its own
// state + the submitted action + the challenge grant, and requires byte-for-byte canonical equality, so the approved
// intent and the executed action cannot differ.
import { randomUUID } from 'node:crypto';
import { fail, exactFields, isoMs, iso, canon } from '../../v3/common/canon.mjs';
import { verifyAssertion } from '../../v3/webauthn/verify.mjs';
import { actionDigest } from '../../v3/root/chain.mjs';
import { PROTOCOL, V4_DOMAINS, d4, d4hex, nonce256, keyDigest, verifyObj, verifyDigest } from '../common/v4.mjs';
import { buildSummary, summaryDigestHex, renderText, renderScreen, screenDigestHex, SCREEN_REGION, RENDERER } from './summary.mjs';

export const INTENT_V = 'safebox.v4.intent';
export const GRANT_V = 'safebox.v4.challenge';
export const GRANT_FIELDS = ['v', 'issuer', 'accountId', 'chainId', 'actionType', 'actionDigest', 'credId', 'challengeNonce', 'sessionId', 'issuedAt', 'notBefore', 'expiresAt'];
export const INTENT_FIELDS = ['v', 'protocol', 'accountId', 'chainId', 'purposeId', 'purposeVersion', 'matrixVersion', 'actionType', 'actionDigest', 'paramsDigest', 'epoch',
  'rootSeq', 'authorityDigest', 'caseId', 'newKeyDigests', 'summaryDigest', 'issuer', 'credId', 'challengeNonce', 'sessionId', 'issuedAt', 'notBefore', 'expiresAt', 'screenDigest'];
export const LEVELS = Object.freeze({ TRUSTED_DISPLAY: 'TRUSTED_DISPLAY_SIM', PROTECTED_CONFIRMATION: 'PROTECTED_CONFIRMATION_SIM', SOFTWARE: 'SOFTWARE_UI_LOWER_ASSURANCE' });
export const TRUSTED_LEVELS = new Set([LEVELS.TRUSTED_DISPLAY, LEVELS.PROTECTED_CONFIRMATION]);

/** Digest of everything an approval must not outlive: epoch, credential/participant sets, matrix, purpose, cases, freeze. */
export function authorityDigest(s) {
  return d4hex(V4_DOMAINS.AUTH_STATE, {
    epoch: String(s.epoch), matrix: s.matrixDigest, purpose: s.purposeDigest,
    creds: Object.values(s.creds).map(c => `${c.credId}|${c.role}|${c.status}|${keyDigest(c.publicKey)}`).sort(),
    guardians: Object.entries(s.guardians).map(([k, g]) => `${k}|${g.status}|${keyDigest(g.publicKey)}`).sort(),
    idvs: Object.entries(s.idvs).map(([k, g]) => `${k}|${keyDigest(g.publicKey)}`).sort(),
    orcs: Object.entries(s.v4.orcs).map(([k, o]) => `${k}|${o.status}|${keyDigest(o.publicKey)}`).sort(),
    case: s.case ? s.case.digest : '-', gcase: s.v4.gcase ? s.v4.gcase.digest : '-',
    freeze: s.freeze.active ? 'frozen:' + s.freeze.freezeId : 'none', lockdown: s.lockdown.active ? 'lockdown:' + s.lockdown.caseId : 'none',
  });
}

/** Public keys a high-risk action would install (the person must see exactly these). */
export function newKeysOf(s, a) {
  const b = a.body ?? {}; const keys = [];
  const pk = (e) => e?.publicKey ?? (e?.registration ? 'webauthn-registration:' + e.registration.clientDataJSON : null);
  if (Array.isArray(b.plan)) b.plan.forEach(p => keys.push(pk(p)));
  if (b.newCredential) keys.push(pk(b.newCredential));
  if (b.newOrc) keys.push(b.newOrc.publicKey);
  if (b.replacement) keys.push(b.replacement.publicKey);
  if (Array.isArray(b.replacements)) b.replacements.forEach(r => keys.push(r?.publicKey));
  if (['RECOVERY_CONSENT', 'RECOVERY_OWNER_AUTHORIZE'].includes(a.type) && s.case && b.caseId === s.case.caseId) s.case.plan.forEach(p => keys.push(p.publicKey));
  return keys.map(k => keyDigest(String(k)));
}
export const caseIdOf = (s, a) => String(a.body?.caseId ?? a.body?.gcaseId ?? (a.type === 'GOV_CASE_CANCEL' ? s.v4.gcase?.gcaseId : null) ?? '-');

/** Builds the exact intent the Root expects for (state, action, grant). Also returns the summary it binds. */
export function buildIntent(s, a, g, { rootSeq = s.seq, screenDigest = '-' } = {}) {
  const summary = buildSummary(s, a, { expiresAt: g.expiresAt });
  const intent = {
    v: INTENT_V, protocol: PROTOCOL, accountId: s.accountId, chainId: s.chainId, purposeId: s.purpose.purposeId, purposeVersion: s.purpose.version,
    matrixVersion: s.matrix.version, actionType: a.type, actionDigest: actionDigest(a).toString('hex'), paramsDigest: d4hex(V4_DOMAINS.INTENT, { params: a.body ?? {} }),
    epoch: String(s.epoch), rootSeq: String(rootSeq), authorityDigest: authorityDigest(s), caseId: caseIdOf(s, a), newKeyDigests: newKeysOf(s, a),
    summaryDigest: summaryDigestHex(summary), issuer: g.issuer, credId: g.credId, challengeNonce: g.challengeNonce, sessionId: g.sessionId,
    issuedAt: g.issuedAt, notBefore: g.notBefore, expiresAt: g.expiresAt, screenDigest,
  };
  return { intent, summary };
}
export const intentDigest = (intent) => d4(V4_DOMAINS.INTENT, intent);

/**
 * Challenge service (its own trust domain): issues unpredictable, short-lived, action- and credential-bound challenges.
 * It authorizes nothing by itself; the Root checks its signature, the time window against the Root's own clock, and
 * consumes the nonce atomically with the transition.
 */
export class ChallengeService {
  constructor({ signer, now, ttlMs = 120_000, issuer = 'challenge-svc', maxPerCredPerHour = 40 }) {
    Object.assign(this, { signer, now, ttlMs, issuer, maxPerCredPerHour });
    this.issued = new Set(); this.recent = new Map(); this.count = 0;
  }
  issue({ accountId, chainId, actionType, actionDigestHex, credId }) {
    const t = this.now();
    const hist = (this.recent.get(credId) ?? []).filter(x => x > t - 3600_000);
    if (hist.length >= this.maxPerCredPerHour) fail('CHALLENGE_RATE_LIMIT', credId);
    hist.push(t); this.recent.set(credId, hist);
    let n; do { n = nonce256(); } while (this.issued.has(n));
    this.issued.add(n); this.count++;
    const statement = { v: GRANT_V, issuer: this.issuer, accountId, chainId, actionType: String(actionType), actionDigest: String(actionDigestHex), credId: String(credId),
      challengeNonce: n, sessionId: randomUUID(), issuedAt: iso(t), notBefore: iso(t), expiresAt: iso(t + this.ttlMs) };
    return { statement, sig: this.signer.signObj(V4_DOMAINS.CHALLENGE, statement) };
  }
}

/**
 * Verifies ONE high-risk approval {credId, intent, grant, webauthn|sig, apc?, screen?} for `credential` (a V3 credential
 * record or an ORC record). Consumes the challenge nonce in the (transition-local) state. Returns { uv, signCount, level }.
 */
export function verifyIntentApproval(s, a, ap, credential, at, { requireUV = true } = {}) {
  exactFields(ap, ['credId', 'intent', 'grant'], ['webauthn', 'sig', 'apc', 'screen'], 'INTENT_APPROVAL_FIELDS');
  const cfg = s.v4.config;
  // 1. challenge grant: genuine, bound to this account / chain / action / credential, inside its window by ROOT time
  const gr = exactFields(ap.grant, ['statement', 'sig'], [], 'GRANT_FIELDS');
  const g = exactFields(gr.statement, GRANT_FIELDS, [], 'GRANT_STATEMENT_FIELDS');
  if (g.v !== GRANT_V || g.issuer !== s.v4.challengeIssuer.id) fail('CHALLENGE_ISSUER');
  if (!verifyObj(V4_DOMAINS.CHALLENGE, g, gr.sig, s.v4.challengeIssuer.publicKey)) fail('CHALLENGE_SIGNATURE');
  if (g.accountId !== s.accountId || g.chainId !== s.chainId) fail('CHALLENGE_WRONG_ACCOUNT');
  const adHex = actionDigest(a).toString('hex');
  if (g.actionDigest !== adHex || g.actionType !== a.type) fail('CHALLENGE_NOT_FOR_THIS_ACTION');
  if (g.credId !== ap.credId) fail('CHALLENGE_NOT_FOR_THIS_CREDENTIAL');
  if (!/^[0-9a-f]{64}$/.test(g.challengeNonce)) fail('CHALLENGE_NONCE_FORMAT');
  const ia = isoMs(g.issuedAt, 'issuedAt'), nb = isoMs(g.notBefore, 'notBefore'), ea = isoMs(g.expiresAt, 'expiresAt');
  if (!(ia <= nb && nb < ea) || ea - ia > Number(cfg.challengeTtlMs)) fail('CHALLENGE_LIFETIME');
  if (ia > at + Number(s.config.skewMs)) fail('CHALLENGE_FROM_FUTURE');
  if (at < nb) fail('CHALLENGE_NOT_YET_VALID');
  if (at >= ea) fail('CHALLENGE_EXPIRED');
  if (s.v4.usedChallenges[g.challengeNonce] !== undefined) fail('CHALLENGE_ALREADY_CONSUMED');
  // 2. the intent must be EXACTLY what the Root derives from its own state + this action + this grant
  const it = exactFields(ap.intent, INTENT_FIELDS, [], 'INTENT_FIELDS');
  if (typeof it.rootSeq !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(it.rootSeq) || Number(it.rootSeq) > s.seq) fail('INTENT_ROOT_SEQ');
  if (typeof it.screenDigest !== 'string' || !/^(-|[0-9a-f]{64})$/.test(it.screenDigest)) fail('INTENT_SCREEN_DIGEST');
  const { intent: expected, summary } = buildIntent(s, a, g, { rootSeq: it.rootSeq, screenDigest: it.screenDigest });
  if (canon(it) !== canon(expected)) {
    const diff = INTENT_FIELDS.filter(k => canon(it[k] ?? '') !== canon(expected[k] ?? ''));
    fail('INTENT_MISMATCH', diff.join(','));
  }
  const dig = intentDigest(it);
  // 3. the credential signed THIS intent digest
  let uv = false, signCount = null;
  if (credential.kind === 'passkey') {
    if (!ap.webauthn || 'sig' in ap) fail('APPROVAL_KIND_MISMATCH');
    const r = verifyAssertion(ap.webauthn, { rp: s.rp, expectedChallenge: dig, credential: { ...credential.webauthn, signCount: credential.signCount }, requireUV });
    uv = r.uv; signCount = r.signCount;
  } else {
    if (typeof ap.sig !== 'string' || 'webauthn' in ap) fail('APPROVAL_KIND_MISMATCH');
    if (!verifyDigest(V4_DOMAINS.INTENT, dig, ap.sig, credential.publicKey)) fail('APPROVAL_BAD_SIGNATURE', ap.credId);
  }
  // 4. confirmation assurance: what the system can actually show about the display path
  let level = LEVELS.SOFTWARE;
  const text = renderText(summary);
  if (credential.kind !== 'passkey' && s.v4.displays[ap.credId] === 'TRUSTED_DISPLAY') level = LEVELS.TRUSTED_DISPLAY; // device renders the summary itself
  if ('apc' in ap) {
    const conf = s.v4.confirmers[ap.credId];
    if (!conf) fail('NO_PROTECTED_CONFIRMATION_KEY_ENROLLED');
    const st = exactFields(ap.apc, ['sig'], [], 'APC_FIELDS');
    if (!verifyObj(V4_DOMAINS.CONFIRM, { prompt: text.split('\n'), extraData: dig.toString('hex') }, st.sig, conf.publicKey)) fail('PROTECTED_CONFIRMATION_INVALID');
    level = LEVELS.PROTECTED_CONFIRMATION;
  }
  // 5. optional screen evidence: evidence only, never raises assurance; if present it must be exact and bound
  if (it.screenDigest !== '-' || 'screen' in ap) {
    const sc = exactFields(ap.screen ?? {}, ['region', 'renderer', 'width', 'digest', 'challengeNonce', 'caseId'], [], 'SCREEN_EVIDENCE_FIELDS');
    if (sc.region !== SCREEN_REGION) fail('SCREEN_EVIDENCE_WRONG_REGION');
    if (sc.renderer !== RENDERER || !/^(32|40|48|64)$/.test(sc.width)) fail('SCREEN_EVIDENCE_RENDERER');
    if (sc.challengeNonce !== g.challengeNonce || sc.caseId !== it.caseId) fail('SCREEN_EVIDENCE_NOT_BOUND');
    if (sc.digest !== it.screenDigest) fail('SCREEN_EVIDENCE_NOT_IN_INTENT');
    if (sc.digest !== screenDigestHex(renderScreen(summary, Number(sc.width)))) fail('SCREEN_EVIDENCE_MISMATCH');
    if (s.v4.screenDigests[sc.digest + '_' + g.challengeNonce] !== undefined) fail('SCREEN_EVIDENCE_REPLAY');
    s.v4.screenDigests[sc.digest + '_' + g.challengeNonce] = String(s.seq + 1);
  }
  // 6. atomic one-time consumption: recorded in the transition-local state, committed only with the transition
  s.v4.usedChallenges[g.challengeNonce] = String(s.seq + 1);
  (s.v4.tx ??= { levels: [] }).levels.push({ credId: ap.credId, level, intent: dig.toString('hex') });
  return { uv, signCount, level, intentDigestHex: dig.toString('hex') };
}
