// V5 protective-hold registry (P4 accountable protective actions, P5 legitimate availability).
// Every FREEZE / SUSPEND / quarantine is an INDEPENDENT hold record with its own issuer, scope, class, evidence class,
// authorization digest, expiry / review deadline, confirmers, release conditions and full transition history.
// The effective restricted state is DERIVED from the union of effective holds; removing one hold never removes another.
import { fail, iso } from '../../v3/common/canon.mjs';
import { d5hex, V5_DOMAINS } from '../common/v5.mjs';

export const HOLD_CLASSES = Object.freeze(['TARGETED_QUARANTINE', 'PROVISIONAL_HOLD', 'CONFIRMED_OWNER_HOLD', 'VERIFIED_INCIDENT_FREEZE']);
export const SCOPE_KINDS = Object.freeze(['GLOBAL', 'CREDENTIAL', 'MERCHANT', 'DELEGATION']);
export const EVIDENCE_CLASSES = Object.freeze({ OWNER: 'OWNER_CREDENTIAL_ASSERTION', CONFIRMED: 'INDEPENDENT_OWNER_CONFIRMATION', SUPERVISOR: 'SUPERVISOR_VERIFIED_EVIDENCE' });
export const TERMINAL_HOLD = new Set(['EXPIRED', 'RELEASED', 'RELEASED_ISSUER_REVOKED', 'RELEASED_BY_CONTEST']);
export const ESCALATION = { TARGETED_QUARANTINE: 0, PROVISIONAL_HOLD: 1, CONFIRMED_OWNER_HOLD: 2, VERIFIED_INCIDENT_FREEZE: 3 };

/** Is the hold restricting at time `at`? (expiry is a pure function of time, so every domain agrees without a transition) */
export const holdEffective = (h, at) => h.status === 'ACTIVE' && (h.expiresAt === null || at < Number(h.expiresAt));
export const scopeKey = (scope) => `${scope.kind}:${scope.target}`;
export function effectiveHolds(s, at) { return Object.values(s.v5.holds).filter(h => holdEffective(h, at)); }
export const globalHolds = (s, at) => effectiveHolds(s, at).filter(h => h.scope.kind === 'GLOBAL');
export const credentialHolds = (s, credId, at) => effectiveHolds(s, at).filter(h => h.scope.kind === 'CREDENTIAL' && h.scope.target === credId);
export const merchantHolds = (s, recipientId, at) => effectiveHolds(s, at).filter(h => h.scope.kind === 'MERCHANT' && h.scope.target === recipientId);
export const delegationHolds = (s, delegationId, at) => effectiveHolds(s, at).filter(h => h.scope.kind === 'DELEGATION' && h.scope.target === delegationId);

/** Digest of everything that defines a hold (bound into commands that act on it). */
export const holdDigest = (s, h) => d5hex(V5_DOMAINS.HOLD, { chainId: s.chainId, holdId: h.holdId, cls: h.class, scope: scopeKey(h.scope), issuers: h.issuers.map(i => i.ref), createdAt: iso(Number(h.createdAt)), authDigest: h.authDigest });

export function pushHistory(h, at, event, by, detail = '-') { h.history.push({ at: String(at), event, by: String(by), detail: String(detail).slice(0, 160) }); if (h.history.length > 64) h.history.splice(1, 1); }

/** Credential refs whose validity keeps a hold alive. Non-credential issuers (supervisor) are never "revoked". */
export const credentialParties = (h) => [...h.issuers, ...h.confirmers].filter(p => p.kind === 'credential' || p.kind === 'orc');
export function partyValid(s, p) {
  if (p.kind === 'orc') return s.v4.orcs[p.ref]?.status === 'active';
  if (p.kind === 'credential') { const c = s.creds[p.ref]; return !!c && (c.status === 'active' || c.status === 'suspended'); }
  return true;
}

/**
 * Re-derives the restricted state (called at the start AND end of every V5 transition, deterministically):
 *   * holds past expiresAt -> EXPIRED (provisional / targeted only; a verified incident freeze has no expiry);
 *   * holds whose EVERY credential party (issuers + confirmers) is now revoked / retired -> RELEASED_ISSUER_REVOKED,
 *     except supervisor-verified incident freezes (they lift only with the trusted repair certificate);
 *   * credential status active <-> suspended follows the CREDENTIAL-scope holds;
 *   * s.freeze (the V3/V4 view the vault replays) = union of GLOBAL holds.
 */
export function normalizeHolds(s, at, fx) {
  for (const h of Object.values(s.v5.holds)) {
    if (h.status !== 'ACTIVE') continue;
    if (h.expiresAt !== null && at >= Number(h.expiresAt)) { h.status = 'EXPIRED'; pushHistory(h, at, 'EXPIRED', 'clock'); fx.push({ type: 'HOLD_EXPIRED', holdId: h.holdId, cls: h.class }); continue; }
    if (h.class === 'VERIFIED_INCIDENT_FREEZE') continue;
    const parties = credentialParties(h);
    if (parties.length && parties.every(p => !partyValid(s, p))) {
      h.status = 'RELEASED_ISSUER_REVOKED'; pushHistory(h, at, 'RELEASED_ISSUER_REVOKED', 'protocol', parties.map(p => p.ref).join(','));
      fx.push({ type: 'HOLD_RELEASED', holdId: h.holdId, reason: 'every issuing / confirming credential is revoked or retired', parties: parties.map(p => p.ref) });
    }
  }
  for (const c of Object.values(s.creds)) {
    if (c.status !== 'active' && c.status !== 'suspended') continue;
    const restricted = credentialHolds(s, c.credId, at).length > 0;
    if (restricted && c.status === 'active') { c.status = 'suspended'; c.suspendedAt = at; fx.push({ type: 'SUSPENDED', credId: c.credId, by: credentialHolds(s, c.credId, at).map(h => h.holdId) }); }
    else if (!restricted && c.status === 'suspended') { c.status = 'active'; delete c.suspendedAt; fx.push({ type: 'UNSUSPENDED', credId: c.credId }); }
  }
  const g = globalHolds(s, at);
  const wasFrozen = s.freeze.active;
  if (g.length) {
    const top = [...g].sort((a, b) => ESCALATION[b.class] - ESCALATION[a.class] || Number(a.createdAt) - Number(b.createdAt))[0];
    s.freeze = { active: true, freezeId: top.holdId, requiresRepair: g.some(h => h.class === 'VERIFIED_INCIDENT_FREEZE'), source: top.issuers[0].kind === 'supervisor' ? 'supervisor' : 'owner', at: wasFrozen ? s.freeze.at : at };
    if (!wasFrozen) fx.push({ type: 'FROZEN', freezeId: top.holdId, source: s.freeze.source, holds: g.map(h => h.holdId) });
  } else if (wasFrozen) {
    s.freeze = { active: false, freezeId: null, requiresRepair: false, source: null, at };
    fx.push({ type: 'UNFROZEN', approvers: [], reason: 'no effective global hold remains' });
  }
}

/** Single-signer budget: total requested restriction time per issuer in the trailing 30 days. */
export function issuerUsage(s, ref, at) {
  const recent = (s.v5.issuerLog[ref] ?? []).filter(x => Number(x.at) > at - 30 * 86_400_000);
  return { ms: recent.reduce((t, x) => t + Number(x.ms), 0), active: Object.values(s.v5.holds).filter(h => holdEffective(h, at) && h.issuers.some(i => i.ref === ref)).length };
}
export function chargeIssuer(s, ref, at, ms) { (s.v5.issuerLog[ref] ??= []).push({ at: String(at), ms: String(ms) }); s.v5.issuerLog[ref] = s.v5.issuerLog[ref].filter(x => Number(x.at) > at - 30 * 86_400_000); }

export function publicHold(h) {
  return { holdId: h.holdId, class: h.class, scope: scopeKey(h.scope), issuers: h.issuers.map(i => `${i.kind}:${i.ref}`), reason: h.reason, evidenceClass: h.evidenceClass,
    createdAt: iso(Number(h.createdAt)), status: h.status, expiresAt: h.expiresAt === null ? null : iso(Number(h.expiresAt)), reviewAt: h.reviewAt ? iso(Number(h.reviewAt)) : null,
    confirmers: h.confirmers.map(c => `${c.kind}:${c.ref}`), escalation: String(ESCALATION[h.class]), releaseConditions: h.releaseConditions, history: h.history.length };
}
export function assertScope(s, scope) {
  if (!scope || typeof scope !== 'object' || !SCOPE_KINDS.includes(scope.kind) || typeof scope.target !== 'string') fail('HOLD_SCOPE');
  if (scope.kind === 'GLOBAL' && scope.target !== '*') fail('HOLD_SCOPE_GLOBAL_TARGET');
  if (scope.kind === 'CREDENTIAL' && !s.creds[scope.target]) fail('HOLD_SCOPE_UNKNOWN_CREDENTIAL');
  if (scope.kind === 'MERCHANT' && !s.purpose.recipients.includes(scope.target)) fail('HOLD_SCOPE_UNKNOWN_MERCHANT');
  if (scope.kind === 'DELEGATION' && !s.v5.delegations[scope.target]) fail('HOLD_SCOPE_UNKNOWN_DELEGATION');
}
