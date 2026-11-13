// Deterministic authorization summaries. The authoritative text a person sees before approving a high-risk action is
// generated HERE, from verified structured data (the Root state replica + the exact action), never by the AI agent.
// The Root recomputes the same summary from its own state; the summary digest is bound into the AuthorizationIntent,
// so a summary that omits or misstates a side effect does not verify.
import { iso } from '../../v3/common/canon.mjs';
import { V4_DOMAINS, d4hex, keyDigest } from '../common/v4.mjs';

export const SUMMARY_V = 'safebox.v4.summary';
export const RENDERER = 'safebox.render.v1';
export const SCREEN_REGION = 'safebox-authorization';

const kd = (pk) => keyDigest(pk).slice(0, 16);
const credLine = (c) => `${c.credId} (${c.role}, key ${kd(c.publicKey)})`;
const asList = (v) => Array.isArray(v) ? v.join('|') : typeof v === 'object' && v ? JSON.stringify(v) : String(v);
const epochLine = (s) => `Epoch ${s.epoch} -> ${s.epoch + 1}: every outstanding approval and pending payment of epoch ${s.epoch} is cancelled`;
const NONE = 'None', UNCHANGED = 'Unchanged';
const AUTH_TEXT = { DAILY: 'pay within the Purpose; co-sign governance', ROOT: 'Purpose Root governance (with daily keys); unfreeze', FREEZE: 'freeze only',
  RECOVERY: 'recovery consent; co-sign recovery-key rotation', ADMIN: 'administration', ORC: 'owner recovery authorization only (never pays or amends)' };
const roleAuth = (role) => `${role}: ${AUTH_TEXT[role] ?? role}`;

/** Protective actions a completed recovery would undo: those imposed ONLY by credentials the case revokes (shown, so the
 * owner approves them explicitly; a hold by any other key, and a supervisor breach freeze, always stay). */
function protectiveLiftLines(s, cs) {
  if (!cs || !s.v4) return [];
  const L = new Set(cs.lost); const out = [];
  for (const [cid, by] of Object.entries(s.v4.suspendedBy ?? {})) if (s.creds[cid]?.status === 'suspended' && by.length && by.every(x => L.has(x))) out.push(`On completion: reactivates ${cid} (suspended only by ${by.join(',')})`);
  for (const h of s.v4.freezeHolds ?? []) if (s.freeze.active && h.by.length && h.by.every(x => L.has(x))) out.push(`On completion: drops freeze hold ${h.freezeId} (placed only by ${h.by.join(',')})`);
  if (s.freeze.active) {
    const keep = (s.v4.freezeHolds ?? []).filter(h => !(h.by.length && h.by.every(x => L.has(x))));
    out.push(keep.length || s.freeze.requiresRepair || s.freeze.source !== 'owner' ? `Freeze ${s.freeze.freezeId} stays (other holds: ${keep.map(h => h.by.join('+')).join(';') || s.freeze.source})` : `On completion: freeze ${s.freeze.freezeId} lifts (no other hold)`);
  }
  return out;
}
function planOf(state, action) {
  const b = action.body ?? {};
  if (Array.isArray(b.plan)) return b.plan.filter(p => p && typeof p === 'object').map(p => ({ credId: String(p.credId), role: String(p.role), publicKey: String(p.publicKey ?? p.registration?.clientDataJSON ?? '?') }));
  if (state.case && (b.caseId === state.case.caseId)) return state.case.plan.map(p => ({ credId: p.credId, role: p.role, publicKey: p.publicKey }));
  return [];
}
const live = (s) => Object.values(s.creds).filter(c => c.status === 'active' || c.status === 'suspended');

/** Builds the structured summary (all values ASCII strings / string arrays). */
export function buildSummary(state, action, { expiresAt }) {
  const t = action.type, b = action.body ?? {}, s = state;
  const out = { v: SUMMARY_V, account: s.accountId, title: t, actionType: t, reason: '-', removes: [], adds: [], affectedParticipants: [], resultingAuthority: [],
    purposeChanges: NONE, paymentChanges: UNCHANGED, reversible: 'n/a', caseId: '-', expires: expiresAt, delay: NONE, sideEffects: [], scope: '-' };
  const cred = (id) => s.creds[id];
  switch (t) {
    case 'ROTATE': {
      const old = cred(b.credId), nc = b.newCredential ?? {};
      out.title = old?.role === 'ROOT' ? 'Administrator Key Replacement' : `${old?.role ?? '?'} Credential Rotation`;
      out.reason = 'Owner-initiated rotation (old key still available)';
      out.removes = old ? [credLine(old)] : [`unknown ${b.credId}`];
      out.adds = [`${nc.credId} (${nc.role}, key ${nc.publicKey ? kd(nc.publicKey) : 'passkey-registration'})`];
      out.resultingAuthority = [`${roleAuth(old?.role)} moves from ${b.credId} to ${nc.credId}`];
      out.paymentChanges = old?.role === 'DAILY' ? 'Payment signing key replaced; Purpose limits unchanged' : UNCHANGED;
      out.reversible = 'Only by another rotation'; out.sideEffects = [epochLine(s)];
      out.scope = `This approval authorizes replacement of ${b.credId} with ${nc.credId} and nothing else.`; break;
    }
    case 'REVOKE': {
      const c = cred(b.credId); out.title = 'Credential Revocation'; out.reason = `requester note (unverified, not part of the effect): ${String(b.reason ?? '-').slice(0, 80)}`;
      out.removes = c ? [credLine(c)] : [`unknown ${b.credId}`]; out.resultingAuthority = [`${c?.role ?? '?'} authority of ${b.credId} removed`];
      out.paymentChanges = c?.role === 'DAILY' ? `${b.credId} can no longer pay` : UNCHANGED; out.reversible = 'No (refill the vacancy)'; out.sideEffects = [epochLine(s)];
      out.scope = `This approval revokes ${b.credId} and nothing else.`; break;
    }
    case 'REPLACE_VACANT': {
      const nc = b.newCredential ?? {}; out.title = 'Refill Revoked Credential'; out.reason = `Vacancy left by ${b.revokedCredId}`;
      out.adds = [`${nc.credId} (${nc.role})`]; out.resultingAuthority = [roleAuth(nc.role) + ` granted to ${nc.credId}`]; out.reversible = 'Only by revocation'; out.sideEffects = [epochLine(s)];
      out.scope = `This approval installs ${nc.credId} in the vacancy of ${b.revokedCredId} and nothing else.`; break;
    }
    case 'AMEND_PURPOSE': {
      const c = b.capsule ?? {}; const diffs = [];
      for (const k of [...new Set([...Object.keys(s.purpose), ...Object.keys(c)])].sort()) if (asList(s.purpose[k]) !== asList(c[k])) diffs.push(`${k}: ${asList(s.purpose[k]).slice(0, 80)} -> ${asList(c[k]).slice(0, 80)}`);
      out.title = 'Purpose Amendment'; out.reason = 'Owner governance'; out.purposeChanges = diffs.length ? diffs.join('; ') : 'No field changes';
      const payKeys = ['recipients', 'perPaymentMaxYocto', 'cumulativeLimitYocto', 'dailyLimitYocto', 'products', 'exactProductsOnly', 'expiresAt'];
      const payDiffs = diffs.filter(d => payKeys.some(k => d.startsWith(k + ':')));
      out.paymentChanges = payDiffs.length ? 'Payment permissions change: ' + payDiffs.map(d => d.split(':')[0]).join(',') : UNCHANGED;
      out.reversible = 'Strengthening only unless the full governance quorum signs again'; out.scope = 'This approval sets the Purpose to exactly the version shown and nothing else.'; break;
    }
    case 'AMEND_MATRIX': {
      const m = b.matrix ?? {}; const changed = Object.keys(m.rules ?? {}).filter(r => JSON.stringify(m.rules[r]) !== JSON.stringify(s.matrix.rules[r])).sort();
      out.title = 'Authority Matrix Amendment'; out.resultingAuthority = changed.map(r => `${r}: ${JSON.stringify(m.rules[r].anyOf)}`); out.scope = `This approval sets authority matrix version ${m.version} and nothing else.`; break;
    }
    case 'UNFREEZE': out.title = 'Lift Freeze'; out.reason = `Freeze ${b.freezeId}`; out.paymentChanges = 'Payments resume within the Purpose'; out.scope = `This approval lifts freeze ${b.freezeId} and nothing else.`; break;
    case 'FREEZE': out.title = 'Freeze SafeBox'; out.paymentChanges = 'All payments stop until unfrozen'; out.scope = 'This approval freezes the SafeBox and nothing else.'; break;
    case 'SUSPEND': case 'UNSUSPEND': { const c = cred(b.credId); out.title = t === 'SUSPEND' ? 'Suspend Credential' : 'Reactivate Credential'; out.removes = t === 'SUSPEND' && c ? [credLine(c)] : []; out.adds = t === 'UNSUSPEND' && c ? [credLine(c)] : []; out.scope = `This approval ${t === 'SUSPEND' ? 'suspends' : 'reactivates'} ${b.credId} and nothing else.`; break; }
    case 'RATIFY_BASELINE': out.title = 'Ratify Credential Baseline'; out.resultingAuthority = live(s).filter(c => c.status === 'active').map(credLine); out.scope = 'This approval fixes the current active credentials as the recovery baseline.'; break;
    case 'RECOVERY_CONSENT': case 'RECOVERY_OWNER_AUTHORIZE': {
      const cs = s.case; const plan = planOf(s, action);
      const recon = cs?.path === 'RECONSTITUTION';
      out.title = t === 'RECOVERY_OWNER_AUTHORIZE' ? (recon ? 'Majority-Loss Reconstitution - Owner Authorization' : 'Key-Loss Recovery - Owner Authorization') : 'Consent to Key-Loss Recovery';
      out.reason = cs ? `Recovery case ${cs.caseId}: ${cs.lost.join(',')} reported lost` : 'no open case';
      out.caseId = cs?.caseId ?? '-';
      out.removes = cs ? (recon ? live(s).map(credLine) : cs.lost.map(x => s.creds[x] ? credLine(s.creds[x]) : x)) : [];
      out.adds = plan.map(p => `${p.credId} (${p.role}, key ${kd(p.publicKey)})`);
      out.resultingAuthority = plan.map(p => roleAuth(p.role) + ` -> ${p.credId}`);
      out.reversible = 'No (a new recovery is required to undo)';
      out.delay = cs ? `Objection window until ${iso(cs.openedAt + Number(s.config.windowMs))}; an unapproved case terminates at that deadline` : NONE;
      out.sideEffects = [epochLine(s), ...(recon ? ['ALL current credentials are retired'] : []), ...protectiveLiftLines(s, cs)];
      out.scope = `This approval authorizes ONLY the credential set shown for case ${out.caseId}; it never authorizes payments, Purpose changes or another case.`; break;
    }
    case 'RECOVERY_CANCEL': case 'RECOVERY_ORC_CANCEL': case 'RECOVERY_WITHDRAW': {
      const cs = s.case; out.title = t === 'RECOVERY_WITHDRAW' ? 'Withdraw Recovery Objection' : 'Cancel Recovery Case'; out.caseId = cs?.caseId ?? String(b.caseId ?? '-');
      out.reason = cs ? `Case ${cs.caseId} claims ${cs.lost.join(',')} lost` : '-'; out.resultingAuthority = ['No credential changes'];
      out.paymentChanges = s.lockdown.active ? 'Emergency lockdown ends; payments resume' : UNCHANGED; out.scope = `This approval affects case ${out.caseId} only.`; break;
    }
    case 'ORC_REPLACE': {
      const o = s.v4?.orcs?.[b.orcId]; out.title = 'Owner Recovery Credential Replacement'; out.removes = o ? [`${b.orcId} (ORC, key ${kd(o.publicKey)})`] : [];
      out.adds = [`${b.newOrc?.id} (ORC, key ${b.newOrc?.publicKey ? kd(b.newOrc.publicKey) : '?'})`]; out.resultingAuthority = [roleAuth('ORC') + ` -> ${b.newOrc?.id}`]; out.sideEffects = [epochLine(s)];
      out.scope = `This approval replaces ${b.orcId} with ${b.newOrc?.id} and nothing else.`; break;
    }
    case 'GOV_CASE_OPEN': case 'GOV_CASE_CANCEL': case 'GUARDIAN_ROTATE': {
      const g = t === 'GOV_CASE_CANCEL' ? (s.v4?.gcase ?? {}) : b;
      const idv = String(g.procedure ?? '').startsWith('IDV');
      out.title = t === 'GOV_CASE_CANCEL' ? 'Cancel Emergency Replacement' : t === 'GUARDIAN_ROTATE' ? 'Guardian Rotation' : (idv ? 'Emergency Identity-Verifier Replacement' : 'Emergency Guardian Replacement');
      out.reason = t === 'GUARDIAN_ROTATE' ? String(b.ground ?? '-') : `${String(g.ground ?? '-')} of ${asList(g.accused ?? [])}`;
      out.caseId = String(g.gcaseId ?? '-');
      out.removes = t === 'GUARDIAN_ROTATE' ? [String(b.guardianId)] : (g.accused ?? []).map(String);
      out.adds = (t === 'GUARDIAN_ROTATE' ? [b.replacement] : (g.replacements ?? [])).filter(Boolean).map(r => `${r.id} (holder ${r.holderId}, key ${r.publicKey ? kd(r.publicKey) : '?'})`);
      out.affectedParticipants = [...Object.keys(s.guardians).filter(x => s.guardians[x].status === 'active').map(x => 'guardian:' + x), ...Object.keys(s.idvs).map(x => 'idv:' + x)];
      out.resultingAuthority = ['Recovery participant set changes only; no owner credential changes'];
      out.reversible = 'Only by another replacement'; out.delay = t === 'GOV_CASE_OPEN' ? `Confidential vote, then ${Number(s.v4?.config.govDelayMs ?? 0) / 3600_000} h objection delay` : NONE;
      out.sideEffects = t === 'GOV_CASE_CANCEL' ? [] : ['Epoch advances at execution: outstanding approvals and pending payments are cancelled'];
      out.scope = t === 'GOV_CASE_CANCEL' ? `This approval cancels governance case ${out.caseId} only.` : 'This approval authorizes replacing exactly the participants shown with exactly the replacements shown; it grants no payment, Purpose, budget, key or unfreeze authority.'; break;
    }
    default: out.title = t; out.scope = `This approval authorizes the ${t} action shown and nothing else.`;
  }
  return out;
}
export const summaryDigestHex = (summary) => d4hex(V4_DOMAINS.SUMMARY, summary);

/** Deterministic text shown by a trusted display (also the Protected-Confirmation prompt). */
export function renderText(sm) {
  const L = [`SafeBox - ${sm.title}`, `Account: ${sm.account}`, `Action: ${sm.actionType}`, `Reason: ${sm.reason}`];
  if (sm.caseId !== '-') L.push(`Case: ${sm.caseId}`);
  for (const x of sm.removes) L.push(`Remove: ${x}`);
  for (const x of sm.adds) L.push(`Add: ${x}`);
  for (const x of sm.affectedParticipants) L.push(`Affected: ${x}`);
  for (const x of sm.resultingAuthority) L.push(`New authority: ${x}`);
  L.push(`Purpose changes: ${sm.purposeChanges}`, `Payment permissions: ${sm.paymentChanges}`, `Reversible: ${sm.reversible}`, `Delay: ${sm.delay}`);
  for (const x of sm.sideEffects) L.push(`Side effect: ${x}`);
  L.push(`Approval expires: ${sm.expires}`, sm.scope);
  return L.join('\n');
}

/** Canonical "framebuffer" of the dedicated SafeBox authorization region (fixed width, fixed font metrics). */
export function renderScreen(sm, width = 48) {
  const lines = [];
  for (const raw of renderText(sm).split('\n')) { let r = raw; do { lines.push(r.slice(0, width).padEnd(width, ' ')); r = r.slice(width); } while (r.length); }
  return { region: SCREEN_REGION, renderer: RENDERER, width: String(width), lines };
}
export const screenDigestHex = (screen) => d4hex(V4_DOMAINS.SCREEN, screen);
