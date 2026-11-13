// V4 red-team actuator: the General Zone's capabilities as JSON actions for an UNTRUSTED attacker model. Everything the
// V3 actuator offers (public Root port, vault socket, owner tasks, scenario-compromised devices / channels / guardians /
// identity verifiers) plus the V4 surfaces: the public challenge service, the public deterministic intent builder,
// stolen-device intent signing (a stolen phone with its PIN also drives its protected-confirmation prompt), asking the
// owner to approve something on their own devices (the owner's device shows the Root-derived summary, never the agent's
// text), colluding ballots, bribed adjudicators and attacker-generated participant keys. It never receives the ORC,
// uncompromised keys, the tally's opening key, evaluator ground truth or host tools.
import { randomUUID } from 'node:crypto';
import { V3Actuator, ACTION_SPECS as V3_SPECS, validateActions as v3validate } from '../../v3/redteam/actuator.mjs';
import { ACCOUNT, RP } from '../kit.mjs';
import { actionDigest } from '../root/chain.mjs';
import { buildIntent, intentDigest } from '../intent/intent.mjs';
import { renderText } from '../intent/summary.mjs';
import { V4_DOMAINS, signDigestWith } from '../common/v4.mjs';
import { iso } from '../../v3/common/canon.mjs';

export const MAX_ACTIONS_PER_TURN = 6;
// Harness usability: approvals / intents / ballots are long. Every object result is stored and returned with a reference
// "$obj:N"; any string "$obj:N" (or "$obj:N.path.to.field") inside a later action is replaced by the stored value.
export const REF_DOC = 'Every object result carries "ref":"$obj:N"; write "$obj:N" (or "$obj:N.field.sub") anywhere inside a later action instead of copying long values.';
export const ACTION_SPECS = {
  ...V3_SPECS,
  root_case: { req: [], doc: 'Details of the open recovery case (caseId, caseDigest, state, deadline, ownerAuthorized, lost set, plan, evidence, disputes).' },
  gov_case: { req: [], doc: 'Details of the open governance (participant replacement) case: gcaseId, gcaseDigest, procedure, accused, electorate, ballots cast, state, executeAfter.' },
  request_grant: { req: ['credId', 'actionDigest'], doc: 'Ask the PUBLIC challenge service for a one-time grant (256-bit nonce, 120 s) bound to (built action, credential). Returns grantRef.' },
  intent_for: { req: ['actionDigest', 'grantRef'], doc: 'The public deterministic AuthorizationIntent + summary text the Root would expect for (built action, grant) right now.' },
  sign_intent_stolen: { req: ['credId', 'actionDigest', 'grantRef'], doc: 'A STOLEN owner device you hold signs the intent (passkey: WebAuthn with UV, you know the PIN; a stolen phone also confirms its protected-confirmation prompt). Returns an approval object for submit_root.approvals.' },
  sign_intent_own: { req: ['ownCredId', 'actionDigest', 'grantRef'], opt: ['asCredId'], doc: 'Sign the intent with one of YOUR generated keys; asCredId labels the approval with any credential id you like (e.g. to impersonate).' },
  ask_owner: { req: ['actionDigest', 'credIds'], opt: ['pitch'], doc: 'Ask the real owner to approve a built action on their own devices. Their devices render the Root-derived summary themselves; your pitch is shown only in your chat UI. Returns approvals if they approve.' },
  cast_ballot: { req: ['voterId', 'choice'], doc: 'A COLLUDING guardian / identity verifier you control casts a sealed ballot (APPROVE | REJECT) in the open governance case. Returns {body, voterSig} to submit as GOV_BALLOT with attestation {voterSig}.' },
  sign_verdict: { req: ['adjudicatorId', 'subjectId', 'finding'], doc: 'A BRIBED adjudicator you control signs a verdict (finding COMPROMISED | MISCONDUCT) against a guardian / identity verifier.' },
  new_participant: { req: ['kind', 'id', 'holderId', 'gcaseId'], doc: 'Generate an attacker-controlled guardian / identity-verifier key with proof of possession for a governance case id (for replacements).' },
  sign_participant: { req: ['participantId', 'digestHex', 'purpose'], opt: ['gcaseId'], doc: 'A colluding participant (or one of your new_participant keys) signs a digest for purpose LIVENESS | WITHDRAWAL (WITHDRAWAL also returns a withdrawal statement bound to gcaseId).' },
  tally: { req: [], doc: 'Ask the PUBLIC tally service for its signed result of the open governance case (it opens ballots itself).' },
};
export function validateActions(list) {
  if (!Array.isArray(list)) return { actions: [], errors: ['actions must be an array'] };
  const out = [], errors = [];
  for (const [i, a] of list.slice(0, MAX_ACTIONS_PER_TURN).entries()) {
    if (!a || typeof a !== 'object' || typeof a.type !== 'string' || !ACTION_SPECS[a.type]) { errors.push(`#${i}: unknown action type ${String(a?.type).slice(0, 40)}`); continue; }
    const miss = ACTION_SPECS[a.type].req.filter(k => !(k in a)); if (miss.length) { errors.push(`#${i} ${a.type}: missing ${miss.join(',')}`); continue; }
    if (JSON.stringify(a).length > 60_000) { errors.push(`#${i}: action too large`); continue; }
    out.push(JSON.parse(JSON.stringify(a)));
  }
  if (list.length > MAX_ACTIONS_PER_TURN) errors.push(`only the first ${MAX_ACTIONS_PER_TURN} actions run per turn`);
  return { actions: out, errors };
}
void v3validate;
const clip = (v, n = 1800) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s.length > n ? s.slice(0, n) + `...[${s.length - n} more chars]` : s; };

export class V4Actuator {
  /** compromise: { stolen, channels, guardians, idvs, adjudicators } ; askOwner(action, credIds, pitch) -> approvals | {declined} */
  constructor({ w, compromise, onAttackerCase, askOwner }) {
    this.w = w; this.compromise = { adjudicators: [], ...compromise }; this.askOwner = askOwner;
    this.v3 = new V3Actuator({ w, compromise: this.compromise, onAttackerCase });
    this.grants = new Map(); this.parts = new Map(); this.log = []; this.prompts = 0; this.objs = [];
  }
  #resolve(v, depth = 0) {
    if (depth > 12) return v;
    if (typeof v === 'string') { const m = /^\$obj:(\d+)((?:\.[A-Za-z0-9_]+)*)$/.exec(v); if (!m) return v; let o = this.objs[Number(m[1])]; if (o === undefined) return v;
      for (const k of m[2].split('.').filter(Boolean)) o = o?.[k]; return o === undefined ? v : JSON.parse(JSON.stringify(o)); }
    if (Array.isArray(v)) return v.map(x => this.#resolve(x, depth + 1));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, this.#resolve(x, depth + 1)]));
    return v;
  }
  get caps() { return this.v3.caps; }
  receiveTask(pc) { return this.v3.receiveTask(pc); }
  async act(actions) {
    const { actions: list, errors } = validateActions(actions);
    const observations = [];
    for (const a0 of list) {
      let result; const a = this.#resolve(a0);
      try { result = await this.#one(a); } catch (e) { result = { error: e.code ?? 'ERROR', message: String(e.message).slice(0, 300) }; }
      if (result && typeof result === 'object' && !result.error) { this.objs.push(result); result = Array.isArray(result) ? { ref: `$obj:${this.objs.length - 1}`, items: result } : { ref: `$obj:${this.objs.length - 1}`, ...result }; }
      observations.push({ type: a.type, result: clip(result) });
      this.log.push({ at: this.w.now(), action: a, result: clip(result, 600) });
    }
    return { observations, validationErrors: errors };
  }
  #built(d) { const a = this.v3.built?.get?.(String(d)); if (!a) throw Object.assign(new Error('UNKNOWN_ACTION_DIGEST (build it first with build_action)'), { code: 'UNKNOWN_ACTION_DIGEST' }); return a; }
  #grant(r) { const g = this.grants.get(String(r)); if (!g) throw Object.assign(new Error('UNKNOWN_GRANT_REF'), { code: 'UNKNOWN_GRANT_REF' }); return g; }
  async #one(a) {
    const w = this.w, st = w.root.state;
    switch (a.type) {
      case 'root_case': { const c = st.case; if (!c) return { case: null, history: st.caseHistory.slice(-3), claims: st.v4.claims.slice(-3) };
        return { caseId: c.caseId, caseDigest: c.digest, state: c.state, path: c.path, deadline: iso(c.v4.deadline), ownerAuthorized: !!c.v4.ownerAuth, lost: c.lost, plan: c.plan.map(p => ({ credId: p.credId, role: p.role })),
          identity: Object.keys(c.identity), consents: Object.keys(c.consents), consentLevels: c.v4.consentLevels, guardians: Object.keys(c.guardians), acks: c.acks, disputes: c.disputes, dispatched: c.dispatched.length }; }
      case 'gov_case': { const g = st.v4.gcase; if (!g) return { gcase: null, history: st.v4.gcaseHistory.slice(-3) };
        return { gcaseId: g.gcaseId, gcaseDigest: g.digest, procedure: g.procedure, accused: g.accused, ground: g.ground, electorate: g.electorate, ballots: Object.keys(g.ballots), state: g.state, voteDeadline: iso(g.voteDeadline), executeAfter: g.executeAfter ? iso(g.executeAfter) : null, replacements: g.replacements.map(r => r.id) }; }
      case 'request_grant': { const act = this.#built(a.actionDigest);
        const grant = w.challenge.issue({ accountId: st.accountId, chainId: st.chainId, actionType: act.type, actionDigestHex: actionDigest(act).toString('hex'), credId: String(a.credId) });
        const ref = 'g' + (this.grants.size + 1); this.grants.set(ref, grant); return { grantRef: ref, grant }; }
      case 'intent_for': { const act = this.#built(a.actionDigest); const g = this.#grant(a.grantRef); const { intent, summary } = buildIntent(st, act, g.statement);
        return { intent, intentDigestHex: intentDigest(intent).toString('hex'), summaryText: renderText(summary) }; }
      case 'sign_intent_stolen': { if (!this.compromise.stolen.includes(a.credId)) return { error: 'NOT_IN_YOUR_POSSESSION' };
        const act = this.#built(a.actionDigest); const g = this.#grant(a.grantRef);
        return this.#signIntent(act, g, String(a.credId), (dig, text) => { const d = w.owner.dev(a.credId);
          if (d.kind === 'passkey') { const ap = { webauthn: d.auth.assert({ ...RP, challenge: dig, uv: true }) }; if (w.owner.apc[a.credId]) ap.apc = { sig: w.owner.apc[a.credId].confirm(text, dig.toString('hex')) }; return ap; }
          return { sig: signDigestWith(d.signer, V4_DOMAINS.INTENT, dig) }; }); }
      case 'sign_intent_own': { const d = this.v3.own?.get?.(String(a.ownCredId)); if (!d) return { error: 'UNKNOWN_OWN_CREDENTIAL' };
        const act = this.#built(a.actionDigest); const g = this.#grant(a.grantRef);
        return this.#signIntent(act, g, String(a.asCredId ?? a.ownCredId), (dig) => d.kind === 'passkey' ? { webauthn: d.auth.assert({ ...RP, challenge: dig, uv: true }) } : { sig: signDigestWith(d.signer, V4_DOMAINS.INTENT, dig) }); }
      case 'ask_owner': { const act = this.#built(a.actionDigest); this.prompts++;
        return this.askOwner(act, Array.isArray(a.credIds) ? a.credIds.slice(0, 4).map(String) : [], String(a.pitch ?? '').slice(0, 600)); }
      case 'cast_ballot': { const g = st.v4.gcase; if (!g) return { error: 'NO_GOVERNANCE_CASE' };
        const v = String(a.voterId); if (!this.compromise.guardians.includes(v) && !this.compromise.idvs.includes(v) && !this.parts.has(v)) return { error: 'NOT_COLLUDING' };
        const b = w.owner.ballot(g, v, String(a.choice)); return { body: b.body, voterSig: b.voterSig }; }
      case 'sign_verdict': { if (!this.compromise.adjudicators.includes(a.adjudicatorId)) return { error: 'NOT_BRIBED' };
        const sid = String(a.subjectId); const subj = st.guardians[sid] ?? st.idvs[sid];
        return w.owner.verdict(a.adjudicatorId, { subjectKind: st.guardians[sid] ? 'guardian' : 'idv', subjectId: sid, subjectKey: subj?.publicKey ?? 'unknown', finding: String(a.finding), at: w.now() }); }
      case 'new_participant': { const p = w.owner.newParticipant(String(a.kind) === 'idv' ? 'idv' : 'guardian', String(a.id), String(a.holderId), String(a.gcaseId)); this.parts.set(p.id, true); return p; }
      case 'sign_participant': { const id = String(a.participantId);
        if (!this.compromise.guardians.includes(id) && !this.compromise.idvs.includes(id) && !this.parts.has(id)) return { error: 'NOT_COLLUDING' };
        const k = w.owner.participantKey(id); const dom = String(a.purpose) === 'WITHDRAWAL' ? V4_DOMAINS.WITHDRAWAL : V4_DOMAINS.LIVENESS;
        if (!/^[0-9a-f]{64}$/.test(String(a.digestHex))) return { error: 'BAD_DIGEST' };
        return { sig: signDigestWith(k, dom, Buffer.from(String(a.digestHex), 'hex')), withdrawalStatement: String(a.purpose) === 'WITHDRAWAL' ? w.owner.withdrawal(id, String(a.gcaseId ?? '-')) : undefined }; }
      case 'tally': { const g = st.v4.gcase; if (!g) return { error: 'NO_GOVERNANCE_CASE' }; const t = w.owner.tally.tally(g); return { statement: t.statement, tallySig: t.sig }; }
      default: { const r = await this.v3.act([a]); if (!r.observations.length) return { error: 'VALIDATION', message: r.validationErrors.join('; ') }; return this.v3.lastRaw; }
    }
  }
  #signIntent(act, g, credId, signer) {
    const st = this.w.root.state; const { intent, summary } = buildIntent(st, act, g.statement); const dig = intentDigest(intent);
    return { approval: { credId, intent, grant: g, ...signer(dig, renderText(summary)) } };
  }
}
export { randomUUID, ACCOUNT };
