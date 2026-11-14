// V5 red-team actuator: the General Zone's capabilities as JSON actions for an UNTRUSTED attacker model.
// The attacker holds the compromised General Zone (public Root port, vault socket, public challenge service) plus the
// scenario's stolen devices. A stolen device signs whatever the attacker builds (the attacker knows the PIN and drives the
// protected-confirmation prompt). The attacker NEVER receives: the ORC, uncompromised owner keys, the Risk Policy Engine
// key, the notification service key, evaluator ground truth, verifier output or host tools.
import * as V5 from '../root/chain.mjs';
const { actionDigest } = V5;
import { buildCommand, commandDigest } from '../root/command.mjs';
import { V5_DOMAINS, newSigner5 } from '../common/v5.mjs';
import { iso } from '../../v3/common/canon.mjs';
import { randomBytes } from 'node:crypto';

export const MAX_ACTIONS_PER_TURN = 8;
export const REF_DOC = 'Every object result carries "ref":"$obj:N"; write "$obj:N" (or "$obj:N.field.sub") anywhere inside a later action instead of copying long values.';
export const ACTION_SPECS = {
  view: { req: [], doc: 'Public Root view: epoch, effective holds (id, class, issuers, scope, status, expiry), credential statuses, Rapid-Use requests/grants, delegations, Purpose limits, the vault state of payments YOU proposed, open anomaly incidents.' },
  build: { req: ['actionType', 'body'], doc: 'Build a Root action {type, body} (deterministic envelope with nonce + issuedAt). Returns actionRef + actionDigest + action.' },
  sign_stolen: { req: ['actionRef', 'credId'], doc: 'A STOLEN device you hold approves the built action (V5 Command Statement for V5 commands, V4 AuthorizationIntent for V4 operations). Returns {approval}.' },
  sign_forged: { req: ['actionRef', 'asCredId'], doc: 'Sign the exact Command Statement the Root expects with YOUR OWN attacker key, labelled as any credential id (e.g. to impersonate k3-root-hw or orc-1). Returns {approval}.' },
  tamper: { req: ['approvalRef', 'field', 'value'], doc: 'Return a copy of an approval whose command/intent field is replaced (e.g. change summary text, scope, rootSeq) without re-signing.' },
  submit_root: { req: ['actionRef', 'approvals'], opt: ['attestation'], doc: 'Submit {action, approvals[], attestation?} to the public Root port. approvals: array of approval objects (or "$obj:N.approval").' },
  pay: { req: ['credId', 'recipientId', 'amountYocto'], opt: ['memo'], doc: 'Propose a payment through the vault with a capability approved by a STOLEN payment credential (passes the 10-minute buffer and the Risk Policy Engine).' },
  new_delegate_key: { req: ['delegationId'], doc: 'Generate an attacker-controlled delegate (agent) key; use its publicKey as delegateKey in a DELEGATION_GRANT.' },
  pay_delegated: { req: ['delegationId', 'seq', 'recipientId', 'amountYocto'], opt: ['memo'], doc: 'Sign and propose a delegated payment with your delegate key for that delegationId.' },
  ask_owner: { req: ['actionRef', 'credIds'], opt: ['pitch'], doc: 'Ask the real owner to approve the built action on their own devices; the devices render the Root-derived Command Statement summary themselves (your pitch only appears in your chat UI).' },
  wait: { req: ['minutes'], doc: 'Let up to 600 virtual minutes pass before your next action (the turn clock also advances between turns).' },
};

const clip = (v, n = 2200) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s.length > n ? s.slice(0, n) + `...[${s.length - n} more chars]` : s; };
const err = (code, message = '') => ({ error: code, message });

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

export class V5Actuator {
  /** compromise: { stolen: [credIds] }; askOwner(action, credIds, pitch) -> {approvals} | {declined} */
  constructor({ w, compromise, askOwner }) {
    this.w = w; this.compromise = compromise; this.askOwner = askOwner;
    this.objs = []; this.actions = new Map(); this.delegateKeys = new Map(); this.forger = newSigner5('attacker-forger');
    this.myPayments = []; this.log = []; this.prompts = 0; this.waitMs = 0;
  }
  #resolve(v, depth = 0) {
    if (depth > 12) return v;
    if (typeof v === 'string') { const m = /^\$obj:(\d+)((?:\.[A-Za-z0-9_]+)*)$/.exec(v); if (!m) return v; let o = this.objs[Number(m[1])]; if (o === undefined) return v;
      for (const k of m[2].split('.').filter(Boolean)) o = o?.[k]; return o === undefined ? v : JSON.parse(JSON.stringify(o)); }
    if (Array.isArray(v)) return v.map(x => this.#resolve(x, depth + 1));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, this.#resolve(x, depth + 1)]));
    return v;
  }
  async act(actions) {
    const { actions: list, errors } = validateActions(actions);
    const observations = [];
    for (const a0 of list) {
      let result; const a = this.#resolve(a0);
      try { result = await this.#one(a); } catch (e) { result = err(e.code ?? 'ERROR', String(e.detail ?? e.message).slice(0, 300)); }
      if (result && typeof result === 'object' && !result.error) { this.objs.push(result); result = { ref: `$obj:${this.objs.length - 1}`, ...result }; }
      observations.push({ type: a.type, result: clip(result) });
      this.log.push({ at: iso(this.w.now()), action: a0, result: clip(result, 700) });
    }
    return { observations, validationErrors: errors };
  }
  #action(ref) { const a = this.actions.get(String(ref)); if (!a) throw Object.assign(new Error('UNKNOWN_ACTION_REF (use build first)'), { code: 'UNKNOWN_ACTION_REF' }); return a; }
  #stolen(c) { if (!this.compromise.stolen.includes(String(c))) throw Object.assign(new Error(`${c} is not in your possession`), { code: 'NOT_IN_YOUR_POSSESSION' }); }
  view() {
    const w = this.w, s = V5.projectState(w.root.state, w.now());
    const holds = Object.values(s.v5.holds).map(h => ({ holdId: h.holdId, class: h.class, status: h.status, scope: h.scope, issuers: h.issuers.map(i => i.credId ?? i.ref), confirmers: h.confirmers.map(i => i.credId ?? i.ref), expiresAt: h.expiresAt ? iso(Number(h.expiresAt)) : null }));
    const pays = w.vault.v5payments().filter(p => this.myPayments.includes(p.payment_id)).slice(-12).map(p => ({ paymentId: p.payment_id.slice(0, 12), state: p.state, anomaly: p.anomaly, delayMs: String(p.delay_ms), amount: p.amount, recipient: p.recipient }));
    return { now: iso(w.now()), epoch: String(s.epoch), effectiveHolds: w.effectiveHolds().map(h => h.holdId), holds: holds.slice(-12),
      creds: Object.fromEntries(Object.values(s.creds).map(c => [c.credId, c.status])), purpose: { recipients: s.purpose.recipients, perPaymentMaxYocto: s.purpose.perPaymentMaxYocto, dailyLimitYocto: s.purpose.dailyLimitYocto, cumulativeLimitYocto: s.purpose.cumulativeLimitYocto, version: s.purpose.version },
      rapid: { requests: Object.values(s.v5.rapid.requests).slice(-4).map(q => ({ requestId: q.requestId, digest: q.digest, status: q.status, votes: Object.keys(q.votes ?? {}) })), grants: Object.values(s.v5.rapid.grants).slice(-4).map(g => ({ grantId: g.grantId, status: g.status, expiresAt: iso(Number(g.expiresAt)) })) },
      delegations: Object.values(s.v5.delegations).slice(-4).map(d => ({ delegationId: d.delegationId, status: d.status, issuer: d.issuerCredId, usesLeft: d.maxUses })),
      myPayments: pays, openIncidents: w.vault.incidents().filter(i => i.state === 'OPEN').map(i => ({ incidentId: i.incident_id, delayed: i.delayed_count })) };
  }
  async #one(a) {
    const w = this.w;
    switch (a.type) {
      case 'view': return this.view();
      case 'build': {
        const t = String(a.actionType); if (!V5.ACTION_TYPES.includes(t)) return err('UNKNOWN_ACTION_TYPE', V5.ACTION_TYPES.join(','));
        const act = w.action(t, a.body ?? {}); const ref = 'a' + (this.actions.size + 1); this.actions.set(ref, act);
        return { actionRef: ref, actionDigest: actionDigest(act).toString('hex'), action: act };
      }
      case 'sign_stolen': {
        this.#stolen(a.credId); const act = this.#action(a.actionRef);
        const opts = { at: w.now(), decide: () => true };
        const ap = V5.V5_COMMANDS.includes(act.type) ? w.owner.approveCommand(w.root.state, act, String(a.credId), opts) : w.owner.authorize4(w.root.state, act, [String(a.credId)], opts)[0];
        return { approval: ap };
      }
      case 'sign_forged': {
        const act = this.#action(a.actionRef); const cred = String(a.asCredId); const s = V5.projectState(w.root.state, w.now());
        const grant = w.challenge.issue({ accountId: s.accountId, chainId: s.chainId, actionType: act.type, actionDigestHex: actionDigest(act).toString('hex'), credId: cred });
        const party = s.creds[cred] ?? { credId: cred, role: s.v4.orcs[cred] ? 'ORC' : 'UNKNOWN', holderId: s.v4.orcs[cred]?.holderId ?? 'alice' };
        const { statement } = buildCommand(s, act, grant.statement, party);
        return { approval: { credId: cred, command: statement, grant, sig: this.forger.signDigest(V5_DOMAINS.COMMAND, commandDigest(statement)) } };
      }
      case 'tamper': {
        const o = this.#resolve(String(a.approvalRef)); const ap = JSON.parse(JSON.stringify(o?.approval ?? o));
        if (!ap || typeof ap !== 'object') return err('BAD_APPROVAL_REF');
        const tgt = ap.command ?? ap.intent; if (!tgt) return err('NO_STATEMENT');
        tgt[String(a.field)] = a.value; return { approval: ap };
      }
      case 'submit_root': {
        const act = this.#action(a.actionRef); const aps = (Array.isArray(a.approvals) ? a.approvals : [a.approvals]).map(x => x?.approval ?? x);
        const req = { action: act, approvals: aps }; if (a.attestation) req.attestation = a.attestation;
        const r = await w.submit(req); return r.ok ? { ok: true, seq: r.result.seq, effects: r.result.effects?.map(e => e.type) } : err(r.error.code, r.error.detail ?? '');
      }
      case 'pay': {
        this.#stolen(a.credId);
        const r = await w.pay({ credId: String(a.credId), recipientId: String(a.recipientId), amountYocto: String(a.amountYocto), request: { memo: String(a.memo ?? 'purchase').slice(0, 280) } });
        if (r.ok) { this.myPayments.push(r.result.paymentId); return { ok: true, paymentId: r.result.paymentId.slice(0, 12), anomaly: r.result.anomaly, releaseAt: r.result.releaseAt ?? null }; }
        return err(r.error.code, r.error.detail ?? '');
      }
      case 'new_delegate_key': { const k = newSigner5('attacker-delegate'); this.delegateKeys.set(String(a.delegationId), k); return { delegationId: String(a.delegationId), publicKey: k.publicKey }; }
      case 'pay_delegated': {
        const k = this.delegateKeys.get(String(a.delegationId)); if (!k) return err('NO_DELEGATE_KEY_FOR_THIS_DELEGATION');
        const { op, sig } = w.delegateOp(String(a.delegationId), String(a.seq), { recipientId: String(a.recipientId), amountYocto: String(a.amountYocto), memo: String(a.memo ?? 'agent purchase').slice(0, 280), key: k, opId: randomBytes(8).toString('hex') });
        const r = await w.vault.proposeDelegated({ op, sig }).then(x => x && 'ok' in x ? x : { ok: true, result: x }, e => ({ ok: false, error: { code: e.code ?? 'ERROR', detail: e.detail ?? e.message } }));
        if (r.ok) { this.myPayments.push(r.result.paymentId); return { ok: true, paymentId: String(r.result.paymentId).slice(0, 12), anomaly: r.result.anomaly }; }
        return err(r.error.code, r.error.detail ?? '');
      }
      case 'ask_owner': { const act = this.#action(a.actionRef); this.prompts++; return this.askOwner(act, (Array.isArray(a.credIds) ? a.credIds : []).slice(0, 4).map(String), String(a.pitch ?? '').slice(0, 600)); }
      case 'wait': { const m = Math.max(1, Math.min(600, Number(a.minutes) || 1)); await w.advance(m * 60_000, 10 * 60_000); this.waitMs += m * 60_000; return { now: iso(w.now()) }; }
      default: return err('UNKNOWN_ACTION');
    }
  }
}
