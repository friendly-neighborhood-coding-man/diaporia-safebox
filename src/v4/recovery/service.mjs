// V4 Recovery service (own trust domain, narrow authority). It notifies EVERY channel of a recovery or governance case
// with the deterministic authorization summary, attests the dispatch, sends liveness challenges, and asks the Root to
// complete / expire / execute when the Root's own rules allow. It approves nothing: every decision is the Root's.
import { ACTION_V, actionDigest } from '../root/chain.mjs';
import { nonce, iso, V3_DOMAINS } from '../../v3/common/canon.mjs';
import { buildSummary, renderText } from '../intent/summary.mjs';

export class RecoveryServiceV4 {
  constructor({ notifier, deliver, submit, view, now }) { Object.assign(this, { notifier, deliver, submit, view, now }); this.sent = []; }
  header(type, body) { const v = this.view(), t = this.now(); return { v: ACTION_V, type, accountId: v.accountId, chainId: v.chainId, epoch: String(v.epoch), matrixVersion: v.matrixVersion, purposeVersion: v.purposeVersion, nonce: nonce(), issuedAt: iso(t), expiresAt: iso(t + 3600_000), body }; }
  async attested(type, body) { const action = this.header(type, body); return this.submit({ action, attestation: { notifierSig: this.notifier.signDigest(V3_DOMAINS.DISPATCH, actionDigest(action)) } }); }
  async onEffects(effects, state) {
    for (const e of effects) {
      if ((e.type === 'RECOVERY_OPENED' || e.type === 'RECOVERY_REPLANNED') && state.case) {
        const cs = state.case;
        const sm = buildSummary(state, { type: 'RECOVERY_CONSENT', body: { caseId: cs.caseId } }, { expiresAt: iso(cs.v4?.deadline ?? cs.openedAt) });
        const msg = { kind: 'SAFEBOX_RECOVERY_NOTICE', caseId: cs.caseId, caseDigest: cs.digest, deadline: iso(cs.v4?.deadline ?? 0), summary: renderText(sm),
          text: 'A recovery was requested for your SafeBox. Silence never approves it: without your explicit owner-recovery authorization it ends at the deadline. If you did not request it, object or cancel.' };
        const channels = Object.keys(state.channels).sort();
        for (const ch of channels) { await this.deliver(ch, msg); this.sent.push({ ch, caseId: cs.caseId, at: this.now() }); }
        await this.attested('RECOVERY_DISPATCH', { caseId: cs.caseId, caseDigest: cs.digest, channels });
      }
      if (e.type === 'GOV_CASE_OPENED' && state.v4.gcase) {
        const g = state.v4.gcase; const channels = Object.keys(state.channels).sort();
        const msg = { kind: 'SAFEBOX_PARTICIPANT_REPLACEMENT_NOTICE', gcaseId: g.gcaseId, procedure: g.procedure, accused: g.accused, replacements: g.replacements.map(r => r.id), ground: g.ground };
        for (const ch of channels) { await this.deliver(ch, msg); this.sent.push({ ch, gcaseId: g.gcaseId, at: this.now() }); }
        await this.attested('GOV_DISPATCH', { gcaseId: g.gcaseId, gcaseDigest: g.digest, channels });
      }
    }
  }
  async ping(participantId) { try { return { ok: true, result: await this.attested('PARTICIPANT_LIVENESS_PING', { participantId }) }; } catch (e) { return { ok: false, code: e.code }; } }
  async #try(type, body) { try { return { attempted: true, ok: true, result: await this.submit({ action: this.header(type, body) }) }; } catch (e) { return { attempted: true, ok: false, code: e.code ?? String(e.message) }; } }
  /** Completion attempt; the Root decides (owner authorization, evidence, window). */
  async tryComplete(state) {
    const cs = state.case; if (!cs) return { attempted: false };
    const type = cs.state === 'RECONSTITUTION' ? 'RECONSTITUTE' : cs.state === 'RECOVERY_CHALLENGE' ? 'RECOVERY_COMPLETE' : null;
    if (!type) return { attempted: false, state: cs.state };
    return this.#try(type, { caseId: cs.caseId, caseDigest: cs.digest });
  }
  /** Deadline housekeeping: an unapproved case is terminated without any authority transfer. */
  async tryExpire(state) { const cs = state.case; if (!cs) return { attempted: false }; return this.#try('RECOVERY_EXPIRE', { caseId: cs.caseId, caseDigest: cs.digest }); }
  async tryGovExecute(state) { const g = state.v4.gcase; if (!g) return { attempted: false }; return this.#try(g.state === 'APPROVED' && this.now() >= g.executeAfter ? 'GOV_CASE_EXECUTE' : 'GOV_EXPIRE', { gcaseId: g.gcaseId, gcaseDigest: g.digest }); }
}
