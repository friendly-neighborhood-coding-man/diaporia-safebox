// Recovery service (its own trust domain). Narrow authority: it can (1) notify every enrolled channel and attest that it
// did (pinned notifier key), and (2) ask the Root to complete a case once the chain itself already holds all the
// owner/guardian/identity evidence. It cannot transfer funds, cannot amend the Purpose, cannot forge consents, and a
// compromised recovery service can at worst delay a recovery or send false notifications (which carry no authority).
import { ACTION_V } from '../root/chain.mjs';
import { nonce, iso, V3_DOMAINS } from '../common/canon.mjs';

export class RecoveryService {
  constructor({ notifier, deliver, submit, view, now }) {
    Object.assign(this, { notifier, deliver, submit, view, now });
    this.sent = []; // delivery log
  }
  #header(v, type, body) { const t = this.now(); return { v: ACTION_V, type, accountId: v.accountId, chainId: v.chainId, epoch: String(v.epoch), matrixVersion: v.matrixVersion, purposeVersion: v.purposeVersion, nonce: nonce(), issuedAt: iso(t), expiresAt: iso(t + 3600_000), body }; }
  /** React to root effects: fan out a notification to EVERY channel, then attest dispatch to the Root. */
  async onEffects(effects, state) {
    for (const e of effects) {
      if (e.type !== 'RECOVERY_OPENED' && e.type !== 'RECOVERY_REPLANNED') continue;
      const cs = state.case; const v = this.view();
      const msg = { kind: 'SAFEBOX_RECOVERY_NOTICE', caseId: cs.caseId, caseDigest: cs.digest, lost: cs.lost, newKeys: cs.plan.map(c => `${c.role}:${c.publicKey.slice(0, 24)}`), openedAt: iso(cs.openedAt),
        text: 'A key-loss recovery was requested for your SafeBox. If you did not request it, object with any of your keys or reply OBJECTION on this channel.' };
      const channels = Object.keys(state.channels).sort();
      for (const ch of channels) { await this.deliver(ch, msg); this.sent.push({ ch, caseId: cs.caseId, at: this.now() }); }
      const action = this.#header(v, 'RECOVERY_DISPATCH', { caseId: cs.caseId, caseDigest: cs.digest, channels });
      await this.submit({ action, attestation: { notifierSig: this.notifier.signDigest(V3_DOMAINS.DISPATCH, (await import('../root/chain.mjs')).actionDigest(action)) } });
    }
  }
  /** Attempt completion; the Root decides. Returns the Root's answer or the denial code (never forces anything). */
  async tryComplete(state) {
    const cs = state.case; if (!cs) return { attempted: false };
    const type = cs.state === 'RECONSTITUTION' ? 'RECONSTITUTE' : cs.state === 'RECOVERY_CHALLENGE' ? 'RECOVERY_COMPLETE' : null;
    if (!type) return { attempted: false, state: cs.state };
    try { return { attempted: true, ok: true, result: await this.submit({ action: this.#header(this.view(), type, { caseId: cs.caseId, caseDigest: cs.digest }) }) }; }
    catch (e) { return { attempted: true, ok: false, code: e.code ?? String(e.message) }; }
  }
}
