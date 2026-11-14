// Simulated owner device (stands in for an independent hardware device). Holds the owner and recovery private keys in
// the test harness only; every approval it produces is a scripted MOCK approval, labelled as such in the evidence.
import { newKeyPair, signEnvelope, randomId, DOMAINS } from '../common/crypto.mjs';
export class OwnerDevice {
  constructor({ account = 'safebox.mock' } = {}) { this.account = account; this.owner = newKeyPair(); this.recovery = newKeyPair(); this.mock = true; }
  /** roles: ['owner'] | ['recovery'] | ['owner','recovery']; epoch must be the Authority's current epoch. */
  cmd(type, body, { epoch, roles = ['owner'], ttlMs = 600_000, nonce = randomId(), ownerKey = this.owner } = {}) {
    const payload = { type, body, nonce, epoch, expiresAt: Date.now() + ttlMs, account: this.account };
    return { envs: roles.map(r => (r === 'owner' ? signEnvelope(DOMAINS.OWNER, payload, ownerKey.privatePem, ownerKey.publicPem) : signEnvelope(DOMAINS.RECOVERY, payload, this.recovery.privatePem, this.recovery.publicPem))) };
  }
}
