// In-process V6 world = the V5 world (Root, Recovery, challenge service, Vault, Mock Ledger, Footprint Journal,
// Risk Engine, Notification outbox, owner world) with the V6 Root state machine, the V6 Vault and the V6 owner world.
// LOGICAL boundaries only; MOCK ledger; simulated owner devices unless a real-device bridge is plugged in.
import { buildV5, T0, ATTACKER, LEDGER_GENESIS, NEAR, near } from '../v5/world.mjs';
import * as V6 from './root/chain.mjs';
import { ExecutionVaultV6 } from './vault/vault.mjs';
import { OwnerWorldV6, ACCOUNT } from './kit.mjs';
import { SimulatedFingerprintGate } from './device/biometric.mjs';
import { NotificationServiceV6 } from './notify/notify6.mjs';

export { T0, ATTACKER, LEDGER_GENESIS, NEAR, near, ACCOUNT };

/**
 * opts.policy6: assurance-policy overrides; opts.fingerprintOnly: credIds that must use FINGERPRINT_ONLY (simulated
 * gate devices are created for them unless opts.gates is given; opts.noGateDevice lists creds whose sensor is absent).
 */
export function buildV6(opts = {}) {
  const fpOnly = opts.fingerprintOnly ?? [];
  const gates = opts.gates ?? Object.fromEntries(fpOnly.filter(c => !(opts.noGateDevice ?? []).includes(c)).map(c => [c, new SimulatedFingerprintGate({ credId: c })]));
  const policy6 = { ...(opts.policy6 ?? {}), fingerprintOnlyCreds: fpOnly, ...(opts.policy6?.fingerprintOnlyCreds ? { fingerprintOnlyCreds: opts.policy6.fingerprintOnlyCreds } : {}) };
  const t0 = opts.clock?.now?.() ?? T0;
  const ownerWorld = opts.ownerWorld ?? new OwnerWorldV6({ t0, profile: 'personal', config: opts.config ?? {}, capsule: opts.capsule ?? {}, config4: opts.config4 ?? {}, config5: opts.config5 ?? {},
    apcCreds: opts.apcCreds, displays: opts.displays, policy6, gates, rp: opts.rp });
  const w = buildV5({ ...opts, ownerWorld, chain: V6, Vault: ExecutionVaultV6, genesisOf: (o) => o.genesis6(), pinnedOf: (o) => o.chainId6,
    notifyClass: opts.notifyClass ?? NotificationServiceV6, notifyOpts: { emergencyOrigin: ownerWorld.policy6.emergency.origin, locatorTtlMs: Number(ownerWorld.policy6.emergency.locatorTtlMs), ...(opts.notifyOpts ?? {}) } });
  w.gates = gates;
  const v5pay = w.pay;
  /** Owner payment through the V6 owner device ceremony (per-transaction approval); V5 path only under LEGACY_V5. */
  w.pay = async ({ credId = 'k1-phone', recipientId = 'merchant-a.mock', amountYocto = (3n * 10n ** 22n).toString(), request = {}, decide, noGate, tamper, requestId, requestDigest, memo } = {}) => {
    if (w.root.state.v6.policy.payment.mode === 'LEGACY_V5') return v5pay({ credId, recipientId, amountYocto, request });
    const pa = w.owner.paymentApproval(w.root.state, { credId, recipientId, amountYocto, at: w.now(), decide, noGate, tamper, requestId, requestDigest, memo });
    if (!pa) return { ok: false, error: { code: w.owner.gateErrors.at(-1)?.code ?? 'OWNER_DECLINED' }, declined: true };
    w.lastApproval = pa;
    return w.gz.request('PROPOSE', { capability: pa.capability, approval: pa.approval, recipientId: pa.capability.recipientId, amountYocto: pa.capability.amountYocto, asset: 'NEAR', memo: request.memo ?? 'owner purchase', ...request });
  };
  w.v5pay = v5pay;
  return w;
}
