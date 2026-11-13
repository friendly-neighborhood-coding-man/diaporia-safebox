// Legitimate-owner recovery procedure (owner side), used by tests and campaigns to measure recovery success/latency.
// It only ever uses evidence the owner genuinely has: surviving devices, independent identity verification, guardians
// who check out-of-band, and new devices it enrolls itself.
import { Device, ACCOUNT } from '../kit.mjs';
import { actionDigest } from '../root/chain.mjs';

let seq = 0;
const ok = (r, what) => { if (!r.ok) throw Object.assign(new Error(`${what}: ${r.error.code} ${r.error.detail ?? ''}`), { code: r.error.code }); return r.result; };

/** Owner opens a case from a NEW device it controls, with a plan of fresh, independent credentials. */
export async function ownerOpenCase(w, { lost, full = false, kind = 'KEY_LOSS', subjectHolderId = 'alice', planHolder = subjectHolderId, caseId = null, attacker = false, planDevices = null }) {
  const st = w.root.state;
  const roles = full ? st.baseline.credIds.map(x => st.creds[x].role) : lost.map(x => st.creds[x]?.role ?? 'DAILY');
  const devices = planDevices ?? roles.map((role, i) => new Device({ credId: `${attacker ? 'evil' : 'new'}-${role.toLowerCase()}-${++seq}-${i}`, role, holderId: planHolder,
    channelId: Object.keys(st.channels).find(c => st.channels[c].holderId === planHolder) ?? Object.keys(st.channels)[0], kind: role === 'ROOT' || role === 'RECOVERY' ? 'ed25519' : 'passkey' }));
  if (!attacker) w.owner.devices.push(...devices);
  const id = caseId ?? `case-${++seq}`;
  if (attacker) w.attackerCaseIds.add(id);
  const a = w.owner.action(w.view(), 'RECOVERY_OPEN', { caseId: id, kind, lost, subjectHolderId, plan: [], note: attacker ? 'lost my keys' : 'owner lost devices' });
  a.body.plan = devices.map(d => d.enrollment(ACCOUNT, `${ACCOUNT}:${a.nonce}`));
  if (!attacker) w.intents.add(actionDigest(a).toString('hex'));
  const r = await w.admin.request('SUBMIT', { request: { action: a } });
  await w.pump();
  return { r, caseId: id, devices };
}

const cs = (w) => w.root.state.case;
const sub = (w, type, extra, opts) => w.submitRaw(type, { caseId: cs(w).caseId, caseDigest: cs(w).digest, ...extra }, opts);

export const evidence = {
  identity: (w, idv = 'idv-1', holderId = null) => sub(w, 'RECOVERY_IDENTITY', { idvId: idv, holderId: holderId ?? (cs(w).kind === 'KEY_LOSS' ? cs(w).subjectHolderId : cs(w).plan[0].holderId), method: 'document-and-liveness', result: 'VERIFIED' }, { attest: (a) => ({ idvSig: w.owner.idvSign(a, idv) }) }),
  official: (w, docType, reg = 'reg-gov') => sub(w, 'RECOVERY_OFFICIAL', { registrarId: reg, docType, docRef: 'doc-' + (++seq), subjectHolderId: cs(w).subjectHolderId }, { attest: (a) => ({ registrarSig: w.owner.registrarSign(a, reg) }) }),
  consent: (w, credId) => sub(w, 'RECOVERY_CONSENT', {}, { approvals: (a) => w.owner.approvals(a, [credId]) }),
  guardian: (w, gid, decision = 'APPROVE') => sub(w, 'RECOVERY_GUARDIAN', { guardianId: gid, decision }, { attest: (a) => ({ guardianSig: w.owner.guardianSign(a, gid, decision) }) }),
  ack: (w, ch, decision = 'NO_OBJECTION') => sub(w, 'RECOVERY_ACK', { channelId: ch, decision }, { attest: (a) => ({ channelSig: w.owner.channelSign(a, ch) }) }),
  object: (w, credId) => sub(w, 'RECOVERY_OBJECT', {}, { approvals: (a) => w.owner.approvals(a, [credId]), intended: false }),
  withdrawCred: (w, credId) => sub(w, 'RECOVERY_WITHDRAW', { channelId: '-' }, { approvals: (a) => w.owner.approvals(a, [credId]) }),
  override: (w) => sub(w, 'RECOVERY_OVERRIDE', {}),
  cancel: (w, credIds) => w.submitRaw('RECOVERY_CANCEL', { caseId: cs(w).caseId }, { approvals: (a) => w.owner.approvals(a, credIds) }),
};

/**
 * Full legitimate procedure after losing `lost` credentials. Returns { outcome, latencyMs, interventions, steps }.
 * outcome: RECOVERED | NEW_EPOCH | RECOVERY_IMPOSSIBLE | FAILED:<code>
 */
export async function legitimateRecovery(w, lost, { ackAll = true, early = true } = {}) {
  const t0 = w.now(); let interventions = 0; const steps = [];
  const step = async (name, p) => { const r = await p; steps.push({ name, ok: r.ok, code: r.ok ? null : r.error.code }); if (!r.ok) throw Object.assign(new Error(name + ':' + r.error.code), { code: r.error.code, detail: r.error.detail }); interventions++; return r.result; };
  try {
    const nBase = w.root.state.baseline.credIds.length;
    const full = lost.length * 2 > nBase;
    const o = await ownerOpenCase(w, { lost, full }); ok(o.r, 'open'); interventions++;
    if (cs(w).state !== 'IDENTITY_CHECK') throw Object.assign(new Error('not dispatched'), { code: 'NOT_DISPATCHED:' + cs(w).state });
    await step('identity-1', evidence.identity(w, 'idv-1'));
    if (cs(w).state === 'RECOVERY_IMPOSSIBLE') return { outcome: 'RECOVERY_IMPOSSIBLE', latencyMs: w.now() - t0, interventions, steps, lockdown: w.root.state.lockdown.active };
    const recon = cs(w).state === 'RECONSTITUTION' || cs(w).state === 'EMERGENCY_LOCKDOWN';
    if (recon) await step('identity-2', evidence.identity(w, 'idv-2'));
    const surv = (await import('../root/chain.mjs')).survivors(w.root.state, cs(w), w.now());
    for (const c of surv) await step('consent ' + c, evidence.consent(w, c));
    const gs = Object.keys(w.root.state.guardians).slice(0, recon ? Number(w.root.state.config.reconGuardianQuorum) : Number(w.root.state.config.guardianQuorum));
    for (const g of gs) await step('guardian ' + g, evidence.guardian(w, g));
    if (ackAll) for (const ch of Object.keys(w.root.state.channels)) await step('ack ' + ch, evidence.ack(w, ch));
    const waitMs = (!recon && early && ackAll) ? Number(w.root.state.config.minWindowMs) : Number(w.root.state.config.windowMs);
    await w.advance(Math.max(0, cs(w).openedAt + waitMs - w.now()) + 60_000, 3600_000);
    const res = await w.recovery.tryComplete(w.root.state);
    await w.pump();
    if (!res.ok) return { outcome: 'FAILED:' + (res.code ?? res.state), latencyMs: w.now() - t0, interventions, steps };
    const last = w.root.state.caseHistory.at(-1);
    return { outcome: last.outcome, latencyMs: w.now() - t0, interventions, steps, epoch: w.root.state.epoch };
  } catch (e) { return { outcome: 'FAILED:' + (e.code ?? e.message), detail: e.detail, latencyMs: w.now() - t0, interventions, steps }; }
}
