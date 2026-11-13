// V4 owner-side recovery procedures (legitimate owner + attacker helpers) and usability accounting.
// Human interactions and cryptographic signatures are counted SEPARATELY:
//   gestures   = physical owner confirmations (device prompt confirmed, new device registered, channel link clicked)
//   prompts    = authentication prompts shown to the owner (including declined ones)
//   signatures = every signature that lands on the Root chain (owner, guardians, IDVs, channels, notifier)
import { Device, ACCOUNT, SimulatedProtectedConfirmation } from '../kit.mjs';
import { actionDigest, survivors } from '../root/chain.mjs';

let seq = 0;
const cs = (w) => w.root.state.case;

/** Opens a recovery case from new devices. Owner-side plan devices get trusted-display / protected-confirmation metadata. */
export async function openCaseV4(w, { lost, full = false, subjectHolderId = 'alice', caseId = null, attacker = false, planDevices = null, orcAttest = null, planMeta = true }) {
  const st = w.root.state;
  const roles = full ? st.baseline.credIds.map(x => st.creds[x].role) : lost.map(x => st.creds[x]?.role ?? 'DAILY');
  const devices = planDevices ?? roles.map((role, i) => new Device({ credId: `${attacker ? 'evil' : 'new'}-${role.toLowerCase()}-${++seq}-${i}`, role, holderId: subjectHolderId,
    channelId: Object.keys(st.channels).find(c => st.channels[c].holderId === subjectHolderId) ?? Object.keys(st.channels)[0], kind: role === 'ROOT' || role === 'RECOVERY' ? 'ed25519' : 'passkey' }));
  if (!attacker) w.owner.devices.push(...devices);
  const id = caseId ?? `case-${++seq}`;
  if (attacker) w.attackerCaseIds.add(id);
  const a = w.owner.action(w.view(), 'RECOVERY_OPEN', { caseId: id, kind: 'KEY_LOSS', lost, subjectHolderId, plan: [], note: attacker ? 'lost my keys' : 'owner lost devices' });
  a.body.plan = devices.map(d => d.enrollment(ACCOUNT, `${ACCOUNT}:${a.nonce}`));
  if (planMeta) {
    const pm = {};
    for (const d of devices) {
      if (d.kind === 'ed25519') pm[d.credId] = { display: 'TRUSTED_DISPLAY' };
      else if (d.role === 'DAILY' || d.role === 'FREEZE') { const k = new SimulatedProtectedConfirmation(d.credId); if (!attacker) w.owner.apc[d.credId] = k; pm[d.credId] = { display: 'NONE', confirmer: { publicKey: k.publicKey, pop: k.pop(ACCOUNT, w.root.state.v3ChainId) } }; }
    }
    a.body.planMeta = pm;
  }
  if (!attacker) { w.intents.add(actionDigest(a).toString('hex')); w.owner.metrics.gestures += devices.length; w.owner.metrics.prompts += devices.length; } // one registration gesture per new device
  const req = { action: a };
  if (orcAttest) req.approvals = w.owner.authorize(w.root.state, a, [orcAttest]);
  const r = await w.submit(req);
  return { r, caseId: id, devices };
}

const sub = (w, type, extra, opts) => w.submitRaw(type, { caseId: cs(w).caseId, caseDigest: cs(w).digest, ...extra }, opts);
export const evidence4 = {
  identity: (w, idv = 'idv-1', holderId = null) => sub(w, 'RECOVERY_IDENTITY', { idvId: idv, holderId: holderId ?? cs(w).subjectHolderId, method: 'document-and-liveness', result: 'VERIFIED' }, { attest: (a) => ({ idvSig: w.owner.idvSign(a, idv) }) }),
  guardian: (w, gid, decision = 'APPROVE') => sub(w, 'RECOVERY_GUARDIAN', { guardianId: gid, decision }, { attest: (a) => ({ guardianSig: w.owner.guardianSign(a, gid, decision) }) }),
  ack: (w, ch, decision = 'NO_OBJECTION', { intended = true } = {}) => sub(w, 'RECOVERY_ACK', { channelId: ch, decision }, { attest: (a) => ({ channelSig: w.owner.channelSign(a, ch) }), intended }),
  consent: (w, credId, opts = {}) => sub(w, 'RECOVERY_CONSENT', {}, { approvals: (a) => w.owner.authorize(w.root.state, a, [credId], opts) }),
  object: (w, credId) => sub(w, 'RECOVERY_OBJECT', {}, { approvals: (a) => w.owner.approvals(a, [credId]), intended: false }),
  orcAuthorize: (w, orcId = 'orc-1', opts = {}) => sub(w, 'RECOVERY_OWNER_AUTHORIZE', { orcId }, { approvals: (a) => w.owner.authorize(w.root.state, a, [orcId], opts) }),
  orcCancel: (w, orcId = 'orc-1') => sub(w, 'RECOVERY_ORC_CANCEL', {}, { approvals: (a) => w.owner.authorize(w.root.state, a, [orcId]) }),
  cancel: (w, credIds) => w.submitRaw('RECOVERY_CANCEL', { caseId: cs(w).caseId }, { approvals: (a) => w.owner.authorize(w.root.state, a, credIds) }),
  override: (w) => sub(w, 'RECOVERY_OVERRIDE', {}),
  expire: async (w) => { const r = await w.recovery.tryExpire(w.root.state); await w.pump(); return r; },
};

function chainSignatures(w, fromSeq) {
  let n = 0; for (const t of w.root.chain(fromSeq)) n += (t.approvals?.length ?? 0) + (t.guardianApprovals?.length ?? 0) + Object.keys(t.attestation ?? {}).length; return n;
}

/**
 * Legitimate owner recovery in V4. Returns outcome + usability accounting.
 * opts: { orc: 'orc-1' | null (ORC available?), ackAll, early }
 */
export async function legitimateRecoveryV4(w, lost, { orc = 'orc-1', ackAll = true, early = true, honestGuardians = null, honestIdvs = null } = {}) {
  const t0 = w.now(), seq0 = w.root.state.seq, m0 = { ...w.owner.metrics };
  const steps = []; let independent = 0, acks = 0;
  const step = async (name, p, { independentSigner = false } = {}) => { const r = await p; steps.push({ name, ok: r.ok, code: r.ok ? null : r.error.code }); if (!r.ok) throw Object.assign(new Error(name + ':' + r.error.code), { code: r.error.code, detail: r.error.detail }); if (independentSigner) independent++; return r.result; };
  const report = (outcome, extra = {}) => ({ outcome, latencyMs: w.now() - t0, gestures: w.owner.metrics.gestures - m0.gestures + acks, prompts: w.owner.metrics.prompts - m0.prompts, channelAcks: acks,
    independentSignerInteractions: independent, signatures: chainSignatures(w, seq0), declined: w.owner.metrics.declined - m0.declined, steps, epoch: w.root.state.epoch, ...extra });
  try {
    const full = lost.length * 2 > w.root.state.baseline.credIds.length;
    let o = await openCaseV4(w, { lost, full });
    // the owner's ORC lifts the per-subject reattempt cooldown / claim budget (never the 1 h global anti-spam interval)
    if (!o.r.ok && /RECOVERY_REATTEMPT_COOLDOWN|RECOVERY_CLAIM_BUDGET_EXHAUSTED/.test(o.r.error.code) && orc && !w.owner.lostOrcs.has(orc)) {
      w.owner.devices.splice(w.owner.devices.length - o.devices.length, o.devices.length); // the refused open registered nothing
      w.owner.metrics.gestures -= o.devices.length; w.owner.metrics.prompts -= o.devices.length;
      o = await openCaseV4(w, { lost, full, orcAttest: orc });
    }
    if (!o.r.ok) return report('FAILED:open:' + o.r.error.code);
    if (cs(w).state !== 'IDENTITY_CHECK') return report('FAILED:NOT_DISPATCHED:' + cs(w).state);
    const idvs = honestIdvs ?? Object.keys(w.root.state.idvs);
    await step('identity-1', evidence4.identity(w, idvs[0]), { independentSigner: true });
    if (cs(w).state === 'RECOVERY_IMPOSSIBLE') { await w.advance(Math.max(0, cs(w).v4.deadline - w.now()) + 60_000, 3600_000); await evidence4.expire(w); return report('RECOVERY_IMPOSSIBLE', { lockdownAfter: w.root.state.lockdown.active }); }
    const recon = ['RECONSTITUTION', 'EMERGENCY_LOCKDOWN'].includes(cs(w).state);
    if (recon) await step('identity-2', evidence4.identity(w, idvs[1]), { independentSigner: true });
    for (const c of survivors(w.root.state, cs(w), w.now())) await step('consent ' + c, evidence4.consent(w, c));
    const gs = (honestGuardians ?? Object.keys(w.root.state.guardians).filter(g => w.root.state.guardians[g].status === 'active')).slice(0, recon ? Number(w.root.state.config.reconGuardianQuorum) : Number(w.root.state.config.guardianQuorum));
    for (const g of gs) await step('guardian ' + g, evidence4.guardian(w, g), { independentSigner: true });
    if (ackAll) for (const ch of Object.keys(w.root.state.channels)) { await step('ack ' + ch, evidence4.ack(w, ch)); acks++; }
    if (recon || !Object.values(cs(w).v4.consentLevels).some(l => l !== 'SOFTWARE_UI_LOWER_ASSURANCE')) {
      if (orc && !w.owner.lostOrcs.has(orc)) await step('orc-authorize', evidence4.orcAuthorize(w, orc));
    }
    const waitMs = (!recon && early && ackAll) ? Number(w.root.state.config.minWindowMs) : Number(w.root.state.config.windowMs);
    await w.advance(Math.max(0, cs(w).openedAt + waitMs - w.now()) + 60_000, 3600_000);
    const res = await w.recovery.tryComplete(w.root.state); await w.pump();
    if (!res.ok) {
      const code = res.code ?? res.state;
      await w.advance(Math.max(0, (cs(w)?.v4.deadline ?? 0) - w.now()) + 60_000, 3600_000);
      if (cs(w)) await evidence4.expire(w);
      return report('FAILED:' + code, { closedAs: w.root.state.caseHistory.at(-1)?.outcome });
    }
    return report(w.root.state.caseHistory.at(-1).outcome);
  } catch (e) { return report('FAILED:' + (e.code ?? e.message), { detail: e.detail }); }
}

// ---------------------------------------------------------------- R-3 governance helpers (owner + independent parties)
const gc = (w) => w.root.state.v4.gcase;
/** Builds verdict evidence from `adjIds` against `subjectId` (guardian | idv). */
export function verdicts(w, subjectId, adjIds, { finding = 'COMPROMISED', kind = null, key = null, at = null } = {}) {
  const st = w.root.state; const k = kind ?? (st.guardians[subjectId] ? 'guardian' : 'idv');
  const subjectKey = key ?? (st.guardians[subjectId] ?? st.idvs[subjectId])?.publicKey ?? 'unknown';
  return adjIds.map(a => w.owner.verdict(a, { subjectKind: k, subjectId, subjectKey, finding, at: at ?? w.now() }));
}
/** Opens a governance (participant replacement) case. Owner quorum via AuthorizationIntents; replacements prove possession. */
export async function openGov(w, { procedure = 'GUARDIAN_EMERGENCY_REPLACE', accused, ground = 'COMPROMISE', evidence = null, adj = ['adj-1', 'adj-2'], owners = ['k1-phone', 'k3-root-hw'],
  replacements = null, gcaseId = null, authOpts = {} }) {
  const id = gcaseId ?? `gcase-${++seq}`;
  const kind = procedure === 'GUARDIAN_EMERGENCY_REPLACE' ? 'guardian' : 'idv';
  const reps = replacements ?? accused.map((x, i) => w.owner.newParticipant(kind, `${kind === 'guardian' ? 'g' : 'idv'}-new-${seq}-${i}`, `${kind}-holder-${seq}-${i}`, id));
  const ev = evidence ?? (ground === 'COMPROMISE' || ground === 'MISCONDUCT' ? accused.flatMap(x => verdicts(w, x, adj, { finding: ground === 'COMPROMISE' ? 'COMPROMISED' : 'MISCONDUCT' }))
    : ground === 'WITHDRAWAL' ? accused.map(x => w.owner.withdrawal(x)) : []);
  const r = await w.ownerAct('GOV_CASE_OPEN', { gcaseId: id, procedure, accused, ground, evidence: ev, replacements: reps }, owners, { authOpts });
  return { r, gcaseId: id, replacements: reps };
}
export async function govVote(w, voterId, choice = 'APPROVE') {
  const g = gc(w); const b = w.owner.ballot(g, voterId, choice);
  return w.submitRaw('GOV_BALLOT', b.body, { attest: () => ({ voterSig: b.voterSig }) });
}
export async function govTally(w, { tamper = null } = {}) {
  const g = gc(w); const t = w.owner.tally.tally(g);
  if (tamper) tamper(t);
  return w.submitRaw('GOV_TALLY', t.statement, { attest: () => ({ tallySig: t.sig }) });
}
export async function govExecute(w) {
  await w.advance(Math.max(0, (gc(w)?.executeAfter ?? w.now()) - w.now()) + 60_000, 3600_000);
  const r = await w.recovery.tryGovExecute(w.root.state); await w.pump(); return r;
}
/** Full emergency replacement: open, notify (service), every remaining eligible member votes, tally, 24 h delay, execute. */
export async function emergencyReplace(w, opts, { voters = null, choice = 'APPROVE' } = {}) {
  const o = await openGov(w, opts); if (!o.r.ok) return { stage: 'open', code: o.r.error.code, detail: o.r.error.detail, o };
  const g = gc(w);
  for (const v of voters ?? g.electorate) { const r = await govVote(w, v, typeof choice === 'function' ? choice(v) : choice); if (!r.ok) return { stage: 'vote', code: r.error.code, voter: v, o }; }
  const t = await govTally(w); if (!t.ok) return { stage: 'tally', code: t.error.code, o };
  if (!gc(w)) return { stage: 'closed', outcome: w.root.state.v4.gcaseHistory.at(-1).outcome, o };
  const x = await govExecute(w); if (!x.ok) return { stage: 'execute', code: x.code, o };
  return { stage: 'done', outcome: w.root.state.v4.gcaseHistory.at(-1).outcome, o };
}
