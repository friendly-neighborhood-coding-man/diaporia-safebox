// In-process V5 world: Root (V5 state machine) + Recovery V4 service + challenge service + Execution Vault V5 (own Root
// replica, anomaly delay, Rapid-Use acceleration, delegated execution) + Mock Ledger + Footprint Journal (with two
// witnesses) + Risk Policy Engine (own key) + Notification outbox (MOCK transport only) + owner world.
// LOGICAL boundaries only (separate objects, separate keys, separate SQLite files); no OS isolation is claimed here.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { MemoryClock } from '../v2/common/clock.mjs';
import { newSigner } from '../v2/common/crypto.mjs';
import { DirectClient } from '../v2/common/wire.mjs';
import { MockLedger, ledgerOps } from '../v2/mock-ledger/ledger.mjs';
import { SensitiveStore } from '../v2/sensitive/store.mjs';
import { RootService, rootOps } from '../v3/root/service.mjs';
import { vaultOps } from '../v3/vault/vault.mjs';
import { iso, nonce as mkNonce } from '../v3/common/canon.mjs';
import * as V5 from './root/chain.mjs';
import { holdDigest } from './root/holds.mjs';
import { OwnerWorldV5, ACCOUNT } from './kit.mjs';
import { RecoveryServiceV4 } from '../v4/recovery/service.mjs';
import { ExecutionVaultV5 } from './vault/vault.mjs';
import { FootprintJournal } from './journal/journal.mjs';
import { RiskPolicyEngine } from './risk/engine.mjs';
import { NotificationService, MockTransport } from './notify/notify.mjs';
import { V5_DOMAINS, d5hex, newSigner5 } from './common/v5.mjs';
import { EvidenceAPI, metricRecomputer, corroborator, deterministicFindings } from './analyst/analyst.mjs';
import { buildReport, renderReportText } from './report/report.mjs';
import { bufferFloorMs } from './risk/buffer.mjs';

export const T0 = Date.parse('2026-11-14T00:00:00.000Z');
export const ATTACKER = 'attacker.mock';
export const LEDGER_GENESIS = Object.freeze({ [ACCOUNT]: '30000000000000000000000000', 'merchant-a.mock': '0', 'merchant-b.mock': '0', 'merchant-c.mock': '0', [ATTACKER]: '0' });
export const NEAR = 10n ** 24n;
export const near = (x) => (BigInt(Math.round(x * 1000)) * NEAR / 1000n).toString();

/** Root transitions that matter to the Footprint Journal (ROOT layer). */
const ROOT_EVENT = (type) => ({ FREEZE: 'HOLD_CREATED', HOLD_CREATE: 'HOLD_CREATED', SUSPEND: 'HOLD_CREATED', HOLD_CONFIRM: 'HOLD_CONFIRMED', HOLD_RELEASE: 'HOLD_RELEASED', UNSUSPEND: 'HOLD_RELEASED',
  CONTEST_PROTECTIVE_HOLD: 'HOLD_CONTESTED', HOLD_EXPIRE: 'HOLD_HOUSEKEEPING', REVOKE: 'CREDENTIAL_REVOKED', ENROLL: 'CREDENTIAL_ENROLLED', ROTATE: 'CREDENTIAL_ROTATED',
  RECOVERY_OPEN: 'RECOVERY_OPENED', RECOVERY_EXECUTE: 'RECOVERY_EXECUTED', RECOVERY_CANCEL: 'RECOVERY_CANCELLED', PURPOSE_CHANGE: 'PURPOSE_CHANGED',
  DELEGATION_GRANT: 'DELEGATION_GRANTED', DELEGATION_REVOKE: 'DELEGATION_REVOKED', RAPID_USE_REQUEST: 'RAPID_USE_REQUESTED', RAPID_USE_APPROVE: 'RAPID_USE_VOTE',
  RAPID_USE_ACTIVATE: 'RAPID_USE_ACTIVATED', RAPID_USE_REVOKE: 'RAPID_USE_REVOKED', RAPID_USE_EXPIRE: 'RAPID_USE_HOUSEKEEPING', INCIDENT_REVIEW: 'INCIDENT_REVIEWED' }[type] ?? 'ROOT_TRANSITION');

export function buildV5({ dir, clock, config = {}, config4 = {}, config5 = {}, capsule = {}, bufferMs = 600_000, ownerWorld = null, transport = null, apcCreds, displays, journalOpts = {} } = {}) {
  dir ??= mkdtempSync(join(tmpdir(), 'sbx5-'));
  clock ??= new MemoryClock(T0);
  const now = () => clock.now();
  const wall = { t: 1_000_000, now() { return this.t; } };
  const owner = ownerWorld ?? new OwnerWorldV5({ t0: clock.now(), profile: 'personal', config, capsule, config4, config5, apcCreds, displays });
  const genesis = owner.genesis5();
  owner.challengeService(now);
  const executor = newSigner('v5-executor');
  const ledger = new MockLedger(join(dir, 'ledger.db'), { now });
  ledger.genesis({ executorAccount: ACCOUNT, executorKey: executor.publicKey, ownerKey: executor.publicKey, accounts: LEDGER_GENESIS, maxPaymentYocto: '60000000000000000000000' });
  const lops = ledgerOps(ledger);
  const ledgerExec = new DirectClient(lops.exec), ledgerRead = new DirectClient(lops.read);
  const journal = new FootprintJournal({ path: join(dir, 'journal.db'), now, accountId: ACCOUNT, ...journalOpts });
  const rootJ = journal.writer('ROOT');
  const engine = new RiskPolicyEngine({ signer: owner.riskEngine, journal: journal.writer('RISK') });
  const mock = transport ?? new MockTransport();
  const notify = new NotificationService({ path: join(dir, 'outbox.db'), now, transport: mock, addressBook: owner.addressBook, journal: journal.writer('NOTIFY'), accountId: ACCOUNT });
  const inbox = {}; const intents = new Set(); const attackerCaseIds = new Set();
  const w = { dir, clock, now, wall, owner, genesis, executor, ledger, ledgerRead, inbox, intents, attackerCaseIds, pendingEffects: [], chain: V5, journal, engine, notify, mock, ACCOUNT,
    engineQueue: [], rejects: [], near };
  const openRoot = () => new RootService({ genesis, pinnedChainId: owner.chainId5, dbPath: join(dir, 'root.db'), now, chain: V5, onEffects: (fx, t) => { w.pendingEffects.push({ fx, t }); } });
  w.root = openRoot(); w.rootOps = rootOps(w.root); w.admin = new DirectClient(w.rootOps.admin);
  const keyContext = (state, affected = null) => {
    const out = {};
    for (const c of Object.values(state.creds)) (out[c.holderId] ??= []).push(`${c.credId === affected ? 'AFFECTED ' : 'enrolled '}${c.credId} (${c.role}, ${c.status})`);
    return out;
  };
  const onIncident = ({ incident, ev, root }) => {
    const hasOwners = V5.ownerPrincipals(root).length > 0;
    notify.enqueue(root, { incident: { incidentId: incident.incident_id, reason: 'unusual spending pattern', pattern: ev.reasons.map(r => r.code).join(', ') },
      kind: 'INCIDENT', keyContextByHolder: keyContext(root, incident.cred_id), delayStatus: `unsettled payments of the affected flow are delayed up to ${Math.round(Number(ev.policy?.delay?.anomalyDelayMs ?? 21_600_000) / 3600_000)} h; settled payments cannot be stopped`, rapidAvailable: hasOwners });
  };
  const onRapidRule = ({ grantId, ruleId, evidence }) => { w.engineQueue.push({ grantId, ruleId, evidence }); };
  const floor = bufferFloorMs(genesis.ext.action.body.config.bufferPolicy);
  const openVault = () => new ExecutionVaultV5({ genesis, pinnedChainId: owner.chainId5, executorAccount: ACCOUNT, bufferMs: floor === 600_000 ? bufferMs : floor, minBufferMs: floor, chain: V5 },
    { store: new SensitiveStore(join(dir, 'vault.db'), { now }), now, wallNow: () => wall.now(), executorSigner: executor, ledger: ledgerExec,
      engine, enginePublicKey: owner.riskEngine.publicKey, journal, onIncident, onRapidRule });
  w.vault = openVault(); w.vops = vaultOps(w.vault); w.gz = new DirectClient(w.vops.gz); w.vctl = new DirectClient(w.vops.ctl);
  w.recovery = new RecoveryServiceV4({ notifier: owner.serviceKeyPairs.notifier, now, view: () => w.root.view(), deliver: async (ch, msg) => { (inbox[ch] ??= []).push(msg); }, submit: async (req) => w.root.submit(req) });
  w.challenge = owner.challenge;
  w.restartVault = () => { w.vault.store.close(); w.vault = openVault(); w.vops = vaultOps(w.vault); w.gz = new DirectClient(w.vops.gz); w.vctl = new DirectClient(w.vops.ctl); return w.vault; };
  w.restartRoot = () => { try { w.root.close(); } catch {} w.root = openRoot(); w.rootOps = rootOps(w.root); w.admin = new DirectClient(w.rootOps.admin); return w.root; };

  /** Every Root submission is journaled (ROOT layer): accepted transitions in full, rejections as rate-limited attempts. */
  const submitRoot = async (req, { principal = null } = {}) => {
    const type = String(req?.action?.type ?? '?').slice(0, 40);
    const signers = (req.approvals ?? []).map(a => String(a?.credId ?? '?'));
    const env = await w.admin.request('SUBMIT', { request: req });
    if (env.ok) {
      const r = env.result;
      rootJ.append({ type: ROOT_EVENT(type), principal: signers.length ? signers.map(c => journal.ref('cred', c)).join('+') : (principal ?? (req.attestation ? 'service' : 'housekeeping')),
        operationDigest: d5hex(V5_DOMAINS.COMMAND, req.action), relatedId: 'seq-' + r.seq, outcome: 'ACCEPTED', epoch: w.root.state.epoch, purposeVersion: w.root.state.purpose.version,
        data: { action: type, effects: r.effects.map(e => e.type).slice(0, 12).join(','), levels: (r.effects.find(e => e.type === 'CONFIRMATION_ASSURANCE')?.levels ?? []).map(x => { const i = x.lastIndexOf(':'); return journal.ref('cred', x.slice(0, i)) + x.slice(i); }).join(',') } });
    } else {
      w.rejects.push({ type, code: env.error.code, detail: env.error.detail ?? '' });
      rootJ.attempt({ type: 'ROOT_REJECTED', principal: signers.length ? signers.map(c => journal.ref('cred', c)).join('+') : (principal ?? '-'), outcome: String(env.error.code), data: { action: type } });
    }
    return env;
  };
  w.pump = async () => {
    for (let i = 0; i < 4 && w.pendingEffects.length; i++) {
      const batch = w.pendingEffects.splice(0);
      for (const { fx } of batch) {
        await w.recovery.onEffects(fx, w.root.state);
        for (const e of fx) if (e.type === 'RAPID_USE_REQUESTED' || e.type === 'RAPID_USE_ACTIVATED')
          notify.enqueue(w.root.state, { incident: { incidentId: e.requestId ?? e.grantId, reason: e.type === 'RAPID_USE_REQUESTED' ? 'Rapid-Use Mode was requested' : 'Rapid-Use Mode was activated', pattern: 'owner-requested exception to the anomaly delay (same limits)' },
            kind: 'RAPID_USE', keyContextByHolder: keyContext(w.root.state), delayStatus: e.type === 'RAPID_USE_ACTIVATED' ? `active until ${e.expiresAt}` : 'pending independent approvals', rapidAvailable: true });
      }
    }
    const r = await w.vctl.call('SYNC_ROOT', { transitions: w.root.chain(w.vault.root.seq) });
    // predefined engine rule (R3 velocity ceiling during Rapid-Use) -> engine-attested RAPID_USE_REVOKE
    while (w.engineQueue.length) {
      const q = w.engineQueue.shift();
      if (w.root.state.v5.rapid.grants[q.grantId]?.status !== 'ACTIVE') continue;
      const a = owner.action(w.view(), 'RAPID_USE_REVOKE', { grantId: q.grantId, reason: 'risk engine predefined rule ' + q.ruleId });
      await submitRoot({ action: a, attestation: engine.rapidRevokeAttestation({ digestHex: V5.actionDigest(a).toString('hex') }, q.ruleId, q.evidence) }, { principal: 'risk-engine' });
      await w.vctl.call('SYNC_ROOT', { transitions: w.root.chain(w.vault.root.seq) });
    }
    return r;
  };
  w.view = () => ({ ...w.root.view(), now: now() });
  const submit = async (req, opts) => { const r = await submitRoot(req, opts); await w.pump(); return r; };
  w.submit = submit;
  w.action = (type, body, opts = {}) => owner.action(w.view(), type, body, opts);
  /** V5 command (Command Statement approvals) for V5-native operations. */
  w.cmd = async (type, body, credIds, extra = {}) => {
    const a = w.action(type, body, extra.actionOpts ?? {});
    if (!extra.notIntended) intents.add(V5.actionDigest(a).toString('hex'));
    const req = { action: a, approvals: owner.authorize5(w.root.state, a, credIds, { at: now(), ...(extra.authOpts ?? {}) }) };
    if (extra.attestation) req.attestation = extra.attestation(a);
    return submit(req);
  };
  /** V4 operation inside the V5 chain (V4 AuthorizationIntents, built against the projected state). */
  w.ownerAct = async (type, body, credIds, extra = {}) => {
    const a = w.action(type, body, extra.actionOpts ?? {});
    if (!extra.notIntended) intents.add(V5.actionDigest(a).toString('hex'));
    const req = { action: a, approvals: owner.authorize4(w.root.state, a, credIds, { at: now(), ...(extra.authOpts ?? {}) }) };
    if (extra.guardians) req.guardianApprovals = owner.guardianApprovals(a, extra.guardians);
    if (extra.attestation) req.attestation = extra.attestation(a);
    return submit(req);
  };
  w.submitRaw = async (type, body, { approvals = null, attest = null, actionOpts = {} } = {}) => {
    const a = w.action(type, body, actionOpts); const req = { action: a };
    if (approvals) req.approvals = approvals(a);
    if (attest) req.attestation = attest(a);
    return submit(req);
  };
  w.holdDigest = (holdId) => holdDigest(w.root.state, w.root.state.v5.holds[holdId]);
  w.hold = (holdId) => w.root.state.v5.holds[holdId];
  w.effectiveHolds = () => V5.effectiveHolds(V5.projectState(w.root.state, now()), now());
  w.frozen = () => V5.projectState(w.root.state, now()).freeze.active;
  w.supervisorFreeze = async (freezeId, reason = 'supervisor: invariant violation observed') =>
    w.submitRaw('FREEZE', { freezeId, reason, source: 'supervisor' }, { attest: (a) => ({ supervisorSig: owner.supervisorFreezeSign(a) }) });
  w.pay = async ({ credId = 'k1-phone', recipientId = 'merchant-a.mock', amountYocto = (3n * 10n ** 22n).toString(), sku = '-', over = {}, request = {} } = {}) => {
    const pc = owner.paycap(w.view(), { credId, recipientId, amountYocto, sku, over });
    return w.gz.request('PROPOSE', { capability: pc.capability, approval: pc.approval, recipientId: pc.capability.recipientId, amountYocto: pc.capability.amountYocto, asset: 'NEAR', memo: request.memo ?? 'owner purchase', ...request });
  };
  /** Delegate-signed operation within a DELEGATION_GRANT scope. */
  w.delegateOp = (delegationId, seq, { recipientId = 'merchant-a.mock', amountYocto = (1n * 10n ** 22n).toString(), memo = 'agent purchase', key = null, opId = null } = {}) => {
    const k = key ?? owner.delegates[delegationId];
    const op = { v: 'safebox.v5.delegated-op', delegationId, seq: String(seq), recipientId, asset: 'NEAR', amountYocto, opId: opId ?? randomBytes(8).toString('hex'), issuedAt: iso(now()), memo };
    return { op, sig: k.signObj(V5_DOMAINS.DELEGATED_OP, op) };
  };
  w.payDelegated = async (delegationId, seq, opts = {}) => { const { op, sig } = w.delegateOp(delegationId, seq, opts); return w.vault.proposeDelegated({ op, sig }); };
  /** Housekeeping: anyone may record that a hold / grant has already ended by time (no authority involved). */
  w.housekeep = async () => {
    const t = now();
    for (const h of Object.values(w.root.state.v5.holds)) if (h.status === 'ACTIVE' && h.expiresAt !== null && t >= Number(h.expiresAt)) { await submit({ action: w.action('HOLD_EXPIRE', { holdId: h.holdId }) }); }
    for (const g of Object.values(w.root.state.v5.rapid.grants)) if (g.status === 'ACTIVE' && t >= Number(g.expiresAt)) { await submit({ action: w.action('RAPID_USE_EXPIRE', { grantId: g.grantId }) }); }
  };
  w.advance = async (ms, step = 60_000) => {
    let left = ms;
    while (left > 0) { const d = Math.min(step, left); clock.advance(d); wall.t += 1; left -= d; await w.vctl.call('HEARTBEAT', {}); await w.housekeep(); await w.pump(); await w.vctl.call('TICK', {}); await notify.drain(); }
  };
  // read-only Security Analyst wiring (evidence view, engine-side recomputation and corroboration)
  w.analyst = { api: new EvidenceAPI(journal) };
  w.analyst.recompute = metricRecomputer(w.analyst.api);
  w.analyst.corroborate = (ref) => corroborator({ journal, vault: w.vault, engine })(ref);
  w.analyst.deterministic = () => deterministicFindings(w.analyst.api).map(f => engine.intakeFinding(f, { eventIds: w.analyst.api.eventIds(), recompute: w.analyst.recompute, corroborate: w.analyst.corroborate }));
  // signed periodic reports, delivered through the same MOCK outbox
  w.reportSigner = newSigner5('report-service');
  w.reports = [];
  w.report = (kind, opts = {}) => {
    const rep = buildReport({ kind, journal, signer: w.reportSigner, now: now(), ...opts });
    w.reports.push(rep);
    journal.writer('REPORT').append({ type: 'REPORT_ISSUED', relatedId: kind, outcome: 'SIGNED', data: { countsDigest: rep.statement.countsDigest, from: rep.statement.from, to: rep.statement.to } });
    notify.enqueue(w.root.state, { incident: { incidentId: `report-${kind.toLowerCase()}-${rep.statement.to}` }, kind: 'REPORT', render: () => ({ subject: `SafeBox ${kind} security report`, text: renderReportText(rep) }) });
    return rep;
  };
  w.newId = (p) => `${p}-${mkNonce().slice(0, 12)}`;
  w.iso = iso;
  return w;
}
export { ACCOUNT, OwnerWorldV5 };
