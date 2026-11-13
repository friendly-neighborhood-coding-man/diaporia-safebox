// In-process V4 world: Root service (V4 state machine), Recovery service V4, challenge service, tally service,
// Execution Vault (replaying the V4 chain itself), Mock Ledger, independent V4 verifier and the owner world.
// LOGICAL boundaries only in this mode (the OS-separated run is scripts/v4/os-services.mjs).
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryClock } from '../v2/common/clock.mjs';
import { newSigner } from '../v2/common/crypto.mjs';
import { DirectClient } from '../v2/common/wire.mjs';
import { MockLedger, ledgerOps } from '../v2/mock-ledger/ledger.mjs';
import { SensitiveStore } from '../v2/sensitive/store.mjs';
import { ACCOUNT } from '../v3/kit.mjs';
import { RootService, rootOps } from '../v3/root/service.mjs';
import { ExecutionVault, vaultOps } from '../v3/vault/vault.mjs';
import { iso } from '../v3/common/canon.mjs';
import * as V4 from './root/chain.mjs';
import { OwnerWorldV4 } from './kit.mjs';
import { RecoveryServiceV4 } from './recovery/service.mjs';
import { verifyV4 } from './supervisor/verifier.mjs';

export const T0 = Date.parse('2026-11-14T00:00:00.000Z');
export const ATTACKER = 'attacker.mock';
export const LEDGER_GENESIS = Object.freeze({ [ACCOUNT]: '30000000000000000000000000', 'merchant-a.mock': '0', 'merchant-b.mock': '0', 'merchant-c.mock': '0', [ATTACKER]: '0' });
export const GENESIS_TOTAL = Object.values(LEDGER_GENESIS).reduce((s, v) => s + BigInt(v), 0n).toString();

export function buildV4({ dir, clock, config = {}, config4 = {}, capsule = {}, bufferMs = 600_000, ownerWorld = null, apcCreds, displays } = {}) {
  dir ??= mkdtempSync(join(tmpdir(), 'sbx4-'));
  clock ??= new MemoryClock(T0);
  const now = () => clock.now();
  const wall = { t: 1_000_000, now() { return this.t; } };
  const owner = ownerWorld ?? new OwnerWorldV4({ t0: clock.now(), profile: 'personal', config, capsule, config4, apcCreds, displays });
  const genesis = owner.genesis4();
  owner.challengeService(now);
  const executor = newSigner('v4-executor');
  const ledger = new MockLedger(join(dir, 'ledger.db'), { now });
  ledger.genesis({ executorAccount: ACCOUNT, executorKey: executor.publicKey, ownerKey: executor.publicKey, accounts: LEDGER_GENESIS, maxPaymentYocto: '60000000000000000000000' });
  const lops = ledgerOps(ledger);
  const ledgerExec = new DirectClient(lops.exec), ledgerRead = new DirectClient(lops.read);
  const inbox = {}; const intents = new Set(); const attackerCaseIds = new Set();
  const w = { dir, clock, now, wall, owner, genesis, executor, ledger, ledgerRead, inbox, intents, attackerCaseIds, pendingEffects: [], chain: V4 };
  const openRoot = () => new RootService({ genesis, pinnedChainId: owner.chainId4, dbPath: join(dir, 'root.db'), now, chain: V4, onEffects: (fx, t) => { w.pendingEffects.push({ fx, t }); } });
  w.root = openRoot(); w.rootOps = rootOps(w.root); w.admin = new DirectClient(w.rootOps.admin);
  w.publicRoot = { request: (op, a) => new DirectClient({ SUBMIT: w.rootOps.admin.SUBMIT, VIEW: w.rootOps.admin.VIEW }).request(op, a) };
  const openVault = () => new ExecutionVault({ genesis, pinnedChainId: owner.chainId4, executorAccount: ACCOUNT, bufferMs, minBufferMs: 600_000, chain: V4 },
    { store: new SensitiveStore(join(dir, 'vault.db'), { now }), now, wallNow: () => wall.now(), executorSigner: executor, ledger: ledgerExec });
  w.vault = openVault(); w.vops = vaultOps(w.vault); w.gz = new DirectClient(w.vops.gz); w.vctl = new DirectClient(w.vops.ctl);
  w.recovery = new RecoveryServiceV4({ notifier: owner.serviceKeyPairs.notifier, now, view: () => w.root.view(), deliver: async (ch, msg) => { (inbox[ch] ??= []).push(msg); }, submit: async (req) => w.root.submit(req) });
  w.challenge = owner.challenge;
  w.restartVault = () => { w.vault.store.close(); w.vault = openVault(); w.vops = vaultOps(w.vault); w.gz = new DirectClient(w.vops.gz); w.vctl = new DirectClient(w.vops.ctl); return w.vault; };
  w.restartRoot = () => { try { w.root.close(); } catch {} w.root = openRoot(); w.rootOps = rootOps(w.root); w.admin = new DirectClient(w.rootOps.admin); return w.root; };
  w.pump = async () => {
    for (let i = 0; i < 4 && w.pendingEffects.length; i++) { const batch = w.pendingEffects.splice(0); for (const { fx } of batch) await w.recovery.onEffects(fx, w.root.state); }
    return w.vctl.call('SYNC_ROOT', { transitions: w.root.chain(w.vault.root.seq) });
  };
  w.view = () => ({ ...w.root.view(), now: now() });
  const submit = async (req) => { const r = await w.admin.request('SUBMIT', { request: req }); await w.pump(); return r; };
  w.submit = submit;
  /** Owner high-risk action through the trusted confirmation ceremony (one grant + prompt per credential). */
  w.ownerAct = async (type, body, credIds, extra = {}) => {
    const a = owner.action(w.view(), type, body, extra.actionOpts ?? {});
    if (!extra.notIntended) intents.add(V4.actionDigest(a).toString('hex'));
    const req = { action: a, approvals: owner.authorize(w.root.state, a, credIds, extra.authOpts ?? {}) };
    if (extra.guardians) req.guardianApprovals = owner.guardianApprovals(a, extra.guardians);
    if (extra.attestation) req.attestation = extra.attestation(a);
    return submit(req);
  };
  /** V3-style (action-digest) approvals, for protective actions and for negative tests. */
  w.legacyAct = async (type, body, credIds, extra = {}) => { const a = owner.action(w.view(), type, body); if (!extra.notIntended) intents.add(V4.actionDigest(a).toString('hex')); return submit({ action: a, approvals: owner.approvals(a, credIds) }); };
  w.submitRaw = async (type, body, { attest = null, approvals = null, guardians = null, intended = true, actionOpts = {} } = {}) => {
    const a = owner.action(w.view(), type, body, actionOpts);
    if (intended) intents.add(V4.actionDigest(a).toString('hex'));
    const req = { action: a };
    if (approvals) req.approvals = approvals(a);
    if (guardians) req.guardianApprovals = owner.guardianApprovals(a, guardians);
    if (attest) req.attestation = attest(a);
    return submit(req);
  };
  w.pay = async ({ credId = 'k1-phone', recipientId = 'merchant-a.mock', amountYocto = (3n * 10n ** 22n).toString(), sku = '-', over = {}, request = {} } = {}) => {
    const pc = owner.paycap(w.view(), { credId, recipientId, amountYocto, sku, over });
    return w.gz.request('PROPOSE', { capability: pc.capability, approval: pc.approval, recipientId: pc.capability.recipientId, amountYocto: pc.capability.amountYocto, asset: 'NEAR', memo: 'owner purchase', ...request });
  };
  w.advance = async (ms, step = 60_000) => { let left = ms; while (left > 0) { const d = Math.min(step, left); clock.advance(d); wall.t += 1; left -= d; await w.vctl.call('HEARTBEAT', {}); await w.pump(); await w.vctl.call('TICK', {}); } };
  w.verify = async () => verifyV4({ genesis, pinnedChainId: owner.chainId4, transitions: w.root.chain(0), ledgerTxs: await ledgerRead.call('TRANSFERS', { sinceSeq: '0' }),
    evidence: await w.vctl.call('EVIDENCE', {}), ownerIntents: intents, attackerCaseIds });
  w.iso = iso;
  return w;
}
