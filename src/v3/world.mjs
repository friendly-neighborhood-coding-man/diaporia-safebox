// In-process V3 world: Root service, Recovery service, Execution Vault, Mock Ledger, independent verifier and the owner
// world, all with the same JSON IPC validation as the OS-isolated deployment. LOGICAL boundaries only in this mode.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryClock } from '../v2/common/clock.mjs';
import { newSigner } from '../v2/common/crypto.mjs';
import { DirectClient } from '../v2/common/wire.mjs';
import { MockLedger, ledgerOps } from '../v2/mock-ledger/ledger.mjs';
import { SensitiveStore } from '../v2/sensitive/store.mjs';
import { OwnerWorld, ACCOUNT, tr as mkTr } from './kit.mjs';
import { RootService, rootOps } from './root/service.mjs';
import { ExecutionVault, vaultOps } from './vault/vault.mjs';
import { RecoveryService } from './recovery/service.mjs';
import { verifyV3 } from './supervisor/verifier.mjs';
import { actionDigest } from './root/chain.mjs';
import { iso } from './common/canon.mjs';

export const T0 = Date.parse('2026-11-14T00:00:00.000Z');
export const MERCHANTS = Object.freeze(['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock']);
export const ATTACKER = 'attacker.mock';
export const LEDGER_GENESIS = Object.freeze({ [ACCOUNT]: '30000000000000000000000000', 'merchant-a.mock': '0', 'merchant-b.mock': '0', 'merchant-c.mock': '0', [ATTACKER]: '0' });
export const GENESIS_TOTAL = Object.values(LEDGER_GENESIS).reduce((s, v) => s + BigInt(v), 0n).toString();

export function buildV3({ dir, clock, profile = 'personal', config = {}, capsule = {}, bufferMs = 600_000, ownerWorld = null } = {}) {
  dir ??= mkdtempSync(join(tmpdir(), 'sbx3-'));
  clock ??= new MemoryClock(T0);
  const now = () => clock.now();
  const wall = { t: 1_000_000, now() { return this.t; } };
  const owner = ownerWorld ?? new OwnerWorld({ t0: clock.now(), profile, config, capsule });
  const genesis = owner.genesis();
  const executor = newSigner('v3-executor');
  const ledger = new MockLedger(join(dir, 'ledger.db'), { now });
  ledger.genesis({ executorAccount: ACCOUNT, executorKey: executor.publicKey, ownerKey: executor.publicKey, accounts: LEDGER_GENESIS, maxPaymentYocto: '60000000000000000000000' });
  const lops = ledgerOps(ledger);
  const ledgerExec = new DirectClient(lops.exec), ledgerRead = new DirectClient(lops.read), ledgerAdmin = new DirectClient(lops.admin);
  const inbox = {}; // channel id -> notifications delivered (owner-side mailboxes)
  const intents = new Set(); // ground truth: digests of actions the OWNER intended (supervisor-side label, never shown to attackers)
  const attackerCaseIds = new Set();
  const w = { dir, clock, now, wall, owner, genesis, executor, ledger, ledgerRead, ledgerAdmin, inbox, intents, attackerCaseIds, rootRejects: [] };

  const openRoot = () => new RootService({ genesis, pinnedChainId: owner.chainId, dbPath: join(dir, 'root.db'), now,
    onEffects: (fx, t) => { w.pendingEffects.push({ fx, t }); } });
  w.pendingEffects = [];
  w.root = openRoot();
  w.rootOps = rootOps(w.root);
  w.admin = new DirectClient(w.rootOps.admin);
  // PUBLIC Root port used by untrusted parties (the General Zone in red-team runs): same SUBMIT verification, nothing else.
  w.publicRoot = { request: (op, a) => new DirectClient({ SUBMIT: w.rootOps.admin.SUBMIT, VIEW: w.rootOps.admin.VIEW }).request(op, a) };
  const openVault = () => new ExecutionVault({ genesis, pinnedChainId: owner.chainId, executorAccount: ACCOUNT, bufferMs, minBufferMs: 600_000 },
    { store: new SensitiveStore(join(dir, 'vault.db'), { now }), now, wallNow: () => wall.now(), executorSigner: executor, ledger: ledgerExec });
  w.vault = openVault();
  w.vops = vaultOps(w.vault);
  w.gz = new DirectClient(w.vops.gz); w.vctl = new DirectClient(w.vops.ctl);
  w.recovery = new RecoveryService({ notifier: owner.serviceKeyPairs.notifier, now, view: () => w.root.view(),
    deliver: async (ch, msg) => { (inbox[ch] ??= []).push(msg); }, submit: async (req) => w.root.submit(req) });

  w.restartVault = () => { w.vault.store.close(); w.vault = openVault(); w.vops = vaultOps(w.vault); w.gz = new DirectClient(w.vops.gz); w.vctl = new DirectClient(w.vops.ctl); return w.vault; };
  w.restartRoot = () => { try { w.root.close(); } catch {} w.root = openRoot(); w.rootOps = rootOps(w.root); w.admin = new DirectClient(w.rootOps.admin); return w.root; };
  /** Propagate: recovery service reacts to root effects, vault syncs from the Root replica feed. */
  w.pump = async () => {
    for (let i = 0; i < 4 && w.pendingEffects.length; i++) {
      const batch = w.pendingEffects.splice(0);
      for (const { fx } of batch) await w.recovery.onEffects(fx, w.root.state);
    }
    return w.vctl.call('SYNC_ROOT', { transitions: w.root.chain(w.vault.root.seq) });
  };
  w.view = () => ({ ...w.root.view(), now: now() });
  /** Owner action: build, sign with the named credentials, submit through the admin (injection) port. */
  w.ownerAct = async (type, body, credIds, extra = {}) => {
    const a = owner.action(w.view(), type, body, extra.actionOpts ?? {});
    if (!extra.notIntended) intents.add(actionDigest(a).toString('hex'));
    const req = { action: a, approvals: owner.approvals(a, credIds, extra.approvalOpts ?? {}) };
    if (extra.guardians) req.guardianApprovals = owner.guardianApprovals(a, extra.guardians);
    if (extra.attestation) req.attestation = extra.attestation(a);
    const r = await w.admin.request('SUBMIT', { request: req });
    await w.pump();
    return r;
  };
  /** Raw submit (attestation-only transitions: guardians, IDV, channels, notifier, supervisor). */
  w.submitRaw = async (type, body, { attest = null, approvals = null, guardians = null, intended = true, actionOpts = {} } = {}) => {
    const a = owner.action(w.view(), type, body, actionOpts);
    if (intended) intents.add(actionDigest(a).toString('hex'));
    const req = { action: a };
    if (approvals) req.approvals = approvals(a);
    if (guardians) req.guardianApprovals = owner.guardianApprovals(a, guardians);
    if (attest) req.attestation = attest(a);
    const r = await w.admin.request('SUBMIT', { request: req });
    await w.pump();
    return r;
  };
  w.pay = async ({ credId = 'k1-phone', recipientId = 'merchant-a.mock', amountYocto = (3n * 10n ** 22n).toString(), sku = '-', over = {}, request = {} } = {}) => {
    const pc = owner.paycap(w.view(), { credId, recipientId, amountYocto, sku, over });
    return w.gz.request('PROPOSE', { capability: pc.capability, approval: pc.approval, recipientId: pc.capability.recipientId, amountYocto: pc.capability.amountYocto, asset: 'NEAR', memo: 'owner purchase', ...request });
  };
  /** Advance virtual time with watchdog heartbeat + vault ticks. */
  w.advance = async (ms, step = 60_000) => {
    let left = ms;
    while (left > 0) { const d = Math.min(step, left); clock.advance(d); wall.t += 1; left -= d; await w.vctl.call('HEARTBEAT', {}); await w.pump(); await w.vctl.call('TICK', {}); }
  };
  w.verify = async () => verifyV3({ genesis, pinnedChainId: owner.chainId, transitions: w.root.chain(0), ledgerTxs: (await ledgerRead.call('TRANSFERS', { sinceSeq: '0' })),
    evidence: await w.vctl.call('EVIDENCE', {}), ownerIntents: intents, attackerCaseIds });
  w.tr = (action, extra) => mkTr(w.root.state, now(), action, extra);
  w.iso = iso;
  return w;
}
