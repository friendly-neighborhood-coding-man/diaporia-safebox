// In-process V2 world: same components and the same JSON IPC validation as the OS-isolated
// deployment, but all zones share one process. Used for fast deterministic tests.
// IMPORTANT: this mode demonstrates LOGICAL boundaries only; OS isolation is NOT exercised here.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryClock } from './common/clock.mjs';
import { newSigner } from './common/crypto.mjs';
import { DirectClient } from './common/wire.mjs';
import { MockLedger, ledgerOps } from './mock-ledger/ledger.mjs';
import { SensitiveZone, SensitiveStore, sensitiveOps } from './sensitive/service.mjs';
import { OwnerSimulator } from './supervisor/owner.mjs';
import { Watchdog, FreezeStore } from './supervisor/watchdog.mjs';

export const T0 = Date.parse('2026-11-13T00:00:00.000Z');
export const EXECUTOR_ACCOUNT = 'safebox-exec.mock';
export const MERCHANTS = Object.freeze(['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock']);
export const ATTACKER = 'attacker.mock';
export const GENESIS = Object.freeze({ [EXECUTOR_ACCOUNT]: '30000000000000000000000000', 'merchant-a.mock': '0', 'merchant-b.mock': '0',
  'merchant-c.mock': '0', [ATTACKER]: '0', 'owner-alice.mock': '0', 'bob-shop.mock': '0' });
export const GENESIS_TOTAL = Object.values(GENESIS).reduce((s, v) => s + BigInt(v), 0n).toString();

export function buildWorld({ dir, clock, injectFlaw = null, settleDelayMs = 0, wall = null, auditFault = null, policyOver = {}, watchdogOpts = {} } = {}) {
  dir ??= mkdtempSync(join(tmpdir(), 'sbx2-'));
  clock ??= new MemoryClock(T0);
  const now = () => clock.now();
  const wallClock = wall ?? { t: 1_000_000, now() { return this.t; } };
  const wallNow = () => wallClock.now();
  const owner = new OwnerSimulator({ now });
  const executor = newSigner('executor');
  const ledger = new MockLedger(join(dir, 'ledger.db'), { now });
  ledger.genesis({ executorAccount: EXECUTOR_ACCOUNT, executorKey: executor.publicKey, ownerKey: owner.operatorKey, accounts: GENESIS,
    maxPaymentYocto: '60000000000000000000000', settleDelayMs });
  const lops = ledgerOps(ledger);
  const ledgerExec = new DirectClient(lops.exec), ledgerRead = new DirectClient(lops.read), ledgerAdmin = new DirectClient(lops.admin);
  let cfg = { trustedOwnerKeys: owner.trustedOwnerKeys(), operatorKey: owner.operatorKey, executorAccount: EXECUTOR_ACCOUNT, minBufferMs: 600_000, leaseMs: 5_000, injectFlaw };
  const openZone = () => new SensitiveZone(cfg, { store: new SensitiveStore(join(dir, 'sensitive.db'), { now, auditFault }), now, wallNow, executorSigner: executor, ledger: ledgerExec });
  let zone = openZone();
  let sops = sensitiveOps(zone);
  const world = {
    dir, clock, now, wallClock, owner, executor, ledger, ledgerRead, ledgerAdmin, ledgerExec, cfg,
    get zone() { return zone; },
    gz: new DirectClient(sops.gz), ctl: new DirectClient(sops.ctl),
    freezeStore: new FreezeStore(join(dir, 'freeze.jsonl')),
    restartSensitive(over = null) { zone.store.close(); if (over) { cfg = { ...cfg, ...over }; world.cfg = cfg; } zone = openZone(); sops = sensitiveOps(zone); world.gz = new DirectClient(sops.gz); world.ctl = new DirectClient(sops.ctl); world.watchdog.sensCtl = world.ctl; return zone; },
  };
  world.watchdog = new Watchdog({ ledgerRead, ledgerAdmin, sensCtl: world.ctl, owner, freezeStore: world.freezeStore, now, wallNow,
    executorKey: executor.publicKey, genesisTotalYocto: GENESIS_TOTAL, ...watchdogOpts });
  world.loadPolicies = async () => {
    await world.ctl.call('LOAD_POLICY', { policy: owner.policy('owner_alice', policyOver) });
    await world.ctl.call('LOAD_POLICY', { policy: owner.policy('owner_bob', { allowedRecipients: ['merchant-c.mock', 'bob-shop.mock'], ...policyOver }) });
  };
  /** Advance virtual time in steps, letting the watchdog heartbeat and the zone process releases. */
  world.advance = async (ms, step = 60_000) => {
    let left = ms;
    while (left > 0) { const d = Math.min(step, left); clock.advance(d); wallClock.t += 1; left -= d; await world.watchdog.scan(); await world.ctl.call('TICK', {}); }
    return world.watchdog.scan();
  };
  return world;
}
