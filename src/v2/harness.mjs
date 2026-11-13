// In-process experiment harness (modes A/B/C) — LOGICAL boundary only (OS isolation not exercised).
import { buildWorld } from './world.mjs';
import { GeneralZone } from './general/zone.mjs';
import { Controller } from './supervisor/controller.mjs';
import { generateWorkload, summarize } from './traffic/schedule.mjs';
import { TECHNIQUES } from './general/attacks.mjs';
import { MERCHANTS, GENESIS_TOTAL } from './world.mjs';
import { DirectClient } from './common/wire.mjs';
import { sensitiveOps } from './sensitive/service.mjs';

export async function runInProcess({ seed, hours = 24, mode = 'B', techniques = TECHNIQUES, injectFlaw = null, onFrozen = null, worldOpts = {} }) {
  const w = buildWorld({ injectFlaw, ...worldOpts });
  await w.loadPolicies();
  await w.watchdog.scan();
  const gzone = new GeneralZone({ gz: w.gz, mode, now: w.now,
    extraClients: (n) => Array.from({ length: n }, () => new DirectClient(sensitiveOps(w.zone).gz)),
    syntheticMetadata: () => 'SBX2-FAKE-ADMIN-TOKEN', ledgerSubmitForTest: (tx) => w.ledgerExec.call('SUBMIT_TX', { tx }) });
  const workload = generateWorkload({ seed, hours, t0: w.now(), techniques, merchants: [...MERCHANTS] });
  const ctl = new Controller({ clock: w.clock, step: async () => { w.wallClock.t += 1; await w.watchdog.scan(); await w.ctl.call('TICK', {}); },
    owner: w.owner, worker: gzone, ledgerRead: w.ledgerRead, isFrozen: () => w.freezeStore.isFrozen(), executorKey: w.executor.publicKey,
    genesisTotalYocto: GENESIS_TOTAL, freezeLog: () => w.freezeStore.freezeLog() });
  ctl.revokeHook = (rev) => w.ctl.call('REVOKE_CAP', { revocation: rev });
  const result = await ctl.run(workload, { onFrozen: onFrozen ? (ev, c) => onFrozen(ev, c, w, gzone) : null });
  return { w, gzone, workload, workloadSummary: summarize(workload), result, watchdogEvents: w.watchdog.events, freezeRecords: w.freezeStore.records,
    sensitiveState: await w.ctl.call('STATE', {}), diagnoserSuggestions: gzone.diagnoser?.suggestions ?? [] };
}
