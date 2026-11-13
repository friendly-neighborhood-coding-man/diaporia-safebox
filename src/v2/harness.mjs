// In-process experiment harness (modes A/B/C) — LOGICAL boundary only (OS isolation not exercised).
import { buildWorld } from './world.mjs';
import { GeneralZone } from './general/zone.mjs';
import { Controller, repairWorkflow } from './supervisor/controller.mjs';
import { spawnSync } from 'node:child_process';
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

/** In-process failure-repair handler: patch = restart the Sensitive Zone without the (drill) flaw. */
export function inProcessRepair({ regressionCmd = null } = {}) {
  const repairs = [];
  const handler = async (ev, ctl, w, gzone) => {
    if (repairs.length >= 3) return false;
    const cur = w.freezeStore.current();
    const r = await repairWorkflow({ controller: ctl, freezeRecord: cur,
      patch: async () => { w.restartSensitive({ injectFlaw: null }); w.watchdog.drillHideFlawFlag = false; return { ok: true, change: 'injectFlaw -> null (restart Sensitive Zone)' }; },
      replay: (i) => gzone.replay(i),
      mutate: async (culprit) => { const m = await ctl.runEvent({ i: 'mut_' + culprit.i, t: w.now(), hour: null, label: 'attack', technique: culprit.technique, amountYocto: culprit.requestedAmountYocto, merchant: culprit.merchant }); m.mutation = true; return m.zone; },
      regression: async () => { if (!regressionCmd) return { ok: true, skipped: 'no regression command (unit context)' };
        const x = spawnSync(regressionCmd[0], regressionCmd.slice(1), { encoding: 'utf8' }); const pass = /# pass (\d+)/.exec(x.stdout)?.[1], fail = /# fail (\d+)/.exec(x.stdout)?.[1];
        return { ok: x.status === 0, pass: Number(pass), fail: Number(fail) }; },
      recover: (a) => w.watchdog.recover(a) });
    repairs.push(r);
    return r.resumed;
  };
  handler.repairs = repairs;
  return handler;
}
