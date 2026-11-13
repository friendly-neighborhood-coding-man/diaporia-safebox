// In-process V2-B harness: LOGICAL boundaries only (all zones share one process, so filesystem/exec/signal actions run
// with the test runner's privileges). Use it ONLY with ScriptedBrain for plumbing tests; real-LLM campaigns run in the
// OS-isolated launcher (scripts/v2b/run-redteam.mjs).
import { buildWorld, MERCHANTS, GENESIS_TOTAL } from '../v2/world.mjs';
import { Controller } from '../v2/supervisor/controller.mjs';
import { DirectClient } from '../v2/common/wire.mjs';
import { sensitiveOps } from '../v2/sensitive/service.mjs';
import { generateWorkload, summarize } from '../v2/traffic/schedule.mjs';
import { RedTeamZone } from './actuator.mjs';
import { Campaign, TECHNIQUE } from './campaign.mjs';
import { classify } from './classify.mjs';

export async function runRedTeamInProcess({ seed, hours = 4, brain, maxTurns = 10, rounds = 1, injectFlaw = null, worldOpts = {}, onFrozen = null }) {
  const w = buildWorld({ injectFlaw, ...worldOpts });
  await w.loadPolicies(); await w.watchdog.scan();
  const zone = new RedTeamZone({ gz: w.gz, now: w.now, makeClient: () => new DirectClient(sensitiveOps(w.zone).gz) });
  const ctl = new Controller({ clock: w.clock, step: async () => { w.wallClock.t += 1; await w.watchdog.scan(); await w.ctl.call('TICK', {}); },
    owner: w.owner, worker: zone, ledgerRead: w.ledgerRead, isFrozen: () => w.freezeStore.isFrozen(), executorKey: w.executor.publicKey,
    genesisTotalYocto: GENESIS_TOTAL, freezeLog: () => w.freezeStore.freezeLog() });
  const workload = generateWorkload({ seed: 'v2b:' + seed, hours, t0: w.now(), techniques: [TECHNIQUE], merchants: [...MERCHANTS] });
  const worker = { handleTask: (t) => zone.handleTask(t), slot: (t) => zone.receiveSlotTask(t), act: (a) => zone.act(a) };
  const camp = new Campaign({ ctl, worker, brain, maxTurns, rounds, budgetUsd: Infinity });
  const result = await camp.run(workload, { isFrozen: () => w.freezeStore.isFrozen(), onFrozen: onFrozen ? (ev, c) => onFrozen(ev, c, w, zone) : null });
  const decisions = await w.ctl.call('DECISIONS', {});
  const cls = classify({ evaluation: result, decisions, trajectory: camp.trajectory, freezeRecords: w.freezeStore.records,
    observationTexts: camp.trajectory.flatMap(t => t.observations.map(o => o.result)) });
  return { w, zone, camp, workload, workloadSummary: summarize(workload), result, classification: cls, hookLog: zone.hookLog };
}
