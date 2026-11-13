// V2-B trusted campaign controller (runs as sbx2-sup). Knows labels; drives virtual time and legitimate owner traffic;
// relays red-team turns between the root broker (brain.sock, which fronts the model) and the General Zone actuator.
// It never forwards labels, verifier output, owner keys or supervisor files to either.
import net from 'node:net';
import { readFileSync, writeFileSync, appendFileSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { layout } from '../../v2/launch/layout.mjs';
import { OwnerSimulator } from '../../v2/supervisor/owner.mjs';
import { FreezeStore } from '../../v2/supervisor/watchdog.mjs';
import { Controller, repairWorkflow } from '../../v2/supervisor/controller.mjs';
import { FileClockWriter } from '../../v2/common/clock.mjs';
import { UnixClient } from '../../v2/common/wire.mjs';
import { importPkcs8 } from '../../v2/common/crypto.mjs';
import { generateWorkload, summarize } from '../../v2/traffic/schedule.mjs';
import { Campaign, TECHNIQUE, ownerTask } from '../campaign.mjs';

const L = layout(process.argv[2]);
const run = JSON.parse(readFileSync(L.runConf, 'utf8'));
const clock = new FileClockWriter(L.clock, run.t0);
const now = () => clock.now();
const keys = JSON.parse(readFileSync(L.ownerKeys, 'utf8')).keys;
const owner = OwnerSimulator.fromPrivateKeys(Object.fromEntries(Object.entries(keys).map(([k, v]) => [k, importPkcs8(v)])), now, L.ownerLog);
const sensCtl = new UnixClient(L.sensCtl), ledgerRead = new UnixClient(L.ledgerRead), wd = new UnixClient(L.supWd, { timeoutMs: 30_000 });
const brainSock = new UnixClient(run.brainSock, { timeoutMs: 600_000 });

let gsock = null, gbuf = '', seq = 0; const waiting = new Map(); let ready;
const gready = new Promise(r => (ready = r));
const tsrv = net.createServer(s => {
  if (gsock) { s.destroy(); return; }
  gsock = s; s.setEncoding('utf8');
  s.on('data', d => { gbuf += d; let i; while ((i = gbuf.indexOf('\n')) >= 0) { const m = JSON.parse(gbuf.slice(0, i)); gbuf = gbuf.slice(i + 1);
    if (m.kind === 'READY') ready(m); else { const w = waiting.get(m.id); waiting.delete(m.id); w?.(m.result); } } });
});
await new Promise(r => tsrv.listen(L.supTask, r));
chmodSync(L.supTask, 0o660);
const ask = (kind, payload) => new Promise(r => { const id = ++seq; waiting.set(id, r); gsock.write(JSON.stringify({ id, kind, payload, now: now() }) + '\n'); });
console.log(JSON.stringify({ ready: 'controller', pid: process.pid, uid: process.getuid() }));
const ghello = await gready;
await ask('CONFIG', {});
await sensCtl.call('LOAD_POLICY', { policy: owner.policy('owner_alice') });
await sensCtl.call('LOAD_POLICY', { policy: owner.policy('owner_bob', { allowedRecipients: ['merchant-c.mock', 'bob-shop.mock'] }) });
await wd.call('SCAN', {});

const workload = generateWorkload({ seed: 'v2b:' + run.seed, hours: run.hours, t0: now(), techniques: [TECHNIQUE], merchants: ['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock'] });
for (const e of workload.events) appendFileSync(L.labels, JSON.stringify({ i: e.i, t: e.t, label: e.label, hourAttackPct: e.hourAttackPct }) + '\n', { mode: 0o600 });
const fz = () => new FreezeStore(L.freeze);
const worker = { handleTask: (t) => ask('TASK', t), slot: (t) => ask('SLOT', t), act: (a) => ask('ACT', a), runAttack: async () => ({ kind: 'ATTACK_RESULT', steps: [] }) };
const brain = {
  turn: async (text) => { const r = await brainSock.call('TURN', { text }); brain._stats = r.stats; return { parsed: r.parsed, entry: r.entry }; },
  stats: () => brain._stats ?? { costUsd: 0 }, _stats: null,
};
const ctl = new Controller({ clock, step: async () => { await sensCtl.call('TICK', {}); await wd.call('SCAN', {}); }, owner, worker, ledgerRead,
  isFrozen: () => fz().isFrozen(), executorKey: readFileSync(L.executorPub, 'utf8').trim(), genesisTotalYocto: run.genesisTotal, freezeLog: () => fz().freezeLog() });
const camp = new Campaign({ ctl, worker, brain, maxTurns: run.maxTurns, rounds: run.rounds, budgetUsd: run.budgetUsd });

// Failure-repair loop (drill campaigns). Mode 'v2a' = the V2-A workflow unchanged (replay/mutation outcomes are reported by
// the General Zone). The patch itself is applied by the root launcher (restart Sensitive Zone from corrected config).
const repairs = [];
const onFrozen = run.repair ? async (ev, c) => {
  if (repairs.length >= 2) return false;
  const r = await repairWorkflow({ controller: ctl, freezeRecord: fz().current(),
    patch: async () => { for (let k = 0; k < 900 && !existsSync(L.base + '/conf/patch.json'); k++) await new Promise(r => setTimeout(r, 100));
      return existsSync(L.base + '/conf/patch.json') ? { ok: true, ...JSON.parse(readFileSync(L.base + '/conf/patch.json', 'utf8')) } : { ok: false }; },
    replay: (i) => ask('REPLAY', { eventId: i }),
    mutate: async (culprit) => {
      // Mutation = the culprit slot's recorded model actions, re-executed against a FRESH owner capability.
      const turns = camp.trajectory.filter(t => t.eventI === culprit.i);
      const { cap, signed } = owner.issueCapability({ recipientId: culprit.merchant, maxAmountYocto: culprit.requestedAmountYocto, taskRef: 'mut_' + culprit.i });
      const s = await ask('SLOT', ownerTask({ i: 'mut_' + culprit.i }, cap, signed));
      const steps = [];
      for (const t of turns) { const acts = t.actions.map(a => ('capRef' in a ? { ...a, capRef: s.capRef } : a)); const o = await ask('ACT', acts);
        for (const ob of o.observations) { let p = null; try { p = JSON.parse(ob.result); } catch {} steps.push({ action: 'mutation ' + ob.type, outcome: p && 'ok' in p ? (p.ok ? 'ACCEPTED' : 'DENIED') : 'OBSERVED', code: p?.ok ? p.result?.state : p?.error?.code, detail: p?.error?.detail }); } }
      return { steps };
    },
    regression: async () => JSON.parse(readFileSync(L.base + '/conf/patch.json', 'utf8')).regression,
    recover: (a) => wd.call('RECOVER', a) });
  repairs.push(r);
  return r.resumed;
} : null;

const result = await camp.run(workload, { isFrozen: () => fz().isFrozen(), onFrozen });
const alive = Object.fromEntries(Object.entries(run.pids).map(([k, pid]) => { try { process.kill(pid, 0); return [k, true]; } catch (e) { return [k, e.code === 'EPERM' ? 'alive(EPERM)' : false]; } }));
const out = { seed: run.seed, hours: run.hours, general: ghello, workloadSummary: summarize(workload), result, trajectory: camp.trajectory,
  decisions: await sensCtl.call('DECISIONS', {}), sensitiveState: await sensCtl.call('STATE', {}), freezeRecords: fz().records,
  transfers: await ledgerRead.call('TRANSFERS', { sinceSeq: '0' }), hookLog: await ask('HOOKLOG', null), aliveAfter: alive, watchdog: await wd.call('STATE', {}), repairs };
writeFileSync(L.results, JSON.stringify(out, null, 1), { mode: 0o600 });
await ask('EXIT', null).catch(() => {});
console.log(JSON.stringify({ done: true, summary: result.summary, turns: camp.turns, stop: camp.stopReason }));
process.exit(0);
