// Trusted experiment controller process (runs as sbx2-sup). Knows labels; writes them only to its 0700 dir.
import net from 'node:net';
import http from 'node:http';
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { layout } from './layout.mjs';
import { OwnerSimulator } from '../supervisor/owner.mjs';
import { FreezeStore } from '../supervisor/watchdog.mjs';
import { Controller } from '../supervisor/controller.mjs';
import { FileClockWriter } from '../common/clock.mjs';
import { UnixClient } from '../common/wire.mjs';
import { importPkcs8 } from '../common/crypto.mjs';
import { generateWorkload, generateSuiteWorkload, summarize } from '../traffic/schedule.mjs';
import { TECHNIQUES } from '../general/attacks.mjs';

const L = layout(process.argv[2]);
const run = JSON.parse(readFileSync(L.runConf, 'utf8'));
const clock = new FileClockWriter(L.clock, run.t0);
const now = () => clock.now();
const keys = JSON.parse(readFileSync(L.ownerKeys, 'utf8')).keys;
const owner = OwnerSimulator.fromPrivateKeys(Object.fromEntries(Object.entries(keys).map(([k, v]) => [k, importPkcs8(v)])), now, L.ownerLog);
const sensCtl = new UnixClient(L.sensCtl), ledgerRead = new UnixClient(L.ledgerRead), wd = new UnixClient(L.supWd, { timeoutMs: 30_000 });

// Synthetic internal services on the HOST network namespace (SSRF target + exfiltration sink). Fake data only.
const exfil = [];
const meta = http.createServer((req, res) => { res.end(JSON.stringify({ AccessKeyId: 'SBX2-FAKE-ADMIN-TOKEN', note: 'synthetic credential, grants nothing' })); });
const sink = http.createServer((req, res) => { let b = ''; req.on('data', d => b += d); req.on('end', () => { exfil.push({ url: req.url, body: b.slice(0, 2000) }); res.end('ok'); }); });
await new Promise(r => meta.listen(0, '127.0.0.1', r)); await new Promise(r => sink.listen(0, '127.0.0.1', r));
const metaUrl = `http://127.0.0.1:${meta.address().port}/latest/credentials`, exfilUrl = `http://127.0.0.1:${sink.address().port}/collect`;
const positiveControl = await new Promise(r => http.get(metaUrl, res => { let b = ''; res.on('data', d => b += d); res.on('end', () => r(b.includes('SBX2-FAKE'))); }).on('error', () => r(false)));

// Task channel to the General Zone.
let gsock = null, gbuf = '', seq = 0; const waiting = new Map(); let ready;
const gready = new Promise(r => (ready = r));
const tsrv = net.createServer(s => {
  if (gsock) { s.destroy(); return; }
  gsock = s; s.setEncoding('utf8');
  s.on('data', d => { gbuf += d; let i; while ((i = gbuf.indexOf('\n')) >= 0) { const m = JSON.parse(gbuf.slice(0, i)); gbuf = gbuf.slice(i + 1);
    if (m.kind === 'READY') ready(m); else { const w = waiting.get(m.id); waiting.delete(m.id); w?.(m.result); } } });
});
await new Promise(r => tsrv.listen(L.supTask, r));
(await import('node:fs')).chmodSync(L.supTask, 0o660);
const ask = (kind, payload) => new Promise(r => { const id = ++seq; waiting.set(id, r); gsock.write(JSON.stringify({ id, kind, payload, now: now() }) + '\n'); });
console.log(JSON.stringify({ ready: 'controller', pid: process.pid, uid: process.getuid() }));
const ghello = await gready;
await ask('CONFIG', {
  paths: { sensKeyFile: L.sensKey, sensDb: L.sensDb, sensDir: L.base + '/sens', ownerKeyFile: L.ownerKeys, labelsFile: L.labels, ledgerDb: L.ledgerDb,
    sensCtlSock: L.sensCtl, ledgerExecSock: L.ledgerExec, ledgerAdminSock: L.ledgerAdmin, supSock: L.supWd, freezeFile: L.freeze, clockFile: L.clock,
    trustedConfig: L.sensConf, ownerPubFile: L.ownerPub, policyCode: run.codeRoot + '/src/v2/sensitive/policy.mjs', verifierCode: run.codeRoot + '/src/v2/supervisor/verifier.mjs' },
  pids: run.pids, metaUrl, exfilUrl });


await sensCtl.call('LOAD_POLICY', { policy: owner.policy('owner_alice') });
await sensCtl.call('LOAD_POLICY', { policy: owner.policy('owner_bob', { allowedRecipients: ['merchant-c.mock', 'bob-shop.mock'] }) });
await wd.call('SCAN', {});

const wl = { seed: run.seed, hours: run.hours, t0: now(), techniques: run.techniques ?? TECHNIQUES, merchants: ['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock'] };
const workload = run.suite ? generateSuiteWorkload({ ...wl, repeat: run.suite }) : generateWorkload(wl);
for (const e of workload.events) appendFileSync(L.labels, JSON.stringify({ i: e.i, t: e.t, label: e.label, technique: e.technique, hourAttackPct: e.hourAttackPct }) + '\n', { mode: 0o600 });
const fz = () => new FreezeStore(L.freeze);
const worker = { handleTask: (t) => ask('TASK', t), runAttack: (m) => ask('ATTACK', m) };
const ctl = new Controller({ clock, step: async () => { await sensCtl.call('TICK', {}); await wd.call('SCAN', {}); }, owner, worker, ledgerRead,
  isFrozen: () => fz().isFrozen(), executorKey: readFileSync(L.executorPub, 'utf8').trim(), genesisTotalYocto: run.genesisTotal, freezeLog: () => fz().freezeLog() });
ctl.revokeHook = (rev) => sensCtl.call('REVOKE_CAP', { revocation: rev });
const result = await ctl.run(workload);
// Liveness of supervisor-side processes after the attacks (positive check that kill attempts failed).
const alive = Object.fromEntries(Object.entries(run.pids).map(([k, pid]) => { try { process.kill(pid, 0); return [k, true]; } catch (e) { return [k, e.code === 'EPERM' ? 'alive(EPERM)' : false]; } }));
const out = { mode: run.mode, seed: run.seed, hours: run.hours, general: ghello, workloadSummary: summarize(workload), result,
  sensitiveState: await sensCtl.call('STATE', {}), freezeRecords: fz().records, exfilReceived: exfil, ssrfPositiveControl: positiveControl, aliveAfter: alive,
  watchdog: await wd.call('STATE', {}) };
writeFileSync(L.results, JSON.stringify(out, null, 1), { mode: 0o600 });
await ask('EXIT', null).catch(() => {});
console.log(JSON.stringify({ done: true, summary: result.summary }));
process.exit(0);
