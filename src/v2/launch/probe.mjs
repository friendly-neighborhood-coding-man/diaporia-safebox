// Isolation probe: run under a given OS principal; attempts each access and reports what the KERNEL allowed.
// Usage: node probe.mjs <base> <label> <pidsJson>
import { readFileSync, writeFileSync, appendFileSync, readdirSync } from 'node:fs';
import net from 'node:net';
import http from 'node:http';
import { layout } from './layout.mjs';

const [base, label, pidsJson, metaUrl] = process.argv.slice(2);
const L = layout(base); const pids = JSON.parse(pidsJson);
const results = {};
async function probe(name, fn) {
  try { await fn(); results[name] = 'ALLOWED'; } catch (e) { results[name] = 'DENIED:' + (e.code ?? e.message?.slice(0, 40)); }
}
const connect = (p) => new Promise((res, rej) => { const s = net.createConnection(p); s.on('connect', () => { s.destroy(); res(); }); s.on('error', rej); });
const get = (u) => new Promise((res, rej) => { const r = http.get(u, { timeout: 1500 }, x => { x.resume(); x.on('end', res); }); r.on('error', rej); r.on('timeout', () => r.destroy(Object.assign(new Error('t'), { code: 'ETIMEDOUT' }))); });

await probe('read:executor_key', () => readFileSync(L.sensKey));
await probe('read:sensitive_db', () => readFileSync(L.sensDb));
await probe('read:owner_keys', () => readFileSync(L.ownerKeys));
await probe('read:labels', () => readFileSync(L.labels));
await probe('read:ledger_db', () => readFileSync(L.ledgerDb));
await probe('list:sens_dir', () => readdirSync(L.base + '/sens'));
await probe('read:executor_pub', () => readFileSync(L.executorPub));
await probe('write:clock', () => appendFileSync(L.clock, ''));
await probe('write:freeze_log', () => appendFileSync(L.freeze, ''));
await probe('write:trusted_conf', () => appendFileSync(L.sensConf, ''));
await probe('write:code', () => appendFileSync(new URL('../sensitive/policy.mjs', import.meta.url), ''));
await probe('connect:sens_gz', () => connect(L.sensGz));
await probe('connect:sens_ctl', () => connect(L.sensCtl));
await probe('connect:ledger_exec', () => connect(L.ledgerExec));
await probe('connect:ledger_read', () => connect(L.ledgerRead));
await probe('connect:ledger_admin', () => connect(L.ledgerAdmin));
await probe('connect:sup_watchdog', () => connect(L.supWd));
await probe('signal:watchdog', () => process.kill(pids.watchdog, 0));
await probe('signal:sensitive', () => process.kill(pids.sensitive, 0));
await probe('signal:ledger', () => process.kill(pids.ledger, 0));
await probe('read:/proc/sensitive/environ', () => readFileSync(`/proc/${pids.sensitive}/environ`));
await probe('net:host_metadata_service', () => get(metaUrl));
console.log(JSON.stringify({ label, uid: process.getuid(), gid: process.getgid(), groups: process.getgroups(), results }));
