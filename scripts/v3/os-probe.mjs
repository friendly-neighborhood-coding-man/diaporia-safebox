#!/usr/bin/env node
// Unprivileged probe: runs as ONE V3 principal and tries every resource in the plan. Prints a JSON row list.
// It never escalates; it only reports what the kernel allowed (OBTAINED) or denied (DENIED:<errno>).
import { readFileSync, appendFileSync, readdirSync } from 'node:fs';
import net from 'node:net';
const plan = JSON.parse(process.argv[2]);
const rows = [];
const tryOp = (what, target, fn) => { try { fn(); rows.push({ what, target, outcome: 'OBTAINED' }); } catch (e) { rows.push({ what, target, outcome: 'DENIED:' + (e.code ?? e.message) }); } };
for (const r of plan.resources) {
  if (r.kind === 'dir') tryOp('list', r.name, () => readdirSync(r.path));
  if (r.kind === 'file') {
    tryOp('read', r.name, () => readFileSync(r.path));
    tryOp('write', r.name, () => appendFileSync(r.path, ''));
  }
}
for (const [who, pid] of Object.entries(plan.pids)) tryOp('signal', 'proc:' + who, () => process.kill(pid, 0));
const netProbe = () => new Promise((res) => {
  const s = net.connect({ host: plan.netHost, port: plan.netPort, timeout: 3000 });
  s.on('connect', () => { s.destroy(); res('OBTAINED'); }); s.on('timeout', () => { s.destroy(); res('DENIED:TIMEOUT'); }); s.on('error', (e) => res('DENIED:' + e.code));
});
rows.push({ what: 'net', target: `${plan.netHost}:${plan.netPort}`, outcome: await netProbe() });
console.log(JSON.stringify({ uid: process.getuid(), gid: process.getgid(), groups: process.getgroups(), rows }));
