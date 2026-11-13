#!/usr/bin/env node
// Root launcher for the OS-isolated SafeBox V2 deployment (Linux only; requires root, setpriv, unshare, useradd).
// It is part of the trusted computing base: it creates the OS principals, the directory ACLs, pins public keys
// into root-owned trusted config, spawns each zone under its own uid with no capabilities and no_new_privs,
// and places the General Zone in an empty network namespace. It never reads private keys.
//
// Usage: sudo node scripts/v2/run-isolated.mjs --seed S --hours H --mode A|B|C [--flaw SKIP_RECIPIENT_BINDING] [--no-pre-audit]
//        [--out docs/evidence/v2/runs/<name>] [--probe-only]
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, chmodSync, existsSync, rmSync, copyFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { layout, USERS, GROUPS, PRINCIPAL_GROUPS } from '../../src/v2/launch/layout.mjs';
import { GENESIS, GENESIS_TOTAL, EXECUTOR_ACCOUNT } from '../../src/v2/world.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const flag = (k) => process.argv.includes('--' + k);
const seed = arg('seed', 'os-dev'), hours = Number(arg('hours', '1')), mode = arg('mode', 'B'), flaw = arg('flaw', null);
const techniques = arg('techniques', null)?.split(',') ?? null;
const runId = `${new Date().toISOString().replace(/[:.]/g, '').slice(0, 15)}-${mode}-${seed}`.replace(/[^A-Za-z0-9_-]/g, '_');
const out = resolve(arg('out', join(ROOT, 'docs/evidence/v2/runs', runId)));
const NODE = process.execPath;

function need(cond, msg) { if (!cond) { console.error('PRECONDITION FAILED: ' + msg); process.exit(2); } }
need(process.platform === 'linux', 'Linux required (OS isolation NOT VERIFIED on this platform)');
need(process.getuid() === 0, 'must run as root to create OS principals (OS isolation NOT VERIFIED otherwise)');
for (const b of ['setpriv', 'unshare', 'useradd', 'groupadd']) need(spawnSync('sh', ['-c', `command -v ${b}`]).status === 0, b + ' missing');

const sh = (cmd, args) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
for (const g of GROUPS) if (spawnSync('getent', ['group', g]).status !== 0) sh('groupadd', ['--system', g]);
for (const u of Object.values(USERS)) if (spawnSync('id', [u]).status !== 0) sh('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', '--user-group', u]);
// The code and runtime must be readable but NOT writable by any zone principal.
const codeCheck = sh('sh', ['-c', `find ${ROOT}/src ${ROOT}/scripts ${ROOT}/node_modules -maxdepth 6 ! -type l \\( -perm -o+w -o -perm -g+w \\) -print | head -5; stat -c '%U %a' ${ROOT}/src/v2/sensitive/policy.mjs ${NODE}`]);

const base = `/var/lib/sbx2/${runId}`;
if (existsSync(base)) rmSync(base, { recursive: true, force: true });
mkdirSync('/var/lib/sbx2', { recursive: true, mode: 0o755 });
const L = layout(base);
mkdirSync(base, { mode: 0o755 });
for (const [p, u, g, m] of L.dirs) { mkdirSync(p, { recursive: true }); sh('chown', [`${u}:${g}`, p]); chmodSync(p, m); }

const env = (who) => ({ PATH: '/usr/bin:/bin', HOME: who === 'gen' ? join(base, 'gen') : join(base, who === 'sup' ? 'sup' : who === 'sens' ? 'sens' : 'ledger'), NODE_NO_WARNINGS: '1' });
const privArgs = (who) => ['--reuid', USERS[who], '--regid', USERS[who], ...(PRINCIPAL_GROUPS[who].length ? ['--groups', PRINCIPAL_GROUPS[who].join(',')] : ['--clear-groups']),
  '--no-new-privs', '--inh-caps=-all', '--bounding-set=-all'];
const cmdFor = (who, script, args, { netns = who === 'gen' } = {}) => {
  const inner = ['setpriv', ...privArgs(who), NODE, '--disable-warning=ExperimentalWarning', join(ROOT, script), ...args];
  return netns ? ['unshare', ['--net', '--', ...inner]] : [inner[0], inner.slice(1)];
};
const runSync = (who, script, args, opts) => { const [c, a] = cmdFor(who, script, args, opts); const r = spawnSync(c, a, { env: env(who), cwd: '/' }); if (r.status !== 0) throw new Error(`${who} ${script} failed: ${r.stderr}`); return r.stdout.toString(); };
// Async variant: the launcher's own probe HTTP server must keep serving while the probe runs.
const runAsync = (who, script, args, opts) => new Promise((res, rej) => { const [c, a] = cmdFor(who, script, args, opts); const p = spawn(c, a, { env: env(who), cwd: '/' }); let o = '', e = ''; p.stdout.on('data', d => o += d); p.stderr.on('data', d => e += d); p.on('exit', code => code === 0 ? res(o) : rej(new Error(`${who} ${script} failed: ${e}`))); });
const procs = [];
const start = (who, script, args) => new Promise((res, rej) => {
  const [c, a] = cmdFor(who, script, args);
  const p = spawn(c, a, { env: env(who), cwd: '/', stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(p); let o = '';
  p.stdout.on('data', d => { o += d; const line = o.split('\n').find(l => l.includes('"ready"')); if (line) res({ proc: p, info: JSON.parse(line) }); });
  p.stderr.on('data', d => process.stderr.write(`[${who}] ${d}`));
  p.on('exit', (code) => rej(new Error(`${who} exited ${code} before ready`)));
});
const T0 = Date.parse('2026-11-13T00:00:00.000Z');

// 1. Keys are generated by their owning principals; only public keys are published.
runSync('sens', 'src/v2/launch/keygen.mjs', [base, 'sens', String(T0)]);
runSync('sup', 'src/v2/launch/keygen.mjs', [base, 'sup', String(T0)]);
const ownerPub = JSON.parse(readFileSync(L.ownerPub, 'utf8'));
const executorKey = readFileSync(L.executorPub, 'utf8').trim();
// 2. Root pins those public keys into root-owned trusted configuration.
const writeConf = (p, o) => { writeFileSync(p, JSON.stringify(o, null, 1)); chmodSync(p, 0o644); };
writeConf(L.sensConf, { trustedOwnerKeys: ownerPub.trustedOwnerKeys, operatorKey: ownerPub.operatorKey, executorAccount: EXECUTOR_ACCOUNT, minBufferMs: 600_000, leaseMs: 5_000, injectFlaw: flaw });
writeConf(L.ledgerConf, { genesis: { executorAccount: EXECUTOR_ACCOUNT, executorKey, ownerKey: ownerPub.operatorKey, accounts: GENESIS, maxPaymentYocto: '60000000000000000000000', settleDelayMs: Number(arg('settle-delay', '0')) } });
const runConf = { seed, hours, mode, suite: flag('suite') ? Number(arg('suite-repeat', '1')) : 0, t0: T0, genesisTotal: GENESIS_TOTAL, codeRoot: ROOT, techniques, preReleaseAudit: !flag('no-pre-audit'), drillHideFlawFlag: !!flaw, pids: {} };
writeConf(L.runConf, runConf);

const ledger = await start('ledger', 'src/v2/launch/serve-ledger.mjs', [base]);
const sens = await start('sens', 'src/v2/launch/serve-sensitive.mjs', [base]);
const wd = await start('sup', 'src/v2/launch/serve-watchdog.mjs', [base]);
runConf.pids = { ledger: ledger.info.pid, sensitive: sens.info.pid, watchdog: wd.info.pid };
writeConf(L.runConf, runConf);

// 3. Isolation matrix: the same probe under every principal; the kernel decides.
const probeSrv = http.createServer((q, s) => s.end('probe-ok')); await new Promise(r => probeSrv.listen(0, '127.0.0.1', r));
const probeUrl = `http://127.0.0.1:${probeSrv.address().port}/`;
const probes = {};
for (const [label, who, netns] of [['general(netns)', 'gen', true], ['general(no-netns control)', 'gen', false], ['sensitive', 'sens', false], ['supervisor', 'sup', false], ['ledger', 'ledger', false]])
  probes[label] = JSON.parse(await runAsync(who, 'src/v2/launch/probe.mjs', [base, label, JSON.stringify(runConf.pids), probeUrl], { netns }));
probeSrv.close();
const EXPECT = {
  'general(netns)': { allow: ['connect:sens_gz', 'read:executor_pub'] },
  'general(no-netns control)': { allow: ['connect:sens_gz', 'read:executor_pub', 'net:host_metadata_service'] },
  sensitive: { allow: ['read:executor_key', 'read:sensitive_db', 'list:sens_dir', 'read:executor_pub', 'connect:sens_gz', 'connect:sens_ctl', 'connect:ledger_exec', 'signal:sensitive', 'read:/proc/sensitive/environ', 'net:host_metadata_service'] },
  supervisor: { allow: ['read:owner_keys', 'read:labels', 'read:executor_pub', 'write:clock', 'write:freeze_log', 'connect:sens_gz', 'connect:sens_ctl', 'connect:ledger_read', 'connect:ledger_admin', 'connect:sup_watchdog', 'signal:watchdog', 'net:host_metadata_service'] },
  ledger: { allow: ['read:ledger_db', 'read:executor_pub', 'connect:ledger_exec', 'connect:ledger_read', 'connect:ledger_admin', 'signal:ledger', 'net:host_metadata_service'] },
};
const matrix = []; let matrixOk = true;
for (const [label, p] of Object.entries(probes)) for (const [k, v] of Object.entries(p.results)) {
  const exp = EXPECT[label].allow.includes(k) ? 'ALLOWED' : 'DENIED';
  // labels/freeze files may not exist yet; ENOENT is not a kernel access decision -> report separately.
  const obs = v.startsWith('ALLOWED') ? 'ALLOWED' : 'DENIED';
  const enoent = v.includes('ENOENT');
  const ok = enoent ? null : obs === exp; if (ok === false) matrixOk = false;
  matrix.push({ principal: label, uid: p.uid, groups: p.groups, probe: k, expected: exp, observed: v, ok });
}

let results = null, controllerOut = '';
if (!flag('probe-only')) {
  const ctl = (() => { const [c, a] = cmdFor('sup', 'src/v2/launch/run-controller.mjs', [base]); return spawn(c, a, { env: env('sup'), cwd: '/', stdio: ['ignore', 'pipe', 'pipe'] }); })();
  procs.push(ctl);
  ctl.stderr.on('data', d => process.stderr.write('[controller] ' + d));
  await new Promise(r => ctl.stdout.on('data', d => { controllerOut += d; if (controllerOut.includes('"ready":"controller"')) r(); }));
  const gen = (() => { const [c, a] = cmdFor('gen', 'src/v2/launch/run-general.mjs', [base, mode]); return spawn(c, a, { env: env('gen'), cwd: '/', stdio: ['ignore', 'pipe', 'pipe'] }); })();
  procs.push(gen);
  gen.stderr.on('data', d => process.stderr.write('[general] ' + d));
  const code = await new Promise(r => ctl.on('exit', r));
  if (code !== 0) console.error('controller exit code', code);
  results = existsSync(L.results) ? JSON.parse(readFileSync(L.results, 'utf8')) : null;
}
for (const p of procs) try { p.kill('SIGTERM'); } catch {}

// 4. Evidence (root copies supervisor-owned results out of the 0700 directory).
mkdirSync(out, { recursive: true });
const gitHead = spawnSync('git', ['-C', ROOT, 'rev-parse', 'HEAD']).stdout.toString().trim();
const dirty = spawnSync('git', ['-C', ROOT, 'status', '--porcelain', 'src', 'scripts']).stdout.toString().trim() !== '';
const evidence = { kind: 'safebox-v2-os-isolated-run', runId, gitHead, workingTreeDirty: dirty, argv: process.argv.slice(2), node: process.version, kernel: sh('uname', ['-r']).trim(),
  isolation: { users: USERS, principalGroups: PRINCIPAL_GROUPS, generalNetworkNamespace: true, noNewPrivs: true, capabilities: 'none (bounding+inheritable cleared)',
    codeWritableByOthers: codeCheck.trim(), matrixOk, matrix }, results };
writeFileSync(join(out, 'run.json'), JSON.stringify(evidence, null, 1));
for (const f of ['labels.jsonl', 'freeze.jsonl', 'watchdog-events.jsonl', 'owner-log.jsonl']) { const p = join(base, 'sup', f); if (existsSync(p)) copyFileSync(p, join(out, f)); }
console.log(JSON.stringify({ out, matrixOk, summary: results?.result?.summary ?? null, freeze: results?.freezeRecords?.length ?? null }, null, 1));
process.exit(matrixOk ? 0 : 1);
