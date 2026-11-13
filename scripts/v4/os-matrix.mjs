#!/usr/bin/env node
// SafeBox V4 OS privilege matrix (Linux + root + setpriv/unshare/useradd). Creates one OS principal per V3 zone, lays
// out each zone's private state with owner-only permissions, starts a long-lived process per principal, then runs an
// unprivileged probe AS each principal (no capabilities, no_new_privs; the General Zone additionally in an empty
// network namespace) against every resource. Writes <out>/os-matrix.json. It never reads or generates real keys:
// the "secret" files contain random placeholder bytes.
//
// Zones: sbx4-root (V4 Purpose Root chain), sbx4-recov (recovery notifier key), sbx4-chal (challenge-issuer signing key +
//        issued-challenge store), sbx4-tally (ballot opening X25519 key + tally signing key), sbx4-orc (stand-in for the
//        owner's ORC device: its signing key never leaves it), sbx4-vault (execution vault + root replica), sbx4-ledger
//        (mock ledger), sbx4-gen (the AI agent / General Zone, empty network namespace).
// LIMITATION: this verifies the OS privilege matrix (who can read/write/signal what), as V3 did. It does not run the
// V4 recovery protocol across these principals; protocol results are in-process (deterministic mock verified).
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const out = resolve(arg('out', join(ROOT, 'docs/evidence/v4/os')));
const need = (c, m) => { if (!c) { console.error('PRECONDITION FAILED: ' + m + ' (OS isolation NOT VERIFIED)'); process.exit(2); } };
need(process.platform === 'linux', 'Linux required'); need(process.getuid() === 0, 'root required');
for (const b of ['setpriv', 'unshare', 'useradd']) need(spawnSync('sh', ['-c', 'command -v ' + b]).status === 0, b + ' missing');

const ZONES = ['root', 'recov', 'chal', 'tally', 'orc', 'vault', 'ledger', 'gen'];
const U = Object.fromEntries(ZONES.map(z => [z, 'sbx4-' + z]));
const sh = (c, a) => execFileSync(c, a, { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
for (const u of Object.values(U)) if (spawnSync('id', [u]).status !== 0) sh('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', '--user-group', u]);
const uid = (u) => Number(sh('id', ['-u', u]).trim());

const base = '/var/lib/sbx4-matrix';
if (existsSync(base)) rmSync(base, { recursive: true, force: true });
mkdirSync(base, { mode: 0o755 });
const resources = [];
const zoneDir = (z) => { const d = join(base, z); mkdirSync(d, { mode: 0o700 }); sh('chown', [`${U[z]}:${U[z]}`, d]); chmodSync(d, 0o700); resources.push({ kind: 'dir', name: z + '/', path: d, owner: z }); return d; };
const file = (z, name, owner = U[z], mode = 0o600) => { const p = join(z === 'trusted' ? join(base, 'trusted') : join(base, z), name); writeFileSync(p, randomBytes(32).toString('hex')); sh('chown', [`${owner}:${owner}`, p]); chmodSync(p, mode); resources.push({ kind: 'file', name: `${z}/${name}`, path: p, owner: z }); };
for (const z of ZONES) zoneDir(z);
file('root', 'root-chain.sqlite'); file('root', 'service-config.json');
file('recov', 'notifier-key.secret'); file('recov', 'cases.sqlite');
file('chal', 'issuer-key.secret'); file('chal', 'issued-challenges.sqlite');
file('tally', 'ballot-x25519.secret'); file('tally', 'tally-sign.secret');
file('orc', 'orc-key.secret');
file('vault', 'vault.sqlite'); file('vault', 'root-replica.sqlite');
file('ledger', 'ledger.sqlite');
file('gen', 'agent-scratch.txt');
mkdirSync(join(base, 'trusted'), { mode: 0o755 });
file('trusted', 'pinned-public-keys.json', 'root', 0o644); // readable by all zones, writable by none

// one long-lived process per principal (signal targets)
const priv = (z) => ['--reuid', U[z], '--regid', U[z], '--clear-groups', '--no-new-privs', '--inh-caps=-all', '--bounding-set=-all'];
const procs = Object.fromEntries(ZONES.map(z => [z, spawn('setpriv', [...priv(z), 'sleep', '120'], { stdio: 'ignore' })]));
await new Promise(r => setTimeout(r, 300));
const pids = Object.fromEntries(Object.entries(procs).map(([z, p]) => [z, p.pid]));
// network target: the egress proxy if configured, otherwise a public address
const px = process.env.HTTPS_PROXY ? new URL(process.env.HTTPS_PROXY) : null;
const plan = { resources, pids, netHost: px?.hostname ?? '1.1.1.1', netPort: Number(px?.port || 443) };

const results = {};
for (const z of ZONES) {
  const inner = ['setpriv', ...priv(z), process.execPath, join(ROOT, 'scripts/v3/os-probe.mjs'), JSON.stringify(plan)];
  const [c, a] = z === 'gen' ? ['unshare', ['--net', '--', ...inner]] : [inner[0], inner.slice(1)];
  const r = spawnSync(c, a, { env: { PATH: '/usr/bin:/bin' }, cwd: '/', encoding: 'utf8', timeout: 60_000 });
  results[z] = r.status === 0 ? JSON.parse(r.stdout.trim().split('\n').at(-1)) : { error: r.stderr };
}
for (const p of Object.values(procs)) p.kill('SIGKILL');

// expected policy: a zone may read/write only its own state; every zone may READ the trusted pinned keys; nobody
// writes them; no zone may signal another zone's process; only the General Zone is denied the network.
const expect = (z, row) => {
  const [owner] = row.target.split('/');
  if (row.what === 'signal') return row.target === 'proc:' + z ? 'OBTAINED' : 'DENIED';
  if (row.what === 'net') return z === 'gen' ? 'DENIED' : 'ANY';
  if (owner === 'trusted') return row.what === 'write' ? 'DENIED' : 'OBTAINED';
  return owner === z ? 'OBTAINED' : 'DENIED';
};
const matrix = [];
for (const z of ZONES) for (const row of results[z].rows ?? []) {
  const want = expect(z, row);
  const ok = want === 'ANY' || (want === 'OBTAINED' ? row.outcome === 'OBTAINED' : row.outcome.startsWith('DENIED'));
  matrix.push({ principal: U[z], uid: results[z].uid, ...row, expected: want, ok });
}
const summary = { verified: 'OS_ENFORCED_LOCAL', principals: Object.fromEntries(ZONES.map(z => [U[z], uid(U[z])])), checks: matrix.length, violations: matrix.filter(m => !m.ok).length,
  genNetwork: matrix.find(m => m.principal === U.gen && m.what === 'net')?.outcome, errors: Object.entries(results).filter(([, v]) => v.error).map(([k, v]) => [k, v.error]) };
mkdirSync(out, { recursive: true });
writeFileSync(join(out, 'os-matrix.json'), JSON.stringify({ summary, matrix }, null, 1) + '\n');
rmSync(base, { recursive: true, force: true });
console.log(JSON.stringify(summary));
process.exit(summary.violations === 0 && summary.errors.length === 0 ? 0 : 1);
