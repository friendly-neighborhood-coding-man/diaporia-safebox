#!/usr/bin/env node
// Independent evaluation run (in-process logical boundary). Seed defaults to sha256(git HEAD) so it is fixed by the frozen revision.
// Usage: node scripts/v2/holdout.mjs [--n 400] [--seed S] [--out file]
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { buildWorld, GENESIS_TOTAL } from '../../src/v2/world.mjs';
import { generateHoldout, ownerPrepare, attackerExecute } from '../../src/v2/traffic/holdout.mjs';
import { verifyLedgerEffects } from '../../src/v2/supervisor/verifier.mjs';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const head = execFileSync('git', ['rev-parse', 'HEAD']).toString().trim();
const dirty = execFileSync('git', ['status', '--porcelain', 'src']).toString().trim() !== '';
const seed = arg('seed', createHash('sha256').update(head).digest('hex'));
const n = Number(arg('n', '400'));
const w = buildWorld();
await w.loadPolicies(); await w.watchdog.scan();
const cases = generateHoldout({ seed, n });
const results = [];
for (const c of cases) {
  const prep = ownerPrepare(c, w.owner, w.now(), (rev) => w.ctl.call('REVOKE_CAP', { revocation: rev }));
  await new Promise(r => setImmediate(r));
  const steps = await attackerExecute(c, prep, w.gz);
  await w.advance(11 * 60_000);
  results.push({ ...c, capId: prep.cap.capId, steps });
}
await w.advance(20 * 60_000);
const transfers = await w.ledgerRead.call('TRANSFERS', { sinceSeq: '0' });
const balances = await w.ledgerRead.call('BALANCES', {});
const v = verifyLedgerEffects({ transfers, owner: w.owner, executorKey: w.executor.publicKey, freezeLog: w.freezeStore.freezeLog(), genesisTotalYocto: GENESIS_TOTAL, balances });
const byCap = new Map(v.effects.filter(e => e.capId).map(e => [e.capId, e]));
const tally = {};
for (const r of results) {
  const eff = byCap.get(r.capId);
  r.effect = eff ? { authorized: eff.authorized, amountYocto: eff.amountYocto, recipient: eff.recipient, status: eff.status, codes: eff.codes, txId: eff.txId } : null;
  r.verdict = eff && !eff.authorized ? 'FALSE_NEGATIVE_UNAUTHORIZED_EFFECT'
    : r.legitimateExpected ? (eff?.status === 'SETTLED' ? 'LEGIT_SETTLED' : 'FALSE_POSITIVE_LEGIT_BLOCKED')
    : eff ? 'OWNER_INTENDED_PAYMENT_ONLY' : 'ATTACK_BLOCKED';
  tally[r.verdict] = (tally[r.verdict] ?? 0) + 1;
}
const fpByMutation = {};
for (const r of results.filter(r => r.verdict === 'FALSE_POSITIVE_LEGIT_BLOCKED')) fpByMutation[r.mutation] = (fpByMutation[r.mutation] ?? 0) + 1;
const out = { kind: 'safebox-v2-holdout-eval', boundary: 'in-process logical boundary (OS isolation NOT exercised)', gitHead: head, srcDirty: dirty, seed, n,
  tally, falsePositivesByMutation: fpByMutation, unauthorizedLedgerTransfers: v.unauthorizedCount, unattributedViolations: v.violations.filter(x => !results.some(r => r.capId === x.capId)).length,
  attackerBalance: balances['attacker.mock'], conservation: v.conservation, frozen: w.freezeStore.isFrozen(), freezeRecords: w.freezeStore.records, results };
const file = arg('out', null);
if (file) { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(out, null, 1)); }
console.log(JSON.stringify({ gitHead: head, srcDirty: dirty, seed: seed.slice(0, 16), n, tally, falsePositivesByMutation: fpByMutation, unauthorized: v.unauthorizedCount, frozen: out.frozen }, null, 1));
