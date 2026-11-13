#!/usr/bin/env node
// Aggregates V2-B campaign evidence (docs/evidence/v2b/campaigns/*/run.json) into one machine-readable summary
// and a markdown table. Reads evidence only; never re-runs or re-scores anything.
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const dir = join(ROOT, 'docs/evidence/v2b/campaigns');
const rows = [];
for (const n of readdirSync(dir).sort()) {
  const p = join(dir, n, 'run.json'); if (!existsSync(p)) continue;
  const r = JSON.parse(readFileSync(p, 'utf8')); const c = r.classification ?? {}; const m = c.metrics ?? {};
  rows.push({ name: n, gitHead: r.gitHead?.slice(0, 7), realLlm: r.realLlmExecuted, model: r.brain?.model, servedModel: r.brain?.servedModel ?? null, flaw: r.config?.flaw ?? null,
    preAudit: r.config?.preReleaseAudit, repair: r.config?.repair, turns: m.llmTurns, slots: m.slots, actions: m.actions, costUsd: r.brain?.costUsd ?? 0,
    tokens: r.brain?.usage ? Object.values(r.brain.usage).reduce((s, v) => s + (v ?? 0), 0) : 0, usage: r.brain?.usage ?? null,
    unauthorized: c.counts?.UNAUTHORIZED_EFFECT, authorized: c.counts?.AUTHORIZED_EFFECT, unintended: c.counts?.LEGIT_BUT_UNINTENDED, failed: c.counts?.FAILED_ATTACK,
    availability: c.counts?.AVAILABILITY_FAILURE, falsePositive: c.counts?.FALSE_POSITIVE, legit: `${m.legitimateSettled}/${m.legitimatePayments}`, legitRate: m.legitimateSuccessRate,
    unauthorizedYocto: m.unauthorizedYocto, firstExploit: m.timeToFirstExploit, containment: m.containment, freezes: m.freezes?.length ?? 0, creds: c.credentialExposure?.canaryHits ?? [],
    bypass: c.bufferOrFreezeBypass, matrixOk: r.isolation?.matrixOk, repairs: r.campaign?.repairs ?? [], stop: r.campaign?.stop });
}
writeFileSync(join(ROOT, 'docs/evidence/v2b/SUMMARY.json'), JSON.stringify(rows, null, 1));
const md = ['| campaign | LLM | model (served) | flaw | turns/actions | unauthorized | authorized | unintended | failed | avail. fail | FP | legit settled | cost USD | creds | freezes |', '|' + ' --- |'.repeat(15)];
for (const x of rows) md.push(`| ${x.name} | ${x.realLlm ? 'yes' : 'no (scripted)'} | ${x.model}${x.servedModel ? ` (${x.servedModel})` : ''} | ${x.flaw ?? '-'} | ${x.turns}/${x.actions} | ${x.unauthorized} | ${x.authorized} | ${x.unintended} | ${x.failed} | ${x.availability} | ${x.falsePositive} | ${x.legit} | ${x.costUsd.toFixed(3)} | ${x.creds.length ? x.creds.join(',') : 'none'} | ${x.freezes} |`);
writeFileSync(join(ROOT, 'docs/evidence/v2b/SUMMARY.md'), md.join('\n') + '\n');
console.log(md.join('\n'));
