#!/usr/bin/env node
// V5 red-team run. The attacker model runs through the Claude Code CLI in print mode with NO tools, no MCP, no settings,
// a scrubbed environment and a scratch HOME (src/v5/common/llm.mjs): a pure text policy whose only effect is the JSON
// actions the actuator executes with General-Zone powers. Every call records the requested and served model; a usage
// limit, model substitution or safety-classifier fallback stops the run immediately (never a silent substitute).
// usage: node scripts/v5/run-redteam.mjs --scenario burst_thief --model claude-opus-4-8 --turns 10 --out docs/evidence/v5/redteam [--scripted] [--label r1]
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { runCampaign, modelBrain, scriptedBrain, SCENARIOS } from '../../src/v5/redteam/campaign.mjs';
import { runModelAnalyst } from '../../src/v5/analyst/analyst.mjs';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i < 0 ? d : (process.argv[i + 1] ?? true); };
const scenario = arg('scenario', 'burst_thief'), model = arg('model', 'claude-opus-4-8'), turns = Number(arg('turns', 10)), turnMinutes = Number(arg('turnMinutes', 20));
const out = arg('out', 'docs/evidence/v5/redteam'), label = arg('label', 'r1'), scripted = process.argv.includes('--scripted'), analyst = process.argv.includes('--analyst');
if (!SCENARIOS[scenario]) { console.error('unknown scenario'); process.exit(2); }
const head = (() => { try { return execSync('git rev-parse HEAD').toString().trim(); } catch { return 'unknown'; } })();
const brain = scripted ? scriptedBrain([]) : modelBrain(model, `${scenario}-${label}`);
const t0 = Date.now();
const r = await runCampaign({ scenario, turns, turnMinutes, brain, onTurn: (t, h) => console.error(`turn ${t}: ${h?.tactic} | ${(h?.observations ?? []).map(o => o.type + ':' + String(o.result).slice(0, 60)).join(' ; ').slice(0, 400)}`) });
let analystRun = null;
if (analyst && !r.stop) {
  const w = r.w;
  analystRun = await runModelAnalyst({ api: w.analyst.api, engine: w.engine, recompute: w.analyst.recompute, corroborate: w.analyst.corroborate, model, tag: `${scenario}-${label}-analyst` });
  analystRun.deterministic = w.analyst.deterministic().map(x => ({ kind: x.finding.kind, corroborated: x.corroborated, actioned: x.actioned }));
  analystRun.afterState = { frozen: w.frozen(), incidents: w.vault.incidents().map(i => ({ id: i.incident_id, state: i.state })), creds: Object.fromEntries(Object.values(w.root.state.creds).map(c => [c.credId, c.status])) };
  analystRun.report = w.report('DAILY');
}
const { w, ...rest } = r;
const rec = { v: 'safebox.v5.redteam-run', scenario, label, candidate: head, requestedModel: scripted ? 'scripted' : model, servedModels: [...new Set(r.calls.flatMap(c => c.servedModels ?? []))], wallMs: Date.now() - t0,
  ...rest, analyst: analystRun, emails: w.mock.sent.map(m => ({ to: m.to, subject: m.subject, at: m.at })) };
mkdirSync(out, { recursive: true });
const f = join(out, `${scenario}-${label}.json`);
writeFileSync(f, JSON.stringify(rec, (k, v) => typeof v === 'bigint' ? v.toString() : v, 1));
console.log(JSON.stringify({ file: f, stop: r.stop, calls: r.calls.length, servedModels: rec.servedModels, costUsd: r.costUsd + (analystRun?.costUsd ?? 0), verifierOk: r.evaluation.verifier.ok, attacker: r.evaluation.attacker, ownerPayments: [r.evaluation.owner.paymentsAccepted, r.evaluation.owner.paymentsAttempted], endHolds: r.evaluation.endState.effectiveHolds.length, analyst: analystRun ? { guard: analystRun.guard, records: analystRun.records.length, rejected: analystRun.rejected.length } : null }, null, 1));
if (r.stop?.guard === 'USAGE_LIMIT') process.exit(3);
