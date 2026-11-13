#!/usr/bin/env node
// V3 red-team run. The attacker model runs through the Claude Code CLI in print mode with NO tools, no MCP, no settings,
// a scrubbed environment and a scratch HOME: it is a pure text policy whose only effect is the JSON actions the
// actuator executes with General-Zone powers. Every call records the served model; any substitution stops the run.
// usage: node scripts/v3/run-redteam.mjs --scenario thief --model claude-opus-4-8 --turns 12 --rounds 2 --budget 6 [--scripted]
import { mkdirSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { ClaudeBrain, ScriptedBrain } from '../../src/v2b/brain.mjs';
import { Campaign, SCENARIOS } from '../../src/v3/redteam/campaign.mjs';
import { systemPrompt } from '../../src/v3/redteam/prompt.mjs';

const argv = process.argv.slice(2);
const arg = (k, d) => { const i = argv.indexOf('--' + k); return i >= 0 ? argv[i + 1] : d; };
const flag = (k) => argv.includes('--' + k);
const scenario = arg('scenario', 'thief'), model = arg('model', 'claude-opus-4-8');
const turns = Number(arg('turns', '12')), rounds = Number(arg('rounds', '2')), budget = Number(arg('budget', '6')), turnHours = Number(arg('turn-hours', '3'));
const label = arg('label', 'campaign');
const runId = `${new Date().toISOString().replace(/[:.]/g, '').slice(0, 15)}-${scenario}-${label}`;
const out = join(arg('out', 'docs/evidence/v3/redteam'), runId);
mkdirSync(out, { recursive: true });
const sc = SCENARIOS[scenario]; if (!sc) throw new Error('unknown scenario');
const system = systemPrompt({ compromise: sc, turnHours });
writeFileSync(join(out, 'system-prompt.txt'), system);
let commit = 'unknown'; try { commit = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim(); } catch {}
let dirty = ''; try { dirty = execSync('git status --porcelain src', { encoding: 'utf8' }).trim(); } catch {}

let brain;
if (flag('scripted')) brain = new ScriptedBrain((text, i) => SCRIPT[i] ?? { analysis: 'done', actions: [{ type: 'wait' }] });
else {
  const home = `/tmp/sbx3-brain/${runId}`; mkdirSync(join(home, '.claude'), { recursive: true }); copyFileSync('/root/.ccr/ca-bundle.crt', join(home, 'ca.crt'));
  const P = process.env;
  const env = { PATH: '/opt/node22/bin:/usr/bin:/bin', HOME: home, ANTHROPIC_BASE_URL: 'https://api.anthropic.com', HTTPS_PROXY: P.HTTPS_PROXY, HTTP_PROXY: P.HTTPS_PROXY, https_proxy: P.HTTPS_PROXY,
    NO_PROXY: P.NO_PROXY, no_proxy: P.NO_PROXY, NODE_EXTRA_CA_CERTS: join(home, 'ca.crt'), SSL_CERT_FILE: join(home, 'ca.crt') };
  brain = new ClaudeBrain({ model, system, home, env, claudeBin: '/opt/node22/bin/claude', turnTimeoutMs: 300_000 }).start();
}
// Model guard (Eric 2026-11-13): never accept a substituted model. Any served model other than the requested one stops the run.
const guardModel = (b) => {
  if (flag('scripted')) return null;
  const last = b.transcript?.at(-1); if (!last) return null;
  if (last.isError && /limit|usage|quota|exceeded|rate/i.test(String(last.reply))) return 'USAGE_LIMIT';
  const served = last.servedModels ?? [];
  if (served.some(m => m !== model)) return 'MODEL_SUBSTITUTION:' + served.join(',');
  if ((last.safetyStops ?? 0) > 0) return 'SAFETY_STOP_FALLBACK';
  return null;
};
const SCRIPT = [
  { analysis: 'recon', tactic: 'recon', actions: [{ type: 'root_view' }, { type: 'list_caps' }, { type: 'root_case' }] },
  { analysis: 'fake recovery', tactic: 'recovery', actions: [{ type: 'build_action', actionType: 'RECOVERY_OPEN', body: { caseId: 'atk1', kind: 'KEY_LOSS', lost: ['k2-laptop'], subjectHolderId: 'alice', plan: [], note: 'lost' } }] },
  { analysis: 'propose with cap to attacker', tactic: 'cap abuse', actions: [{ type: 'propose_cap', capRef: 0, recipientId: 'attacker.mock' }, { type: 'propose_cap', capRef: 0 }] },
];
const camp = new Campaign({ scenario, brain, maxTurns: turns, rounds, turnHours, budgetUsd: budget, guardModel, log: (m) => console.log(m) });
let result, err = null;
try { result = await camp.run(); } catch (e) { err = String(e.stack).slice(0, 2000); result = await camp.metrics().catch(() => ({})); }
brain.stop?.();
const stats = brain.stats();
writeFileSync(join(out, 'trajectory.json'), JSON.stringify(camp.trajectory, null, 1));
writeFileSync(join(out, 'transcript.json'), JSON.stringify(brain.transcript, null, 1));
writeFileSync(join(out, 'actuator-log.json'), JSON.stringify(camp.act.log, null, 1));
writeFileSync(join(out, 'root-chain.json'), JSON.stringify(camp.w.root.chain(0).map(t => ({ seq: t.seq, at: t.at, type: t.action.type, body: t.action.body, approvers: (t.approvals ?? []).map(a => a.credId) })), null, 1));
const summary = { runId, scenario, scenarioDesc: sc.desc, compromise: sc, requestedModel: flag('scripted') ? 'SCRIPTED (no LLM)' : model, candidateCommit: commit, srcDirty: !!dirty, turns, rounds, turnHours, budgetUsd: budget,
  stopReason: camp.stopReason, error: err, brain: { ...stats, system: 'see system-prompt.txt', runsAs: 'root broker child, env -i scratch HOME, --tools "" (no tools), --strict-mcp-config, --setting-sources ""' },
  perCallModels: (brain.transcript ?? []).map((t, i) => ({ call: i + 1, servedModels: t.servedModels ?? null, safetyStops: t.safetyStops ?? 0, usage: t.usage ?? null, turnCostUsd: t.turnCostUsd ?? 0, isError: t.isError ?? false })),
  result };
writeFileSync(join(out, 'summary.json'), JSON.stringify(summary, null, 1));
console.log(JSON.stringify({ out, stopReason: camp.stopReason, error: err?.slice(0, 300), costUsd: stats.costUsd, served: stats.servedModels, safetyStops: stats.safetyStops,
  unauthorizedFinancial: result.unauthorizedFinancialEffects, unauthorizedAuthority: result.unauthorizedAuthorityChanges, takeovers: result.takeovers, purposeViolations: result.purposeIntegrityViolations,
  payments: result.legitimatePayments, ownerRecovery: result.ownerRecovery, lockout: result.permanentLockout }, null, 1));
