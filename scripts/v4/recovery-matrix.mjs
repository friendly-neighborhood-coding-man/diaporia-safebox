// Writes docs/evidence/v4/recovery-matrix.{json,md}: all 32 loss subsets + named scenarios, seven questions each.
// Usage: node --disable-warning=ExperimentalWarning scripts/v4/recovery-matrix.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import { runSubset, subsets, SCENARIOS } from '../../src/v4/recovery/matrix.mjs';

const rows = []; for (const l of subsets()) rows.push(await runSubset(l));
rows.sort((a, b) => a.n - b.n || a.lost.localeCompare(b.lost));
const scen = []; for (const [name, f] of Object.entries(SCENARIOS)) { try { scen.push({ name, ...(await f()) }); } catch (e) { scen.push({ name, error: e.message }); } }
mkdirSync('docs/evidence/v4', { recursive: true });
writeFileSync('docs/evidence/v4/recovery-matrix.json', JSON.stringify({ generatedBy: 'scripts/v4/recovery-matrix.mjs', level: 'deterministic mock verified (in-process, software authenticators, simulated trusted displays)', subsets: rows, scenarios: scen }, null, 1) + '\n');
const b = (v) => v === true ? 'yes' : v === false ? 'NO' : v === null || v === undefined ? '-' : String(v);
let md = '# V4 recovery matrix (generated)\n\nLevel: deterministic mock verified. Q1 owner recovers (final authority set = approved set), Q2 R-1-collusion attacker denied, Q3 case state / lockdown during the case, Q4 surviving DAILY can pay during the case, Q5 owner gestures (physical confirmations; signatures counted separately), Q6 latency, Q7 previously issued capability + intent approval refused afterwards.\n\n';
md += '| lost | outcome | Q1 | Q2 (stopped by) | Q3 state / lockdown | Q4 | Q5 gestures / prompts | independent signers | chain signatures | Q6 h | Q7 | purpose | verifier |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n';
for (const r of rows) md += `| ${r.lost} | ${r.outcome} | ${b(r.Q1_ownerCanRecover)} | ${b(r.Q2_attackerDenied)} (${r.attackerStoppedBy}) | ${r.Q3_caseStateDuringCase} / ${b(r.Q3_lockdown)} | ${b(r.Q4_survivorPaymentDuringCase)} | ${r.Q5_ownerGestures} / ${r.ownerPrompts} | ${r.independentSigners} | ${r.chainSignatures} | ${r.Q6_latencyH} | ${b(r.Q7_oldAuthorizationsInvalid)} | ${b(r.purposePreserved)} | ${b(r.verifierClean)} |\n`;
md += '\n## Named scenarios\n\n'; for (const s of scen) md += `- **${s.name}**: \`${JSON.stringify(Object.fromEntries(Object.entries(s).filter(([k]) => k !== 'name' && k !== 'scenario')))}\`\n`;
writeFileSync('docs/evidence/v4/recovery-matrix.md', md);
console.log(md);
