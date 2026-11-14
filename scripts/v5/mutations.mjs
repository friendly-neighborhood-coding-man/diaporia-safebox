// Mutation checks for the V5 controls: each mutation removes or weakens one check in place, runs the V5 suites, restores
// the file. A mutation is "caught" when at least one test fails. Writes docs/evidence/v5/mutations.json.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
const C = 'src/v5/root/chain.mjs', CMD = 'src/v5/root/command.mjs', HD = 'src/v5/root/holds.mjs', V = 'src/v5/vault/vault.mjs';
const M = [
  ['Command: exact statement equality removed', CMD, "if (canon(st) !== canon(expected)) fail('COMMAND_MISMATCH'", "if (false) fail('COMMAND_MISMATCH'"],
  ['Command: challenge single-use removed', CMD, "if (s.v4.usedChallenges[g.challengeNonce] !== undefined) fail('CHALLENGE_ALREADY_CONSUMED');", ''],
  ['Command: TRUSTED level not enforced', CMD, "if (st.requiredLevel === 'TRUSTED' && !party.isOrc && !TRUSTED_LEVELS.has(level))", 'if (false)'],
  ['Holds: confirmed-hold release without trusted confirmation', C, "if (h.class === 'CONFIRMED_OWNER_HOLD' && !anyTrusted(ps)) fail(", 'if (false) fail('],
  ['Holds: incident-freeze release without trusted confirmation', C, "if (!anyTrusted(ps)) fail('TRUSTED_CONFIRMATION_REQUIRED', 'release of a verified incident freeze');", ''],
  ['Holds: revoked-issuer holds keep restricting (anti-lockout removed)', HD, 'if (parties.length && parties.every(p => !partyValid(s, p))) {', 'if (false) {'],
  ['Holds: one surviving party no longer keeps a confirmed hold (any revoked party drops it)', HD, 'parties.every(p => !partyValid(s, p))', 'parties.some(p => !partyValid(s, p))'],
  ['Holds: issuer budget removed', C, "if (u.ms + dur > Number(s.v5.config.issuerBudgetMs)) fail('HOLD_ISSUER_BUDGET_EXHAUSTED'", "if (false) fail('HOLD_ISSUER_BUDGET_EXHAUSTED'"],
  ['Contest: ORC not required', C, "if (!ps.some(p => p.isOrc)) fail('CONTEST_NEEDS_ORC');", ''],
  ['Contest: suspect may sign its own contest', C, "if (ps.some(p => p.credId === suspect.credId)) fail('CONTEST_SIGNED_BY_SUSPECT');", ''],
  ['Contest: holds not attributable to the suspect can be dropped', C, "if (!h.issuers.some(i => i.ref === suspect.credId)) fail('CONTEST_HOLD_NOT_ATTRIBUTABLE_TO_SUSPECT', hid);", ''],
  ['Incident review: LEGITIMATE verdict without trusted confirmation', C, "if (!anyTrusted(ps)) fail('TRUSTED_CONFIRMATION_REQUIRED', 'LEGITIMATE verdict releases delayed payments');", ''],
  ['Delegation: recipients outside the Purpose allowed', C, "b.recipients.some(r => !s.purpose.recipients.includes(r))) fail('DELEGATION_RECIPIENT_NOT_IN_PURPOSE')", "false) fail('DELEGATION_RECIPIENT_NOT_IN_PURPOSE')"],
  ['Rapid-Use: 24 h maximum removed', C, "if (dur < 600_000 || dur > Number(s.v5.config.rapidMaxMs)) fail('RAPID_DURATION_MAX_24H');", "if (dur < 600_000) fail('RAPID_DURATION_MAX_24H');"],
  ['Rapid-Use: several keys of one human count as several votes', C, "if (q.votes[key]) fail('RAPID_DUPLICATE_PRINCIPAL_VOTE'", "if (false) fail('RAPID_DUPLICATE_PRINCIPAL_VOTE'"],
  ['Rapid-Use: the bursting credential may vouch for itself', C, "if (q.scope.credIds.includes(p.credId)) fail('RAPID_FACTOR_IS_AFFECTED_CREDENTIAL'", "if (false) fail('RAPID_FACTOR_IS_AFFECTED_CREDENTIAL'"],
  ['Vault: engine decision signature not checked', V, "if (!verifyObj5(V5_DOMAINS.RISK_ENGINE, dec.statement, dec.sig, this.enginePublicKey)) fail('ENGINE_DECISION_SIGNATURE');", ''],
  ['Vault: hard delay cap removed', V, 'const ms = Math.min(delayMs, MAX_DELAY_MS);', 'const ms = delayMs * 10;'],
  ['Vault: delay does not move the capability window (F-V5-01 regression)', V, 'cap_expires_at=MAX(cap_expires_at, ?)', 'cap_expires_at=MIN(cap_expires_at, ?)'],
  ['Vault: Rapid-Use grant covers other flows', V, 'const inFlow = delegationId ? g.scope.delegationIds.includes(delegationId) : g.scope.credIds.includes(credId);', 'const inFlow = true;'],
  ['Vault: Rapid-Use ignores restricted credentials', V, "if (g.scope.credIds.some(c => this.root.creds[c]?.status !== 'active' || credentialHolds(this.root, c, now).length)) continue;", ''],
];
const tests = readdirSync('tests/v5').filter(f => f.endsWith('.test.mjs')).map(f => 'tests/v5/' + f);
const rows = [];
for (const [name, file, from, to] of M) {
  const orig = readFileSync(file, 'utf8');
  if (!orig.includes(from)) { rows.push({ name, file, error: 'PATTERN_NOT_FOUND' }); console.log(JSON.stringify(rows.at(-1))); continue; }
  writeFileSync(file, orig.replace(from, to));
  try {
    const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--test', ...tests], { encoding: 'utf8', timeout: 900_000 });
    const fail = Number(/# fail (\d+)/.exec(r.stdout)?.[1] ?? -1);
    const failing = [...r.stdout.matchAll(/^not ok \d+ - (.*)$/gm)].map(m => m[1]).slice(0, 6);
    rows.push({ name, file, caught: fail > 0, failingTests: fail, examples: failing });
  } finally { writeFileSync(file, orig); }
  console.log(JSON.stringify(rows.at(-1)));
}
mkdirSync('docs/evidence/v5', { recursive: true });
writeFileSync(process.argv[2] ?? 'docs/evidence/v5/mutations.json', JSON.stringify({ generatedBy: 'scripts/v5/mutations.mjs', caught: rows.filter(r => r.caught).length, total: rows.length, rows }, null, 1) + '\n');
