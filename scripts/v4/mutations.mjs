// Mutation checks for the V4 controls: each mutation removes one check in place, runs the V4 suites, restores the file.
// A mutation is "caught" when at least one test fails. Writes docs/evidence/v4/mutations.json.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const M = [
  ['R-1: RECONSTITUTE without ORC authorization', 'src/v4/root/chain.mjs', "if (!cs.v4.ownerAuth || cs.v4.ownerAuth.caseDigest !== cs.digest) fail('OWNER_AUTHORIZATION_REQUIRED'", "if (false) fail('OWNER_AUTHORIZATION_REQUIRED'"],
  ['R-1: ORC authorization not bound to the case digest', 'src/v4/root/chain.mjs', "cs.v4.ownerAuth.caseDigest !== cs.digest) fail('OWNER_AUTHORIZATION_REQUIRED'", "false) fail('OWNER_AUTHORIZATION_REQUIRED'"],
  ['R-1: reattempt cooldown removed', 'src/v4/root/chain.mjs', "if (!ownerAttested && last && at < last.closedAt", "if (false && last && at < last.closedAt"],
  ['R-1: plan-key burn removed', 'src/v4/root/chain.mjs', "for (const p of cs.plan) if (s.v4.burnedPlanKeys[keyDigest(p.publicKey)]) fail('PLAN_KEY_PREVIOUSLY_REJECTED', p.credId);\n    cs.v4 = { openNonce", "cs.v4 = { openNonce"],
  ['R-1: claim budget removed', 'src/v4/root/chain.mjs', "if (!ownerAttested && fails.filter(c => c.closedAt > at - 30 * D).length >=", "if (false && fails.filter(c => c.closedAt > at - 30 * D).length >="],
  ['R-1: expiry allowed before the deadline', 'src/v4/root/chain.mjs', "if (!(at >= hardEnd || (majority && unapprovedMajority) || unapprovedAny)) fail('RECOVERY_NOT_EXPIRED');", ""],
  ['Intent: canonical intent equality removed', 'src/v4/intent/intent.mjs', "if (canon(it) !== canon(expected)) {", "if (false) {"],
  ['Intent: challenge single-use removed', 'src/v4/intent/intent.mjs', "if (s.v4.usedChallenges[g.challengeNonce] !== undefined) fail('CHALLENGE_ALREADY_CONSUMED');", ""],
  ['Intent: challenge expiry removed', 'src/v4/intent/intent.mjs', "if (at >= ea) fail('CHALLENGE_EXPIRED');", ""],
  ['Intent: grant bound to action removed', 'src/v4/intent/intent.mjs', "if (g.actionDigest !== adHex || g.actionType !== a.type) fail('CHALLENGE_NOT_FOR_THIS_ACTION');", ""],
  ['Intent: APC prompt check removed', 'src/v4/intent/intent.mjs', "if (!verifyObj(V4_DOMAINS.CONFIRM, { prompt: text.split('\\n'), extraData: dig.toString('hex') }, st.sig, conf.publicKey)) fail('PROTECTED_CONFIRMATION_INVALID');", ""],
  ['Confirmation: CRITICAL trusted-path requirement removed', 'src/v4/root/chain.mjs', "if (CRITICAL.has(a.type) && !s.v4.tx.levels.some(x => TRUSTED_LEVELS.has(x.level)))", "if (false)"],
  ['R-3: accused not excluded from electorate', 'src/v4/root/chain.mjs', ".filter(v => !b.accused.includes(v) && !s.v4.disqualified[v]).sort();", ".filter(v => !s.v4.disqualified[v]).sort();"],
  ['R-3: adjudicator quorum removed', 'src/v4/root/chain.mjs', "if (ok.size < Number(s.v4.config.adjudicatorQuorum)) fail('ACCUSATION_NOT_ESTABLISHED'", "if (false) fail('ACCUSATION_NOT_ESTABLISHED'"],
  ['R-3: owner quorum distinct roles removed', 'src/v4/root/chain.mjs', "if (roles.size < 2) fail('EMERGENCY_OWNER_QUORUM_NOT_MET'", "if (roles.size < 1) fail('EMERGENCY_OWNER_QUORUM_NOT_MET'"],
  ['R-3: tally openings not checked', 'src/v4/root/chain.mjs', "!== g.ballots[o.voterId].commitment) fail('TALLY_OPENING_MISMATCH', o.voterId);", "!== g.ballots[o.voterId].commitment && false) fail('TALLY_OPENING_MISMATCH', o.voterId);"],
  ['R-3: replacement PoP removed', 'src/v4/root/chain.mjs', "r.pop, r.publicKey)) fail('REPLACEMENT_POP_INVALID', r.id);", "r.pop, r.publicKey) && false) fail('REPLACEMENT_POP_INVALID', r.id);"],
  ['R-3: security delay removed', 'src/v4/root/chain.mjs', "if (at < g.executeAfter) fail('GOV_SECURITY_DELAY_OPEN');", ""],
  ['R-3: empty electorate allowed', 'src/v4/root/chain.mjs', "if (!electorate.length) fail('EMERGENCY_ELECTORATE_EMPTY'", "if (false) fail('EMERGENCY_ELECTORATE_EMPTY'"],
  ['F-V4-01: suspended survivor consent not counted', 'src/v4/root/chain.mjs', "if (!suspendedSurvivorConsent(s, a, tr, at, fx)) H3.RECOVERY_CONSENT", "H3.RECOVERY_CONSENT"],
  ['F-V4-01: protective actions of revoked keys not lifted at completion', 'src/v4/root/chain.mjs', "installPlanMeta(s, cs);\n    liftProtectiveActionsOfLost(s, cs.lost, fx);\n  },\n  RECONSTITUTE", "installPlanMeta(s, cs);\n  },\n  RECONSTITUTE"],
  ['F-V4-01: owner-imposed suspensions lifted too (over-broad repair)', 'src/v4/root/chain.mjs', "by.length && by.every(x => L.has(x))", "by.length"],
];
const rows = [];
for (const [name, file, from, to] of M) {
  const orig = readFileSync(file, 'utf8');
  if (!orig.includes(from)) { rows.push({ name, file, error: 'PATTERN_NOT_FOUND' }); continue; }
  writeFileSync(file, orig.replace(from, to));
  try {
    const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--test', 'tests/v4/r1-closure.test.mjs', 'tests/v4/r3-governance.test.mjs', 'tests/v4/intent-ui.test.mjs', 'tests/v4/ballot-integration.test.mjs', 'tests/v4/mutation-kills.test.mjs', 'tests/v4/f01-suspension-lockout.test.mjs'], { encoding: 'utf8', timeout: 600_000 });
    const fail = Number(/# fail (\d+)/.exec(r.stdout)?.[1] ?? -1);
    rows.push({ name, file, caught: fail > 0, failingTests: fail });
  } finally { writeFileSync(file, orig); }
  console.log(JSON.stringify(rows.at(-1)));
}
mkdirSync('docs/evidence/v4', { recursive: true });
writeFileSync(process.argv[2] ?? 'docs/evidence/v4/mutations.json', JSON.stringify({ generatedBy: 'scripts/v4/mutations.mjs', caught: rows.filter(r => r.caught).length, total: rows.length, rows }, null, 1) + '\n');
