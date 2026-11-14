// Mutation checks for the V5 controls: each mutation removes or weakens one check in place, runs the V5 suites, restores
// the file. A mutation is "caught" when at least one test fails. Writes docs/evidence/v51/mutations.json (the frozen V5 file docs/evidence/v5/mutations.json is never overwritten by default).
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
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
  // V5.1: F-V5-01 was fixed by moving the capability window with the delay; P2 replaces that with an owner-signed horizon.
  ['Vault: horizon deadline not written to the release check (P2)', V, `this.store.db.prepare("UPDATE payments SET cap_expires_at=? WHERE payment_id=? AND state='BUFFERED'").run(settleDeadline, paymentId);`, ''],
  ['Vault: Rapid-Use grant covers other flows', V, 'const inFlow = delegationId ? g.scope.delegationIds.includes(delegationId) : g.scope.credIds.includes(credId);', 'const inFlow = true;'],
  ['Vault: Rapid-Use ignores restricted credentials', V, "if (g.scope.credIds.some(c => this.root.creds[c]?.status !== 'active' || credentialHolds(this.root, c, now).length)) continue;", ''],
  // ---- V5.1 P1 / P2 controls
  ['Vault: settlement gate ignores the horizon (P2)', V, "if (now >= r.cap_expires_at || (r.settle_deadline !== null && now >= r.settle_deadline)) why = 'SETTLEMENT_HORIZON_EXPIRED';", "if (false) why = 'SETTLEMENT_HORIZON_EXPIRED';"],
  ['Vault: delay extends the latest settlement (P2)', V, `this.store.db.prepare("UPDATE payments SET release_at=?, updated_at=? WHERE payment_id=? AND state='BUFFERED'").run(release, this.now(), paymentId);`,
    `this.store.db.prepare("UPDATE payments SET release_at=?, cap_expires_at=MAX(cap_expires_at, ?), updated_at=? WHERE payment_id=? AND state='BUFFERED'").run(release, release + 600_000, this.now(), paymentId); this.store.db.prepare('UPDATE v5_pay SET settle_deadline=MAX(settle_deadline, ?) WHERE payment_id=?').run(release + 600_000, paymentId);`],
  ['Vault: unresolved HIGH-risk payment auto-releases (P1)', V, "else if (r.release_at <= now && r.risk_class === 'HIGH' && r.anomaly === 'ANOMALY_PAYMENT_DELAY') why = 'HIGH_RISK_UNRESOLVED';", ''],
  ['Vault: incident escalation not applied to pending payments (P1)', V, ".run(next, incidentId).changes;", ".run(next, '-').changes;"],
  ['Vault: release re-check of the delegation removed (P1)', V, "if (!d || d.status === 'REVOKED') why = 'RELEASE_RECHECK_DELEGATION_REVOKED';", ''],
  ['Vault: release re-check of Purpose removed (P1)', V, "if (pv.length) why = 'RELEASE_RECHECK_PURPOSE:' + pv.join(',');", ''],
  ['Engine: hard ceiling not classified HIGH (P1)', 'src/v5/risk/engine.mjs', "if (ev.hard) return 'HIGH';", ''],
  ['Engine: escalated incident not classified HIGH (P1)', 'src/v5/risk/engine.mjs', "if (openIncident && (openIncident.risk_class === 'HIGH' || Number(openIncident.triggers ?? 0) >= Number(P.delay.escalateAfterDelayed))) return 'HIGH';", ''],
  ['Engine: security-correlated delay not classified HIGH (P1)', 'src/v5/risk/engine.mjs', "if (ev.features?.securityCorrelated === 'true' && ev.decision === 'DELAY') return 'HIGH';", ''],
  ['Verifier: settlement-horizon check removed (P2)', 'src/v5/supervisor/verifier.mjs', "{ v.push('EFFECT_AFTER_SETTLEMENT_HORIZON'); out.horizon.violations++; }", '{ out.horizon.violations += 0; }'],
  ['Verifier: HIGH-risk resolution check removed (P1)', 'src/v5/supervisor/verifier.mjs', "if (!review && !grant) v.push('HIGH_RISK_SETTLED_WITHOUT_RESOLUTION');", ''],
  ['Genesis: settlement-horizon bounds removed (P2)', C, "if (n.settlementHorizonMs < H || n.settlementHorizonMs > 72 * H) fail('V5_CONFIG_SETTLEMENT_HORIZON', 'between 1 h and 72 h');", ''],
  // ---- V5.1 P4 buffer + pending-slot repair
  ['Vault: signed tier ignored, every payment gets the 30 s floor (P4)', V, 'tierToBufferMs(this.bufferPolicy(), dec.statement.tier)', '0'],
  ['Vault: engine statement for another buffer policy accepted (P4)', V, "if (dec.statement.bufferPolicy !== this.bufferPolicy()) fail('ENGINE_BUFFER_POLICY_MISMATCH');", ''],
  ['Vault: fail-closed cancellation of unevaluated payments removed (F2/N2)', V, "    for (const r of rows) this.store.move(r.payment_id, 'BUFFERED', 'CANCELLED', 'vault', { reason }, { reason });", ''],
  ['Vault: evaluation-complete marker ignored (N2)', V, "AND (v.payment_id IS NULL OR v.evaluated=0) AND", 'AND v.payment_id IS NULL AND'],
  ['Verifier: cap evidence not bound to the tx paymentId (N1)', 'src/v5/supervisor/verifier.mjs', "if (ev.payment_id !== paymentId) v.push('EFFECT_CAP_NOT_BOUND_TO_PAYMENT');", ''],
  ['Verifier: HIGH resolution accepts any LEGITIMATE review of the credential (N3)', 'src/v5/supervisor/verifier.mjs', "const rv = sE.v5.incidentReviews[inc];", "const rv = Object.values(sE.v5.incidentReviews).find(r => r.verdict === 'LEGITIMATE' && r.credId === fl.credId);"],
  ['Verifier: hidden open incident not checked (R8)', 'src/v5/supervisor/verifier.mjs', "if (!grant) hidden.push(pid);", ''],
  ['Verifier: flow from the vault row instead of signed evidence (F1)', 'src/v5/supervisor/verifier.mjs', "const fl = flowOf(paymentId);", "const fl = vp ? { flow: vp.flow, credId: vp.cred_id, delegationId: vp.delegation_id } : null;"],
  ['Buffer: sticky tier floor removed (P4 anti-reset)', 'src/v5/risk/buffer.mjs', "n = Math.max(n, N('stickyTier') || 0);", ''],
  ['Buffer: flow value uses this payment only (P4 anti-splitting)', 'src/v5/risk/buffer.mjs', 'flowValue1hBps: String(bps(v1h > amt ? v1h : amt, per)),', 'flowValue1hBps: String(bps(amt, per)),'],
  ['Buffer: open incident does not raise the tier (P4)', 'src/v5/risk/buffer.mjs', "if (i.openIncident === 'true') n += 3;", ''],
  ['Verifier: early release before the signed buffer not flagged (P4)', 'src/v5/supervisor/verifier.mjs', "if (tx.submitted_at < proposedAt + payBuffer) { v.push('BUFFER_BYPASSED'); out.buffer.violations++; }", ''],
  ['Verifier: tier not recomputed from the signed inputs (P4)', 'src/v5/supervisor/verifier.mjs', "String(tierFromInputs(s0.tierInputs, bufferPolicy)) === s0.tier", 'true'],
  ['Verifier: tier-reset check removed (P4)', 'src/v5/supervisor/verifier.mjs', 'if (x.tier < exp) resets.push(x.id);', ''],
  ['Vault: incident-flow pending cap removed (repair)', V, "return n >= INCIDENT_FLOW_PENDING_MAX ? ['INCIDENT_FLOW_PENDING_LIMIT'] : [];", 'return [];'],
];
// Higher-order mutants (P3): remove a check AND the path that makes it redundant. A first-order survivor whose
// higher-order mutant is caught is a verified redundant (defence-in-depth) check, not an untested one.
const HO = [
  ['HO: challenge single-use + action-nonce replay check removed', [[CMD, "if (s.v4.usedChallenges[g.challengeNonce] !== undefined) fail('CHALLENGE_ALREADY_CONSUMED');", ''], ['src/v3/root/chain.mjs', "if (state.usedNonces[action.nonce] !== undefined) fail('ACTION_REPLAY');", '']]],
  ['HO: challenge single-use + duplicate-approval check removed', [[CMD, "if (s.v4.usedChallenges[g.challengeNonce] !== undefined) fail('CHALLENGE_ALREADY_CONSUMED');", ''], [C, "if (new Set(ids).size !== ids.length) fail('DUPLICATE_APPROVAL');", '']]],
  ['HO: Rapid-Use restricted-scope check removed in the vault AND on the Root', [[V, "if (g.scope.credIds.some(c => this.root.creds[c]?.status !== 'active' || credentialHolds(this.root, c, now).length)) continue;", ''], [C, "else if (g.scope.credIds.some(c => s.creds[c]?.status !== 'active')) why = 'ENDED_CREDENTIAL_RESTRICTED';", '']]],
  ['HO: horizon gate + horizon deadline in the release check both removed', [[V, "if (now >= r.cap_expires_at || (r.settle_deadline !== null && now >= r.settle_deadline)) why = 'SETTLEMENT_HORIZON_EXPIRED';", "if (false) why = 'SETTLEMENT_HORIZON_EXPIRED';"], [V, `this.store.db.prepare("UPDATE payments SET cap_expires_at=? WHERE payment_id=? AND state='BUFFERED'").run(settleDeadline, paymentId);`, '']]],
];
const ALL = [...M.map(([name, file, from, to]) => [name, [[file, from, to]]]), ...HO];
const ONLY = process.env.MUTANTS ? new RegExp(process.env.MUTANTS) : null;
const tests = readdirSync('tests/v5').filter(f => f.endsWith('.test.mjs')).map(f => 'tests/v5/' + f);
const rows = [];
for (const [name, patches] of ALL) {
  if (ONLY && !ONLY.test(name)) continue;
  const files = [...new Set(patches.map(p => p[0]))]; const orig = Object.fromEntries(files.map(f => [f, readFileSync(f, 'utf8')]));
  const cur = { ...orig }; let missing = null;
  for (const [file, from, to] of patches) { if (!cur[file].includes(from)) { missing = file; break; } cur[file] = cur[file].replace(from, to); }
  if (missing) { rows.push({ name, files, error: 'PATTERN_NOT_FOUND:' + missing }); console.log(JSON.stringify(rows.at(-1))); continue; }
  for (const f of files) writeFileSync(f, cur[f]);
  try {
    const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--test', ...tests], { encoding: 'utf8', timeout: 900_000 });
    const fail = Number(/# fail (\d+)/.exec(r.stdout)?.[1] ?? -1);
    const failing = [...r.stdout.matchAll(/^not ok \d+ - (.*)$/gm)].map(m => m[1]).slice(0, 6);
    rows.push({ name, files, order: patches.length, caught: fail > 0, failingTests: fail, examples: failing });
  } finally { for (const f of files) writeFileSync(f, orig[f]); }
  console.log(JSON.stringify(rows.at(-1)));
}
mkdirSync(dirname(process.argv[2] ?? 'docs/evidence/v51/mutations.json'), { recursive: true });
writeFileSync(process.argv[2] ?? 'docs/evidence/v51/mutations.json', JSON.stringify({ generatedBy: 'scripts/v5/mutations.mjs', firstOrder: { caught: rows.filter(r => r.order === 1 && r.caught).length, total: rows.filter(r => r.order === 1).length }, higherOrder: { caught: rows.filter(r => r.order > 1 && r.caught).length, total: rows.filter(r => r.order > 1).length }, caught: rows.filter(r => r.caught).length, total: rows.length, rows }, null, 1) + '\n');
