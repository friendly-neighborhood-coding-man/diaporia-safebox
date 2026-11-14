// Mutation checks for the V6 controls (fingerprint gate, per-payment owner approval, Vault nonce single-use, Emergency
// Freeze console, V6 verifier, closeout verifier fixes E1/E3/Rapid-Use, Gmail least-privilege, RS256, loopback RP).
// Each mutant removes or weakens ONE check in place, runs the V6 suites, restores the file. "Caught" = >=1 test fails.
// Run in a separate git worktree (it edits sources in place):  node scripts/v6/mutations.mjs [out.json]
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
const VA = 'src/v6/vault/vault.mjs', PA = 'src/v6/vault/payment-approval.mjs', RC = 'src/v6/root/chain.mjs', BIO = 'src/v6/device/biometric.mjs',
  CON = 'src/v6/emergency/console.mjs', KIT = 'src/v6/kit.mjs', VER6 = 'src/v6/supervisor/verifier.mjs', VER5 = 'src/v5/supervisor/verifier.mjs',
  GM = 'src/v6/notify/gmail.mjs', WA = 'src/v3/webauthn/verify.mjs', C3 = 'src/v3/root/chain.mjs';
const M = [
  // Vault
  ['Vault: V6 challenge nonce single-use removed', VA, "if (this.store.db.prepare('SELECT 1 FROM v6_challenges WHERE nonce=?').get(pre.nonce)) fail('CHALLENGE_ALREADY_CONSUMED');", ''],
  // hardening P0.3: evidence and single use inside the payment transaction
  ['P0.3: V3 in-transaction record hook not called', 'src/v3/vault/vault.mjs', "this.proposeTxRecord({ paymentId, cap, credId: v.credId });", ''],
  ['P0.3: core reached without V6 verification accepted', VA, "if (this.policy6().payment.mode === 'PER_TRANSACTION') fail('V6_PAYMENT_APPROVAL_REQUIRED', 'no verified approval in this transaction');", ''],
  ['P0.3: in-transaction challenge check removed', VA, "if (this.store.db.prepare('SELECT 1 FROM v6_challenges WHERE nonce=?').get(p.pre.nonce)) fail('CHALLENGE_ALREADY_CONSUMED', 'in transaction');", ''],
  // hardening P0.1: HIGH_ASSURANCE fails closed for same-user gate keys
  ['P0.1: verifyGate HIGH_ASSURANCE check removed', BIO, "if (assurance !== 'LOCAL_GATE' && !highAssuranceGate(k)) fail('FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE', `${credId}: gate key ${k.kind} is usable by same-user code without a finger`);", ''],
  ['P0.1: a TPM-backed same-user key treated as isolated', BIO, "export const ISOLATED_GATE_KINDS = Object.freeze([]);", "export const ISOLATED_GATE_KINDS = Object.freeze(['WINBIO_TPM', 'SIMULATED']);"],
  ['P0.1: Root command gates verified without the assurance mode', RC, "gateKeys: s.v6.gateKeys, assurance: s.v6.policy.fingerprintAssurance ?? 'LOCAL_GATE' });", "gateKeys: s.v6.gateKeys });"],
  ['P0.1: Vault payment gates verified without the assurance mode', PA, "gateKeys: s.v6.gateKeys, assurance: s.v6.policy.fingerprintAssurance ?? 'LOCAL_GATE' });", "gateKeys: s.v6.gateKeys });"],
  ['P0.1: device prompts the sensor for a command that cannot be accepted', 'src/v6/kit.mjs', "#highUnavailable(g) { return (this.policy6.fingerprintAssurance ?? 'LOCAL_GATE') !== 'LOCAL_GATE' && !highAssuranceGate({ kind: g.kind }); }", "#highUnavailable(g) { return false; }"],
  ['P0.1: device prompts the sensor for a payment that cannot be accepted', 'src/v6/kit.mjs', "if ((s.v6.policy.fingerprintAssurance ?? 'LOCAL_GATE') !== 'LOCAL_GATE' && !highAssuranceGate(s.v6.gateKeys[credId])) { this.gateErrors.push({ credId, code: 'FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE' }); return null; }", ''],
  ['P0.1: console gate prompts for a command that cannot be accepted', 'src/v6/device/gate-service.mjs', "if ((st.v6?.policy?.fingerprintAssurance ?? 'LOCAL_GATE') !== 'LOCAL_GATE' && !highAssuranceGate(st.v6?.gateKeys?.[r0.credId])) fail('FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE');", ''],
  ['P0.1: assurance mode not validated', 'src/v6/common/v6.mjs', "if ('fingerprintAssurance' in p && !FP_ASSURANCE.includes(p.fingerprintAssurance)) fail('V6_POLICY_FP_ASSURANCE');", ''],
  ['P0.1 review: fingerprint-only credential pays without V6 approval under LEGACY_V5', VA, "if (v && (strict || fpCreds.includes(v.credId))) {", "if (v && strict) {"],
  ['P0.1 review: in-transaction fingerprint-only guard removed', VA, "if (this.policy6().fingerprintOnlyCreds.includes(ctx.credId)) fail('V6_PAYMENT_APPROVAL_REQUIRED', 'fingerprint-only credential without a verified approval');", ''],
  // hardening P1.8: DNS rebinding
  ['P1.8: console Host check removed', 'src/v6/emergency/console.mjs', "if (!this.#hostOk(String(req.headers?.host ?? ''))) {", "if (false) {"],
  ['P1.8: console Host check skipped for the real listener', 'src/v6/emergency/console.mjs', "}, { requireHost: true });", "});"],
  // hardening P1.7: immediate checkpoints for security-critical events
  ['P1.7: critical events not checkpointed immediately', 'src/v5/journal/journal.mjs', "if (seq % this.checkpointEvery === 0 || CHECKPOINT_NOW_TYPES.has(event.type)) this.checkpoint();", "if (seq % this.checkpointEvery === 0) this.checkpoint();"],
  // final independent review (1569fc6)
  ['Review3: verifier checks fingerprint-only approvals only under PER_TRANSACTION', 'src/v6/supervisor/verifier.mjs', "if (s0.v6.policy.payment.mode === 'PER_TRANSACTION' || s0.v6.policy.fingerprintOnlyCreds.includes(approval.credId)) {", "if (s0.v6.policy.payment.mode === 'PER_TRANSACTION') {"],
  ['Review3: gate prompt only neutralises the exact separator', 'src/v6/device/winbio-gate.mjs', ".replaceAll('|', '/')).join(' | ');", ".replaceAll(' | ', ' / ')).join(' | ');"],
  ['Review3: wrapper accepts a helper without the owner confirmation', 'src/v6/device/winbio-gate.mjs', "if (j.ownerConfirmed !== true) fail(", "if (false) fail("],
  // hardening P1.6: bounded console memory under a flood
  ['P1.6: pending logins not capped', 'src/v6/emergency/console.mjs', "while (this.logins.size > PENDING_LOGINS_MAX) this.logins.delete(this.logins.keys().next().value);", ''],
  ['P1.6: audit log not bounded', 'src/v6/emergency/console.mjs', "if (this.audit.length > AUDIT_MAX) {", "if (false) {"],
  // hardening P0.2: the gate reviews the console's prepared object against its own Root replica
  ['P0.2: prepared command not compared to the Root rebuild', 'src/v6/device/command-review.mjs', "if (canon(statement) !== canon(command)) fail('PREPARED_COMMAND_MISMATCH');", ''],
  ['P0.2: prepared grant not Root-pinned', 'src/v6/device/command-review.mjs', "if (!verifyObj(V4_DOMAINS.CHALLENGE, grant.statement, grant.sig, s.v4.challengeIssuer.publicKey)) fail('PREPARED_GRANT_NOT_ROOT_PINNED');", ''],
  ['P0.2: future rootSeq accepted', 'src/v6/device/command-review.mjs', "|| Number(command.rootSeq) > Number(s.seq)", ''],
  ['P0.2: gate shows the console digest instead of the rebuilt text', 'src/v6/device/gate-service.mjs', "challengeNonce: r0.grant.statement.challengeNonce, at, display: rv.text });", "challengeNonce: r0.grant.statement.challengeNonce, at, display: null });"],
  ['P0.2: payment summaryDigest not recomputed', PA, "if (b.summaryDigest !== summaryDigestOf(paymentSummary(s, b, { memo: null }))) fail('V6_SUMMARY_NOT_CANONICAL');", ''],
  ['Vault: delegation policy check removed', VA, "if (this.policy6().delegation !== 'BOUNDED_DELEGATION_ALLOWED') fail('DELEGATION_DISABLED_BY_POLICY');", ''],
  // payment approval binding
  ['Payment: owner approval not required', PA, "if (!v6) fail('V6_PAYMENT_APPROVAL_REQUIRED', 'per-transaction owner approval policy');", "if (!v6) return null;"],
  ['Payment: binding mismatch ignored', PA, "if (mism.length) fail('V6_BINDING_MISMATCH', mism.join(','));", ''],
  ['Payment: amount not bound', PA, "for (const k of ['recipientId', 'asset', 'amountYocto', 'purposeId', 'purposeVersion', 'epoch'])", "for (const k of ['recipientId', 'asset', 'purposeId', 'purposeVersion', 'epoch'])"],
  ['Payment: recipient not bound', PA, "for (const k of ['recipientId', 'asset', 'amountYocto', 'purposeId', 'purposeVersion', 'epoch'])", "for (const k of ['asset', 'amountYocto', 'purposeId', 'purposeVersion', 'epoch'])"],
  ['Payment: policy version not bound', PA, "if (b.policyVersion !== s.v6.policy.version) mism.push('policyVersion');", ''],
  ['Payment: taskRef not bound to binding', PA, "if (cap.taskRef !== taskRefFor(b)) mism.push('taskRef');", ''],
  ['Payment: assurance downgrade accepted', PA, "if (b.assurance !== requiredAssurance(s, credId)) fail('V6_ASSURANCE_MISMATCH'", "if (false) fail('V6_ASSURANCE_MISMATCH'"],
  ['Payment: challenge signature not checked', PA, "if (!verifyObj(V4_DOMAINS.CHALLENGE, g, gr.sig, s.v4.challengeIssuer.publicKey)) fail('CHALLENGE_SIGNATURE');", ''],
  ['Payment: challenge not bound to request digest', PA, "if (g.actionType !== PAY_ACTION_TYPE || g.actionDigest !== b.requestDigest) fail('CHALLENGE_NOT_FOR_THIS_REQUEST');", ''],
  ['Payment: challenge not bound to credential', PA, "if (g.credId !== credId) fail('CHALLENGE_NOT_FOR_THIS_CREDENTIAL');", ''],
  // fingerprint gate
  ['Gate: fingerprint-only credential needs no gate', RC, "const need = typeof ap.credId === 'string' && !s.v4.orcs[ap.credId] && s.creds[ap.credId] && fingerprintOnly(s, ap.credId);", 'const need = false;'],
  ['Gate: gate key PoP not checked at genesis', RC, "if (!verifyEs256Obj(V6_DOMAINS.GATE_POP, { accountId: st.accountId, v5ChainId: st.chainId, credId, gateKeyId: k.gateKeyId }, k.pop, k.spki)) fail('GATE_KEY_POP');", ''],
  ['Gate: missing gate accepted', BIO, "if (!gate) fail('FINGERPRINT_GATE_REQUIRED', credId);", "if (!gate) return;"],
  ['Gate: method not checked (PIN/UV accepted as fingerprint)', BIO, "if (st.method !== GATE_METHOD) fail('GATE_METHOD_NOT_FINGERPRINT', String(st.method));", ''],
  ['Gate: result not checked', BIO, "if (st.result !== 'MATCH') fail('GATE_RESULT_NOT_MATCH', String(st.result));", ''],
  ['Gate: bound digest not checked', BIO, "if (st.boundDigest !== boundDigestHex) fail('GATE_NOT_FOR_THIS_DIGEST');", ''],
  ['Gate: challenge nonce not checked', BIO, "if (st.challengeNonce !== challengeNonce) fail('GATE_NOT_FOR_THIS_CHALLENGE');", ''],
  ['Gate: signature not checked', BIO, "if (!verifyEs256Obj(V6_DOMAINS.BIOMETRIC_GATE, st, x.sig, k.spki)) fail('GATE_BAD_SIGNATURE');", ''],
  ['Gate: staleness not checked', BIO, "if (at - t > maxAgeMs) fail('GATE_STALE');", ''],
  ['Gate: wrong credential accepted', BIO, "if (st.credId !== credId || st.gateKeyId !== k.gateKeyId) fail('GATE_WRONG_CREDENTIAL');", ''],
  // emergency console
  ['Console: Origin check removed', CON, "if (!h.origin || h.origin !== this.origin) deny(403, 'ORIGIN_REJECTED', String(h.origin ?? 'none'));", ''],
  ['Console: CSRF token not checked', CON, "if (csrf && !eq(req.headers?.['x-safebox-csrf'] ?? '', sess.csrf)) deny(403, 'CSRF_TOKEN_INVALID');", ''],
  ['Console: login challenge reusable', CON, "if (L.used) deny(403, 'LOGIN_ALREADY_USED');", ''],
  ['Console: proposal reusable', CON, "if (prop.state !== 'PREPARED') deny(409, 'PROPOSAL_ALREADY_USED', prop.state);", ''],
  ['Console: proposal not bound to session', CON, "if (prop.sid !== sess.sid) deny(403, 'PROPOSAL_NOT_FOR_THIS_SESSION');", ''],
  ['Console: confirm phrase not required', CON, "if (confirm !== CONFIRM_PHRASE) deny(400, 'EXPLICIT_CONFIRMATION_REQUIRED');", ''],
  ['Console: unknown incident accepted', CON, "const row = this.incident(id); if (!row) deny(404, 'INCIDENT_UNKNOWN', 'no incident with this id was opened by the Risk Engine');", "const row = this.incident(id) ?? { incident_id: id, state: 'OPEN' };"],
  ['Console: approval not checked against prepared command', CON, "if (canon(ap.command ?? null) !== canon(prop.command)) deny(403, 'APPROVAL_NOT_FOR_PREPARED_COMMAND');", ''],
  ['Console: approval not checked against prepared challenge', CON, "if (canon(ap.grant ?? null) !== canon(prop.grant)) deny(403, 'APPROVAL_NOT_FOR_PREPARED_CHALLENGE');", ''],
  ['Console: direct FREEZE may forge an emergency reason', CON, "if (String(b.reason ?? '').startsWith('EMERGENCY_FREEZE')) deny(400, 'USE_EMERGENCY_FREEZE_FLOW');", ''],
  // owner device
  ['Device: signs a prepared command that differs from its own rebuild', KIT, "if (canon(statement) !== canon(command)) { this.gateErrors.push({ credId, code: 'PREPARED_COMMAND_MISMATCH' }); return null; }", ''],
  ['Device: prepared grant not checked against Root-pinned issuer', KIT, "if (!verifyObj(V4_DOMAINS.CHALLENGE, grant.statement, grant.sig, s.v4.challengeIssuer.publicKey)) { this.gateErrors.push({ credId, code: 'PREPARED_GRANT_NOT_ROOT_PINNED' }); return null; }", ''],
  // V6 verifier
  ['Verifier6: missing owner approval not flagged', VER6, "if (!x || x.payment_id !== paymentId) codes.push('OWNER_APPROVAL_MISSING');", ''],
  ['Verifier6: reused challenge not flagged', VER6, "if (nonces.has(r.nonce) && nonces.get(r.nonce) !== capId) codes.push('OWNER_APPROVAL_CHALLENGE_REUSED');", ''],
  ['Verifier6: misreported level not flagged', VER6, "if (r.level !== x.level) codes.push('OWNER_APPROVAL_LEVEL_MISREPORTED');", ''],
  ['Verifier6: delegated effect while disabled not flagged', VER6, "if (policy.delegation !== 'BOUNDED_DELEGATION_ALLOWED') codes.push('DELEGATED_EFFECT_WHILE_DELEGATION_DISABLED');", ''],
  ['Verifier6: malformed emergency reason not flagged', VER6, "if (!m) out.v6.emergency.violations.push({ holdId: h.holdId, code: 'EMERGENCY_FREEZE_REASON_MALFORMED' });", 'if (!m) {}'],
  ['Verifier6: freeze for unknown incident not flagged', VER6, "else if (journal && !opened.has(m[1])) out.v6.emergency.violations.push({ holdId: h.holdId, code: 'EMERGENCY_FREEZE_UNKNOWN_INCIDENT' });", ''],
  // closeout verifier fixes (V5 verifier)
  ['Verifier5 E3: older-open-incident decision not flagged', VER5, "if (ref !== '-' && open.length && maybeOpen.includes(ref) && incs.get(ref).t0 < Math.max(...open.map(id => incs.get(id).t0))) wrongOpen.push(pid);", ''],
  ['Verifier5 E1: hidden open incident not flagged', VER5, 'if (!grant) hidden.push(pid);', ''],
  ['Verifier5 Rapid: early release covered without a grant', VER5, 'const grant = !review && rapidCover(sE, sf, tx, paymentId, proposedAt);', 'const grant = !review;'],
  // Gmail
  ['Gmail: scope not checked', GM, "if (scopes.length !== 1 || scopes[0] !== GMAIL_SEND_SCOPE) {", 'if (false) {'],
  ['Gmail: ON without SAFEBOX_ALLOW_REAL_EMAIL', GM, "this.enabled = env.SAFEBOX_ALLOW_REAL_EMAIL === '1' && ", 'this.enabled = '],
  ['Gmail: recipient allowlist removed', GM, "if (!this.allowed.has(String(to).trim().toLowerCase())) {", 'if (false) {'],
  // WebAuthn / RP
  ['Genesis RP: loopback exception widened to any http origin', C3, "/^http:\\/\\/localhost:[1-9][0-9]{1,4}$/.test(b.rp.origin)", "/^http:\\/\\//.test(b.rp.origin)"],
];
// Higher-order mutants: a first-order survivor whose higher-order mutant is caught is a verified redundant check.
const HO = [
  ['HO: P0.3 challenge single use removed in the pre-check, the transaction AND the primary key', [[VA, "if (this.store.db.prepare('SELECT 1 FROM v6_challenges WHERE nonce=?').get(pre.nonce)) fail('CHALLENGE_ALREADY_CONSUMED');", ''], [VA, "if (this.store.db.prepare('SELECT 1 FROM v6_challenges WHERE nonce=?').get(p.pre.nonce)) fail('CHALLENGE_ALREADY_CONSUMED', 'in transaction');", ''], [VA, 'v6_challenges (nonce TEXT PRIMARY KEY,', 'v6_challenges (nonce TEXT,']]],
  ['HO: P0.1 review: fingerprint-only LEGACY_V5 guard removed in the pre-check AND the transaction', [[VA, "if (v && (strict || fpCreds.includes(v.credId))) {", "if (v && strict) {"], [VA, "if (this.policy6().fingerprintOnlyCreds.includes(ctx.credId)) fail('V6_PAYMENT_APPROVAL_REQUIRED', 'fingerprint-only credential without a verified approval');", '']]],
  ['HO: RS256 modulus minimum removed in BOTH the COSE parser and the signature check', [[WA, "pk.asymmetricKeyDetails.modulusLength >= 2048 && ", ''], [WA, "n.length < 256 || ", '']]],
];
const ONLY = process.env.MUTANTS ? new RegExp(process.env.MUTANTS) : null;
const suite = (d) => readdirSync(d).filter(f => f.endsWith('.test.mjs')).map(f => d + '/' + f);
const ALL = [...M.map(([name, file, from, to]) => [name, [[file, from, to]]]), ...HO];
const rows = [];
for (const [name, patches] of ALL) {
  if (ONLY && !ONLY.test(name)) continue;
  const files = [...new Set(patches.map(p => p[0]))]; const origs = Object.fromEntries(files.map(f => [f, readFileSync(f, 'utf8')]));
  const cur = { ...origs }; let missing = null;
  for (const [f, from, to] of patches) { if (!cur[f].includes(from)) { missing = f; break; } cur[f] = cur[f].replace(from, to); }
  const file = files.join(',');
  if (missing) { rows.push({ name, file, error: 'PATTERN_NOT_FOUND:' + missing }); console.log(JSON.stringify(rows.at(-1))); continue; }
  // V5 verifier mutants also run the V5 suites (their original tests live there)
  const tests = [...suite('tests/v6'), ...(files.some(f => f.startsWith('src/v5/')) ? suite('tests/v5') : [])];
  for (const f of files) writeFileSync(f, cur[f]);
  try {
    const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--test', ...tests], { encoding: 'utf8', timeout: 600_000 });
    const fail = Number(/# fail (\d+)/.exec(r.stdout)?.[1] ?? -1);
    rows.push({ name, file, order: patches.length, caught: fail !== 0, failingTests: fail, examples: [...r.stdout.matchAll(/^not ok \d+ - (.*)$/gm)].map(m => m[1]).slice(0, 4) });
  } finally { for (const f of files) writeFileSync(f, origs[f]); }
  console.log(JSON.stringify(rows.at(-1)));
}
const out = process.argv[2] ?? 'docs/evidence/v6/mutations.json';
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ generatedBy: 'scripts/v6/mutations.mjs', suites: 'tests/v6 (+ tests/v5 for src/v5 mutants)', caught: rows.filter(r => r.caught).length, total: rows.length, patternErrors: rows.filter(r => r.error).length, rows }, null, 1) + '\n');
