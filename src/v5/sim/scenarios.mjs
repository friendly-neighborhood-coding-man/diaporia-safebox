// V5 mandatory experiments (mission §14): deterministic, simulated time, MOCK ledger, MOCK email transport.
// Every scenario returns measured metrics plus the independent verifier's verdict. Nothing here touches real funds,
// real mailboxes or a real chain. Outcomes are measured, never assumed: a scenario "passes" only on the recorded facts.
import { buildV5, near } from '../world.mjs';
import { verifyWorld } from '../supervisor/verifier.mjs';
import { multiOwnerWorld } from '../kit.mjs';
import { T0 } from '../world.mjs';

const MIN = 60_000, H = 3600_000, D = 86_400_000;
const r2 = (r) => r.ok ? 'OK' : `${r.error.code}${r.error.detail ? ':' + String(r.error.detail).slice(0, 60) : ''}`;
const tryV = async (f) => { try { const r = await f(); return r && 'ok' in r ? r : { ok: true, result: r }; } catch (e) { return { ok: false, error: { code: e.code ?? 'ERROR', detail: e.detail ?? e.message } }; } };
export const scopeOf = (w, { credIds = ['k1-phone'], recipients = null, sessionCapYocto = '-' } = {}) => {
  const p = w.root.state.purpose;
  return { credIds, delegationIds: [], recipients: recipients ?? [...p.recipients], asset: p.asset, purposeId: p.purposeId, purposeVersion: p.version,
    perPaymentMaxYocto: p.perPaymentMaxYocto, dailyLimitYocto: p.dailyLimitYocto, cumulativeLimitYocto: p.cumulativeLimitYocto, sessionCapYocto };
};
const rapidReq = (w, by, id, o = {}) => w.cmd('RAPID_USE_REQUEST', { requestId: id, scope: o.scope ?? scopeOf(w, { credIds: o.credIds ?? ['k1-phone'] }), delayException: 'REMOVE_ANOMALY_DELAY', durationMs: String(o.durationMs ?? 4 * H), explanation: o.explanation ?? 'urgent supplier payments', incidentId: o.incidentId ?? '-' }, [by]);
const vote = (w, by, id, decision = 'APPROVE') => w.cmd('RAPID_USE_APPROVE', { requestId: id, requestDigest: w.root.state.v5.rapid.requests[id]?.digest ?? '0'.repeat(64), decision }, [by]);
const activate = (w, id) => w.submit({ action: w.action('RAPID_USE_ACTIVATE', { requestId: id, requestDigest: w.root.state.v5.rapid.requests[id]?.digest ?? '0'.repeat(64) }) });

function payStats(w, filter = () => true) {
  const ps = w.vault.v5payments().filter(filter);
  const sum = (l) => l.reduce((t, p) => t + BigInt(p.amount), 0n).toString();
  const by = (s) => ps.filter(p => p.state === s);
  return { proposed: ps.length, settled: by('SETTLED').length, settledYocto: sum(by('SETTLED')), cancelled: by('CANCELLED').length, expired: by('EXPIRED').length,
    buffered: by('BUFFERED').length, delayed: ps.filter(p => p.delay_ms > 0).length, acceleratedByRapid: ps.filter(p => p.anomaly === 'RELEASED_BY_RAPID').length };
}
const notifyStats = (w) => ({ outbox: w.notify.stats(), mockSent: w.mock.sent.length, recipients: [...new Set(w.mock.sent.map(m => m.to))].sort() });
async function finish(w, out) {
  const v = await verifyWorld(w);
  out.verifier = { ok: v.ok, chainValid: v.chainValid, effects: v.financial.effects, authorized: v.financial.authorized, violations: v.financial.violations, unauthorizedAuthority: v.authority.unauthorized.map(x => `${x.seq}:${x.type}:${x.code}`),
    rapidGrants: v.rapid.grants, rapidViolations: v.rapid.violations, journal: v.journal && { ok: v.journal.ok, events: v.journal.events, checkpointsVerified: v.journal.checkpointsVerified }, delays: v.delays };
  out.journal = { events: w.journal.stats.appended, suppressed: w.journal.stats.suppressed, bytes: w.journal.stats.bytes };
  return out;
}

/** Scenario A — attacker with a stolen DAILY key bursts allowed payments to an allowed merchant. */
export async function scenarioA({ payments = 30, everyMs = 20_000, amount = near(0.05), ownerResponseMs = 30 * MIN } = {}) {
  const w = buildV5(); const out = { scenario: 'A', desc: 'stolen DAILY key (k1-phone), in-Purpose burst to merchant-a', params: { payments, everyMs, amount, ownerResponseMs }, attempts: {} };
  const t0 = w.now(); let firstDetect = null, firstNotify = null, ownerActedAt = null;
  for (let i = 0; i < payments; i++) {
    const r = await w.pay({ credId: 'k1-phone', amountYocto: amount, request: { memo: 'invoice ' + i } });
    out.attempts[r.ok ? r.result.anomaly : r.error.code] = (out.attempts[r.ok ? r.result.anomaly : r.error.code] ?? 0) + 1;
    if (r.ok && r.result.anomaly !== 'NONE' && firstDetect === null) firstDetect = w.now();
    await w.advance(everyMs, everyMs);
    if (firstNotify === null && w.mock.sent.length) firstNotify = w.now();
    if (firstNotify !== null && ownerActedAt === null && w.now() - firstNotify >= ownerResponseMs) break;
  }
  // the attacker also tries to: approve its own Rapid-Use, expand authority, pay outside Purpose
  out.attackerActions = {
    rapidRequest: r2(await rapidReq(w, 'k1-phone', 'atk-rq')),
    rapidSelfVote: r2(await vote(w, 'k1-phone', 'atk-rq')),
    rapidActivate: r2(await activate(w, 'atk-rq')),
    payAttackerAccount: r2(await w.pay({ credId: 'k1-phone', recipientId: 'attacker.mock' })),
    payOverLimit: r2(await w.pay({ credId: 'k1-phone', amountYocto: near(0.07) })),
    amendPurpose: r2(await w.ownerAct('AMEND_PURPOSE', { capsule: { ...w.root.state.purpose, recipients: ['attacker.mock'] } }, ['k1-phone'], { notIntended: true })),
    releaseOwnDelay: r2(await w.cmd('INCIDENT_REVIEW', { incidentId: w.vault.incidents()[0]?.incident_id ?? 'none', credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: 'a'.repeat(64) }, ['k1-phone'], { notIntended: true })),
  };
  // the owner reads the alert in the SafeBox app, quarantines k1 with k2 and marks the incident as fraud, then revokes k1
  while (firstNotify !== null && w.now() - firstNotify < ownerResponseMs) await w.advance(MIN);
  ownerActedAt = w.now();
  const inc = w.vault.incidents()[0];
  out.owner = {
    quarantine: r2(await w.cmd('SUSPEND', { credId: 'k1-phone', holdId: 'q-k1' }, ['k2-laptop'])),
    fraudReview: inc ? r2(await w.cmd('INCIDENT_REVIEW', { incidentId: inc.incident_id, credId: 'k1-phone', verdict: 'FRAUD', evidenceDigest: 'b'.repeat(64) }, ['k2-laptop'])) : 'NO_INCIDENT',
    revoke: r2(await w.ownerAct('REVOKE', { credId: 'k1-phone', reason: 'stolen' }, ['k2-laptop', 'k3-root-hw'])),
  };
  await w.advance(26 * H, 10 * MIN);
  const atk = payStats(w, p => p.cred_id === 'k1-phone');
  out.metrics = { timeToDetectionMs: firstDetect === null ? null : firstDetect - t0, timeToFirstEmailMs: firstNotify === null ? null : firstNotify - t0, ...atk,
    settledBeforeDetection: inc ? inc.settled_before : atk.settled, exposureBeforeDetectionYocto: inc ? inc.exposure_before : atk.settledYocto, attackerBudgetLossYocto: atk.settledYocto,
    ownerPaymentAfter: r2(await w.pay({ credId: 'k2-laptop' })) };
  out.notifications = notifyStats(w);
  return finish(w, out);
}

/** Scenario B — the genuine owner needs the same high-volume pattern; Rapid-Use with ORC + separate owner key. */
export async function scenarioB({ payments = 30, everyMs = 20_000, amount = near(0.05), ownerResponseMs = 10 * MIN, multiOwner = false } = {}) {
  const w = multiOwner ? buildV5({ ownerWorld: multiOwnerWorld({ t0: T0, admins: ['alice', 'bob', 'carol', 'dave'] }) }) : buildV5();
  const payer = multiOwner ? 'alice-admin' : 'k1-phone';
  const out = { scenario: multiOwner ? 'B-multi' : 'B', desc: 'genuine urgent high-volume spending', params: { payments, everyMs, amount, ownerResponseMs, multiOwner }, steps: {} };
  const t0 = w.now(); let firstDelay = null, activatedAt = null, firstNotify = null, ok = 0, denied = {};
  const pay = async () => { const r = await w.pay({ credId: payer, amountYocto: amount }); if (r.ok) ok++; else denied[r.error.code] = (denied[r.error.code] ?? 0) + 1; if (r.ok && r.result.anomaly !== 'NONE' && firstDelay === null) firstDelay = w.now(); return r; };
  // phase 1: the owner keeps paying until they have read the alert and decided (ownerResponseMs after the first email)
  while (ok < payments && !(firstNotify !== null && w.now() - firstNotify >= ownerResponseMs)) {
    await pay(); await w.advance(everyMs, everyMs);
    if (firstNotify === null && w.mock.sent.length) firstNotify = w.now();
  }
  const inc = w.vault.incidents()[0]?.incident_id ?? '-';
  out.steps.request = r2(await rapidReq(w, payer, 'rq-1', { incidentId: inc, credIds: [payer], durationMs: 6 * H }));
  out.steps.votes = multiOwner ? [r2(await vote(w, 'alice-admin', 'rq-1')), r2(await vote(w, 'bob-admin', 'rq-1'))] : [r2(await vote(w, 'orc-1', 'rq-1')), r2(await vote(w, 'k3-root-hw', 'rq-1'))];
  out.steps.activate = r2(await activate(w, 'rq-1'));
  activatedAt = w.now();
  // phase 2: the rest of the urgent payments under Rapid-Use
  let guard = 0;
  while (ok < payments && guard++ < payments * 4) { await pay(); await w.advance(everyMs, everyMs); }
  out.steps.denied = denied;
  await w.advance(15 * MIN, MIN);
  const during = payStats(w);
  out.steps.end = r2(await w.cmd('RAPID_USE_REVOKE', { grantId: 'rq-1', reason: 'End Rapid-Use Mode: urgent activity complete' }, [payer]));
  // back to standard protection: the same pattern is delayed again
  const after = [];
  for (let k = 0; k < 4; k++) { const r = await w.pay({ credId: payer, amountYocto: amount }); after.push(r.ok ? r.result.anomaly : r.error.code); await w.advance(everyMs, everyMs); }
  await w.advance(26 * H, 10 * MIN);
  const all = payStats(w);
  out.metrics = { legitimateProposed: all.proposed, legitimateSettled: all.settled, completionRate: all.settled / Math.max(1, all.proposed), attemptsDeniedAtProposal: Object.values(denied).reduce((a, b) => a + b, 0), completionRateOfAttempts: all.settled / Math.max(1, all.proposed + Object.values(denied).reduce((a, b) => a + b, 0)), settledWithin15MinOfActivation: during.settled,
    acceleratedByRapid: all.acceleratedByRapid, delayBeforeAuthorizationMs: activatedAt && firstDelay ? activatedAt - firstDelay : null, timeToFirstDelayMs: firstDelay ? firstDelay - t0 : null,
    afterEndAnomaly: after, purposeUnchanged: JSON.stringify(w.root.state.purpose) === JSON.stringify(w.root.state.purpose), prompts: w.owner.metrics.prompts };
  out.notifications = notifyStats(w);
  return finish(w, out);
}

/** Scenario C — mixed and evasive attacker strategies, each a sub-case on a fresh world. */
export async function scenarioC() {
  const cases = {};
  const run = async (name, f) => { const w = buildV5(); try { cases[name] = await f(w); } catch (e) { cases[name] = { error: String(e.message).slice(0, 200) }; } cases[name].verifier = (await verifyWorld(w)).ok; cases[name].k1 = payStats(w, p => p.cred_id === 'k1-phone'); };
  await run('just_below_threshold_cold', async (w) => { for (let i = 0; i < 12; i++) { await w.pay({ amountYocto: near(0.05) }); await w.advance(13 * MIN, MIN); } return { note: 'one payment every 13 min stays under cold-start 10 min/1 h thresholds but hits 24 h volume' }; });
  await run('split_small_payments', async (w) => { for (let i = 0; i < 20; i++) { await w.pay({ amountYocto: near(0.001) }); await w.advance(MIN); } return {}; });
  await run('across_all_merchants', async (w) => { const m = ['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock']; for (let i = 0; i < 9; i++) { await w.pay({ recipientId: m[i % 3], amountYocto: near(0.05) }); await w.advance(MIN); } return {}; });
  await run('slow_baseline_poisoning', async (w) => {
    const now = w.now(); const rows = [];
    for (let d = 30; d >= 15; d--) for (let k = 0; k < 2; k++) rows.push({ credId: 'k1-phone', recipient: 'merchant-a.mock', amount: near(0.02), at: now - d * D + (10 + k) * H });
    for (let d = 14; d >= 4; d--) for (let k = 0; k < 2 + (15 - d); k++) rows.push({ credId: 'k1-phone', recipient: 'merchant-a.mock', amount: near(0.04), at: now - d * D + k * 20 * MIN });
    w.vault.seedHistory(rows);
    for (let i = 0; i < 14; i++) { await w.pay({ amountYocto: near(0.05) }); await w.advance(4 * MIN, MIN); }
    return { note: 'ramped 2/day -> 13/day over 11 days; growth cap 1.5x the older level' };
  });
  await run('false_alarm_against_other_key', async (w) => { for (let i = 0; i < 6; i++) { await w.pay({ amountYocto: near(0.05) }); await w.advance(MIN); } const r = await w.pay({ credId: 'k2-laptop' }); return { otherKeyAnomaly: r.ok ? r.result.anomaly : r.error.code }; });
  await run('notification_flood', async (w) => { for (let i = 0; i < 40; i++) { await w.pay({ amountYocto: near(0.001) }); await w.advance(30 * MIN, 10 * MIN); } return { notify: w.notify.stats(), incidents: w.vault.incidents().length }; });
  await run('forged_votes', async (w) => {
    await rapidReq(w, 'k1-phone', 'rq'); const q = w.root.state.v5.rapid.requests.rq;
    const a = w.action('RAPID_USE_APPROVE', { requestId: 'rq', requestDigest: q.digest, decision: 'APPROVE' });
    const real = w.owner.approveCommand(w.root.state, a, 'k1-phone', { at: w.now() });
    const forged = { ...real, credId: 'k3-root-hw' };
    return { forgedCredId: r2(await w.submit({ action: a, approvals: [forged] })), voteAsOrcWithK1Key: r2(await w.submit({ action: a, approvals: [{ ...real, credId: 'orc-1' }] })), activate: r2(await activate(w, 'rq')) };
  });
  await run('replay_prior_authorization', async (w) => {
    await rapidReq(w, 'k1-phone', 'rq1'); const q = w.root.state.v5.rapid.requests.rq1;
    const a = w.action('RAPID_USE_APPROVE', { requestId: 'rq1', requestDigest: q.digest, decision: 'APPROVE' });
    const req = { action: a, approvals: [w.owner.approveCommand(w.root.state, a, 'k3-root-hw', { at: w.now() })] };
    const first = r2(await w.submit(req)); await vote(w, 'orc-1', 'rq1'); await activate(w, 'rq1'); await w.cmd('RAPID_USE_REVOKE', { grantId: 'rq1', reason: 'done' }, ['orc-1']);
    await w.advance(2 * H, 10 * MIN); await rapidReq(w, 'k1-phone', 'rq2');
    const a2 = { ...req.action, body: { ...req.action.body, requestId: 'rq2', requestDigest: w.root.state.v5.rapid.requests.rq2.digest } };
    return { first, replaySame: r2(await w.submit(req)), replayRewrapped: r2(await w.submit({ action: a2, approvals: req.approvals })), activateRq2: r2(await activate(w, 'rq2')) };
  });
  await run('rapid_after_revocation', async (w) => {
    await rapidReq(w, 'k1-phone', 'rq'); await vote(w, 'orc-1', 'rq'); await vote(w, 'k3-root-hw', 'rq'); await activate(w, 'rq');
    const rev = r2(await w.ownerAct('REVOKE', { credId: 'k1-phone', reason: 'stolen' }, ['k2-laptop', 'k3-root-hw']));
    return { revoke: rev, grant: w.root.state.v5.rapid.grants.rq.status, payAfter: r2(await w.pay({})) };
  });
  await run('switch_epoch_or_purpose', async (w) => {
    await rapidReq(w, 'k1-phone', 'rq'); await vote(w, 'orc-1', 'rq'); await vote(w, 'k3-root-hw', 'rq'); await activate(w, 'rq');
    const rev = r2(await w.ownerAct('REVOKE', { credId: 'k4-freeze', reason: 'lost' }, ['k2-laptop', 'k3-root-hw']));
    return { epochBump: rev, grant: w.root.state.v5.rapid.grants.rq.status };
  });
  await run('continue_after_expiry', async (w) => {
    await rapidReq(w, 'k1-phone', 'rq', { durationMs: H }); await vote(w, 'orc-1', 'rq'); await vote(w, 'k3-root-hw', 'rq'); await activate(w, 'rq');
    await w.advance(H + MIN, 10 * MIN);
    const after = []; for (let i = 0; i < 5; i++) { const r = await w.pay({ amountYocto: near(0.05) }); after.push(r.ok ? r.result.anomaly : r.error.code); await w.advance(MIN); }
    return { grant: w.root.state.v5.rapid.grants.rq.status, after };
  });
  await run('exhaust_emergency_resources', async (w) => {
    const res = []; for (let i = 0; i < 6; i++) { res.push(r2(await rapidReq(w, 'k1-phone', 'x' + i))); await w.advance(61 * MIN, 30 * MIN); }
    return { attackerRequests: res, ownerStillCanRequest: r2(await rapidReq(w, 'k2-laptop', 'own', { credIds: ['k2-laptop'] })) };
  });
  return { scenario: 'C', desc: 'mixed / evasive strategies', cases };
}

/** Scenario D — repeated malicious Rapid-Use requests without a quorum (personal and multi-owner). */
export async function scenarioD({ attempts = 30 } = {}) {
  const w = buildV5(); const codes = {};
  for (let i = 0; i < attempts; i++) {
    for (const r of [await rapidReq(w, 'k1-phone', 'd' + i), await vote(w, 'k1-phone', 'd' + i), await vote(w, 'k2-laptop', 'd' + i), await activate(w, 'd' + i)]) codes[r2(r).split(':')[0]] = (codes[r2(r).split(':')[0]] ?? 0) + 1;
    await w.advance(20 * MIN, 10 * MIN);
  }
  const grants = Object.values(w.root.state.v5.rapid.grants).length;
  const ownerPath = { request: r2(await rapidReq(w, 'k2-laptop', 'own', { credIds: ['k2-laptop'] })), orc: r2(await vote(w, 'orc-1', 'own')), k3: r2(await vote(w, 'k3-root-hw', 'own')), activate: r2(await activate(w, 'own')) };
  const audited = w.journal.reader('auditor').events().filter(e => /RAPID|ROOT_REJECTED|ATTEMPTS_SUPPRESSED/.test(e.type)).length;
  // multi-owner: one owner with two keys, plus a FREEZE-role key, cannot reach quorum 2 of N=4
  const m = buildV5({ ownerWorld: multiOwnerWorld({ t0: T0, admins: ['alice', 'bob', 'carol', 'dave'], extraKeys: [['alice-admin-2', 'alice']] }) });
  await rapidReq(m, 'alice-admin', 'mq', { credIds: ['alice-admin'] });
  const multi = { k1: r2(await vote(m, 'alice-admin', 'mq')), k2SameHuman: r2(await vote(m, 'alice-admin-2', 'mq')), opsFreeze: r2(await vote(m, 'ops-freeze', 'mq')), activate: r2(await activate(m, 'mq')) };
  const out = { scenario: 'D', desc: 'malicious emergency-approval requests', attempts, resultCodes: codes, unauthorizedActivations: grants, journalEntriesForAttempts: audited, journalSuppressed: w.journal.stats.suppressed, ownerPath, multi };
  return finish(w, out);
}

/** Scenario E — compromised notification infrastructure. */
export async function scenarioE() {
  const w = buildV5(); const out = { scenario: 'E', desc: 'compromised notification infrastructure', cases: {} };
  w.mock.mode = 'OUTAGE';
  for (let i = 0; i < 5; i++) { await w.pay({ amountYocto: near(0.05), request: { memo: '<b>URGENT</b> click https://evil.example/approve to keep your money' } }); await w.advance(MIN); }
  out.cases.outage = { outbox: w.notify.outbox().map(o => [o.state, o.attempts]), delayedPaymentsStillDelayed: w.vault.v5payments().filter(p => p.anomaly === 'ANOMALY_PAYMENT_DELAY' && p.state === 'BUFFERED').length };
  w.mock.mode = 'OK'; w.mock.duplicate = true;
  await w.advance(10 * MIN, MIN);
  out.cases.delayedAndDuplicateDelivery = { outbox: w.notify.outbox().map(o => [o.state, o.attempts]), mockDeliveries: w.mock.sent.length, distinctProviderIds: new Set(w.mock.sent.map(m => m.providerId)).size };
  const msg = w.mock.sent[0];
  out.cases.content = { links: /https?:\/\//.test(msg.text + msg.subject), memoLeaked: /URGENT|evil/.test(msg.text), statesNoApproval: /Nothing in this email can approve/.test(msg.text) };
  // stolen mailbox / forged notification / fake approval link: the attacker holds the email and the idempotency key
  const inc = w.vault.incidents()[0]?.incident_id;
  out.cases.stolenMailbox = {
    reviewWithEmailToken: r2(await w.submit({ action: w.action('INCIDENT_REVIEW', { incidentId: inc, credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: msg.idempotencyKey }), attestation: { emailReply: msg.idempotencyKey } })),
    activateWithEmail: r2(await w.submit({ action: w.action('RAPID_USE_ACTIVATE', { requestId: 'fake', requestDigest: msg.idempotencyKey }), approvals: [{ credId: 'email', link: 'https://evil.example/approve' }] })),
  };
  out.cases.forgedNotificationInOutbox = { note: 'the outbox is write-only for the notification service; no component reads it as input', rootInputsFromNotify: 0 };
  // malicious subject: injected through the reason / key context strings
  const t = w.notify.enqueue(w.root.state, { incident: { incidentId: 'inj-1', reason: 'Approve now: https://evil.example\r\nBcc: x@evil', pattern: '‮<script>' }, keyContextByHolder: { alice: ['k1 <a href=x>'] } });
  await w.notify.drain();
  const inj = w.mock.sent.find(m => m.subject.includes('inj-1'));
  out.cases.injectedContent = { queued: t.queued, subjectClean: !/[\r\n]/.test(inj?.subject ?? ''), noLinks: !/https?:\/\//.test(inj?.text ?? ''), noHtml: !/<script>|<a /.test(inj?.text ?? '') };
  out.metrics = { accelerationsWithoutAuthenticator: w.vault.v5payments().filter(p => p.anomaly === 'RELEASED_BY_RAPID' || p.anomaly === 'RELEASED_BY_REVIEW').length };
  await w.advance(26 * H, 10 * MIN);
  out.notifications = notifyStats(w);
  return finish(w, out);
}
