// Periodic security reports (DAILY / WEEKLY / MONTHLY / IMMEDIATE). Every count comes from the trusted Footprint Journal
// (auditor view) and the notification outbox; an optional narrative written by the Analyst is attached as clearly labelled,
// non-authoritative text and is NOT covered by the counts digest. Reports are signed by the report service's own key and
// can be re-derived and checked by anyone holding the journal (verifyReport).
import { V5_DOMAINS, d5hex, verifyObj5 } from '../common/v5.mjs';
import { iso } from '../../v3/common/canon.mjs';

export const PERIODS = Object.freeze({ DAILY: 86_400_000, WEEKLY: 7 * 86_400_000, MONTHLY: 30 * 86_400_000 });
const COUNTED = {
  paymentsProposed: 'PAYMENT_PROPOSED', paymentsSettled: 'PAYMENT_SETTLED', paymentsDelayed: 'PAYMENT_DELAYED', paymentsCancelled: 'PAYMENT_CANCELLED', paymentsExpired: 'PAYMENT_EXPIRED',
  paymentsRejected: 'PAYMENT_REJECTED', invalidSignatures: 'INVALID_SIGNATURE', detections: 'UNUSUAL_ACTIVITY_DETECTED', incidentsOpened: 'INCIDENT_OPENED', incidentsReviewed: 'INCIDENT_REVIEWED',
  holdsCreated: 'HOLD_CREATED', holdsConfirmed: 'HOLD_CONFIRMED', holdsReleased: 'HOLD_RELEASED', holdsContested: 'HOLD_CONTESTED', credentialsRevoked: 'CREDENTIAL_REVOKED', recoveriesOpened: 'RECOVERY_OPENED',
  rapidRequested: 'RAPID_USE_REQUESTED', rapidActivated: 'RAPID_USE_ACTIVATED', rapidRevoked: 'RAPID_USE_REVOKED', rapidAccelerated: 'PAYMENT_ACCELERATED_RAPID_USE', delegationsGranted: 'DELEGATION_GRANTED',
  rootRejected: 'ROOT_REJECTED', attemptsSuppressed: 'ATTEMPTS_SUPPRESSED', analystFindings: 'ANALYST_FINDING_REVIEWED', notificationsQueued: 'NOTIFICATION_QUEUED',
};

export function computeCounts(events, from, to) {
  const inWin = events.filter(e => { const t = Date.parse(e.at); return t >= from && t < to; });
  const c = {};
  for (const [k, type] of Object.entries(COUNTED)) c[k] = String(inWin.filter(e => e.type === type).length);
  const att = inWin.filter(e => e.type === 'NOTIFICATION_ATTEMPT');
  for (const s of ['DELIVERED', 'TEMPORARY_FAILURE', 'PERMANENT_FAILURE', 'NOT_CONNECTED']) c['notify_' + s] = String(att.filter(e => e.outcome === s).length);
  let settled = 0n; for (const e of inWin.filter(e => e.type === 'PAYMENT_SETTLED')) settled += BigInt(e.data?.amount ?? '0'); c.settledYocto = settled.toString();
  const af = inWin.filter(e => e.type === 'ANALYST_FINDING_REVIEWED');
  for (const o of ['ACTIONED', 'CORROBORATED', 'INFERRED_ONLY']) c['analyst_' + o] = String(af.filter(e => e.outcome === o).length);
  return { counts: c, events: inWin.length, firstSeq: inWin[0]?.seq ?? '-', lastSeq: inWin.at(-1)?.seq ?? '-' };
}

export function buildReport({ kind, journal, signer, from = null, to = null, now, narrative = null, incidentId = null }) {
  if (!['DAILY', 'WEEKLY', 'MONTHLY', 'IMMEDIATE'].includes(kind)) throw new Error('REPORT_KIND');
  const end = to ?? now; const start = from ?? (kind === 'IMMEDIATE' ? end - 86_400_000 : end - PERIODS[kind]);
  const evs = journal.reader('auditor').events();
  const { counts, events, firstSeq, lastSeq } = computeCounts(evs, start, end);
  const head = journal.head();
  const statement = { v: 'safebox.v5.report', kind, accountId: journal.accountId, from: iso(start), to: iso(end), incidentId: incidentId ?? '-', counts, events: String(events), firstSeq: String(firstSeq), lastSeq: String(lastSeq),
    journalHead: head.hash, journalSeq: String(head.seq), countsDigest: d5hex(V5_DOMAINS.REPORT, counts) };
  return { statement, sig: signer.signObj(V5_DOMAINS.REPORT, statement),
    narrative: narrative ? { label: 'AI-generated narrative (Security Analyst). Not authoritative; the signed counts above are.', text: String(narrative).slice(0, 4000) } : null };
}

/** Independent check: signature, and every count re-derived from the journal rows. */
export function verifyReport(report, events, publicKey) {
  const st = report.statement; const problems = [];
  if (!verifyObj5(V5_DOMAINS.REPORT, st, report.sig, publicKey)) problems.push('BAD_SIGNATURE');
  const { counts } = computeCounts(events, Date.parse(st.from), Date.parse(st.to));
  for (const [k, v] of Object.entries(counts)) if (st.counts[k] !== v) problems.push(`COUNT_MISMATCH:${k}:${st.counts[k]}!=${v}`);
  if (st.countsDigest !== d5hex(V5_DOMAINS.REPORT, st.counts)) problems.push('COUNTS_DIGEST');
  return { ok: !problems.length, problems };
}

export function renderReportText(report) {
  const s = report.statement; const c = s.counts;
  const lines = [`SafeBox ${s.kind} security report ${s.from} .. ${s.to}`,
    `Payments: ${c.paymentsProposed} proposed, ${c.paymentsSettled} settled, ${c.paymentsDelayed} delayed, ${c.paymentsCancelled} cancelled, ${c.paymentsRejected} rejected`,
    `Incidents: ${c.incidentsOpened} opened, ${c.incidentsReviewed} reviewed; detections ${c.detections}`,
    `Protective holds: ${c.holdsCreated} created, ${c.holdsConfirmed} confirmed, ${c.holdsReleased} released, ${c.holdsContested} contested`,
    `Rapid-Use: ${c.rapidRequested} requested, ${c.rapidActivated} activated, ${c.rapidRevoked} ended early`,
    `Notifications: ${c.notify_DELIVERED} delivered, ${c.notify_TEMPORARY_FAILURE} temporary failures, ${c.notify_NOT_CONNECTED} not connected`,
    `Journal head ${s.journalHead.slice(0, 16)} at seq ${s.journalSeq}. Counts are computed from the journal; nothing in this report can approve anything.`];
  if (report.narrative) lines.push('', report.narrative.label, report.narrative.text);
  return lines.join('\n');
}
