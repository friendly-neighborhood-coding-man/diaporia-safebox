// V5 Risk Policy Engine: the ONLY component that decides whether a predefined protective condition applies.
// It is deterministic (detector.mjs + RISK_POLICY_V1), versioned (policy digest in every decision) and signs its
// decisions with its own key. It can only (a) request a BOUNDED anomaly delay of specific unsettled payments, and
// (b) END a Rapid-Use grant under one of the predefined rules. It cannot sign owner approvals, freeze, unfreeze,
// release, change Purpose, or start / extend Rapid-Use. The Security Analyst's findings are DATA to it: a finding can
// at most ask it to re-run its own deterministic checks (corroboration); the finding's prose never acts.
import { fail, exactFields } from '../../v3/common/canon.mjs';
import { V5_DOMAINS, d5hex } from '../common/v5.mjs';
import { evaluate, RISK_POLICY_V1, policyDigest } from './detector.mjs';
import { bufferDecision } from './buffer.mjs';
import { createHash } from 'node:crypto';
/** P1 (N3/N4): an incident's id is derived from the payment whose engine decision opened it, so the independent
 *  verifier can bind every HIGH decision and every owner review to one incident from the engine journal alone. */
export const incidentIdFor = (paymentId) => 'inc-' + createHash('sha256').update('DIAPORIA_SAFEBOX_V51_INCIDENT\n' + String(paymentId)).digest('hex').slice(0, 24);

export const FINDING_KINDS = Object.freeze(['UNUSUAL_SPENDING', 'CORRELATED_SECURITY_EVENTS', 'NOTIFICATION_ANOMALY', 'JOURNAL_INTEGRITY', 'PROTECTIVE_HOLD_PATTERN', 'RAPID_USE_PATTERN', 'OTHER']);
export const RECOMMENDATIONS = Object.freeze(['NONE', 'REQUEST_VERIFICATION', 'OWNER_REVIEW', 'REPORT_ONLY']);
export const CLAIM_CLASSES = Object.freeze(['OBSERVED', 'INFERRED']); // CORROBORATED / ACTIONED are assigned by the engine, never by the model

/**
 * V5.1 (P1) deterministic LOW / HIGH classification of a delay decision. HIGH when the evidence is strong enough that
 * an unresolved payment must NOT settle automatically: any hard ceiling, a soft score of at least twice the delay
 * threshold, correlation with a recent security event, or an incident that has already escalated (>= escalateAfterDelayed
 * delayed payments). Everything else that is delayed is LOW (bounded delay, then conditional settlement).
 */
export function riskClassOf(ev, openIncident, P = RISK_POLICY_V1) {
  if (ev.hard) return 'HIGH';
  if (Number(ev.score) >= 2 * Number(P.decision.delayScore)) return 'HIGH';
  if (ev.features?.securityCorrelated === 'true' && ev.decision === 'DELAY') return 'HIGH';
  // escalation counts the incident's own DELAY decisions (triggers), not the payments swept into it by the flow-wide delay
  if (openIncident && (openIncident.risk_class === 'HIGH' || Number(openIncident.triggers ?? 0) >= Number(P.delay.escalateAfterDelayed))) return 'HIGH';
  return 'LOW';
}

export class RiskPolicyEngine {
  constructor({ signer, policy = RISK_POLICY_V1, journal = null }) {
    this.signer = signer; this.policy = policy; this.digest = policyDigest(policy); this.journal = journal;
    this.decisions = 0; this.findings = [];
  }
  /** Deterministic evaluation + signed decision. The vault verifies the signature and enforces its own hard caps. */
  decide(p, ctx, { openIncident = null, bufferPolicy = 'FIXED_600' } = {}) {
    const ev = evaluate(p, ctx, this.policy);
    const buf = bufferDecision(p, ctx, ev, { policy: bufferPolicy, openIncident });
    let action = 'NONE', delayMs = '0';
    if (ctx.rapid) {
      // Rapid-Use: the approved flow is not delayed for anomalies, but monitoring continues and the hard velocity ceiling still applies
      if (ev.reasons.some(r => r.code === 'RAPID_USE_VELOCITY_CEILING')) { action = 'DELAY_AND_END_RAPID'; delayMs = this.policy.delay.anomalyDelayMs; }
    } else if (ev.decision === 'DELAY' || openIncident) {
      action = 'DELAY';
      delayMs = openIncident && Number(openIncident.delayed_count) >= Number(this.policy.delay.escalateAfterDelayed) ? this.policy.delay.maxDelayMs : this.policy.delay.anomalyDelayMs;
    }
    const riskClass = action === 'NONE' ? 'NONE' : riskClassOf(ev, openIncident, this.policy);
    const statement = { kind: 'ANOMALY_DECISION', paymentId: p.paymentId, flow: p.flow, action, delayMs, riskClass, bufferPolicy: buf.policy, tier: buf.tier, bufferMs: buf.bufferMs, tierInputs: buf.inputs,
      policy: this.policy.version, policyDigest: this.digest,
      evaluationDigest: d5hex(V5_DOMAINS.RISK_ENGINE, { reasons: ev.reasons.map(r => r.code), features: ev.features }), incidentRef: openIncident?.incident_id ?? '-' };
    this.decisions++;
    const sig = this.signer.signObj(V5_DOMAINS.RISK_ENGINE, statement);
    // the engine records its own decisions through its own (RISK-layer) writer, independent of the vault's records
    // every buffer decision is journaled by the engine itself (RISK layer), so the verifier can cross-check the vault
    this.journal?.append({ type: 'BUFFER_DECISION', relatedId: p.paymentId, outcome: buf.policy, data: { tier: buf.tier, bufferMs: buf.bufferMs, inputs: buf.inputs } });
    if (action !== 'NONE' || ev.decision !== 'NONE') this.journal?.append({ type: 'ENGINE_DECISION', relatedId: p.paymentId, outcome: action, data: { delayMs, riskClass, incidentRef: statement.incidentRef, level: ev.decision, policy: this.policy.version, evaluationDigest: statement.evaluationDigest } });
    return { ev, statement, sig };
  }
  rapidRevokeAttestation(action, ruleId, evidenceDigest) {
    return { engineSig: this.signer.signObj(V5_DOMAINS.RISK_ENGINE, { kind: 'RAPID_USE_REVOKE', actionDigest: action.digestHex, ruleId, evidenceDigest }), ruleId, evidenceDigest };
  }

  /**
   * Schema-validated intake of an Analyst finding. Returns the classified record. Rules:
   *  * unknown fields / kinds / recommendations are rejected (no free-form tool or command channel exists);
   *  * an OBSERVED claim must cite existing journal events and, if it states a metric, the metric must equal the
   *    engine's own recomputation; otherwise it is downgraded to UNSUPPORTED (never silently accepted);
   *  * CORROBORATED is assigned only when the engine's deterministic detector independently agrees;
   *  * ACTIONED is assigned only when a predefined rule actually acted.
   */
  intakeFinding(f, { eventIds, recompute, corroborate }) {
    exactFields(f, ['findingId', 'kind', 'severity', 'flowRef', 'claims', 'recommendation', 'summary'], [], 'FINDING_FIELDS');
    if (!/^[a-z0-9-]{3,48}$/.test(f.findingId)) fail('FINDING_ID');
    if (!FINDING_KINDS.includes(f.kind)) fail('FINDING_KIND');
    if (!['LOW', 'MEDIUM', 'HIGH'].includes(f.severity)) fail('FINDING_SEVERITY');
    if (typeof f.flowRef !== 'string' || f.flowRef.length > 64) fail('FINDING_FLOW');
    if (typeof f.summary !== 'string' || f.summary.length > 600) fail('FINDING_SUMMARY');
    if (!Array.isArray(f.claims) || f.claims.length > 12) fail('FINDING_CLAIMS');
    exactFields(f.recommendation, ['kind', 'note'], [], 'FINDING_RECOMMENDATION');
    if (!RECOMMENDATIONS.includes(f.recommendation.kind)) fail('FINDING_RECOMMENDATION_KIND', 'the analyst can only recommend verification or review');
    const claims = f.claims.map(c => {
      exactFields(c, ['cls', 'text', 'eventIds'], ['metric'], 'FINDING_CLAIM_FIELDS');
      if (!CLAIM_CLASSES.includes(c.cls)) return { ...c, cls: 'REJECTED_CLASS', note: 'the model cannot assign ' + String(c.cls).slice(0, 20) };
      if (typeof c.text !== 'string' || c.text.length > 400 || !Array.isArray(c.eventIds) || c.eventIds.length > 32) return { ...c, cls: 'REJECTED_SHAPE' };
      if (c.cls === 'OBSERVED') {
        if (!c.eventIds.length || c.eventIds.some(e => !eventIds.has(e))) return { ...c, cls: 'UNSUPPORTED', note: 'cited events do not exist' };
        if (c.metric) { exactFields(c.metric, ['name', 'value'], [], 'FINDING_METRIC'); const truth = recompute(c.metric.name, f.flowRef); if (truth === null || String(truth) !== String(c.metric.value)) return { ...c, cls: 'UNSUPPORTED', note: `metric ${c.metric.name}: engine computes ${truth}` }; }
      }
      return c;
    });
    const rec = { finding: { ...f, claims }, at: null, corroborated: false, actioned: false };
    if (f.recommendation.kind === 'REQUEST_VERIFICATION') { const r = corroborate(f.flowRef); rec.corroborated = !!r?.corroborated; rec.actioned = !!r?.actioned; rec.engineResult = r?.detail ?? '-'; }
    this.findings.push(rec);
    this.journal?.append({ type: 'ANALYST_FINDING_REVIEWED', relatedId: f.findingId, outcome: rec.actioned ? 'ACTIONED' : rec.corroborated ? 'CORROBORATED' : 'INFERRED_ONLY',
      evidenceRefs: claims.flatMap(c => c.eventIds ?? []).slice(0, 32), data: { kind: f.kind, observed: String(claims.filter(c => c.cls === 'OBSERVED').length), inferred: String(claims.filter(c => c.cls === 'INFERRED').length), unsupported: String(claims.filter(c => !CLAIM_CLASSES.includes(c.cls)).length) } });
    return rec;
  }
}
export { RISK_POLICY_V1, policyDigest };
