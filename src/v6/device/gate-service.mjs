// Local fingerprint-gate service for the Owner Console page (real-device runner). The console page cannot reach the
// WinBio helper itself; it asks this service, which runs in the owner's runner process, to attest a COMMAND digest.
import { commandDigest } from '../../v5/root/command.mjs';
import { exactFields, fail } from '../../v3/common/canon.mjs';
import { reviewPrepared } from './command-review.mjs';
import { highAssuranceGate } from './biometric.mjs';

/**
 * LEGACY decision (bf7403d, extracted verbatim from scripts/v6/real-device.mjs, kept for the P0.2 reproducer):
 * signs any digest the console currently holds as PREPARED, i.e. it TRUSTS the console's own proposal list and shows
 * the human only "<subject> <digest prefix>" in the gate window.
 */
export function legacyConsoleGate({ consoleObj, gates, now }, q) {
  const g = gates[q.credId]; if (!g) throw Object.assign(new Error('no gate'), { code: 'FINGERPRINT_ONLY_UNSUPPORTED' });
  const prepared = new Set([...[...consoleObj.proposals.values()].filter((x) => x.state === 'PREPARED').map((x) => commandDigest(x.command).toString('hex')),
    ...[...consoleObj.bundles.values()].filter((x) => x.state === 'OPEN').flatMap((x) => [...x.challenges.values()].map((c) => c.command ? commandDigest(c.command).toString('hex') : null))]);
  if (q.subject !== 'COMMAND' || !prepared.has(q.boundDigestHex)) throw Object.assign(new Error('not prepared'), { code: 'GATE_DIGEST_NOT_PREPARED_BY_CONSOLE' });
  return g.attest({ accountId: q.accountId, chainId: q.chainId, subject: q.subject, boundDigestHex: q.boundDigestHex, challengeNonce: q.challengeNonce, at: now() });
}

/**
 * P0.2 decision (issue #14). Trusts NOTHING the console holds or says: the request must carry the prepared
 * {action, grant, command}; the owner side rebuilds the exact Command Statement from its OWN Root replica
 * (reviewPrepared: Root-pinned grant, credential, account, expiry, rootSeq, canonical statement) and the gate window
 * shows the text derived from that rebuilt statement. Only then is the physical fingerprint asked for, bound to the
 * rebuilt statement's digest. The console's proposal list is not consulted at all.
 */
export function consoleGate({ rootState, gates, now }, q) {
  const r0 = exactFields(q, ['subject', 'credId', 'action', 'grant', 'command'], ['accountId', 'chainId', 'boundDigestHex', 'challengeNonce'], 'GATE_REQUEST_FIELDS');
  if (r0.subject !== 'COMMAND') fail('GATE_REQUEST_SUBJECT');
  const g = gates[r0.credId]; if (!g) fail('FINGERPRINT_ONLY_UNSUPPORTED');
  const at = now(); const st = rootState();
  // P0.1: never prompt for a fingerprint the Root will refuse (HIGH_ASSURANCE with a same-user gate key)
  if ((st.v6?.policy?.fingerprintAssurance ?? 'LOCAL_GATE') !== 'LOCAL_GATE' && !highAssuranceGate(st.v6?.gateKeys?.[r0.credId])) fail('FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE');
  const rv = reviewPrepared(st, { action: r0.action, grant: r0.grant, command: r0.command }, r0.credId, at);
  // the page's own digest/nonce hints (if any) must agree; they never select what is signed
  if (r0.boundDigestHex !== undefined && r0.boundDigestHex !== rv.digestHex) fail('GATE_REQUEST_DIGEST_MISMATCH');
  if (r0.challengeNonce !== undefined && r0.challengeNonce !== r0.grant.statement.challengeNonce) fail('GATE_REQUEST_NONCE_MISMATCH');
  return g.attest({ accountId: rv.statement.accountId, chainId: rv.statement.chainId, subject: 'COMMAND', boundDigestHex: rv.digestHex,
    challengeNonce: r0.grant.statement.challengeNonce, at, display: rv.text });
}
