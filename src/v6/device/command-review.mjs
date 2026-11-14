// Owner-device review of a command PREPARED elsewhere (the Owner Console). P0.2 (issue #14): the owner side never
// trusts the console's statement, digest or display text. It rebuilds the exact canonical Command Statement from its
// OWN verified Root projection plus the Root-pinned grant, refuses any difference, and derives the text it shows from
// that rebuilt statement and the action itself. Used by the simulated owner device (kit.approvePrepared) and by the
// real-device fingerprint-gate service, so both apply one rule.
import { fail, canon } from '../../v3/common/canon.mjs';
import { actionDigest } from '../../v3/root/chain.mjs';
import { projectState } from '../../v5/root/chain.mjs';
import { buildCommand, commandDigest } from '../../v5/root/command.mjs';
import { V4_DOMAINS, verifyObj } from '../../v4/common/v4.mjs';

const plain = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
/** Device-derived detail lines for the human (the action is bound by actionDigest; nothing here comes from the page). */
export function actionDetailLines(a) {
  const out = [];
  if (a.type === 'FREEZE') out.push(`Scope: GLOBAL (every unsettled payment of ${a.accountId} is held; settled payments cannot be undone)`, `Hold: ${a.body.freezeId} (${a.body.source === 'owner' ? 'PROVISIONAL_HOLD, 24 h unless independently confirmed' : a.body.source})`, `Reason: ${String(a.body.reason).slice(0, 160)}`);
  if (a.type === 'HOLD_RELEASE') out.push(`Releases hold: ${a.body.holdId} (digest ${String(a.body.holdDigest).slice(0, 16)}...)`);
  out.push(`Action expires: ${a.expiresAt}`);
  return out;
}

/**
 * Returns { statement, digestHex, text } for the prepared {action, grant, command} if and only if it is exactly what this
 * Root state produces for `credId`. Throws PREPARED_* otherwise. `at` = the reviewer's own clock.
 */
export function reviewPrepared(state, prepared, credId, at) {
  if (!plain(prepared)) fail('PREPARED_FORMAT');
  const { action, grant, command } = prepared;
  if (!plain(action) || !plain(grant) || !plain(grant.statement) || !plain(command)) fail('PREPARED_FORMAT');
  const s = projectState(state, at);
  const party = s.creds[credId];
  if (!party || command.credId !== credId || grant.statement.credId !== credId) fail('PREPARED_NOT_FOR_THIS_DEVICE');
  if (grant.statement.actionDigest !== actionDigest(action).toString('hex') || grant.statement.actionType !== action.type) fail('PREPARED_GRANT_MISMATCH');
  if (!verifyObj(V4_DOMAINS.CHALLENGE, grant.statement, grant.sig, s.v4.challengeIssuer.publicKey)) fail('PREPARED_GRANT_NOT_ROOT_PINNED');
  if (grant.statement.accountId !== s.accountId || grant.statement.chainId !== s.chainId) fail('PREPARED_WRONG_ACCOUNT');
  if (!(at < Date.parse(grant.statement.expiresAt))) fail('PREPARED_EXPIRED');
  // the console may only choose WHEN it prepared (rootSeq <= the reviewer's head); everything else is rebuilt
  if (!/^[0-9]+$/.test(String(command.rootSeq)) || Number(command.rootSeq) > Number(s.seq)) fail('PREPARED_ROOT_SEQ');
  const { statement, text: base } = buildCommand(s, action, grant.statement, party, { rootSeq: command.rootSeq });
  if (canon(statement) !== canon(command)) fail('PREPARED_COMMAND_MISMATCH');
  return { statement, digestHex: commandDigest(statement).toString('hex'), base, text: [base, ...actionDetailLines(action)].join('\n') };
}
