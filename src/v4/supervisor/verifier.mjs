// Independent V4 verifier (supervisor domain). Replays the V4 chain from the pinned genesis with the V4 state machine,
// which re-derives every AuthorizationIntent from (state, action, grant) and re-checks every trusted-confirmation and
// ballot opening, then checks every ledger effect (V3 verifier logic, unchanged) and lists authority changes.
// It also reports, per authority change, the confirmation assurance levels that authorized it.
import * as V4 from '../root/chain.mjs';
import { verifyV3, AUTHORITY_TYPES as V3_TYPES } from '../../v3/supervisor/verifier.mjs';

export const AUTHORITY_TYPES_V4 = new Set([...V3_TYPES, 'RECOVERY_OWNER_AUTHORIZE', 'RECOVERY_ORC_CANCEL', 'ORC_REPLACE', 'GOV_CASE_OPEN', 'GOV_CASE_EXECUTE', 'GOV_CASE_CANCEL', 'GUARDIAN_ROTATE']);
// RECOVERY_EXPIRE / GOV_EXPIRE are housekeeping terminations that transfer no authority (not listed as authority changes).
const TAKEOVER = ['RECOVERY_COMPLETE', 'RECONSTITUTE', 'GOV_CASE_EXECUTE'];

export function verifyV4(args) {
  const out = verifyV3({ ...args, chain: V4, authorityTypes: AUTHORITY_TYPES_V4, takeoverTypes: TAKEOVER });
  // confirmation assurance per authority change (from a second, independent replay)
  out.assurance = [];
  out.participants = { removed: [], added: [] };
  if (out.chainValid) {
    let st = V4.genesisState(args.genesis, { pinnedChainId: args.pinnedChainId });
    for (const tr of args.transitions) {
      const r = V4.applyTransition(st, tr); st = r.state;
      const lv = r.effects.find(e => e.type === 'CONFIRMATION_ASSURANCE');
      if (lv && AUTHORITY_TYPES_V4.has(tr.action.type)) out.assurance.push({ seq: tr.seq, type: tr.action.type, levels: lv.levels });
      const ex = r.effects.find(e => e.type === 'GOV_EXECUTED'); if (ex) { out.participants.removed.push(...ex.removed); out.participants.added.push(...ex.added); }
    }
  }
  return out;
}
