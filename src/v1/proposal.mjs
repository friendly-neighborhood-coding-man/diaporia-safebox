// Upstream integration contract: how DIAPORIA Buy, another agent, or an MCP host PROPOSES
// an economic action. A proposal carries intent + opaque context only. It cannot carry
// authorization, signer, contract, nonce, expiry timestamps, method, gas or any key material.
import { fail, requireExactFields, simpleId, atomicAmount, testnetAccountId, isPlainObject } from './canonical.mjs';
import { ACTIONS } from './intent.mjs';

export const PROPOSAL_VERSION = 'safebox.proposal.v1';
export const MAX_PROPOSAL_BYTES = 8192;
const FIELDS = ['v', 'principalId', 'mandateId', 'action', 'recipientId', 'amountYocto', 'ttlSeconds', 'context'];
const CONTEXT_FIELDS = ['source', 'summary', 'evidenceRefs'];
const PRINTABLE = /^[\x20-\x7e]*$/;

/**
 * Validate an untrusted proposal. Accepts either a JSON string or a plain object.
 * Returns a frozen, normalised proposal. `context` is stored for audit but NEVER
 * influences any execution field.
 */
export function parseProposal(input) {
  let obj = input;
  if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > MAX_PROPOSAL_BYTES) fail('INPUT_TOO_LARGE');
    try { obj = JSON.parse(input); } catch { fail('MALFORMED_JSON'); }
  } else {
    let size;
    try { size = Buffer.byteLength(JSON.stringify(input) ?? '', 'utf8'); } catch { fail('MALFORMED_INPUT'); }
    if (size > MAX_PROPOSAL_BYTES) fail('INPUT_TOO_LARGE');
  }
  if (!isPlainObject(obj)) fail('INVALID_PROPOSAL');
  requireExactFields(obj, FIELDS);
  if (obj.v !== PROPOSAL_VERSION) fail('UNSUPPORTED_VERSION');
  simpleId(obj.principalId, 'principalId');
  simpleId(obj.mandateId, 'mandateId');
  if (!Object.values(ACTIONS).includes(obj.action)) fail('UNSUPPORTED_ACTION');
  testnetAccountId(obj.recipientId, 'recipientId');
  atomicAmount(obj.amountYocto, 'amountYocto');
  if (typeof obj.ttlSeconds !== 'string' || !/^[1-9][0-9]{0,3}$/.test(obj.ttlSeconds) || Number(obj.ttlSeconds) > 1800) fail('INVALID_TTL');
  const c = obj.context;
  if (!isPlainObject(c)) fail('INVALID_CONTEXT');
  requireExactFields(c, CONTEXT_FIELDS);
  if (typeof c.source !== 'string' || !/^[a-z0-9][a-z0-9._:-]{0,63}$/.test(c.source)) fail('INVALID_CONTEXT', 'source');
  if (typeof c.summary !== 'string' || c.summary.length > 500 || !PRINTABLE.test(c.summary)) fail('INVALID_CONTEXT', 'summary');
  if (!Array.isArray(c.evidenceRefs) || c.evidenceRefs.length > 10 ||
      !c.evidenceRefs.every(r => typeof r === 'string' && r.length <= 200 && PRINTABLE.test(r))) fail('INVALID_CONTEXT', 'evidenceRefs');
  return Object.freeze({ ...obj, context: Object.freeze({ ...c, evidenceRefs: Object.freeze([...c.evidenceRefs]) }) });
}

/**
 * Agent/MCP-host tool surface. Deliberately contains NO authorize, sign, mandate,
 * key, or raw-transaction tools. `request_execution` succeeds only for an intent that
 * the owner has already authorized out of band; completion is reported only from
 * independent chain verification.
 */
export function createAgentTools(service) {
  return Object.freeze({
    safebox_propose_payment: (proposal) => {
      const r = service.propose(proposal);
      return { intentId: r.intentId, digest: r.digest, status: 'AWAITING_OWNER_AUTHORIZATION',
        note: 'Owner must review and sign in the SafeBox owner authorizer. This tool cannot authorize.' };
    },
    safebox_get_status: (intentId) => service.publicStatus(intentId),
    safebox_request_execution: async (intentId) => {
      await service.execute(intentId, { actor: 'agent' });
      return service.publicStatus(intentId);
    },
  });
}
