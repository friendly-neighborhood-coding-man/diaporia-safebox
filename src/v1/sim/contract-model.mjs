// SIMULATION ONLY: a JavaScript model of contract/src/lib.rs (safebox-payment) used by
// the offline simulated chain. It mirrors the Rust checks one-for-one; the Rust contract
// is the authoritative implementation. Shared vectors: tests/vectors/contract-vectors.json.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { baseDecode } from 'near-api-js';

export const INTENT_DOMAIN = 'DIAPORIA_SAFEBOX_INTENT_V1\n';
export const AUTHZ_DOMAIN = 'DIAPORIA_SAFEBOX_AUTHZ_V1\n';
const INTENT_KEYS = ['action', 'amountYocto', 'asset', 'attachedDepositYocto', 'chainId', 'createdAt', 'expiresAt', 'gas',
  'intentId', 'mandateId', 'method', 'networkId', 'nonce', 'principalId', 'receiverId', 'recipientId', 'signerAccountId', 'v'];
const AUTHZ_KEYS = ['challenge', 'expiresAt', 'intentDigest', 'intentId', 'issuedAt', 'ownerKey', 'principalId', 'v'];

export class ContractPanic extends Error { constructor(m) { super(m); this.code = m; } }
const panic = (m) => { throw new ContractPanic(m); };

function strictObject(text, keys) {
  let o; try { o = JSON.parse(text); } catch { panic('ERR_BAD_JSON'); }
  if (!o || typeof o !== 'object' || Array.isArray(o)) panic('ERR_BAD_JSON');
  const k = Object.keys(o).sort();
  if (k.length !== keys.length || k.some((x, n) => x !== keys[n])) panic('ERR_FIELDS');
  if (!k.every(x => typeof o[x] === 'string')) panic('ERR_FIELDS');
  return o;
}
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
function isoMs(s) { if (!ISO.test(s)) panic('ERR_TIME_FORMAT'); return Date.parse(s); }

export class SafeBoxPaymentContractModel {
  constructor({ contractId, ownerId, ownerPrincipalId, ownerAuthKey, executorId, maxPaymentYocto }) {
    Object.assign(this, { contractId, ownerId, ownerPrincipalId, ownerAuthKey, executorId, maxPaymentYocto: BigInt(maxPaymentYocto) });
    this.used = new Set(); this.revoked = new Set();
  }
  view(method, args) {
    if (method === 'is_nonce_used') return this.used.has(args.nonce);
    if (method === 'get_config') return { owner_id: this.ownerId, owner_principal_id: this.ownerPrincipalId, owner_auth_key: this.ownerAuthKey,
      executor_id: this.executorId, max_payment_yocto: this.maxPaymentYocto.toString() };
    panic('ERR_NO_VIEW');
  }
  /** ctx: {predecessor, attachedDeposit, blockTimestampMs, balance}. Returns {logs, transfers}. */
  call(method, argsBytes, ctx) {
    if (method === 'revoke_nonce') {
      if (ctx.predecessor !== this.ownerId) panic('ERR_NOT_OWNER');
      const { nonce } = JSON.parse(Buffer.from(argsBytes).toString());
      this.revoked.add(nonce); return { logs: [], transfers: [] };
    }
    if (method !== 'execute_payment') panic('ERR_NO_METHOD');
    if (ctx.predecessor !== this.executorId) panic('ERR_NOT_EXECUTOR');
    if (ctx.attachedDeposit !== 0n) panic('ERR_DEPOSIT');
    let args; try { args = JSON.parse(Buffer.from(argsBytes).toString('utf8')); } catch { panic('ERR_BAD_ARGS'); }
    // near-sdk argument decoding: the three named string args are required (extra keys are ignored by serde).
    const { intent: intentText, authorization: authzText, signature } = args ?? {};
    if (typeof intentText !== 'string' || typeof authzText !== 'string' || typeof signature !== 'string') panic('ERR_BAD_ARGS');
    if (intentText.length > 4096 || authzText.length > 2048) panic('ERR_TOO_LARGE');
    const intent = strictObject(intentText, INTENT_KEYS);
    const authz = strictObject(authzText, AUTHZ_KEYS);
    // 1. owner signature over the authorization statement
    if (authz.v !== 'safebox.authz.v1') panic('ERR_AUTHZ_VERSION');
    if (authz.ownerKey !== this.ownerAuthKey) panic('ERR_OWNER_KEY');
    const sig = Buffer.from(signature, 'base64');
    if (sig.length !== 64) panic('ERR_SIG_FORMAT');
    const raw = Buffer.from(baseDecode(this.ownerAuthKey.slice(8)));
    const pub = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' });
    if (!verify(null, Buffer.concat([Buffer.from(AUTHZ_DOMAIN), Buffer.from(authzText)]), pub, sig)) panic('ERR_BAD_SIGNATURE');
    // 2. authorization is bound to these exact intent bytes
    const digest = createHash('sha256').update(Buffer.concat([Buffer.from(INTENT_DOMAIN), Buffer.from(intentText)])).digest('hex');
    if (authz.intentDigest !== digest) panic('ERR_DIGEST');
    if (authz.intentId !== intent.intentId || authz.principalId !== intent.principalId) panic('ERR_BINDING');
    if (intent.principalId !== this.ownerPrincipalId) panic('ERR_PRINCIPAL');
    // 3. fixed-purpose payment fields
    if (intent.v !== 'safebox.intent.v1' || intent.chainId !== 'near' || intent.networkId !== 'testnet') panic('ERR_NETWORK');
    if (intent.action !== 'SAFEBOX_CONTRACT_PAYMENT' || intent.method !== 'execute_payment') panic('ERR_ACTION');
    if (intent.receiverId !== this.contractId) panic('ERR_WRONG_CONTRACT');
    if (intent.signerAccountId !== ctx.predecessor) panic('ERR_SIGNER');
    if (intent.asset !== 'NEAR' || intent.attachedDepositYocto !== '0') panic('ERR_ASSET');
    if (!/^[1-9][0-9]{0,38}$/.test(intent.amountYocto)) panic('ERR_AMOUNT');
    const amount = BigInt(intent.amountYocto);
    if (amount >= (1n << 128n)) panic('ERR_AMOUNT');
    if (amount > this.maxPaymentYocto) panic('ERR_OVER_MAX');
    if (intent.recipientId === this.contractId) panic('ERR_RECIPIENT');
    // 4. expiry (block time) and one-use nonce
    if (ctx.blockTimestampMs >= isoMs(intent.expiresAt) || ctx.blockTimestampMs >= isoMs(authz.expiresAt)) panic('ERR_EXPIRED');
    if (!/^[0-9a-f]{32}$/.test(intent.nonce)) panic('ERR_NONCE_FORMAT');
    if (this.revoked.has(intent.nonce)) panic('ERR_REVOKED');
    if (this.used.has(intent.nonce)) panic('ERR_NONCE_USED');
    if (amount > ctx.balance) panic('ERR_BALANCE');
    this.used.add(intent.nonce);
    const event = { standard: 'diaporia_safebox', version: '1.0.0', event: 'payment_executed',
      data: [{ intent_id: intent.intentId, nonce: intent.nonce, recipient: intent.recipientId, amount: intent.amountYocto }] };
    return { logs: ['EVENT_JSON:' + JSON.stringify(event)], transfers: [{ to: intent.recipientId, amount }] };
  }
}
