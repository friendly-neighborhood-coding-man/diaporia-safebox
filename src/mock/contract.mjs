// MOCK ONLY. Contract and replay demonstration; NOT a security boundary.
// No real authentication, signing keys, durable store, or NEAR connection.
import { createHash, randomUUID } from 'node:crypto';

const own = (v, k) => Object.prototype.hasOwnProperty.call(v, k);
const fields = ['principalId', 'action', 'recipientId', 'asset', 'amountAtomic', 'expiresAt'];

export function canonicalIntent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('INVALID_INTENT');
  if (Object.keys(input).length !== fields.length ||
      Object.keys(input).some(k => !fields.includes(k)) ||
      fields.some(k => !own(input, k))) throw new Error('UNEXPECTED_OR_MISSING_FIELD');
  for (const key of ['principalId', 'recipientId']) {
    if (typeof input[key] !== 'string' || !/^[a-zA-Z0-9._-]{1,100}$/.test(input[key])) {
      throw new Error('INVALID_' + key.toUpperCase());
    }
  }
  if (input.action !== 'MOCK_TRANSFER' || input.asset !== 'TEST_NEAR') throw new Error('UNSUPPORTED_ACTION');
  if (typeof input.amountAtomic !== 'string' || !/^[1-9][0-9]{0,39}$/.test(input.amountAtomic)) {
    throw new Error('INVALID_AMOUNT');
  }
  if (typeof input.expiresAt !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(input.expiresAt) ||
      !Number.isFinite(Date.parse(input.expiresAt)) ||
      new Date(input.expiresAt).toISOString() !== input.expiresAt) {
    throw new Error('INVALID_EXPIRY');
  }
  return Object.freeze(Object.fromEntries(fields.map(k => [k, input[k]])));
}

function sha256(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

export class MockSafeBox {
  #intents = new Map();
  #effects = [];
  constructor({now = () => Date.now()} = {}) { this.now = now; }

  prepare(input) {
    const intent = canonicalIntent(input);
    if (Date.parse(intent.expiresAt) <= this.now()) throw new Error('EXPIRED');
    const id = randomUUID();
    const nonce = randomUUID();
    const digest = sha256({id, nonce, intent});
    this.#intents.set(id, {nonce, intent, digest, state: 'PREPARED'});
    return Object.freeze({id, digest, intent});
  }

  // Simulates approval only. NOT authentication. Never connect this to real funds.
  recordMockApproval(id, {principalId, digest}) {
    const record = this.#intents.get(id);
    if (!record || record.state !== 'PREPARED') throw new Error('NOT_PREPARED');
    if (principalId !== record.intent.principalId || digest !== record.digest) throw new Error('APPROVAL_MISMATCH');
    if (Date.parse(record.intent.expiresAt) <= this.now()) throw new Error('EXPIRED');
    record.state = 'APPROVED';
  }

  executeOnce(id, submittedIntent) {
    const record = this.#intents.get(id);
    if (!record || record.state !== 'APPROVED') throw new Error('NOT_APPROVED_OR_ALREADY_USED');
    const canonical = canonicalIntent(submittedIntent);
    if (sha256({id, nonce: record.nonce, intent: canonical}) !== record.digest) throw new Error('INTENT_TAMPERED');
    if (Date.parse(record.intent.expiresAt) <= this.now()) throw new Error('EXPIRED');
    // Only in-memory one-use. Real execution requires durable atomic consume + idempotency.
    record.state = 'CONSUMED';
    const result = Object.freeze({id, result: 'MOCK_EXECUTED', ...canonical});
    this.#effects.push(result);
    return result;
  }

  get mockEffects() { return [...this.#effects]; }
}
