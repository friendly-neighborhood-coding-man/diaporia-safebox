// WP1 — Canonical sealed intent for NEAR Testnet (safebox.intent.v1).
import { randomBytes, randomUUID } from 'node:crypto';
import {
  DOMAINS, fail, requireExactFields, canonicalJson, parseCanonical, domainDigestHex,
  atomicAmount, isoMillis, simpleId, uuidV4, hex, testnetAccountId, formatYocto,
} from './canonical.mjs';

export const INTENT_VERSION = 'safebox.intent.v1';
export const ACTIONS = Object.freeze({
  NATIVE: 'NEAR_NATIVE_TRANSFER',
  CONTRACT: 'SAFEBOX_CONTRACT_PAYMENT',
});
export const CONTRACT_METHOD = 'execute_payment';
export const CONTRACT_GAS = '30000000000000'; // 30 Tgas, fixed; gas is NOT a spending mandate
export const MAX_INTENT_TTL_MS = 30 * 60_000;

const COMMON = ['v', 'intentId', 'principalId', 'mandateId', 'chainId', 'networkId', 'action',
  'signerAccountId', 'receiverId', 'recipientId', 'asset', 'amountYocto', 'nonce', 'createdAt', 'expiresAt'];
const CONTRACT_EXTRA = ['method', 'gas', 'attachedDepositYocto'];

export function fieldsFor(action) {
  if (action === ACTIONS.NATIVE) return COMMON;
  if (action === ACTIONS.CONTRACT) return [...COMMON, ...CONTRACT_EXTRA];
  fail('UNSUPPORTED_ACTION', String(action).slice(0, 40));
}

// Validates a complete intent object. Every execution field is explicit; nothing is defaulted.
export function validateIntent(obj) {
  if (!obj || typeof obj !== 'object') fail('INVALID_INTENT');
  const action = obj.action;
  requireExactFields(obj, fieldsFor(action));
  if (obj.v !== INTENT_VERSION) fail('UNSUPPORTED_VERSION');
  uuidV4(obj.intentId);
  simpleId(obj.principalId, 'principalId');
  simpleId(obj.mandateId, 'mandateId');
  if (obj.chainId !== 'near') fail('WRONG_CHAIN');
  if (obj.networkId !== 'testnet') fail('WRONG_NETWORK', String(obj.networkId).slice(0, 20));
  testnetAccountId(obj.signerAccountId, 'signerAccountId');
  testnetAccountId(obj.receiverId, 'receiverId');
  testnetAccountId(obj.recipientId, 'recipientId');
  if (obj.asset !== 'NEAR') fail('UNSUPPORTED_ASSET');
  atomicAmount(obj.amountYocto, 'amountYocto');
  hex(obj.nonce, 16, 'nonce');
  isoMillis(obj.createdAt, 'createdAt');
  isoMillis(obj.expiresAt, 'expiresAt');
  const ttl = Date.parse(obj.expiresAt) - Date.parse(obj.createdAt);
  if (ttl <= 0 || ttl > MAX_INTENT_TTL_MS) fail('INVALID_EXPIRY_WINDOW');
  if (obj.recipientId === obj.signerAccountId) fail('SELF_PAYMENT');
  if (action === ACTIONS.NATIVE) {
    if (obj.receiverId !== obj.recipientId) fail('RECEIVER_RECIPIENT_MISMATCH');
  } else {
    if (obj.method !== CONTRACT_METHOD) fail('WRONG_METHOD');
    if (obj.gas !== CONTRACT_GAS) fail('WRONG_GAS');
    if (obj.attachedDepositYocto !== '0') fail('WRONG_DEPOSIT');
    if (obj.receiverId === obj.recipientId) fail('RECIPIENT_IS_CONTRACT');
  }
  return Object.freeze({ ...obj });
}

export function sealIntent(obj) {
  const intent = validateIntent(obj);
  const canonical = canonicalJson(intent);
  return Object.freeze({ intent, canonical, digest: domainDigestHex(DOMAINS.INTENT, canonical) });
}

export function parseSealedIntent(canonical) {
  return sealIntent(parseCanonical(canonical));
}

// Builds a fresh intent from trusted configuration + validated proposal values.
export function buildIntent({ principalId, mandateId, action, signerAccountId, contractId, recipientId,
  amountYocto, ttlMs, now }) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_INTENT_TTL_MS) fail('INVALID_TTL');
  const created = new Date(now);
  const base = {
    v: INTENT_VERSION, intentId: randomUUID(), principalId, mandateId, chainId: 'near', networkId: 'testnet',
    action, signerAccountId, recipientId, asset: 'NEAR', amountYocto,
    nonce: randomBytes(16).toString('hex'),
    createdAt: created.toISOString(), expiresAt: new Date(now + ttlMs).toISOString(),
  };
  if (action === ACTIONS.NATIVE) base.receiverId = recipientId;
  else if (action === ACTIONS.CONTRACT) {
    Object.assign(base, { receiverId: contractId, method: CONTRACT_METHOD, gas: CONTRACT_GAS, attachedDepositYocto: '0' });
  } else fail('UNSUPPORTED_ACTION');
  return sealIntent(base);
}

// Authoritative human display, derived only from the canonical record.
export function displayIntent(sealed) {
  const i = sealed.intent;
  const lines = [
    `SAFEBOX AUTHORIZATION REQUEST  (${i.v})`,
    `  network        : NEAR ${i.networkId}  (chain ${i.chainId})`,
    `  action         : ${i.action}`,
    `  pay recipient  : ${i.recipientId}`,
    `  amount         : ${formatYocto(i.amountYocto)}  (= ${i.amountYocto} yoctoNEAR)`,
    `  signer account : ${i.signerAccountId}`,
    `  tx receiver    : ${i.receiverId}`,
  ];
  if (i.action === ACTIONS.CONTRACT) lines.push(`  contract call  : ${i.receiverId}.${i.method}(gas=${i.gas}, deposit=${i.attachedDepositYocto})`);
  lines.push(`  principal      : ${i.principalId}   mandate: ${i.mandateId}`,
    `  intent id      : ${i.intentId}`, `  one-use nonce  : ${i.nonce}`,
    `  valid          : ${i.createdAt} .. ${i.expiresAt}`, `  intent digest  : ${sealed.digest}`);
  return lines.join('\n');
}
