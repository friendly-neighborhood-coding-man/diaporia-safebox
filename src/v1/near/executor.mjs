// WP4 — NEAR Testnet executor.
// The executor accepts only an intent id. It reconstructs the transaction from the
// trusted sealed-intent record, re-verifies the owner's signature against a PINNED
// owner key, checks every parameter of the encoded transaction, and only then signs.
import { closeSync, fstatSync, openSync, readSync, constants as C } from 'node:fs';
import { createHash } from 'node:crypto';
import { KeyPair, KeyPairSigner, createTransaction, actions, baseDecode, baseEncode, Transaction, SignedTransaction } from 'near-api-js';
import { fail, SafeBoxError } from '../canonical.mjs';
import { parseSealedIntent, ACTIONS, CONTRACT_METHOD } from '../intent.mjs';
import { verifyAuthorization, parseAuthorization } from '../authz.mjs';

// Contract call arguments are derived deterministically from stored, owner-signed records.
export function contractArgsBytes(row) {
  return Buffer.from(JSON.stringify({ intent: row.canonical, authorization: row.authz, signature: row.authz_sig }), 'utf8');
}

/** Loads a near-cli style credential file. The key is captured in a closure and never serialised. */
function readRestrictedFile(path, code) {
  let fd;
  try { fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW | (C.O_NONBLOCK ?? 0)); }
  catch (e) {
    if (e.code === 'ELOOP') fail(code + '_SYMLINK');
    throw e;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) fail(code + '_NOT_A_FILE');
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) fail(code + '_TOO_PERMISSIVE', 'chmod 600 required');
    if (st.size > (1 << 20)) fail(code + '_TOO_LARGE');
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, null);
      if (n === 0) break;
      off += n;
    }
    if (off !== buf.length) fail(code + '_SHORT_READ');
    return buf.toString('utf8');
  } finally { closeSync(fd); }
}

export function loadExecutorSigner(path, expectedAccountId) {
  const f = JSON.parse(readRestrictedFile(path, 'EXECUTOR_KEY_FILE'));
  if (f.account_id !== expectedAccountId) fail('EXECUTOR_ACCOUNT_MISMATCH');
  const kp = KeyPair.fromString(f.private_key ?? f.secret_key);
  if (kp.getPublicKey().toString() !== f.public_key) fail('EXECUTOR_KEY_MISMATCH');
  return executorSignerFromKeyPair(expectedAccountId, kp);
}
export function executorSignerFromKeyPair(accountId, kp) {
  const signer = new KeyPairSigner(kp);
  const publicKey = kp.getPublicKey();
  return Object.freeze({
    accountId, publicKey: publicKey.toString(), publicKeyObject: publicKey,
    signTransaction: (tx) => signer.signTransaction(tx),
    toJSON() { return { accountId, publicKey: publicKey.toString() }; },
  });
}

function sameBytes(a, b) { return Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0; }

function expectedFromIntent(sealed, row) {
  const i = sealed.intent;
  if (i.action === ACTIONS.NATIVE) return { receiverId: i.recipientId, kind: 'transfer', deposit: BigInt(i.amountYocto) };
  return { receiverId: i.receiverId, kind: 'functionCall', methodName: CONTRACT_METHOD, args: contractArgsBytes(row),
    gas: BigInt(i.gas), deposit: BigInt(i.attachedDepositYocto) };
}

/** Independent re-check of an encoded transaction against the sealed intent. Throws on any difference. */
export function verifyEncodedTransaction(encoded, { sealed, row, signerAccountId, publicKey }) {
  const tx = Transaction.decode(encoded);
  const exp = expectedFromIntent(sealed, row);
  if (tx.signerId !== signerAccountId || tx.signerId !== sealed.intent.signerAccountId) fail('PRESIGN_SIGNER_MISMATCH');
  if (tx.publicKey.toString() !== publicKey) fail('PRESIGN_KEY_MISMATCH');
  if (tx.receiverId !== exp.receiverId) fail('PRESIGN_RECEIVER_MISMATCH');
  if (tx.nonceIndex !== undefined && tx.nonceIndex !== null) fail('PRESIGN_UNEXPECTED_TX_VERSION');
  if (!Array.isArray(tx.actions) || tx.actions.length !== 1) fail('PRESIGN_ACTION_COUNT');
  const a = tx.actions[0];
  const kinds = Object.keys(a).filter(k => k !== 'enum' && a[k] !== undefined);
  if (kinds.length !== 1 || kinds[0] !== exp.kind) fail('PRESIGN_ACTION_KIND', kinds.join(','));
  if (exp.kind === 'transfer') {
    if (BigInt(a.transfer.deposit) !== exp.deposit) fail('PRESIGN_AMOUNT_MISMATCH');
  } else {
    const fc = a.functionCall;
    if (fc.methodName !== exp.methodName) fail('PRESIGN_METHOD_MISMATCH');
    if (!sameBytes(fc.args, exp.args)) fail('PRESIGN_ARGS_MISMATCH');
    if (BigInt(fc.gas) !== exp.gas) fail('PRESIGN_GAS_MISMATCH');
    if (BigInt(fc.deposit) !== exp.deposit) fail('PRESIGN_DEPOSIT_MISMATCH');
  }
  return tx;
}

export class NearTestnetExecutor {
  /**
   * @param config   from makeTestnetConfig (networkId is always 'testnet')
   * @param rpc      NearJsonRpcClient (or the explicitly SIMULATED chain in tests/offline demo)
   * @param signer   executor signer (loadExecutorSigner); the only holder of signing material
   * @param trustedOwnerKeys  { principalId: 'ed25519:...' } pinned from operator config
   */
  constructor({ config, rpc, signer, trustedOwnerKeys, now = () => Date.now() }) {
    if (config.networkId !== 'testnet') fail('WRONG_NETWORK');
    if (signer.accountId !== config.signerAccountId) fail('EXECUTOR_ACCOUNT_MISMATCH');
    this.config = config; this.rpc = rpc; this.signer = signer; this.now = now;
    this.trustedOwnerKeys = Object.freeze({ ...trustedOwnerKeys });
    this.signCount = 0; // number of transactions this executor has signed (for metrics)
  }

  /** Builds and signs the transaction for a RESERVED intent. Does not broadcast. */
  async buildSigned(store, intentId) {
    const row = store.get(intentId);
    if (!row) fail('UNKNOWN_INTENT');
    if (row.state !== 'RESERVED' || row.tx_hash) fail('NOT_RESERVED', row.state);
    const sealed = parseSealedIntent(row.canonical);
    if (sealed.digest !== row.digest || sealed.intent.intentId !== intentId) fail('STORED_INTENT_CORRUPT');
    const i = sealed.intent;
    // Re-verify owner authority from pinned keys (defence against a tampered database).
    // Authorization freshness was enforced when it was accepted and at reservation; here we
    // re-check signature + bindings (evaluated at the statement's own issue time) and intent expiry.
    if (!row.authz || !row.authz_sig) fail('NOT_AUTHORIZED');
    verifyAuthorization({ sealed, authorization: row.authz, signature: row.authz_sig,
      trustedOwnerKey: this.trustedOwnerKeys[i.principalId], expectedChallenge: row.challenge,
      now: Date.parse(parseAuthorization(row.authz).issuedAt) });
    if (this.now() >= Date.parse(i.expiresAt)) fail('INTENT_EXPIRED');
    if (i.networkId !== this.config.networkId || i.chainId !== this.config.chainId) fail('WRONG_NETWORK');
    if (i.signerAccountId !== this.config.signerAccountId) fail('SIGNER_NOT_CONFIGURED');
    if (i.action === ACTIONS.CONTRACT && i.receiverId !== this.config.contractId) fail('CONTRACT_NOT_CONFIGURED');

    const chainId = await this.rpc.chainId();
    if (chainId !== 'testnet') fail('RPC_CHAIN_ID_NOT_TESTNET', String(chainId).slice(0, 20));
    const ak = await this.rpc.accessKey(this.signer.accountId, this.signer.publicKey);
    const perm = ak.permission;
    let keyKind;
    if (i.action === ACTIONS.CONTRACT) {
      const fc = perm?.FunctionCall;
      if (!fc || fc.receiver_id !== this.config.contractId || fc.method_names?.length !== 1 || fc.method_names[0] !== CONTRACT_METHOD) {
        fail('EXECUTOR_KEY_NOT_RESTRICTED', 'contract mode requires a FunctionCall key limited to execute_payment');
      }
      keyKind = 'FunctionCall(execute_payment)';
    } else {
      if (perm !== 'FullAccess') fail('EXECUTOR_KEY_NOT_FULL_ACCESS', 'native transfers require a FullAccess key on a dedicated account');
      keyKind = 'FullAccess';
    }
    const blockHash = await this.rpc.finalBlockHash();
    // Durable allocator: never reuse a nonce already signed by SafeBox (even if never broadcast).
    const local = store.maxSignerNonce(this.signer.publicKey);
    const nonce = (ak.nonce > local ? ak.nonce : local) + 1n;
    const exp = expectedFromIntent(sealed, row);
    const act = exp.kind === 'transfer' ? actions.transfer(exp.deposit)
      : actions.functionCall(exp.methodName, exp.args, exp.gas, exp.deposit);
    const tx = createTransaction(this.signer.accountId, this.signer.publicKeyObject, exp.receiverId, nonce, [act], baseDecode(blockHash));
    const encoded = tx.encode();
    verifyEncodedTransaction(encoded, { sealed, row, signerAccountId: this.signer.accountId, publicKey: this.signer.publicKey });

    const { txHash, signedTransaction } = await this.signer.signTransaction(Transaction.decode(encoded));
    this.signCount++;
    const signedBytes = signedTransaction.encode();
    // Post-sign self-check: the signed bytes still decode to the verified transaction and the hash matches.
    const back = SignedTransaction.decode(signedBytes);
    if (!sameBytes(back.transaction.encode(), encoded)) fail('POSTSIGN_MISMATCH');
    const hash = createHash('sha256').update(encoded).digest();
    if (!sameBytes(hash, txHash)) fail('POSTSIGN_HASH_MISMATCH');
    return {
      txHash: baseEncode(txHash), signedTxB64: Buffer.from(signedBytes).toString('base64'),
      signerPublicKey: this.signer.publicKey, signerNonce: nonce.toString(), blockHash, keyKind,
    };
  }

  async broadcast(signedTxB64) { return this.rpc.sendTx(signedTxB64, 'FINAL'); }
}

export { SafeBoxError };
