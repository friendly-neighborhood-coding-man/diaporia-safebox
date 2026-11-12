// SIMULATED NEAR TESTNET — offline test double. Not a blockchain, not evidence of real execution.
// It decodes real near-api-js signed transactions, verifies the Ed25519 signature against the
// registered access key, enforces nonces / access-key permissions / block-hash recency, applies
// transfers and the contract model, and answers with NEAR RPC-shaped results (EXPERIMENTAL_tx_status).
// Every transaction hash it produces is tagged in `simulated` so it can never be reported as chain evidence.
import { createHash, randomBytes } from 'node:crypto';
import { SignedTransaction, baseEncode as b58raw } from 'near-api-js';
const baseEncode = (b) => b58raw(new Uint8Array(b));
import { RpcTimeoutError, RpcError } from '../near/rpc.mjs';
import { ContractPanic } from './contract-model.mjs';

const FEE = 100_000_000_000_000_000_000n; // flat simulated fee (0.0001 NEAR)

export class SimulatedNearTestnet {
  constructor({ chainId = 'testnet', now = () => Date.now() } = {}) {
    this.simulated = true;
    this.chain = chainId; this.now = now;
    this.accounts = new Map(); this.contracts = new Map();
    this.blocks = []; this.txs = new Map(); this.effects = []; this.faults = [];
    this.calls = { send: 0, signedAccepted: 0 };
    this.produceBlock();
  }
  produceBlock() { const h = baseEncode(randomBytes(32)); this.blocks.push(h); if (this.blocks.length > 100) this.blocks.shift(); return h; }
  createAccount(id, balance = 0n) { this.accounts.set(id, { balance: BigInt(balance), keys: new Map() }); }
  addKey(id, publicKey, permission = 'FullAccess', nonce = 1000n) { this.accounts.get(id).keys.set(publicKey, { nonce, permission }); }
  deployContract(id, model) { this.contracts.set(id, model); }
  balance(id) { return this.accounts.get(id)?.balance ?? 0n; }
  /** Queue a fault for the next send_tx: 'timeout_after_execute' | 'timeout_before_execute' | 'drop' | 'delay_final' | 'transport_error'. */
  injectFault(f) { this.faults.push(f); }

  async chainId() { return this.chain; }
  async accessKey(accountId, publicKey) {
    const k = this.accounts.get(accountId)?.keys.get(publicKey);
    if (!k) throw new RpcError('HANDLER_ERROR', 'UNKNOWN_ACCESS_KEY', publicKey);
    return { nonce: k.nonce, permission: k.permission };
  }
  async finalBlockHash() { return this.produceBlock(); }
  async viewFunction(contractId, method, args) { return this.contracts.get(contractId).view(method, args); }

  async sendTx(signedTxB64) {
    this.calls.send++;
    const fault = this.faults.shift();
    if (fault === 'transport_error') throw new RpcError('TRANSPORT', 'ECONNRESET', 'simulated');
    if (fault === 'timeout_before_execute') throw new RpcTimeoutError('simulated timeout (not executed)');
    if (fault === 'drop') { this.dropped = (this.dropped ?? 0) + 1; throw new RpcTimeoutError('simulated timeout (dropped)'); }
    const result = this.#apply(Buffer.from(signedTxB64, 'base64'));
    if (fault === 'timeout_after_execute') throw new RpcTimeoutError('simulated timeout (executed)');
    if (fault === 'delay_final') { result.pendingQueries = 1; result.final_execution_status = 'EXECUTED_OPTIMISTIC'; return this.#view(result); }
    return this.#view(result);
  }
  async txStatus(txHash, sender) {
    const r = this.txs.get(txHash);
    if (!r || r.transaction.signer_id !== sender) return null;
    if (r.pendingQueries > 0) { r.pendingQueries--; return this.#view({ ...r, final_execution_status: 'EXECUTED_OPTIMISTIC' }); }
    r.final_execution_status = 'FINAL';
    return this.#view(r);
  }
  #view(r) { const { pendingQueries, ...rest } = r; return structuredClone(rest); }

  #apply(bytes) {
    let stx;
    try { stx = SignedTransaction.decode(bytes); } catch { throw new RpcError('HANDLER_ERROR', 'INVALID_TRANSACTION', 'decode'); }
    const tx = stx.transaction;
    const encoded = tx.encode();
    const hashBytes = createHash('sha256').update(encoded).digest();
    const hash = baseEncode(hashBytes);
    if (this.txs.has(hash)) return this.txs.get(hash); // identical rebroadcast is idempotent
    const acct = this.accounts.get(tx.signerId);
    const key = acct?.keys.get(tx.publicKey.toString());
    if (!key) throw new RpcError('HANDLER_ERROR', 'INVALID_TRANSACTION', 'InvalidAccessKeyError');
    if (!tx.publicKey.verify(hashBytes, stx.signature.ed25519Signature.data)) throw new RpcError('HANDLER_ERROR', 'INVALID_TRANSACTION', 'InvalidSignature');
    if (tx.nonce <= key.nonce) throw new RpcError('HANDLER_ERROR', 'INVALID_TRANSACTION', 'InvalidNonce');
    if (!this.blocks.includes(baseEncode(tx.blockHash))) throw new RpcError('HANDLER_ERROR', 'INVALID_TRANSACTION', 'Expired');
    if (key.permission !== 'FullAccess') {
      const fc = key.permission.FunctionCall;
      const a = tx.actions[0]?.functionCall;
      if (tx.actions.length !== 1 || !a || tx.receiverId !== fc.receiver_id || !fc.method_names.includes(a.methodName) || BigInt(a.deposit) !== 0n) {
        throw new RpcError('HANDLER_ERROR', 'INVALID_TRANSACTION', 'RequiresFullAccess');
      }
    }
    key.nonce = tx.nonce;
    this.calls.signedAccepted++;
    acct.balance -= FEE;
    const rid = () => baseEncode(randomBytes(32));
    const firstRid = rid();
    const receipts = [], receiptsOutcome = [];
    const jsonActions = tx.actions.map(a => a.transfer ? { Transfer: { deposit: a.transfer.deposit.toString() } }
      : { FunctionCall: { method_name: a.functionCall.methodName, args: Buffer.from(a.functionCall.args).toString('base64'),
        gas: Number(a.functionCall.gas), deposit: a.functionCall.deposit.toString() } });
    receipts.push({ predecessor_id: tx.signerId, receiver_id: tx.receiverId, receipt_id: firstRid,
      receipt: { Action: { signer_id: tx.signerId, actions: jsonActions } } });
    let status;
    const a0 = tx.actions[0];
    if (a0.transfer) {
      const amt = BigInt(a0.transfer.deposit);
      const to = this.accounts.get(tx.receiverId);
      if (acct.balance < amt) { status = { Failure: { ActionError: { kind: 'LackBalanceForState' } } }; }
      else if (!to) { status = { Failure: { ActionError: { kind: { AccountDoesNotExist: { account_id: tx.receiverId } } } } }; }
      else { acct.balance -= amt; to.balance += amt; this.effects.push({ txHash: hash, from: tx.signerId, to: tx.receiverId, amount: amt }); status = { SuccessValue: '' }; }
      receiptsOutcome.push({ id: firstRid, outcome: { executor_id: tx.receiverId, logs: [], receipt_ids: [], status } });
    } else {
      const fc = a0.functionCall;
      const model = this.contracts.get(tx.receiverId);
      const cacct = this.accounts.get(tx.receiverId);
      try {
        if (!model) throw new ContractPanic('CodeDoesNotExist');
        const out = model.call(fc.methodName, fc.args, { predecessor: tx.signerId, attachedDeposit: BigInt(fc.deposit),
          blockTimestampMs: this.now(), balance: cacct.balance });
        const childIds = out.transfers.map(() => rid());
        receiptsOutcome.push({ id: firstRid, outcome: { executor_id: tx.receiverId, logs: out.logs, receipt_ids: childIds, status: { SuccessValue: '' } } });
        out.transfers.forEach((t, n) => {
          receipts.push({ predecessor_id: tx.receiverId, receiver_id: t.to, receipt_id: childIds[n],
            receipt: { Action: { signer_id: tx.signerId, actions: [{ Transfer: { deposit: t.amount.toString() } }] } } });
          const dest = this.accounts.get(t.to);
          let st;
          if (!dest) st = { Failure: { ActionError: { kind: { AccountDoesNotExist: { account_id: t.to } } } } };
          else { cacct.balance -= t.amount; dest.balance += t.amount; this.effects.push({ txHash: hash, from: tx.receiverId, to: t.to, amount: t.amount }); st = { SuccessValue: '' }; }
          receiptsOutcome.push({ id: childIds[n], outcome: { executor_id: t.to, logs: [], receipt_ids: [], status: st } });
          if (st.Failure) status = st;
        });
        status ??= { SuccessValue: '' };
      } catch (e) {
        if (!(e instanceof ContractPanic)) throw e;
        status = { Failure: { ActionError: { kind: { FunctionCallError: { ExecutionError: `Smart contract panicked: ${e.message}` } } } } };
        receiptsOutcome.push({ id: firstRid, outcome: { executor_id: tx.receiverId, logs: [], receipt_ids: [], status } });
      }
    }
    // Gas refund receipt from "system" (as on the real network) — must be ignored by the verifier.
    const refundId = rid();
    receipts.push({ predecessor_id: 'system', receiver_id: tx.signerId, receipt_id: refundId,
      receipt: { Action: { signer_id: tx.signerId, actions: [{ Transfer: { deposit: '1000' } }] } } });
    receiptsOutcome.push({ id: refundId, outcome: { executor_id: tx.signerId, logs: [], receipt_ids: [], status: { SuccessValue: '' } } });
    const record = {
      final_execution_status: 'FINAL', status,
      transaction: { hash, signer_id: tx.signerId, public_key: tx.publicKey.toString(), nonce: Number(tx.nonce), receiver_id: tx.receiverId,
        actions: jsonActions, signature: 'ed25519:' + baseEncode(stx.signature.ed25519Signature.data) },
      transaction_outcome: { id: hash, outcome: { executor_id: tx.signerId, receipt_ids: [firstRid], status: { SuccessReceiptId: firstRid }, logs: [] } },
      receipts_outcome: receiptsOutcome, receipts,
    };
    this.txs.set(hash, record);
    this.produceBlock();
    return record;
  }
}
