// Minimal NEAR JSON-RPC client (raw JSON-RPC 2.0 over fetch) with explicit timeouts.
// Method names/params follow https://docs.near.org/api/rpc/ (status, query, block, send_tx, EXPERIMENTAL_tx_status).
import { fail } from '../canonical.mjs';

export class RpcTimeoutError extends Error { constructor(m) { super(m); this.code = 'RPC_TIMEOUT'; } }
export class RpcError extends Error {
  constructor(name, causeName, message) { super(`${name}/${causeName}: ${message}`); this.code = 'RPC_ERROR'; this.rpcName = name; this.causeName = causeName; }
}

export class NearJsonRpcClient {
  constructor({ url, timeoutMs = 20_000, fetchImpl = globalThis.fetch }) {
    this.url = url; this.timeoutMs = timeoutMs; this.fetch = fetchImpl;
  }
  async #call(method, params, timeoutMs = this.timeoutMs) {
    let res;
    try {
      res = await this.fetch(this.url, {
        method: 'POST', headers: { 'content-type': 'application/json' }, redirect: 'error',
        body: JSON.stringify({ jsonrpc: '2.0', id: 'safebox', method, params }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      if (e?.name === 'TimeoutError' || e?.name === 'AbortError') throw new RpcTimeoutError(`${method} timed out`);
      throw new RpcError('TRANSPORT', e?.name ?? 'Error', String(e?.message ?? e).slice(0, 200));
    }
    const text = await res.text();
    if (text.length > 4_000_000) fail('RPC_RESPONSE_TOO_LARGE');
    let body; try { body = JSON.parse(text); } catch { throw new RpcError('HTTP', String(res.status), 'non-JSON response'); }
    if (body.error) {
      const causeName = body.error.cause?.name ?? body.error.name ?? 'UNKNOWN';
      if (causeName === 'TIMEOUT_ERROR') throw new RpcTimeoutError(`${method}: node TIMEOUT_ERROR`);
      throw new RpcError(body.error.name ?? 'ERROR', causeName, JSON.stringify(body.error.data ?? body.error.message ?? '').slice(0, 300));
    }
    return body.result;
  }
  async chainId() { return (await this.#call('status', [])).chain_id; }
  async accessKey(accountId, publicKey) {
    const r = await this.#call('query', { request_type: 'view_access_key', finality: 'final', account_id: accountId, public_key: publicKey });
    return { nonce: BigInt(r.nonce), permission: r.permission };
  }
  async finalBlockHash() { return (await this.#call('block', { finality: 'final' })).header.hash; }
  async sendTx(signedTxB64, waitUntil = 'FINAL') {
    return this.#call('send_tx', { signed_tx_base64: signedTxB64, wait_until: waitUntil });
  }
  /** Returns null when the node reports UNKNOWN_TRANSACTION; throws on any other failure. */
  async txStatus(txHash, senderAccountId) {
    try { return await this.#call('EXPERIMENTAL_tx_status', { tx_hash: txHash, sender_account_id: senderAccountId, wait_until: 'NONE' }); }
    catch (e) { if (e instanceof RpcError && e.causeName === 'UNKNOWN_TRANSACTION') return null; throw e; }
  }
  async viewFunction(contractId, methodName, args) {
    const r = await this.#call('query', { request_type: 'call_function', finality: 'final', account_id: contractId,
      method_name: methodName, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') });
    return JSON.parse(Buffer.from(r.result).toString('utf8'));
  }
}
