// SEEN regression tests for the NEAR executor (WP4) and the independent verifier (WP5).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyPair, createTransaction, actions, baseDecode } from 'near-api-js';
import { makeTestnetConfig, explorerUrl } from '../../src/v1/near/config.mjs';
import { verifyEncodedTransaction, loadExecutorSigner, contractArgsBytes } from '../../src/v1/near/executor.mjs';
import { verifyTxOutcome } from '../../src/v1/near/verifier.mjs';
import { NearJsonRpcClient, RpcTimeoutError } from '../../src/v1/near/rpc.mjs';
import { parseSealedIntent } from '../../src/v1/intent.mjs';
import { makeWorld, signMandate, proposal, ownerAuthorize, asAuthz, NEAR, EXECUTOR, CONTRACT, MERCHANT, ATTACKER } from '../support/harness.mjs';

async function confirmed(native = false) {
  const w = makeWorld();
  const svc = w.open(native ? w.nativeExecutor : w.contractExecutor);
  const m = signMandate(w.owners.owner_alice, { action: native ? 'NEAR_NATIVE_TRANSFER' : 'SAFEBOX_CONTRACT_PAYMENT' });
  svc.registerMandate({ mandate: m.statement, signature: m.signature });
  const p = svc.propose(proposal(native ? { action: 'NEAR_NATIVE_TRANSFER' } : {}));
  svc.authorize(p.intentId, asAuthz(ownerAuthorize(w.owners.owner_alice, svc.authorizationRequest(p.intentId), w.now())));
  await svc.execute(p.intentId);
  const row = svc.store.get(p.intentId);
  const status = await w.chain.txStatus(row.tx_hash, EXECUTOR);
  return { w, svc, row, sealed: parseSealedIntent(row.canonical), status };
}

test('config is testnet-only with an exact RPC allowlist', () => {
  assert.equal(makeTestnetConfig({ rpcUrl: 'https://rpc.testnet.near.org', signerAccountId: EXECUTOR }).networkId, 'testnet');
  for (const url of ['https://rpc.mainnet.near.org', 'http://rpc.testnet.near.org', 'https://rpc.testnet.near.org/../x', 'https://user:pw@rpc.testnet.near.org',
    'https://rpc.testnet.near.org?x=1', 'file:///etc/passwd', 'http://169.254.169.254', 'sim://near-testnet']) {
    assert.throws(() => makeTestnetConfig({ rpcUrl: url, signerAccountId: EXECUTOR }), /RPC_NOT_ALLOWLISTED|INVALID_RPC_URL|SIMULATED_RPC_NOT_ALLOWED/, url);
  }
  assert.throws(() => makeTestnetConfig({ rpcUrl: 'https://rpc.testnet.near.org', signerAccountId: 'exec.near' }), /NOT_A_TESTNET_ACCOUNT/);
  assert.equal(explorerUrl('abc'), 'https://testnet.nearblocks.io/txns/abc');
});

test('pre-sign check rejects any transaction that differs from the sealed intent', async () => {
  const { w, row, sealed } = await confirmed();
  const kp = w.execKey; const pk = kp.getPublicKey();
  const bh = baseDecode(await w.chain.finalBlockHash());
  const good = createTransaction(EXECUTOR, pk, CONTRACT, 5n, [actions.functionCall('execute_payment', contractArgsBytes(row), 30_000_000_000_000n, 0n)], bh);
  const ctx = { sealed, row, signerAccountId: EXECUTOR, publicKey: pk.toString() };
  assert.ok(verifyEncodedTransaction(good.encode(), ctx));
  const variants = {
    PRESIGN_RECEIVER_MISMATCH: createTransaction(EXECUTOR, pk, 'other.testnet', 5n, good.actions, bh),
    PRESIGN_ACTION_COUNT: createTransaction(EXECUTOR, pk, CONTRACT, 5n, [...good.actions, actions.transfer(1n)], bh),
    PRESIGN_ACTION_KIND: createTransaction(EXECUTOR, pk, CONTRACT, 5n, [actions.transfer(NEAR)], bh),
    PRESIGN_METHOD_MISMATCH: createTransaction(EXECUTOR, pk, CONTRACT, 5n, [actions.functionCall('withdraw', contractArgsBytes(row), 30_000_000_000_000n, 0n)], bh),
    PRESIGN_ARGS_MISMATCH: createTransaction(EXECUTOR, pk, CONTRACT, 5n, [actions.functionCall('execute_payment', Buffer.from('{}'), 30_000_000_000_000n, 0n)], bh),
    PRESIGN_GAS_MISMATCH: createTransaction(EXECUTOR, pk, CONTRACT, 5n, [actions.functionCall('execute_payment', contractArgsBytes(row), 300_000_000_000_000n, 0n)], bh),
    PRESIGN_DEPOSIT_MISMATCH: createTransaction(EXECUTOR, pk, CONTRACT, 5n, [actions.functionCall('execute_payment', contractArgsBytes(row), 30_000_000_000_000n, 1n)], bh),
    PRESIGN_SIGNER_MISMATCH: createTransaction('other.testnet', pk, CONTRACT, 5n, good.actions, bh),
    PRESIGN_KEY_MISMATCH: createTransaction(EXECUTOR, KeyPair.fromRandom('ed25519').getPublicKey(), CONTRACT, 5n, good.actions, bh),
  };
  for (const [code, tx] of Object.entries(variants)) assert.throws(() => verifyEncodedTransaction(tx.encode(), ctx), new RegExp(code), code);
});

test('verifier: CONFIRMED only for the exact finalized effect (contract and native)', async () => {
  for (const native of [false, true]) {
    const { row, sealed, status } = await confirmed(native);
    const args = native ? undefined : contractArgsBytes(row).toString('base64');
    const v = verifyTxOutcome({ sealed, row, status, nowIso: 'now', expectedArgsB64: args });
    assert.equal(v.verdict, 'CONFIRMED');
    // Pending finality is not completion.
    assert.equal(verifyTxOutcome({ sealed, row, status: { ...status, final_execution_status: 'EXECUTED_OPTIMISTIC' }, nowIso: 'now', expectedArgsB64: args }).verdict, 'PENDING');
    // An RPC answer about a different transaction / signer / amount is a MISMATCH, never a success.
    const other = structuredClone(status); other.transaction.signer_id = ATTACKER;
    assert.equal(verifyTxOutcome({ sealed, row, status: other, nowIso: 'now', expectedArgsB64: args }).verdict, 'MISMATCH');
    // A value transfer to an unexpected account is flagged as anomalous.
    const extra = structuredClone(status);
    extra.receipts.push({ predecessor_id: native ? EXECUTOR : CONTRACT, receiver_id: ATTACKER, receipt_id: 'X', receipt: { Action: { actions: [{ Transfer: { deposit: '5' } }] } } });
    extra.receipts_outcome.push({ id: 'X', outcome: { executor_id: ATTACKER, logs: [], receipt_ids: [], status: { SuccessValue: '' } } });
    assert.notEqual(verifyTxOutcome({ sealed, row, status: extra, nowIso: 'now', expectedArgsB64: args }).verdict, 'CONFIRMED');
    // A failed transfer receipt means FAILED with no effect.
    const failed = structuredClone(status);
    const transferReceipt = failed.receipts.find(r => r.receiver_id === MERCHANT);
    const oc = failed.receipts_outcome.find(o => o.id === transferReceipt.receipt_id);
    oc.outcome.status = { Failure: { ActionError: {} } }; failed.status = { Failure: {} };
    const fv = verifyTxOutcome({ sealed, row, status: failed, nowIso: 'now', expectedArgsB64: args });
    assert.equal(fv.verdict, 'FAILED'); assert.equal(fv.effect.kind, 'NONE');
  }
});

test('RPC client maps node TIMEOUT_ERROR and unknown transactions correctly (stubbed fetch)', async () => {
  const reply = (body) => async () => ({ status: 200, text: async () => JSON.stringify(body) });
  const t = new NearJsonRpcClient({ url: 'https://rpc.testnet.near.org', fetchImpl: reply({ error: { name: 'HANDLER_ERROR', cause: { name: 'TIMEOUT_ERROR' } } }) });
  await assert.rejects(t.sendTx('AA=='), RpcTimeoutError);
  const u = new NearJsonRpcClient({ url: 'https://rpc.testnet.near.org', fetchImpl: reply({ error: { name: 'HANDLER_ERROR', cause: { name: 'UNKNOWN_TRANSACTION' } } }) });
  assert.equal(await u.txStatus('h', EXECUTOR), null);
  const c = new NearJsonRpcClient({ url: 'https://rpc.testnet.near.org', fetchImpl: reply({ result: { chain_id: 'testnet' } }) });
  assert.equal(await c.chainId(), 'testnet');
  const slow = new NearJsonRpcClient({ url: 'https://rpc.testnet.near.org', timeoutMs: 20, fetchImpl: (_u, o) => new Promise((_, rej) => { const keep = setTimeout(() => {}, 5000); o.signal.addEventListener('abort', () => { clearTimeout(keep); rej(o.signal.reason); }); }) });
  await assert.rejects(slow.chainId(), RpcTimeoutError);
});

test('executor key file: permissions, account binding, and no secret in serialisation, DB or journal', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'safebox-key-'));
  const kp = KeyPair.fromRandom('ed25519');
  const path = join(dir, 'exec.json');
  writeFileSync(path, JSON.stringify({ account_id: EXECUTOR, public_key: kp.getPublicKey().toString(), private_key: kp.toString() }));
  chmodSync(path, 0o644);
  if (process.platform !== 'win32') assert.throws(() => loadExecutorSigner(path, EXECUTOR), /TOO_PERMISSIVE/);
  chmodSync(path, 0o600);
  assert.throws(() => loadExecutorSigner(path, 'other.testnet'), /EXECUTOR_ACCOUNT_MISMATCH/);
  const signer = loadExecutorSigner(path, EXECUTOR);
  assert.ok(!JSON.stringify(signer).includes(kp.toString().slice(8, 20)));
  const { w, svc } = await confirmed();
  const secrets = [w.execKey.toString().slice(8), w.nativeKey.toString().slice(8)];
  const dbBytes = readFileSync(w.dbPath).toString('latin1') + JSON.stringify(svc.store.journal());
  for (const s of secrets) assert.ok(!dbBytes.includes(s), 'executor secret must not reach the database');
});
