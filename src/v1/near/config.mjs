// Explicit NEAR network configuration. TESTNET ONLY: there is no mainnet code path.
import { fail, testnetAccountId } from '../canonical.mjs';

export const NETWORK_ID = 'testnet';
// Official / widely documented public Testnet RPC endpoints (docs.near.org "RPC providers").
export const TESTNET_RPC_ALLOWLIST = Object.freeze([
  'https://rpc.testnet.near.org',
  'https://test.rpc.fastnear.com',
  'https://rpc.testnet.fastnear.com',
  'https://archival-rpc.testnet.near.org',
]);
export const EXPLORER_TX_BASE = 'https://testnet.nearblocks.io/txns/';

export function makeTestnetConfig({ rpcUrl, signerAccountId, contractId = null, allowSimulated = false }) {
  if (rpcUrl === 'sim://near-testnet') {
    if (!allowSimulated) fail('SIMULATED_RPC_NOT_ALLOWED');
  } else {
    let u;
    try { u = new URL(rpcUrl); } catch { fail('INVALID_RPC_URL'); }
    const origin = `${u.protocol}//${u.host}`;
    if (u.username || u.password || (u.pathname !== '/' && u.pathname !== '') || u.search || u.hash ||
        !TESTNET_RPC_ALLOWLIST.includes(origin)) fail('RPC_NOT_ALLOWLISTED', origin.slice(0, 80));
    rpcUrl = origin;
  }
  testnetAccountId(signerAccountId, 'signerAccountId');
  if (contractId !== null) testnetAccountId(contractId, 'contractId');
  return Object.freeze({ networkId: NETWORK_ID, chainId: 'near', rpcUrl, signerAccountId, contractId });
}

export const explorerUrl = (txHash) => EXPLORER_TX_BASE + encodeURIComponent(txHash);
