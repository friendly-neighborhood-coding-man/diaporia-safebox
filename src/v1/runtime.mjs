// Builds a SafeBox service from an operator config file. Secrets are referenced by PATH only.
import { readFileSync } from 'node:fs';
import { SafeBoxStore } from './store.mjs';
import { SafeBoxService } from './service.mjs';
import { NearTestnetExecutor, loadExecutorSigner } from './near/executor.mjs';
import { NearJsonRpcClient } from './near/rpc.mjs';
import { makeTestnetConfig } from './near/config.mjs';
import { requireExactFields } from './canonical.mjs';
import { rawFromKeyId } from './authz.mjs';

export function loadConfig(path) {
  const c = JSON.parse(readFileSync(path, 'utf8'));
  requireExactFields(c, ['v', 'dbPath', 'rpcUrl', 'signerAccountId', 'contractId', 'executorKeyFile', 'owners']);
  if (c.v !== 'safebox.config.v1') throw new Error('unsupported config version');
  for (const k of Object.values(c.owners)) rawFromKeyId(k);
  return c;
}

export function openRuntime(configPath, { withExecutor = true } = {}) {
  const c = loadConfig(configPath);
  const config = makeTestnetConfig({ rpcUrl: c.rpcUrl, signerAccountId: c.signerAccountId, contractId: c.contractId });
  const rpc = new NearJsonRpcClient({ url: config.rpcUrl });
  const store = new SafeBoxStore(c.dbPath);
  const executor = withExecutor ? new NearTestnetExecutor({ config, rpc, signer: loadExecutorSigner(c.executorKeyFile, c.signerAccountId), trustedOwnerKeys: c.owners }) : null;
  const service = new SafeBoxService({ store, trustedOwnerKeys: c.owners, signerAccountId: c.signerAccountId, contractId: c.contractId, executor, rpc });
  return { service, store, config, rpc };
}
