#!/usr/bin/env node
// REAL NEAR TESTNET demonstration (operator-run). Requires funded Testnet accounts and keys that the
// operator created; this script never creates accounts, never generates keys, and never touches mainnet.
//   SAFEBOX_CONFIG            path to safebox.config.json (rpcUrl must be an allow-listed TESTNET endpoint)
//   SAFEBOX_OWNER_KEY_FILE    owner authorization key (read ONLY by the separate bin/safebox-owner.mjs process)
//   SAFEBOX_DEMO_PRINCIPAL, SAFEBOX_DEMO_MANDATE_ID, SAFEBOX_DEMO_ACTION, SAFEBOX_DEMO_RECIPIENT, SAFEBOX_DEMO_AMOUNT_YOCTO
// Usage: node demo/testnet-v1.mjs [--preflight-only]
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openRuntime, loadConfig } from '../src/v1/runtime.mjs';
import { CONTRACT_METHOD } from '../src/v1/intent.mjs';

const REQUIRED = ['SAFEBOX_CONFIG', 'SAFEBOX_OWNER_KEY_FILE', 'SAFEBOX_DEMO_PRINCIPAL', 'SAFEBOX_DEMO_MANDATE_ID', 'SAFEBOX_DEMO_ACTION', 'SAFEBOX_DEMO_RECIPIENT', 'SAFEBOX_DEMO_AMOUNT_YOCTO'];
const preflightOnly = process.argv.includes('--preflight-only');
const missing = REQUIRED.filter(k => !process.env[k] && !(preflightOnly && k !== 'SAFEBOX_CONFIG'));
if (missing.length) {
  console.log(`UNVERIFIED: NEAR testnet demo not run. Missing prerequisites: ${missing.join(', ')}`);
  console.log('See docs/near-v1-operator-guide.md. No transaction was signed or sent.');
  process.exit(2);
}
const env = process.env;
const ROOT = fileURLToPath(new URL('..', import.meta.url));

async function preflight(rt, cfg) {
  const report = {};
  report.chainId = await rt.rpc.chainId();
  if (report.chainId !== 'testnet') throw new Error(`RPC chain_id is ${report.chainId}, refusing`);
  const exec = JSON.parse(readFileSync(cfg.executorKeyFile, 'utf8'));
  const ak = await rt.rpc.accessKey(cfg.signerAccountId, exec.public_key);
  report.executorKey = ak.permission === 'FullAccess' ? 'FullAccess' : ak.permission.FunctionCall;
  if (cfg.contractId) {
    report.contract = await rt.rpc.viewFunction(cfg.contractId, 'get_config', {});
    const fc = ak.permission.FunctionCall;
    report.executorKeyRestrictedToContract = !!fc && fc.receiver_id === cfg.contractId && fc.method_names.length === 1 && fc.method_names[0] === CONTRACT_METHOD;
    const own = cfg.owners[report.contract.owner_principal_id];
    report.contractOwnerKeyMatchesPinnedKey = own === report.contract.owner_auth_key;
    report.contractExecutorMatches = report.contract.executor_id === cfg.signerAccountId;
  }
  return report;
}

const cfg = loadConfig(env.SAFEBOX_CONFIG);
const rt = openRuntime(env.SAFEBOX_CONFIG);
const pf = await preflight(rt, cfg);
console.log('PREFLIGHT', JSON.stringify(pf, null, 2));
if (preflightOnly) process.exit(0);

const work = mkdtempSync(join(tmpdir(), 'safebox-testnet-'));
const proposal = { v: 'safebox.proposal.v1', principalId: env.SAFEBOX_DEMO_PRINCIPAL, mandateId: env.SAFEBOX_DEMO_MANDATE_ID, action: env.SAFEBOX_DEMO_ACTION,
  recipientId: env.SAFEBOX_DEMO_RECIPIENT, amountYocto: env.SAFEBOX_DEMO_AMOUNT_YOCTO, ttlSeconds: '900',
  context: { source: 'safebox-testnet-demo', summary: 'SafeBox V1 testnet demonstration payment', evidenceRefs: [] } };
const prepared = rt.service.propose(proposal);
const reqPath = join(work, 'request.json'), authPath = join(work, 'authorization.json');
writeFileSync(reqPath, JSON.stringify(rt.service.authorizationRequest(prepared.intentId), null, 2));
console.log(`PREPARED intent ${prepared.intentId} digest ${prepared.digest}`);
console.log('Owner authorization runs in a separate process; it reads the owner key, shows the parameters and asks for confirmation.');
const owner = spawnSync(process.execPath, [join(ROOT, 'bin/safebox-owner.mjs'), 'authorize', '--key', env.SAFEBOX_OWNER_KEY_FILE, '--request', reqPath, '--out', authPath],
  { stdio: 'inherit' });
if (owner.status !== 0 || !existsSync(authPath)) { console.log('NOT AUTHORIZED by owner. Nothing signed.'); process.exit(3); }
const auth = JSON.parse(readFileSync(authPath, 'utf8'));
rt.service.authorize(prepared.intentId, auth);
console.log('AUTHORIZED (owner Ed25519 signature verified against pinned key)');
let st = await rt.service.execute(prepared.intentId, { actor: 'operator' });
for (let k = 0; k < 8 && !['CONFIRMED', 'FAILED'].includes(st.state); k++) {
  await new Promise(r => setTimeout(r, 2000 * (k + 1)));
  st = await rt.service.reconcile(prepared.intentId, { rebroadcast: true });
}
const evidence = { intentId: prepared.intentId, digest: prepared.digest, state: st.state, txHash: st.txHash, effect: st.effect, evidence: st.evidence,
  journal: rt.store.journal(prepared.intentId).map(j => ({ at: j.at, from: j.from_state, to: j.to_state, actor: j.actor, detail: JSON.parse(j.detail) })), preflight: pf };
mkdirSync(join(ROOT, 'docs/evidence'), { recursive: true });
const evPath = join(ROOT, 'docs/evidence', `testnet-run-${prepared.intentId}.json`);
writeFileSync(evPath, JSON.stringify(evidence, null, 2) + '\n');
if (st.state === 'CONFIRMED' && !st.evidence?.simulated) {
  console.log(`VERIFIED ON NEAR TESTNET: ${st.txHash}\n  ${st.evidence.explorerUrl}\n  evidence: ${evPath}`);
} else {
  console.log(`NOT VERIFIED: final state ${st.state}. Evidence: ${evPath}. Re-run: node bin/safebox.mjs reconcile --config ${env.SAFEBOX_CONFIG} --intent ${prepared.intentId}`);
  process.exitCode = 4;
}
