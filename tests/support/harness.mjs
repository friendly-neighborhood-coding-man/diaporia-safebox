// Offline harness: SIMULATED NEAR testnet + real Ed25519 keys generated in memory per test run.
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyPair } from 'near-api-js';
import { DOMAINS } from '../../src/v1/canonical.mjs';
import { ownerSignerFromKeyObject, authorizationStatement, revocationStatement, MANDATE_VERSION } from '../../src/v1/authz.mjs';
import { parseSealedIntent, ACTIONS } from '../../src/v1/intent.mjs';
import { SafeBoxStore } from '../../src/v1/store.mjs';
import { SafeBoxService } from '../../src/v1/service.mjs';
import { NearTestnetExecutor, executorSignerFromKeyPair } from '../../src/v1/near/executor.mjs';
import { makeTestnetConfig } from '../../src/v1/near/config.mjs';
import { SimulatedNearTestnet } from '../../src/v1/sim/simulated-near.mjs';
import { SafeBoxPaymentContractModel } from '../../src/v1/sim/contract-model.mjs';

export const NEAR = 10n ** 24n;
export const T0 = Date.parse('2026-11-13T00:00:00.000Z');
export const EXECUTOR = 'safebox-exec.testnet';
export const CONTRACT = 'safebox-pay.testnet';
export const MERCHANT = 'merchant.testnet';
export const ATTACKER = 'attacker.testnet';

export function newOwner(principalId = 'owner_alice') {
  return ownerSignerFromKeyObject(principalId, generateKeyPairSync('ed25519').privateKey);
}

export function makeWorld({ dbPath, principals = ['owner_alice', 'owner_bob'], clock } = {}) {
  const time = clock ?? { t: T0 };
  const now = () => time.t;
  const owners = Object.fromEntries(principals.map(p => [p, newOwner(p)]));
  const trustedOwnerKeys = Object.fromEntries(principals.map(p => [p, owners[p].publicKey]));
  const chain = new SimulatedNearTestnet({ now });
  const execKey = KeyPair.fromRandom('ed25519');
  const nativeKey = KeyPair.fromRandom('ed25519');
  chain.createAccount(EXECUTOR, 100n * NEAR);
  chain.addKey(EXECUTOR, execKey.getPublicKey().toString(), { FunctionCall: { receiver_id: CONTRACT, method_names: ['execute_payment'], allowance: null } });
  chain.addKey(EXECUTOR, nativeKey.getPublicKey().toString(), 'FullAccess');
  chain.createAccount(CONTRACT, 50n * NEAR);
  chain.createAccount(MERCHANT, 0n);
  chain.createAccount(ATTACKER, 0n);
  chain.deployContract(CONTRACT, new SafeBoxPaymentContractModel({ contractId: CONTRACT, ownerId: 'alice-owner.testnet',
    ownerPrincipalId: 'owner_alice', ownerAuthKey: owners.owner_alice.publicKey, executorId: EXECUTOR, maxPaymentYocto: (5n * NEAR).toString() }));
  dbPath ??= join(mkdtempSync(join(tmpdir(), 'safebox-')), 'safebox.db');
  const config = makeTestnetConfig({ rpcUrl: 'sim://near-testnet', signerAccountId: EXECUTOR, contractId: CONTRACT, allowSimulated: true });
  const mk = (kp) => new NearTestnetExecutor({ config, rpc: chain, signer: executorSignerFromKeyPair(EXECUTOR, kp), trustedOwnerKeys, now });
  const contractExecutor = mk(execKey), nativeExecutor = mk(nativeKey);
  const open = (executor = contractExecutor) => {
    const store = new SafeBoxStore(dbPath, { now });
    return new SafeBoxService({ store, trustedOwnerKeys, signerAccountId: EXECUTOR, contractId: CONTRACT, executor, now });
  };
  return { time, now, owners, trustedOwnerKeys, chain, dbPath, config, contractExecutor, nativeExecutor, execKey, nativeKey, open };
}

export function signMandate(owner, { mandateId = 'm_' + owner.principalId.slice(6), action = ACTIONS.CONTRACT, maxPer = 2n * NEAR,
  maxTotal = 3n * NEAR, recipients = [MERCHANT], from = T0 - 1000, to = T0 + 86_400_000 } = {}) {
  return owner.signStatement(DOMAINS.MANDATE, { v: MANDATE_VERSION, mandateId, principalId: owner.principalId, ownerKey: owner.publicKey,
    action, maxPerIntentYocto: maxPer.toString(), maxTotalYocto: maxTotal.toString(), allowedRecipients: [...recipients].sort(),
    validFrom: new Date(from).toISOString(), expiresAt: new Date(to).toISOString() });
}

export function proposal(over = {}) {
  return { v: 'safebox.proposal.v1', principalId: 'owner_alice', mandateId: 'm_alice', action: ACTIONS.CONTRACT,
    recipientId: MERCHANT, amountYocto: NEAR.toString(), ttlSeconds: '600',
    context: { source: 'diaporia-buy', summary: 'Buy synthetic test item', evidenceRefs: ['offer:demo-1'] }, ...over };
}

/** Owner-side authorizer: recomputes the digest from the canonical intent, then signs. */
export function ownerAuthorize(owner, req, now, ttlMs) {
  const sealed = parseSealedIntent(req.canonical);
  return owner.signStatement(DOMAINS.AUTHZ, authorizationStatement({ sealed, challenge: req.challenge, ownerKey: owner.publicKey, now, ttlMs }));
}

export function ownerRevoke(owner, req, now) {
  const sealed = parseSealedIntent(req.canonical);
  const r = owner.signStatement(DOMAINS.REVOKE, revocationStatement({ sealed, ownerKey: owner.publicKey, now }));
  return { revocation: r.statement, signature: r.signature };
}
export const asAuthz = (s) => ({ authorization: s.statement, signature: s.signature });
