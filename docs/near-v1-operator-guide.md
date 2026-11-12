# SafeBox V1 — Operator Guide (NEAR **Testnet** only)

## 0. Offline (no secrets, no network, no funds)

```bash
npm ci
npm test               # 59 JS tests: V0 mock + V1 (simulated NEAR testnet)
npm run test:contract  # Rust contract unit tests incl. shared vectors (needs Rust >= 1.95)
npm run demo           # V0 mock demo (unchanged)
npm run demo:v1        # V1 end-to-end on the SIMULATED chain
npm run evidence       # rewrites docs/evidence/near-v1-adversarial-metrics.json
```

## 1. Prerequisites for a real Testnet run

- Node.js ≥ 22.13, Rust ≥ 1.95 with `wasm32-unknown-unknown`, and NEAR CLI (`near`, near-cli-rs). The
  CLI syntax below follows near-cli-rs; confirm each command with `near --help` for your installed version.
- Testnet accounts you control (never reuse a mainnet identity):
  - `safebox-exec-YOURNAME.testnet` — executor; pays gas only.
  - `safebox-pay-YOURNAME.testnet` — payment contract (contract mode); funded with a few testnet NEAR.
  - `YOURNAME-owner.testnet` — contract owner account (revoke / withdraw).
  - a recipient account, e.g. `YOURNAME-merchant.testnet`.
- Keep every key file outside the repository with mode `0600`. Do not paste keys into an AI chat.

## 2. Owner authorization key (separate from NEAR keys)

Run on the owner's machine (ideally a different device or OS user than the AI agent):

```bash
node bin/safebox-owner.mjs keygen --principal owner_yourname --out ~/.safebox/owner_yourname.key.json
```

Copy the printed `ownerPublicKey` into `owners` of your `safebox.config.json`
(template: `safebox.config.example.json`).

## 3. Deploy the payment contract (contract mode, recommended)

```bash
npm run build:contract   # -> contract/target/wasm32-unknown-unknown/release/safebox_payment.wasm
# If NEAR rejects the module (newer rustc emits wasm features older runtimes refuse), build with cargo-near instead:
#   cargo install cargo-near && (cd contract && cargo near build non-reproducible-wasm)

near contract deploy safebox-pay-YOURNAME.testnet \
  use-file contract/target/wasm32-unknown-unknown/release/safebox_payment.wasm \
  with-init-call new json-args '{"owner_id":"YOURNAME-owner.testnet","owner_principal_id":"owner_yourname","owner_auth_key":"ed25519:OWNER_PUBLIC_KEY","executor_id":"safebox-exec-YOURNAME.testnet","max_payment_yocto":"100000000000000000000000"}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send

near tokens YOURNAME-owner.testnet send-near safebox-pay-YOURNAME.testnet '1 NEAR' network-config testnet sign-with-keychain send
```

Give the executor a **Function-Call key limited to `execute_payment`** (generate the key pair with the CLI,
store its credential JSON as `executorKeyFile`; the `allowance` is a gas allowance, not a spending cap):

```bash
near account add-key safebox-exec-YOURNAME.testnet grant-function-call-access \
  --allowance '0.25 NEAR' --contract-account-id safebox-pay-YOURNAME.testnet --function-names execute_payment \
  autogenerate-new-keypair save-to-keychain network-config testnet sign-with-keychain send
```

The executor credential file must look like `{"account_id": "...", "public_key": "ed25519:...", "private_key": "ed25519:..."}`.

## 4. Owner-signed mandate

```bash
node bin/safebox-owner.mjs sign-mandate --key ~/.safebox/owner_yourname.key.json --mandate-id m_demo \
  --action SAFEBOX_CONTRACT_PAYMENT --max-per-yocto 100000000000000000000000 --max-total-yocto 300000000000000000000000 \
  --recipients YOURNAME-merchant.testnet --hours 24 --out mandate.json
node bin/safebox.mjs register-mandate --config safebox.config.json --file mandate.json
```

## 5. Preflight (read-only) and the Testnet demo

```bash
SAFEBOX_CONFIG=safebox.config.json node demo/testnet-v1.mjs --preflight-only
# expects: chainId "testnet", executorKeyRestrictedToContract true, contractOwnerKeyMatchesPinnedKey true, contractExecutorMatches true

SAFEBOX_CONFIG=safebox.config.json \
SAFEBOX_OWNER_KEY_FILE=~/.safebox/owner_yourname.key.json \
SAFEBOX_DEMO_PRINCIPAL=owner_yourname SAFEBOX_DEMO_MANDATE_ID=m_demo \
SAFEBOX_DEMO_ACTION=SAFEBOX_CONTRACT_PAYMENT SAFEBOX_DEMO_RECIPIENT=YOURNAME-merchant.testnet \
SAFEBOX_DEMO_AMOUNT_YOCTO=10000000000000000000000 \
npm run demo:testnet
```

The owner step runs `bin/safebox-owner.mjs authorize` as a separate process: it shows the parameters and
requires typing the first 16 characters of the intent digest. On success the script prints
`VERIFIED ON NEAR TESTNET: <hash>` with a `https://testnet.nearblocks.io/txns/<hash>` link and writes
`docs/evidence/testnet-run-<intentId>.json`. Anything else prints `NOT VERIFIED` and the reconcile command.
Without prerequisites it prints `UNVERIFIED ...` and exits 2 without signing anything.

## 6. Manual flow (owner on a separate device)

```bash
node bin/safebox.mjs propose   --config safebox.config.json --file proposal.json --request-out request.json
# move request.json to the owner device:
node bin/safebox-owner.mjs authorize --key owner.key.json --request request.json --out authorization.json
# move authorization.json back:
node bin/safebox.mjs authorize --config safebox.config.json --file authorization.json
node bin/safebox.mjs execute   --config safebox.config.json --intent <id>
node bin/safebox.mjs status    --config safebox.config.json --intent <id>
node bin/safebox.mjs reconcile --config safebox.config.json --intent <id> [--rebroadcast]
node bin/safebox.mjs recover   --config safebox.config.json      # after any crash
node bin/safebox.mjs journal   --config safebox.config.json --intent <id>
```

Kill switches: `safebox-owner revoke` (before reservation); on-chain
`near contract call-function as-transaction safebox-pay-YOURNAME.testnet revoke_nonce json-args '{"nonce":"<intent nonce>"}' ... sign-as YOURNAME-owner.testnet`;
`withdraw` returns unused funds to the owner account.

## 7. Native mode (optional, weaker)

For `NEAR_NATIVE_TRANSFER` proposals the executor must hold a **FullAccess** key (NEAR Function-Call keys
cannot transfer value), so use a separate config whose `executorKeyFile` is a FullAccess key on a
**dedicated** executor account that holds only the test budget, plus a mandate with
`--action NEAR_NATIVE_TRANSFER`. The executor refuses native intents with a Function-Call key and contract
intents with a FullAccess key. Limits in native mode are enforced only by SafeBox, not by the chain.
