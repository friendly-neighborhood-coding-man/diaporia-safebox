/**
 * Reproducible LOCAL MOCK demonstration (no network beyond loopback, no real NEAR, no real e-mail):
 *   external MCP client (official SDK) -> OAuth 2.1 + PKCE consent -> get_safebox_status / check_payment / prepare_payment
 *   -> separate simulated owner-device approval (V5 OwnerWorld, harness only) -> Vault verification on its own Root replica
 *   -> settlement buffer -> MOCK ledger settlement -> get_payment_status with an independently verified receipt.
 * Usage: npm run demo [-- --evidence <file.json>]
 */
import { writeFileSync } from "node:fs";
import { startHarness } from "../harness/mockWorld.js";
import { call, mcpClient, obtainTokens } from "../harness/client.js";

const evIdx = process.argv.indexOf("--evidence");
const evidencePath = evIdx > 0 ? process.argv[evIdx + 1] : null;
const log: Array<{ step: string; data: unknown }> = [];
const step = (s: string, data: unknown) => { log.push({ step: s, data }); console.log(`\n== ${s}\n${JSON.stringify(data, null, 2)}`); };

const h = await startHarness();
try {
  step("0. gateway up (loopback, MOCK)", await (await fetch(`${h.url}/healthz`)).json());
  const t = await obtainTokens(h.url, h.logins.alice);
  step("1. OAuth: dynamic registration + PKCE S256 consent + token exchange", { clientId: t.clientId, tokenType: t.body.token_type, scope: t.body.scope, expiresIn: t.body.expires_in, accessTokenPrefix: t.access.slice(0, 4) + "…" });
  const ai = await mcpClient(h.url, t.access, "demo-external-ai");
  step("2. tools offered to this token", (await ai.listTools()).tools.map((x) => x.name));
  step("3. get_safebox_status", await call(ai, "get_safebox_status"));
  const pay = { recipientId: "merchant-a.mock", amountYocto: "30000000000000000000000", asset: "NEAR" };
  step("4. check_payment (estimate, not an authorization)", await call(ai, "check_payment", pay));
  const prep = await call(ai, "prepare_payment", { ...pay, memo: "Coffee beans order #1042", idempotencyKey: "demo-order-1042-0001" });
  step("5. prepare_payment (approval request only)", prep);
  step("6. get_payment_status before owner approval", await call(ai, "get_payment_status", { requestId: prep.requestId }));
  const balBefore = (await h.worlds["sbx-alice"].ledgerRead.call("BALANCES", {}));
  const dev = h.devices["sbx-alice"]!;
  const res = await dev.approve(prep.requestId, { decide: (text) => { step("7a. owner device shows (from its own verified Root view)", text.split("\n")); return true; } });
  step("7b. owner approved on the simulated enrolled device -> Vault PROPOSE", res);
  step("8. get_payment_status during the settlement buffer", await call(ai, "get_payment_status", { requestId: prep.requestId }));
  await dev.settle();
  const final = await call(ai, "get_payment_status", { requestId: prep.requestId });
  step("9. get_payment_status after the buffer (Vault release + MOCK ledger settlement)", final);
  const balAfter = (await h.worlds["sbx-alice"].ledgerRead.call("BALANCES", {}));
  step("10. MOCK ledger balances (independent read)", { merchantBefore: balBefore["merchant-a.mock"], merchantAfter: balAfter["merchant-a.mock"] });
  const summary = { result: final.settledVerified ? "LOCAL_MOCK_E2E_PASS" : "LOCAL_MOCK_E2E_FAIL", settledVerified: final.settledVerified, vaultState: final.vault?.vaultState, ledgerStatus: final.ledgerReceipt?.ledgerStatus,
    merchantCredited: (BigInt(balAfter["merchant-a.mock"]) - BigInt(balBefore["merchant-a.mock"])).toString(), notVerified: ["real MCP hosts (ChatGPT/Claude/Grok)", "real WebAuthn hardware / OS isolation", "NEAR testnet or mainnet"] };
  step("RESULT", summary);
  await ai.close();
  if (evidencePath) writeFileSync(evidencePath, JSON.stringify({ generatedBy: "scripts/demo-mock-e2e.ts", environment: "MOCK", steps: log }, null, 2));
  process.exitCode = final.settledVerified ? 0 : 1;
} finally { await h.close(); }
