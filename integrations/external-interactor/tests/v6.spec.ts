// V6 Workflow A through the External AI Interactor: prepare_payment (AI, via MCP) -> exact payment request -> enrolled
// owner device -> Root-pinned one-time challenge bound to THIS request -> canonical summary -> fingerprint gate
// (fingerprint-only credential) -> one signature over the exact capability -> Vault (V6 binding check + FIXED_600 buffer)
// -> MOCK settlement -> independent V6 verifier. The AI side never holds a key, a gate or a signing path.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { startHarness, type Harness } from "../harness/mockWorld.js";
import { safeboxRoot } from "../src/safebox/loadV5.js";
import { call, mcpClient, obtainTokens } from "../harness/client.js";

const PAY = { recipientId: "merchant-a.mock", amountYocto: "30000000000000000000000", asset: "NEAR" };
const V6 = { fingerprintOnly: ["k2-laptop"] };
const hs: Harness[] = [];
after(async () => { for (const h of hs) await h.close(); });
const start = async () => { const h = await startHarness({ v6: V6 }); hs.push(h); return h; };
const verifier = async () => (await import(pathToFileURL(join(safeboxRoot(), "src/v6/supervisor/verifier.mjs")).href)) as { verifyWorld6: (w: unknown) => Promise<any> };
const prepare = async (h: Harness, key: string) => {
  const t = await obtainTokens(h.url, h.logins.alice); const ai = await mcpClient(h.url, t.access);
  const prep = await call(ai, "prepare_payment", { ...PAY, memo: "order " + key, idempotencyKey: "v6-order-" + key.padStart(12, "0") });
  return { ai, prep };
};

test("V6-A E2E: MCP prepare -> fingerprint-only owner approval bound to the request -> Vault -> FIXED_600 -> MOCK settlement -> V6 verifier clean", async () => {
  const h = await start(); const w = h.worlds["sbx-alice"];
  const { ai, prep } = await prepare(h, "1");
  assert.equal(prep.state, "AWAITING_OWNER_APPROVAL"); assert.equal(prep.signed, false);
  const tools = (await ai.listTools()).tools.map((x) => x.name).sort();
  assert.deepEqual(tools, ["check_payment", "get_payment_status", "get_safebox_status", "prepare_payment"], "no signing / biometric / key tool over MCP");
  const dev = h.devices["sbx-alice"]!;
  const res = await dev.approve(prep.requestId, { credId: "k2-laptop" }) as any;
  assert.equal(res.state, "SUBMITTED_TO_VAULT", JSON.stringify(res)); assert.equal(res.vaultState, "BUFFERED");
  const b = dev.lastV6.approval.v6.binding;
  assert.equal(b.requestId, prep.requestId); assert.equal(b.assurance, "FINGERPRINT_ONLY"); assert.ok(dev.lastV6.approval.v6.gate);
  for (const k of ["accountId", "chainId", "recipientId", "asset", "amountYocto", "purposeId", "purposeVersion", "credId", "epoch", "policyVersion", "requestId", "requestDigest", "approvalExpiresAt", "challengeNonce"]) assert.ok(b[k], k);
  await w.advance(9 * 60_000);
  assert.equal((await call(ai, "get_payment_status", { requestId: prep.requestId })).settledVerified, false, "FIXED_600 not skipped");
  await dev.settle();
  assert.equal((await call(ai, "get_payment_status", { requestId: prep.requestId })).settledVerified, true);
  const v = await (await verifier()).verifyWorld6(w);
  assert.equal(v.ok, true, JSON.stringify(v.v6)); assert.equal(v.v6.ownerApprovals.checked, 1);
  await ai.close();
});

test("V6-A UV credential: phone approval (Windows-Hello-style UV, PIN fallback possible) is labelled UV, not fingerprint", async () => {
  const h = await start(); const { ai, prep } = await prepare(h, "2");
  const dev = h.devices["sbx-alice"]!;
  const res = await dev.approve(prep.requestId, { credId: "k1-phone" }) as any;
  assert.equal(res.state, "SUBMITTED_TO_VAULT"); assert.equal(dev.lastV6.assurance, "UV"); assert.equal(dev.lastV6.approval.v6.gate, undefined);
  await ai.close();
});

test("V6-A refusals: legacy V5 paycap, missing gate, PIN-only, binding for another request, tampered amount -> nothing reaches settlement", async () => {
  const h = await start(); const w = h.worlds["sbx-alice"]; const dev = h.devices["sbx-alice"]!;
  const r1 = await prepare(h, "3");
  const legacy = await dev.approve(r1.prep.requestId, { credId: "k1-phone", legacyV5: true }) as any;
  assert.equal(legacy.state, "VAULT_REJECTED"); assert.equal(legacy.vaultCode, "V6_PAYMENT_APPROVAL_REQUIRED");
  const r2 = await prepare(h, "4");
  const ng = await dev.approve(r2.prep.requestId, { credId: "k2-laptop", noGate: true }) as any;
  assert.equal(ng.state, "VAULT_REJECTED"); assert.equal(ng.vaultCode, "FINGERPRINT_GATE_REQUIRED");
  const r3 = await prepare(h, "5");
  w.gates["k2-laptop"].next("PIN_ONLY");
  const pin = await dev.approve(r3.prep.requestId, { credId: "k2-laptop" }) as any;
  assert.deepEqual(pin.refusedByDevice, ["BIOMETRIC_PIN_NOT_ACCEPTED"]);
  const r4 = await prepare(h, "6"); const r5 = await prepare(h, "7");
  // an approval bound to request r5 submitted against r4: the adapter's exactness check refuses it
  const other = await dev.approve(r4.prep.requestId, { credId: "k1-phone", tamperBinding: (b: any) => { b.requestId = r5.prep.requestId; } }).catch((e: any) => ({ code: e.code, detail: e.details })) as any;
  assert.equal(other.code, "CAPABILITY_MISMATCH"); assert.ok(other.detail.fields.includes("v6.requestId"));
  const amt = await dev.approve(r5.prep.requestId, { credId: "k1-phone", tamperBinding: (b: any) => { b.amountYocto = "1"; } }).catch((e: any) => ({ code: e.code, detail: e.details })) as any;
  assert.equal(amt.code, "CAPABILITY_MISMATCH");
  await w.advance(20 * 60_000);
  assert.equal(w.vault.v5payments().length, 0);
  assert.equal((await w.ledgerRead.call("TRANSFERS", { sinceSeq: "0" })).length, 0);
  for (const r of [r1, r2, r3, r4, r5]) await r.ai.close();
});

test("V6-A replay: a genuine V6 approval cannot be reused at the Vault (challenge nonce consumed durably)", async () => {
  const h = await start(); const w = h.worlds["sbx-alice"]; const dev = h.devices["sbx-alice"]!;
  const { ai, prep } = await prepare(h, "8");
  assert.equal((await dev.approve(prep.requestId, { credId: "k1-phone" }) as any).state, "SUBMITTED_TO_VAULT");
  const pa = dev.lastV6;
  const again = await w.gz.request("PROPOSE", { capability: pa.capability, approval: pa.approval, recipientId: PAY.recipientId, amountYocto: PAY.amountYocto, asset: "NEAR", memo: "replay" });
  assert.equal(again.ok, false); assert.match(again.error.code, /CAP_ALREADY_USED|CHALLENGE_ALREADY_CONSUMED|REPLAY|WEBAUTHN_SIGNCOUNT_NOT_INCREASING/);
  await ai.close();
});
