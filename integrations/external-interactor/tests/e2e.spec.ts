import { test, after } from "node:test";
import assert from "node:assert/strict";
import { startHarness, type Harness } from "../harness/mockWorld.js";
import { call, mcpClient, obtainTokens } from "../harness/client.js";

const PAY = { recipientId: "merchant-a.mock", amountYocto: "30000000000000000000000", asset: "NEAR" };
const hs: Harness[] = [];
after(async () => { for (const h of hs) await h.close(); });
const start = async (o = {}) => { const h = await startHarness(o); hs.push(h); return h; };

test("E2E: official MCP client -> OAuth -> status/check/prepare -> separate owner device approval -> Vault -> buffer -> MOCK settlement -> verified status", async () => {
  const h = await start();
  const t = await obtainTokens(h.url, h.logins.alice);
  const ai = await mcpClient(h.url, t.access);
  assert.deepEqual((await ai.listTools()).tools.map((x) => x.name).sort(), ["check_payment", "get_payment_status", "get_safebox_status", "prepare_payment"]);
  const st = await call(ai, "get_safebox_status");
  assert.equal(st.accountRef, "sbx-alice"); assert.equal(st.environment, "MOCK"); assert.equal(st.protection.frozen, false);
  assert.equal(st.settlement.minimumBufferMs, 600_000);
  const chk = await call(ai, "check_payment", PAY);
  assert.equal(chk.isAuthorization, false); assert.equal(chk.wouldBeAcceptedForOwnerApproval, true);
  const prep = await call(ai, "prepare_payment", { ...PAY, memo: "order 1", idempotencyKey: "e2e-order-000000001" });
  assert.equal(prep.state, "AWAITING_OWNER_APPROVAL"); assert.equal(prep.paymentEffect, "NONE"); assert.equal(prep.signed, false); assert.equal(prep.settled, false);
  // preparing created NO Vault payment and NO ledger effect
  const w = h.worlds["sbx-alice"];
  assert.equal(w.vault.v5payments().length, 0);
  assert.equal((await w.ledgerRead.call("TRANSFERS", { sinceSeq: "0" })).length, 0);
  const before = await call(ai, "get_payment_status", { requestId: prep.requestId });
  assert.equal(before.requestState, "AWAITING_OWNER_APPROVAL"); assert.equal(before.vault, null); assert.equal(before.settledVerified, false);

  const res = await h.devices["sbx-alice"]!.approve(prep.requestId) as any;
  assert.equal(res.state, "SUBMITTED_TO_VAULT"); assert.equal(res.vaultState, "BUFFERED");
  const mid = await call(ai, "get_payment_status", { requestId: prep.requestId });
  assert.equal(mid.vault.vaultState, "BUFFERED"); assert.equal(mid.settledVerified, false);
  // the buffer is not skipped: 9 minutes in, still not settled
  await w.advance(9 * 60_000);
  assert.equal((await call(ai, "get_payment_status", { requestId: prep.requestId })).settledVerified, false);
  await h.devices["sbx-alice"]!.settle();
  const fin = await call(ai, "get_payment_status", { requestId: prep.requestId });
  assert.equal(fin.vault.vaultState, "SETTLED"); assert.equal(fin.ledgerReceipt.ledgerStatus, "SETTLED"); assert.equal(fin.ledgerReceipt.matchesRequest, true); assert.equal(fin.settledVerified, true);
  const bal = await w.ledgerRead.call("BALANCES", {});
  assert.equal(bal["merchant-a.mock"], PAY.amountYocto);
  // Vault journal shows the request was executed by the existing V5 path (capability verified against its Root replica)
  assert.equal(w.vault.v5payments()[0].state, "SETTLED");
  await ai.close();
});

test("E2E idempotency: a retried prepare returns the same request; retry after approval does not create a second payment", async () => {
  const h = await start();
  const t = await obtainTokens(h.url, h.logins.alice);
  const ai = await mcpClient(h.url, t.access);
  const a = await call(ai, "prepare_payment", { ...PAY, idempotencyKey: "idem-key-0000000001" });
  const b = await call(ai, "prepare_payment", { ...PAY, idempotencyKey: "idem-key-0000000001" });
  assert.equal(a.requestId, b.requestId); assert.equal(b.idempotentReplay, true);
  await h.devices["sbx-alice"]!.approve(a.requestId);
  const c = await call(ai, "prepare_payment", { ...PAY, idempotencyKey: "idem-key-0000000001" });
  assert.equal(c.requestId, a.requestId); assert.equal(c.state, "SUBMITTED_TO_VAULT");
  await h.devices["sbx-alice"]!.settle();
  assert.equal(h.worlds["sbx-alice"].vault.v5payments().length, 1);
  await ai.close();
});

test("E2E owner declines: nothing is proposed to the Vault, status reports OWNER_DECLINED", async () => {
  const h = await start();
  const t = await obtainTokens(h.url, h.logins.alice);
  const ai = await mcpClient(h.url, t.access);
  const p = await call(ai, "prepare_payment", { ...PAY, idempotencyKey: "decline-0000000001" });
  const r = await h.devices["sbx-alice"]!.approve(p.requestId, { decide: () => false });
  assert.deepEqual(r, { declined: true });
  assert.equal((await call(ai, "get_payment_status", { requestId: p.requestId })).requestState, "OWNER_DECLINED");
  assert.equal(h.worlds["sbx-alice"].vault.v5payments().length, 0);
  await ai.close();
});

test("status output is redacted: no credential ids, device keys, contact addresses or chain internals", async () => {
  const h = await start();
  const t = await obtainTokens(h.url, h.logins.alice);
  const ai = await mcpClient(h.url, t.access);
  const s = JSON.stringify(await call(ai, "get_safebox_status")) + JSON.stringify(await call(ai, "check_payment", PAY));
  for (const bad of ["k1-phone", "k2-laptop", "k3-root-hw", "ed25519:", "security.example.test", "orc-", "chainId", "publicKey"]) assert.ok(!s.includes(bad), bad);
  await ai.close();
});
