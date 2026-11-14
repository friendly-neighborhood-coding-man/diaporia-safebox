import { test, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError, type OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import type { OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { startHarness, type Harness } from "../harness/mockWorld.js";
import { ALL, REDIRECT, authorizeUrl, consent, mcpClient, obtainTokens, pkce, rawMcp, register, tokenRequest } from "../harness/client.js";
import { OAuthAuthority } from "../src/auth/oauth.js";
import { AccountDirectory } from "../src/auth/accounts.js";

const hs: Harness[] = [];
after(async () => { for (const h of hs) await h.close(); });
const start = async (o = {}) => { const h = await startHarness(o); hs.push(h); return h; };

test("official MCP SDK OAuthClientProvider completes discovery, dynamic registration, PKCE S256 and token exchange", async () => {
  const h = await start();
  let saved: OAuthClientInformationMixed | undefined; let tokens: OAuthTokens | undefined; let verifier = ""; let authUrl: URL | null = null;
  const provider: OAuthClientProvider = {
    get redirectUrl() { return REDIRECT; },
    get clientMetadata(): OAuthClientMetadata { return { client_name: "SDK host", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none", scope: ALL }; },
    clientInformation: () => saved, saveClientInformation: (c) => { saved = c; },
    tokens: () => tokens, saveTokens: (t) => { tokens = t; },
    redirectToAuthorization: (u) => { authUrl = u; },
    saveCodeVerifier: (v) => { verifier = v; }, codeVerifier: () => verifier,
  };
  const transport = new StreamableHTTPClientTransport(new URL(`${h.url}/mcp`), { authProvider: provider });
  await assert.rejects(new Client({ name: "x", version: "1" }).connect(transport), UnauthorizedError);
  assert.match(saved!.client_id, /^scl_/);
  const u = authUrl as unknown as URL;
  assert.equal(u.searchParams.get("code_challenge_method"), "S256");
  assert.equal(u.searchParams.get("resource"), `${h.url}/mcp`);
  const c = await consent(h.url, u.toString(), { login: h.logins.alice });
  assert.equal(c.status, 303);
  const back = new URL(c.location!);
  assert.equal(back.searchParams.get("iss"), h.url);
  await transport.finishAuth(back.searchParams.get("code")!);
  assert.match(tokens!.access_token, /^sat_/);
  const c2 = new Client({ name: "x", version: "1" });
  await c2.connect(new StreamableHTTPClientTransport(new URL(`${h.url}/mcp`), { authProvider: provider }));
  assert.equal((await c2.listTools()).tools.length, 4);
  await c2.close();
});

test("RFC 9728/8414 metadata; unauthenticated /mcp gets 401 with resource_metadata challenge", async () => {
  const h = await start();
  const prm = await (await fetch(`${h.url}/.well-known/oauth-protected-resource/mcp`)).json() as any;
  assert.equal(prm.resource, `${h.url}/mcp`); assert.deepEqual(prm.authorization_servers, [h.url]);
  const asm = await (await fetch(`${h.url}/.well-known/oauth-authorization-server`)).json() as any;
  assert.deepEqual(asm.code_challenge_methods_supported, ["S256"]);
  assert.ok(!asm.grant_types_supported.includes("implicit") && !asm.grant_types_supported.includes("password") && !asm.grant_types_supported.includes("client_credentials"));
  const r = await rawMcp(h.url, null, { jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(r.status, 401);
  assert.equal(r.www, `Bearer resource_metadata="${h.url}/.well-known/oauth-protected-resource", scope="${ALL}"`);
  const bad = await rawMcp(h.url, "sat_" + "A".repeat(43), { jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(bad.status, 401); assert.match(bad.www!, /error="invalid_token"/);
});

test("registration refuses non-https / fragment / credential redirects, unsupported grants and unknown scopes", async () => {
  const h = await start();
  for (const bad of ["http://evil.example/cb", "https://a.example/cb#x", "https://u:p@a.example/cb", "javascript:alert(1)", "file:///etc/passwd"]) assert.equal((await register(h.url, { redirect_uris: [bad] })).status, 400, bad);
  assert.equal((await register(h.url, { redirect_uris: [REDIRECT], grant_types: ["client_credentials"] })).body.error, "invalid_client_metadata");
  assert.equal((await register(h.url, { redirect_uris: [REDIRECT], scope: "safebox.payment.sign" })).body.error, "invalid_scope");
});

test("unregistered redirect is never redirected to; PKCE plain refused; wrong resource refused", async () => {
  const h = await start();
  const reg = await register(h.url); const { challenge } = pkce();
  const evil = await fetch(authorizeUrl(h.url, reg.body.client_id, challenge, { redirect_uri: "https://evil.example/cb" }), { redirect: "manual" });
  assert.equal(evil.status, 400); assert.equal(evil.headers.get("location"), null);
  const plain = await fetch(authorizeUrl(h.url, reg.body.client_id, challenge, { code_challenge_method: "plain" }), { redirect: "manual" });
  assert.equal(new URL(plain.headers.get("location")!).searchParams.get("error"), "invalid_request");
  const res = await fetch(authorizeUrl(h.url, reg.body.client_id, challenge, { resource: "https://other.example/mcp" }), { redirect: "manual" });
  assert.equal(new URL(res.headers.get("location")!).searchParams.get("error"), "invalid_target");
});

test("CSRF: consent POST needs the per-request csrf token AND a same-origin Origin/Referer", async () => {
  const h = await start();
  const reg = await register(h.url); const { challenge } = pkce();
  const wrongCsrf = await consent(h.url, authorizeUrl(h.url, reg.body.client_id, challenge), { login: h.logins.alice, csrf: "forged" });
  assert.equal(wrongCsrf.status, 400); assert.equal(wrongCsrf.location, null);
  const crossOrigin = await consent(h.url, authorizeUrl(h.url, reg.body.client_id, challenge), { login: h.logins.alice, origin: "https://evil.example" });
  assert.equal(crossOrigin.status, 403);
  const noOrigin = await consent(h.url, authorizeUrl(h.url, reg.body.client_id, challenge), { login: h.logins.alice, origin: null });
  assert.equal(noOrigin.status, 403);
  const wrongLogin = await consent(h.url, authorizeUrl(h.url, reg.body.client_id, challenge), { login: "x".repeat(40) });
  assert.equal(wrongLogin.status, 401); assert.equal(wrongLogin.location, null);
});

test("authorization code replay revokes the issued tokens; stolen code from another client is refused; PKCE verifier mismatch refused", async () => {
  const h = await start();
  const t = await obtainTokens(h.url, h.logins.alice);
  assert.equal(t.status, 200);
  const replay = await tokenRequest(h.url, { grant_type: "authorization_code", code: t.code, code_verifier: t.verifier, client_id: t.clientId, redirect_uri: REDIRECT });
  assert.equal(replay.body.error, "invalid_grant");
  assert.equal((await rawMcp(h.url, t.access, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 401, "tokens from a replayed code are revoked");
  // stolen code
  const reg = await register(h.url); const other = await register(h.url); const { verifier, challenge } = pkce();
  const c = await consent(h.url, authorizeUrl(h.url, reg.body.client_id, challenge), { login: h.logins.alice });
  const code = new URL(c.location!).searchParams.get("code")!;
  assert.equal((await tokenRequest(h.url, { grant_type: "authorization_code", code, code_verifier: verifier, client_id: other.body.client_id, redirect_uri: REDIRECT })).body.error, "invalid_grant");
  assert.equal((await tokenRequest(h.url, { grant_type: "authorization_code", code, code_verifier: pkce().verifier, client_id: reg.body.client_id, redirect_uri: REDIRECT })).body.error, "invalid_grant");
});

test("refresh rotation: reuse revokes the family; a refresh cannot widen scope; revocation ends access", async () => {
  const h = await start();
  const t = await obtainTokens(h.url, h.logins.alice, { scope: "safebox.status.read safebox.payment.read" });
  const narrow = await tokenRequest(h.url, { grant_type: "refresh_token", refresh_token: t.refresh, client_id: t.clientId, scope: ALL });
  assert.equal(narrow.body.error, "invalid_scope");
  const r1 = await tokenRequest(h.url, { grant_type: "refresh_token", refresh_token: t.refresh, client_id: t.clientId });
  assert.equal(r1.status, 200);
  const reuse = await tokenRequest(h.url, { grant_type: "refresh_token", refresh_token: t.refresh, client_id: t.clientId });
  assert.equal(reuse.body.error, "invalid_grant");
  assert.equal((await rawMcp(h.url, r1.body.access_token, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 401, "refresh reuse revoked the whole family");
  const t2 = await obtainTokens(h.url, h.logins.alice);
  await fetch(`${h.url}/oauth/revoke`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: t2.access, client_id: t2.clientId }) });
  assert.equal((await rawMcp(h.url, t2.access, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 401);
});

test("session expiry: an expired access token is refused (injected clock)", async () => {
  let t0 = Date.now(); const now = () => t0;
  const h = await start({ now, oauth: { accessTokenTtlSec: 60 } });
  const t = await obtainTokens(h.url, h.logins.alice);
  assert.equal((await rawMcp(h.url, t.access, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 200);
  t0 += 61_000;
  const r = await rawMcp(h.url, t.access, { jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(r.status, 401); assert.match(r.www!, /invalid_token/);
});

test("wrong resource audience: a token minted for another resource is refused by this resource server", () => {
  const db = new DatabaseSync(":memory:"); const accounts = new AccountDirectory(); accounts.add("login-" + "a".repeat(30), "alice", "sbx-alice");
  const other = new OAuthAuthority(db, accounts, { issuer: "http://127.0.0.1:1", resource: "http://127.0.0.1:1/mcp", offeredScopes: ["safebox.status.read"] });
  const mine = new OAuthAuthority(db, accounts, { issuer: "http://127.0.0.1:2", resource: "http://127.0.0.1:2/mcp", offeredScopes: ["safebox.status.read"] });
  const reg = other.register({ redirect_uris: [REDIRECT] }); const { verifier, challenge } = pkce();
  const b = other.beginAuthorization(new URLSearchParams({ client_id: String(reg.body.client_id), redirect_uri: REDIRECT, response_type: "code", code_challenge: challenge, code_challenge_method: "S256", scope: "safebox.status.read" }));
  assert.ok(b.ok);
  const done = other.completeAuthorization(new URLSearchParams([["request_id", (b as any).pending.id], ["csrf", (b as any).pending.csrf], ["decision", "approve"], ["login_secret", "login-" + "a".repeat(30)], ["scope", "safebox.status.read"]]));
  const code = new URL((done as any).redirect).searchParams.get("code")!;
  const tok = other.token(new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: String(reg.body.client_id) }));
  const header = `Bearer ${tok.body.access_token}`;
  assert.ok(other.verifyAccessToken(header));
  assert.equal(mine.verifyAccessToken(header), null);
});

test("scope selection: the owner can grant less than asked; a no-scope request never gets payment preparation", async () => {
  const h = await start();
  const t = await obtainTokens(h.url, h.logins.alice, { keepScopes: ["safebox.status.read"] });
  const ai = await mcpClient(h.url, t.access);
  assert.deepEqual((await ai.listTools()).tools.map((x) => x.name), ["get_safebox_status"]);
  await ai.close();
  const d = await obtainTokens(h.url, h.logins.alice, { scope: "" });
  assert.equal(d.body.scope, "safebox.status.read safebox.payment.read");
});
