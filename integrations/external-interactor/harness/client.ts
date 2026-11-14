/** Test/demo MCP host: official MCP SDK client + a scripted human on the OAuth consent page. */
import { createHash, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

export const REDIRECT = "http://127.0.0.1:53682/callback";
export const ALL = "safebox.status.read safebox.payment.check safebox.payment.prepare safebox.payment.read";
export const pkce = () => { const verifier = randomBytes(32).toString("base64url"); return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") }; };

export async function register(url: string, body: Record<string, unknown> = { client_name: "Mock MCP host", redirect_uris: [REDIRECT] }) {
  const r = await fetch(`${url}/oauth/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() as any };
}
export function authorizeUrl(url: string, clientId: string, challenge: string, extra: Record<string, string> = {}) {
  const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "S256", state: "st-1", resource: `${url}/mcp`, scope: ALL, ...extra });
  return `${url}/oauth/authorize?${q}`;
}
/** Plays the human on the consent page. */
export async function consent(url: string, authUrl: string, opts: { login?: string; decision?: "approve" | "deny"; keepScopes?: string[]; origin?: string | null; csrf?: string } = {}) {
  const pg = await fetch(authUrl, { redirect: "manual" });
  if (pg.status !== 200) return { status: pg.status, location: pg.headers.get("location"), html: await pg.text(), offered: [] as string[] };
  const html = await pg.text();
  const requestId = /name="request_id" value="([^"]+)"/.exec(html)![1]!;
  const csrf = /name="csrf" value="([^"]+)"/.exec(html)![1]!;
  const offered = [...html.matchAll(/name="scope" value="([^"]+)"/g)].map((m) => m[1]!);
  const form = new URLSearchParams({ request_id: requestId, csrf: opts.csrf ?? csrf, decision: opts.decision ?? "approve", login_secret: opts.login ?? "" });
  for (const s of opts.keepScopes ?? offered) form.append("scope", s);
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
  if (opts.origin !== null) headers.Origin = opts.origin ?? url;
  const r = await fetch(`${url}/oauth/authorize`, { method: "POST", body: form, redirect: "manual", headers });
  return { status: r.status, location: r.headers.get("location"), html: r.status === 303 ? "" : await r.text(), offered };
}
export async function tokenRequest(url: string, form: Record<string, string>) {
  const r = await fetch(`${url}/oauth/token`, { method: "POST", body: new URLSearchParams(form), headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  return { status: r.status, body: await r.json() as any };
}
export async function obtainTokens(url: string, login: string, opts: { scope?: string; keepScopes?: string[] } = {}) {
  const reg = await register(url);
  const { verifier, challenge } = pkce();
  const c = await consent(url, authorizeUrl(url, reg.body.client_id, challenge, opts.scope !== undefined ? { scope: opts.scope } : {}), { login, ...(opts.keepScopes ? { keepScopes: opts.keepScopes } : {}) });
  if (!c.location) throw new Error("consent failed: " + c.status + " " + c.html.slice(0, 300));
  const code = new URL(c.location).searchParams.get("code")!;
  const t = await tokenRequest(url, { grant_type: "authorization_code", code, code_verifier: verifier, client_id: reg.body.client_id, redirect_uri: REDIRECT, resource: `${url}/mcp` });
  return { clientId: reg.body.client_id as string, code, verifier, status: t.status, body: t.body, access: t.body.access_token as string, refresh: t.body.refresh_token as string };
}
export async function mcpClient(url: string, accessToken: string, name = "mock-ai-host") {
  const client = new Client({ name, version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${accessToken}` } } }));
  return client;
}
export async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const r = await client.callTool({ name, arguments: args }) as any;
  if (r.isError) throw Object.assign(new Error("tool error: " + JSON.stringify(r.content)), { result: r, body: JSON.parse(r.content?.[0]?.text ?? "{}") });
  return r.structuredContent as any;
}
export async function callError(client: Client, name: string, args: Record<string, unknown> = {}) {
  const r = await client.callTool({ name, arguments: args }) as any;
  if (!r.isError) throw new Error("expected tool error, got " + JSON.stringify(r.structuredContent));
  const text = r.content?.[0]?.text ?? "";
  try { return JSON.parse(text).error ?? { code: "?", message: text }; } catch { return { code: "SDK_VALIDATION", message: text }; }
}
export async function rawMcp(url: string, token: string | null, body: unknown, headers: Record<string, string> = {}) {
  const h: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  const r = await fetch(`${url}/mcp`, { method: "POST", headers: h, body: typeof body === "string" ? body : JSON.stringify(body) });
  const text = await r.text(); let json: any = null; try { json = JSON.parse(text); } catch { /* */ }
  return { status: r.status, json, text, www: r.headers.get("www-authenticate") };
}
