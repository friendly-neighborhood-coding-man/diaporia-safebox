import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { OAuthAuthority, type PendingAuthorization } from "../auth/oauth.js";
import type { AccountDirectory } from "../auth/accounts.js";
import { SCOPES } from "../auth/scopes.js";
import { createInteractorMcpServer, Limiter } from "../mcp/server.js";
import { resolveMode, type DeploymentMode, type ModePolicy } from "../mode.js";
import { jsonDepth } from "../schemas.js";
import type { AiPort } from "../safebox/SafeBoxService.js";

export interface AppConfig {
  mode: DeploymentMode;
  host: string;
  port: number;
  /** Externally visible origin, e.g. http://127.0.0.1:8791 */
  baseUrl: string;
  /** SQLite file for OAuth clients/codes/tokens (gateway-side; holds no SafeBox authority). */
  oauthDbPath: string;
  accounts: AccountDirectory;
  /** The ONLY SafeBox capability the gateway receives. */
  ai: AiPort;
  oauth?: { accessTokenTtlSec?: number; refreshTokenTtlSec?: number; codeTtlSec?: number; maxClients?: number };
  limits?: { mcpPerMinute?: number; preparePerMinute?: number; webPerMinute?: number };
  now?: () => number;
}

export const MAX_BODY_BYTES = 16 * 1024;
export const MAX_JSON_DEPTH = 10;

export interface App { server: Server; oauth: OAuthAuthority; policy: ModePolicy; listen(): Promise<string>; close(): Promise<void> }

const SCOPE_TEXT: Record<string, string> = {
  [SCOPES.STATUS]: "Read your SafeBox protection status and Purpose limits (redacted)",
  [SCOPES.CHECK]: "Check whether a payment would fit your SafeBox policy (estimate only)",
  [SCOPES.PREPARE]: "Prepare payment approval requests that YOU must approve on your enrolled SafeBox device",
  [SCOPES.PAYMENT_READ]: "Read the status of approval requests and payments it prepared for you",
};

export function createApp(cfg: AppConfig): App {
  const now = cfg.now ?? Date.now;
  const policy = resolveMode(cfg.mode, cfg.host, cfg.baseUrl);
  const base = new URL(cfg.baseUrl);
  const db = new DatabaseSync(cfg.oauthDbPath);
  db.exec("PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;");
  const oauth = new OAuthAuthority(db, cfg.accounts, { issuer: base.origin, resource: `${base.origin}/mcp`, offeredScopes: policy.offeredScopes, ...(cfg.oauth ?? {}) }, now);
  const allowedHosts = [...new Set([base.host, ...(policy.mode === "mock-loopback" ? [`127.0.0.1:${cfg.port}`, `localhost:${cfg.port}`] : [])])];
  const allowedOrigins = [...new Set([base.origin, ...(policy.mode === "mock-loopback" ? [`http://127.0.0.1:${cfg.port}`, `http://localhost:${cfg.port}`] : [])])];
  const mcpLimiter = new Limiter(cfg.limits?.mcpPerMinute ?? 120, 60_000, now);
  const prepareLimiter = new Limiter(cfg.limits?.preparePerMinute ?? 10, 60_000, now);
  const webLimiter = new Limiter(cfg.limits?.webPerMinute ?? 60, 60_000, now);

  const sameOrigin = (req: IncomingMessage) => {
    const o = req.headers.origin;
    if (typeof o === "string") return allowedOrigins.includes(o);
    const r = req.headers.referer;
    if (typeof r === "string") { try { return allowedOrigins.includes(new URL(r).origin); } catch { return false; } }
    return false; // no Origin and no Referer: refuse (CSRF defence for the consent form)
  };

  const server = createServer(async (req, res) => {
    try {
      securityHeaders(res);
      const url = new URL(req.url ?? "/", base.origin);
      const ip = req.socket.remoteAddress ?? "unknown";
      if (!allowedHosts.includes(req.headers.host ?? "")) return send(res, 421, { error: "Host not allowed" });
      if (url.pathname === "/healthz") return send(res, 200, { ok: true, mode: policy.mode, environment: "MOCK", preparationEnabled: policy.preparationEnabled, paymentExecutionViaGateway: false });

      if (url.pathname === "/mcp") {
        if (req.method !== "POST") { res.setHeader("Allow", "POST"); return send(res, 405, { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed (stateless server)" }, id: null }); }
        const origin = req.headers.origin;
        if (origin && !allowedOrigins.includes(origin)) return send(res, 403, { error: "Origin not allowed" });
        const principal = oauth.verifyAccessToken(req.headers.authorization);
        if (!principal) {
          res.setHeader("WWW-Authenticate", oauth.challenge(req.headers.authorization ? "invalid_token" : undefined));
          return send(res, 401, { error: "Missing or invalid bearer token" });
        }
        if (!mcpLimiter.take(`${principal.tokenFingerprint}|${ip}`)) return send(res, 429, { error: "Rate limit exceeded" });
        let body: unknown;
        try { body = JSON.parse(await readText(req)); } catch (e) { return send(res, (e as { status?: number }).status ?? 400, { jsonrpc: "2.0", error: { code: -32700, message: "Parse error or body too large" }, id: null }); }
        if (jsonDepth(body) > MAX_JSON_DEPTH) return send(res, 400, { jsonrpc: "2.0", error: { code: -32600, message: "Request nesting too deep" }, id: null });
        const mcp = createInteractorMcpServer(cfg.ai, principal, policy, prepareLimiter);
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true, enableDnsRebindingProtection: true, allowedHosts, allowedOrigins });
        res.on("close", () => { void transport.close(); void mcp.close(); });
        await mcp.connect(transport);
        await transport.handleRequest(req, res, body);
        return;
      }

      if (!webLimiter.take(ip)) return send(res, 429, { error: "Rate limit exceeded" });
      const p = url.pathname;
      if (req.method === "GET" && (p === "/.well-known/oauth-protected-resource" || p === "/.well-known/oauth-protected-resource/mcp")) return send(res, 200, oauth.protectedResourceMetadata(), true);
      if (req.method === "GET" && p === "/.well-known/oauth-authorization-server") return send(res, 200, oauth.authorizationServerMetadata(), true);
      if (p === "/oauth/register" && req.method === "POST") { let b: unknown; try { b = JSON.parse(await readText(req)); } catch { b = null; } const out = oauth.register(b); return send(res, out.status, out.body); }
      if (p === "/oauth/token" && req.method === "POST") { const out = oauth.token(new URLSearchParams(await readText(req)), header(req, "authorization")); return send(res, out.status, out.body); }
      if (p === "/oauth/revoke" && req.method === "POST") { const out = oauth.revoke(new URLSearchParams(await readText(req)), header(req, "authorization")); return send(res, out.status, out.body); }
      if (p === "/oauth/authorize" && req.method === "GET") {
        const r = oauth.beginAuthorization(url.searchParams);
        if (!r.ok) {
          if (r.redirect) { res.statusCode = 302; res.setHeader("Location", r.redirect); return res.end(); }
          return html(res, 400, page("Authorization request refused", `<p>${esc(r.error.error)}</p><p>${esc(r.error.description)}</p>`));
        }
        return html(res, 200, consentPage(r.pending, policy), formAction(r.pending.redirectUri));
      }
      if (p === "/oauth/authorize" && req.method === "POST") {
        if (!sameOrigin(req)) return send(res, 403, { error: "Origin not allowed" });
        const form = new URLSearchParams(await readText(req));
        const pend = oauth.getPending(form.get("request_id"));
        const out = oauth.completeAuthorization(form);
        if ("redirect" in out) { res.statusCode = 303; res.setHeader("Location", out.redirect); return res.end(); }
        if (pend && out.error.status === 401) return html(res, 401, consentPage(pend, policy, "Sign-in not recognized."), formAction(pend.redirectUri));
        return html(res, out.error.status, page("Authorization failed", `<p>${esc(out.error.error)}</p><p>${esc(out.error.description)}</p>`));
      }
      // There is no owner, approval, device, signing, settlement or vault route on this gateway in ANY mode.
      if (/^\/(owner|approve|approval|device|sign|settle|vault|root|ledger|admin)(\/|$)/.test(p)) return send(res, 403, { error: "Not available on the AI gateway: owner approval happens only on an enrolled SafeBox device" });
      return send(res, 404, { error: "Not found" });
    } catch {
      if (!res.headersSent) send(res, 500, { error: "Internal error" });
    }
  });

  return {
    server, oauth, policy,
    listen: () => new Promise((resolve) => server.listen(cfg.port, cfg.host, () => {
      const a = server.address(); resolve(typeof a === "object" && a ? `http://${cfg.host}:${a.port}` : cfg.baseUrl);
    })),
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => { try { db.close(); } catch { /* */ } resolve(); }); }),
  };
}

function header(req: IncomingMessage, name: string): string | undefined { const v = req.headers[name]; return Array.isArray(v) ? v[0] : v; }
function securityHeaders(res: ServerResponse) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
}
function send(res: ServerResponse, status: number, body: unknown, cors = false) {
  res.statusCode = status; res.setHeader("Content-Type", "application/json");
  if (cors) res.setHeader("Access-Control-Allow-Origin", "*");
  res.end(JSON.stringify(body));
}
function html(res: ServerResponse, status: number, body: string, extraFormAction?: string) {
  res.statusCode = status; res.setHeader("Content-Type", "text/html; charset=utf-8");
  if (extraFormAction) res.setHeader("Content-Security-Policy", `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${extraFormAction}; frame-ancestors 'none'; base-uri 'none'`);
  res.end(body);
}
function formAction(redirectUri: string): string { try { return new URL(redirectUri).origin; } catch { return ""; } }
async function readText(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []; let n = 0;
  for await (const c of req) { n += (c as Buffer).length; if (n > MAX_BODY_BYTES) throw Object.assign(new Error("body too large"), { status: 413 }); chunks.push(c as Buffer); }
  return Buffer.concat(chunks).toString("utf8");
}
export function esc(s: string): string { return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)); }
function page(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title></head><body style="font-family:system-ui;max-width:640px;margin:2rem auto">`
    + `<p style="background:#fde68a;padding:.5rem">MOCK environment: no real NEAR moves. This page grants an AI client limited access; it can never approve a payment.</p><h1>${esc(title)}</h1>${body}</body></html>`;
}
function consentPage(p: PendingAuthorization, policy: ModePolicy, error?: string): string {
  const scopes = p.scopes.map((s) => `<label><input type="checkbox" name="scope" value="${esc(s)}" checked> ${esc(SCOPE_TEXT[s] ?? s)}</label><br>`).join("");
  return page("Allow an AI client to use your SafeBox?", `${error ? `<p style="color:#b91c1c">${esc(error)}</p>` : ""}
    <p>Client (self-registered, name not verified): <b>${esc(p.clientName)}</b></p><p>Returns to: <code>${esc(p.redirectUri)}</code></p>
    <p>Mode: ${esc(policy.mode)}. Payments always need your approval on an enrolled SafeBox device; this permission cannot approve, sign or settle anything.</p>
    <form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="${esc(p.id)}"><input type="hidden" name="csrf" value="${esc(p.csrf)}">
    ${scopes}<p><label>Sign-in (development placeholder): <input type="password" name="login_secret" autocomplete="off"></label></p>
    <button name="decision" value="approve">Allow</button> <button name="decision" value="deny">Deny</button></form>`);
}
