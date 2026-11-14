import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { AccountDirectory } from "./accounts.js";
import { ALL_SCOPES, DEFAULT_SCOPES, type Principal } from "./scopes.js";

/**
 * OAuth 2.1 authorization server + resource-server token check for the SafeBox MCP endpoint.
 * Pattern adopted from DIAPORIA Agent Commerce PR #9 (src/auth/oauth.ts): RFC 9728 protected-resource metadata,
 * RFC 8414 AS metadata, RFC 7591 dynamic registration, authorization code + mandatory PKCE S256, exact redirect match
 * (loopback port may vary, RFC 8252 §7.3), RFC 8707 audience-bound tokens, refresh rotation with reuse detection,
 * RFC 7009 revocation, RFC 9207 `iss`.
 *
 * SafeBox-specific: a token is bound to ONE user AND that user's SafeBox account at consent time; a token is an AI-client
 * credential and can never approve, sign or settle a payment.
 */
export interface OAuthConfig {
  issuer: string;
  resource: string;
  accessTokenTtlSec?: number;
  refreshTokenTtlSec?: number;
  codeTtlSec?: number;
  maxClients?: number;
  offeredScopes: string[];
}

export class OAuthError extends Error {
  constructor(readonly error: string, readonly description: string, readonly status = 400) { super(description); }
  body() { return { error: this.error, error_description: this.description }; }
}

export interface PendingAuthorization {
  id: string; csrf: string; clientId: string; clientName: string; redirectUri: string; state: string | null;
  scopes: string[]; codeChallenge: string; resource: string; expiresAt: number;
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const token = (prefix: string) => `${prefix}_${randomBytes(32).toString("base64url")}`;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
type Row = Record<string, any>;

function eqHex(a: string, b: string): boolean {
  const x = Buffer.from(a, "hex"); const y = Buffer.from(b, "hex");
  return x.length === y.length && timingSafeEqual(x, y);
}

export function validateRedirectUri(raw: unknown): string {
  if (typeof raw !== "string" || raw.length > 500) throw new OAuthError("invalid_redirect_uri", "redirect_uri must be a string of at most 500 characters");
  let u: URL;
  try { u = new URL(raw); } catch { throw new OAuthError("invalid_redirect_uri", "redirect_uri is not an absolute URL"); }
  if (u.hash) throw new OAuthError("invalid_redirect_uri", "redirect_uri must not contain a fragment");
  if (u.username || u.password) throw new OAuthError("invalid_redirect_uri", "redirect_uri must not contain credentials");
  if (u.protocol === "https:") return u.toString();
  if (u.protocol === "http:" && LOOPBACK_HOSTS.has(u.hostname)) return u.toString();
  throw new OAuthError("invalid_redirect_uri", "redirect_uri must be https, or http on a loopback address");
}

export function redirectMatches(registered: string, presented: string): boolean {
  if (registered === presented) return true;
  try {
    const r = new URL(registered); const p = new URL(presented);
    return r.protocol === "http:" && p.protocol === "http:" && LOOPBACK_HOSTS.has(r.hostname) && r.hostname === p.hostname &&
      r.pathname === p.pathname && r.search === p.search && !p.hash && !p.username && !p.password;
  } catch { return false; }
}

function parseScopes(raw: string | null | undefined, offered: readonly string[]): string[] {
  if (raw === null || raw === undefined || raw.trim() === "") return DEFAULT_SCOPES.filter((s) => offered.includes(s));
  const asked = [...new Set(raw.trim().split(/\s+/))];
  const unknown = asked.filter((s) => !offered.includes(s));
  if (unknown.length) throw new OAuthError("invalid_scope", `Unsupported scope(s): ${unknown.join(" ").slice(0, 200)}`);
  return asked;
}

export class OAuthAuthority {
  readonly accessTtl: number; readonly refreshTtl: number; readonly codeTtl: number; readonly maxClients: number; readonly offered: string[];
  private readonly pending = new Map<string, PendingAuthorization>();

  constructor(private readonly db: DatabaseSync, private readonly accounts: AccountDirectory, readonly cfg: OAuthConfig, private readonly now: () => number = Date.now) {
    this.accessTtl = cfg.accessTokenTtlSec ?? 900;
    this.refreshTtl = cfg.refreshTokenTtlSec ?? 7 * 86400;
    this.codeTtl = cfg.codeTtlSec ?? 60;
    this.maxClients = cfg.maxClients ?? 200;
    this.offered = cfg.offeredScopes.filter((x) => (ALL_SCOPES as string[]).includes(x));
    db.exec(`
      CREATE TABLE IF NOT EXISTS oauth_clients (client_id TEXT PRIMARY KEY, client_name TEXT NOT NULL, redirect_uris_json TEXT NOT NULL,
        auth_method TEXT NOT NULL, secret_hash TEXT, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS oauth_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL, account_ref TEXT NOT NULL, redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL, resource TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, family_id TEXT);
      CREATE TABLE IF NOT EXISTS oauth_tokens (token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('access','refresh')), family_id TEXT NOT NULL,
        client_id TEXT NOT NULL, user_id TEXT NOT NULL, account_ref TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL,
        expires_at INTEGER NOT NULL, revoked_at INTEGER, used_at INTEGER, created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS oauth_tokens_by_family ON oauth_tokens(family_id);`);
  }

  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try { const r = fn(); this.db.exec("COMMIT"); return r; } catch (e) { try { this.db.exec("ROLLBACK"); } catch { /* */ } throw e; }
  }

  protectedResourceMetadata() {
    return { resource: this.cfg.resource, authorization_servers: [this.cfg.issuer], scopes_supported: this.offered, bearer_methods_supported: ["header"], resource_name: "SafeBox External AI Interactor (MOCK)" };
  }
  get resourceMetadataUrl(): string { return `${this.cfg.issuer}/.well-known/oauth-protected-resource`; }
  authorizationServerMetadata() {
    const i = this.cfg.issuer;
    return { issuer: i, authorization_endpoint: `${i}/oauth/authorize`, token_endpoint: `${i}/oauth/token`, registration_endpoint: `${i}/oauth/register`, revocation_endpoint: `${i}/oauth/revoke`,
      response_types_supported: ["code"], response_modes_supported: ["query"], grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
      revocation_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"], scopes_supported: this.offered, authorization_response_iss_parameter_supported: true };
  }
  challenge(error?: "invalid_token" | "insufficient_scope", scope: string = this.offered.join(" ")): string {
    return `Bearer resource_metadata="${this.resourceMetadataUrl}"${error ? `, error="${error}"` : ""}${scope ? `, scope="${scope}"` : ""}`;
  }

  register(body: unknown): { status: number; body: Record<string, unknown> } {
    try {
      if (!body || typeof body !== "object" || Array.isArray(body)) throw new OAuthError("invalid_client_metadata", "Body must be a JSON object");
      const b = body as Record<string, unknown>;
      if (!Array.isArray(b.redirect_uris) || b.redirect_uris.length < 1 || b.redirect_uris.length > 5) throw new OAuthError("invalid_redirect_uri", "redirect_uris must list 1 to 5 URIs");
      const uris = b.redirect_uris.map(validateRedirectUri);
      const method = b.token_endpoint_auth_method === undefined ? "none" : String(b.token_endpoint_auth_method);
      if (!["none", "client_secret_post", "client_secret_basic"].includes(method)) throw new OAuthError("invalid_client_metadata", "Unsupported token_endpoint_auth_method");
      const grants = Array.isArray(b.grant_types) ? b.grant_types.map(String) : ["authorization_code", "refresh_token"];
      if (grants.some((g) => !["authorization_code", "refresh_token"].includes(g))) throw new OAuthError("invalid_client_metadata", "Only authorization_code and refresh_token grants are supported");
      const responseTypes = Array.isArray(b.response_types) ? b.response_types.map(String) : ["code"];
      if (responseTypes.some((r) => r !== "code")) throw new OAuthError("invalid_client_metadata", "Only response_type code is supported");
      if (b.scope !== undefined) parseScopes(String(b.scope), this.offered);
      const name = typeof b.client_name === "string" && b.client_name.trim() ? b.client_name.trim().replace(/[^\x20-\x7e]/g, "?").slice(0, 80) : "Unnamed MCP client";
      const count = Number((this.db.prepare("SELECT COUNT(*) AS n FROM oauth_clients").get() as Row).n);
      if (count >= this.maxClients) throw new OAuthError("temporarily_unavailable", "Client registration limit reached", 503);
      const clientId = `scl_${randomBytes(16).toString("hex")}`;
      const secret = method === "none" ? null : token("scs");
      this.db.prepare("INSERT INTO oauth_clients(client_id,client_name,redirect_uris_json,auth_method,secret_hash,created_at) VALUES (?,?,?,?,?,?)")
        .run(clientId, name, JSON.stringify(uris), method, secret ? sha(secret) : null, this.now());
      return { status: 201, body: { client_id: clientId, client_id_issued_at: Math.floor(this.now() / 1000), ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
        client_name: name, redirect_uris: uris, token_endpoint_auth_method: method, grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] } };
    } catch (e) { return this.errorResponse(e); }
  }

  private client(clientId: string | null | undefined) {
    if (!clientId || !/^scl_[0-9a-f]{32}$/.test(clientId)) return null;
    const r = this.db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(clientId) as Row | undefined;
    return r ? { clientId, name: String(r.client_name), redirectUris: JSON.parse(String(r.redirect_uris_json)) as string[], authMethod: String(r.auth_method), secretHash: r.secret_hash === null ? null : String(r.secret_hash) } : null;
  }

  beginAuthorization(q: URLSearchParams): { ok: true; pending: PendingAuthorization } | { ok: false; error: OAuthError; redirect: string | null } {
    const client = this.client(q.get("client_id"));
    if (!client) return { ok: false, error: new OAuthError("invalid_client", "Unknown client_id"), redirect: null };
    const ru = q.get("redirect_uri");
    const redirectUri = ru ?? (client.redirectUris.length === 1 ? client.redirectUris[0]! : null);
    if (!redirectUri || !client.redirectUris.some((r) => redirectMatches(r, redirectUri))) return { ok: false, error: new OAuthError("invalid_request", "redirect_uri is not registered for this client"), redirect: null };
    const state = q.get("state");
    const fail = (e: OAuthError) => ({ ok: false as const, error: e, redirect: this.errorRedirect(redirectUri, e, state) });
    if (q.get("response_type") !== "code") return fail(new OAuthError("unsupported_response_type", "response_type must be code"));
    const challenge = q.get("code_challenge") ?? "";
    if (q.get("code_challenge_method") !== "S256" || !S256_CHALLENGE.test(challenge)) return fail(new OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required"));
    const resource = q.get("resource") ?? this.cfg.resource;
    if (resource !== this.cfg.resource) return fail(new OAuthError("invalid_target", "resource must be this server's MCP endpoint"));
    let scopes: string[];
    try { scopes = parseScopes(q.get("scope"), this.offered); } catch (e) { return fail(e as OAuthError); }
    this.gc();
    const pending: PendingAuthorization = { id: randomBytes(18).toString("base64url"), csrf: randomBytes(18).toString("base64url"), clientId: client.clientId, clientName: client.name,
      redirectUri, state, scopes, codeChallenge: challenge, resource, expiresAt: this.now() + 10 * 60_000 };
    this.pending.set(pending.id, pending);
    return { ok: true, pending };
  }
  getPending(id: string | null | undefined): PendingAuthorization | null {
    const p = id ? this.pending.get(id) : undefined;
    return p && p.expiresAt > this.now() ? p : null;
  }
  completeAuthorization(form: URLSearchParams): { redirect: string } | { error: OAuthError } {
    const p = this.getPending(form.get("request_id"));
    const csrf = form.get("csrf") ?? "";
    if (!p || csrf.length !== p.csrf.length || !timingSafeEqual(Buffer.from(csrf), Buffer.from(p.csrf))) return { error: new OAuthError("invalid_request", "Authorization request expired or invalid; start again from your AI client", 400) };
    if (form.get("decision") !== "approve") {
      this.pending.delete(p.id);
      return { redirect: this.errorRedirect(p.redirectUri, new OAuthError("access_denied", "The user denied the request"), p.state) };
    }
    const who = this.accounts.verify(form.get("login_secret"));
    if (!who) return { error: new OAuthError("access_denied", "Sign-in not recognized", 401) };
    const granted = p.scopes.filter((s) => form.getAll("scope").includes(s));
    if (!granted.length) return { error: new OAuthError("invalid_scope", "Select at least one permission, or deny the request", 400) };
    this.pending.delete(p.id);
    const code = token("sac");
    this.db.prepare("INSERT INTO oauth_codes(code_hash,client_id,user_id,account_ref,redirect_uri,scope,resource,challenge,expires_at) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(sha(code), p.clientId, who.userId, who.accountRef, p.redirectUri, granted.join(" "), p.resource, p.codeChallenge, this.now() + this.codeTtl * 1000);
    const u = new URL(p.redirectUri);
    u.searchParams.set("code", code);
    if (p.state !== null) u.searchParams.set("state", p.state);
    u.searchParams.set("iss", this.cfg.issuer);
    return { redirect: u.toString() };
  }
  private errorRedirect(redirectUri: string, e: OAuthError, state: string | null): string {
    const u = new URL(redirectUri);
    u.searchParams.set("error", e.error); u.searchParams.set("error_description", e.description);
    if (state !== null) u.searchParams.set("state", state);
    u.searchParams.set("iss", this.cfg.issuer);
    return u.toString();
  }

  token(form: URLSearchParams, authorization?: string): { status: number; body: Record<string, unknown> } {
    try {
      const client = this.authenticateClient(form, authorization);
      const grant = form.get("grant_type");
      if (grant === "authorization_code") return { status: 200, body: this.exchangeCode(client, form) };
      if (grant === "refresh_token") return { status: 200, body: this.refresh(client, form) };
      throw new OAuthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
    } catch (e) { return this.errorResponse(e); }
  }
  private authenticateClient(form: URLSearchParams, authorization?: string) {
    let id = form.get("client_id"); let secret = form.get("client_secret");
    const basic = /^Basic ([A-Za-z0-9+/=]+)$/.exec(authorization ?? "");
    if (basic) {
      const [bi, ...rest] = Buffer.from(basic[1]!, "base64").toString("utf8").split(":");
      try { id = decodeURIComponent(bi ?? ""); secret = decodeURIComponent(rest.join(":")); } catch { throw new OAuthError("invalid_client", "Malformed client credentials", 401); }
    }
    const client = this.client(id);
    if (!client) throw new OAuthError("invalid_client", "Unknown client", 401);
    if (client.authMethod !== "none" && (!secret || !client.secretHash || !eqHex(sha(secret), client.secretHash))) throw new OAuthError("invalid_client", "Client authentication failed", 401);
    return client;
  }
  private exchangeCode(client: { clientId: string }, form: URLSearchParams) {
    const code = form.get("code") ?? ""; const verifier = form.get("code_verifier") ?? "";
    const r = this.db.prepare("SELECT * FROM oauth_codes WHERE code_hash = ?").get(sha(code)) as Row | undefined;
    if (!r || r.client_id !== client.clientId) throw new OAuthError("invalid_grant", "Invalid authorization code");
    if (r.used_at !== null) { if (r.family_id) this.revokeFamily(String(r.family_id)); throw new OAuthError("invalid_grant", "Authorization code already used"); }
    if (Number(r.expires_at) <= this.now()) throw new OAuthError("invalid_grant", "Authorization code expired");
    const ru = form.get("redirect_uri");
    if (ru !== null && ru !== r.redirect_uri) throw new OAuthError("invalid_grant", "redirect_uri does not match the authorization request");
    const resource = form.get("resource");
    if (resource !== null && resource !== r.resource) throw new OAuthError("invalid_target", "resource does not match the authorization request");
    if (!VERIFIER.test(verifier) || createHash("sha256").update(verifier).digest("base64url") !== r.challenge) throw new OAuthError("invalid_grant", "PKCE verification failed");
    const family = `fam_${randomBytes(12).toString("hex")}`;
    return this.tx(() => {
      const upd = this.db.prepare("UPDATE oauth_codes SET used_at = ?, family_id = ? WHERE code_hash = ? AND used_at IS NULL").run(this.now(), family, sha(code));
      if (upd.changes !== 1) throw new OAuthError("invalid_grant", "Authorization code already used");
      return this.issue(family, client.clientId, String(r.user_id), String(r.account_ref), String(r.scope), String(r.resource));
    });
  }
  private refresh(client: { clientId: string }, form: URLSearchParams) {
    const rt = form.get("refresh_token") ?? "";
    const r = this.db.prepare("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'").get(sha(rt)) as Row | undefined;
    if (!r || r.client_id !== client.clientId) throw new OAuthError("invalid_grant", "Invalid refresh token");
    if (r.revoked_at !== null) throw new OAuthError("invalid_grant", "Refresh token revoked");
    if (r.used_at !== null) { this.revokeFamily(String(r.family_id)); throw new OAuthError("invalid_grant", "Refresh token reuse detected; grant revoked"); }
    if (Number(r.expires_at) <= this.now()) throw new OAuthError("invalid_grant", "Refresh token expired");
    const resource = form.get("resource");
    if (resource !== null && resource !== r.resource) throw new OAuthError("invalid_target", "resource does not match the grant");
    const had = String(r.scope).split(" ");
    const asked = form.get("scope");
    const scope = asked === null ? had : parseScopes(asked, this.offered);
    if (scope.some((s) => !had.includes(s))) throw new OAuthError("invalid_scope", "A refresh cannot widen the granted scope");
    return this.tx(() => {
      const upd = this.db.prepare("UPDATE oauth_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL").run(this.now(), sha(rt));
      if (upd.changes !== 1) throw new OAuthError("invalid_grant", "Refresh token already used");
      return this.issue(String(r.family_id), client.clientId, String(r.user_id), String(r.account_ref), scope.join(" "), String(r.resource));
    });
  }
  private issue(family: string, clientId: string, userId: string, accountRef: string, scope: string, resource: string) {
    const access = token("sat"); const refresh = token("srt"); const t = this.now();
    const ins = this.db.prepare("INSERT INTO oauth_tokens(token_hash,kind,family_id,client_id,user_id,account_ref,scope,resource,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)");
    ins.run(sha(access), "access", family, clientId, userId, accountRef, scope, resource, t + this.accessTtl * 1000, t);
    ins.run(sha(refresh), "refresh", family, clientId, userId, accountRef, scope, resource, t + this.refreshTtl * 1000, t);
    return { access_token: access, token_type: "Bearer", expires_in: this.accessTtl, refresh_token: refresh, scope };
  }
  revokeFamily(family: string): void { this.db.prepare("UPDATE oauth_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL").run(this.now(), family); }
  revoke(form: URLSearchParams, authorization?: string): { status: number; body: Record<string, unknown> } {
    try {
      const client = this.authenticateClient(form, authorization);
      const r = this.db.prepare("SELECT family_id, client_id FROM oauth_tokens WHERE token_hash = ?").get(sha(form.get("token") ?? "")) as Row | undefined;
      if (r && r.client_id === client.clientId) this.revokeFamily(String(r.family_id));
      return { status: 200, body: {} };
    } catch (e) { return this.errorResponse(e); }
  }

  /** `Authorization: Bearer <access token>` for THIS resource only. */
  verifyAccessToken(header: string | undefined): Principal | null {
    const m = /^Bearer (sat_[A-Za-z0-9_-]{43})$/.exec(header ?? "");
    if (!m) return null;
    const h = sha(m[1]!);
    const r = this.db.prepare("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'access'").get(h) as Row | undefined;
    if (!r || r.revoked_at !== null || Number(r.expires_at) <= this.now() || r.resource !== this.cfg.resource) return null;
    return { userId: String(r.user_id), accountRef: String(r.account_ref), clientId: String(r.client_id), scopes: new Set(String(r.scope).split(" ").filter((s) => this.offered.includes(s))), kind: "OAUTH_ACCESS_TOKEN", tokenFingerprint: h.slice(0, 12) };
  }
  private gc() {
    const t = this.now();
    for (const [k, v] of this.pending) if (v.expiresAt <= t) this.pending.delete(k);
    if (this.pending.size > 2000) this.pending.clear();
  }
  private errorResponse(e: unknown): { status: number; body: Record<string, unknown> } {
    if (e instanceof OAuthError) return { status: e.status, body: e.body() };
    return { status: 500, body: { error: "server_error", error_description: "Internal error" } };
  }
}
