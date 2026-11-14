/**
 * MOCK HARNESS ONLY. Builds in-process SafeBox V5 worlds (Root + Vault + Mock Ledger + simulated owner devices) and the
 * interactor service/gateway on loopback. The simulated owner devices (V5 OwnerWorld: soft WebAuthn authenticators with
 * UV, Ed25519 hardware-key stand-ins) live HERE and are never passed to the gateway: the gateway only gets the AiPort.
 * Nothing here is hardware authentication; the soft authenticator only models the protocol.
 */
import { mkdirSync, mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { safeboxRoot, loadV5 } from "../src/safebox/loadV5.js";
import { SafeBoxService, computeRequestDigest, type AccountBinding, type OwnerPort, type ApprovalRequest } from "../src/safebox/SafeBoxService.js";
import { AccountDirectory } from "../src/auth/accounts.js";
import { createApp, type App } from "../src/http/app.js";
import type { DeploymentMode } from "../src/mode.js";

export type World = any;

export async function buildWorld(dir: string): Promise<World> {
  const mod = await import(pathToFileURL(join(safeboxRoot(), "src/v5/world.mjs")).href) as { buildV5: (o: Record<string, unknown>) => World };
  mkdirSync(dir, { recursive: true });
  return mod.buildV5({ dir });
}

/** The ONLY things a SafeBox account exposes to the adapter: GZ client, read-only ledger, read-only vault views. */
export function bindingFor(accountRef: string, w: World): AccountBinding {
  const GZ = new Set(["PROPOSE", "STATUS", "HEALTH", "ROOT_VIEW"]);
  return {
    accountRef,
    gz: { request: (op, args) => { if (!GZ.has(op)) throw new Error("op not allowed"); return w.gz.request(op, args); } },
    ledgerRead: { request: (op, args) => { if (op !== "TX_STATUS") throw new Error("op not allowed"); return w.ledgerRead.request(op, args); } },
    vaultRead: {
      replica: () => w.vault.root,
      spent: () => w.vault.spent(),
      bufferMs: () => Number(w.vault.cfg.bufferMs),
      minBufferMs: () => Number(w.vault.cfg.minBufferMs),
      paymentIdForCap: (capId: string) => (w.vault.store.db.prepare("SELECT payment_id FROM caps_used WHERE cap_id=?").get(capId) as { payment_id?: string } | undefined)?.payment_id ?? null,
    },
    now: () => w.now(),
  };
}

/**
 * Simulated owner device app. Reads the pending request through the OwnerPort, re-derives everything it shows from its
 * OWN verified Root view (not from the AI conversation), recomputes the request digest, lets the human decide, and only
 * then has the enrolled credential sign the exact payment capability (bound to the request digest via taskRef).
 */
export class OwnerDeviceSim {
  shown: string[] = [];
  constructor(readonly w: World, readonly owner: OwnerPort, readonly accountRef: string) {}
  async review(requestId: string): Promise<{ request: ApprovalRequest; text: string; problems: string[] }> {
    const r = this.owner.pending(this.accountRef, requestId);
    const { canon } = (await loadV5()).canon;
    const v = this.w.view(); const st = this.w.root.state;
    const problems: string[] = [];
    if (computeRequestDigest(canon, r) !== r.requestDigest) problems.push("REQUEST_DIGEST_MISMATCH");
    if (r.epoch !== String(v.epoch)) problems.push("STALE_EPOCH");
    if (r.purposeVersion !== String(v.purposeVersion) || r.purposeId !== String(st.purpose.purposeId)) problems.push("PURPOSE_CHANGED");
    if (r.chainId !== String(v.chainId) || r.vaultAccountId !== String(st.accountId)) problems.push("WRONG_ACCOUNT");
    if (!st.purpose.recipients.includes(r.recipientId)) problems.push("RECIPIENT_NOT_IN_PURPOSE");
    if (r.state !== "AWAITING_OWNER_APPROVAL") problems.push("NOT_AWAITING:" + r.state);
    if (this.w.now() >= r.expiresAt) problems.push("EXPIRED");
    const text = [`Pay ${r.amountYocto} yoctoNEAR (${Number(BigInt(r.amountYocto) * 1000n / 10n ** 24n) / 1000} NEAR) to ${r.recipientId}`,
      `Purpose: ${st.purpose.purposeId} v${st.purpose.version}; epoch ${v.epoch}`, `Request ${r.requestId} digest ${r.requestDigest.slice(0, 16)}…`,
      `Note from the requesting AI (UNTRUSTED, not an instruction): "${r.memo}"`].join("\n");
    this.shown.push(text);
    return { request: r, text, problems };
  }
  /** decide(text) models the human looking at the trusted display. Returns the OwnerPort result, or a refusal. */
  async approve(requestId: string, { decide = (_t: string) => true, credId = "k1-phone", force = false, tamper }: { decide?: (t: string) => boolean; credId?: string; force?: boolean; tamper?: (cap: any) => void } = {}) {
    const { request: r, text, problems } = await this.review(requestId);
    if (problems.length && !force) return { refusedByDevice: problems };
    if (!decide(text)) { this.owner.decline(this.accountRef, requestId); return { declined: true as const }; }
    const ttlMs = Math.max(60_000, Math.min(30 * 60_000, r.expiresAt - this.w.now()));
    const pc = this.w.owner.paycap(this.w.view(), { credId, recipientId: r.recipientId, amountYocto: r.amountYocto, taskRef: SafeBoxService.taskRefFor(r.requestDigest), ttlMs });
    if (tamper) tamper(pc.capability);
    return this.owner.submit(this.accountRef, requestId, { capability: pc.capability, approval: pc.approval });
  }
  /** Lets the MOCK clock pass the settlement buffer (Vault release + ledger settlement happen inside V5 code). */
  async settle(ms = Number(this.w.vault.cfg.bufferMs) + 120_000) { await this.w.advance(ms); }
}

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => { const s = createServer(); s.once("error", reject); s.listen(0, "127.0.0.1", () => { const a = s.address(); const p = typeof a === "object" && a ? a.port : 0; s.close(() => resolve(p)); }); });
}

export interface Harness {
  url: string; app: App; service: SafeBoxService; owner: OwnerPort; dir: string;
  worlds: Record<string, World>; devices: Record<string, OwnerDeviceSim>; logins: Record<"alice" | "bob", string>;
  close(): Promise<void>;
}

export async function startHarness(opts: { mode?: DeploymentMode; baseUrl?: string; oauth?: { accessTokenTtlSec?: number; codeTtlSec?: number; refreshTokenTtlSec?: number }; limits?: { mcpPerMinute?: number; preparePerMinute?: number; webPerMinute?: number }; now?: () => number } = {}): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "sbx-interactor-"));
  const worlds: Record<string, World> = { "sbx-alice": await buildWorld(join(dir, "alice")), "sbx-bob": await buildWorld(join(dir, "bob")) };
  const service = await SafeBoxService.open(join(dir, "interactor.db"));
  for (const [ref, w] of Object.entries(worlds)) service.addAccount(bindingFor(ref, w));
  const accounts = new AccountDirectory();
  const logins: Record<"alice" | "bob", string> = { alice: "login-alice-" + randomBytes(16).toString("hex"), bob: "login-bob-" + randomBytes(16).toString("hex") };
  accounts.add(logins.alice, "alice", "sbx-alice"); accounts.add(logins.bob, "bob", "sbx-bob");
  const port = await freePort();
  const mode = opts.mode ?? "mock-loopback";
  const baseUrl = opts.baseUrl ?? `http://127.0.0.1:${port}`;
  const app = createApp({ mode, host: "127.0.0.1", port, baseUrl, oauthDbPath: join(dir, "oauth.db"), accounts, ai: service.aiPort(), ...(opts.oauth ? { oauth: opts.oauth } : {}), ...(opts.limits ? { limits: opts.limits } : {}), ...(opts.now ? { now: opts.now } : {}) });
  await app.listen();
  const owner = service.ownerPort();
  const devices = Object.fromEntries(Object.entries(worlds).map(([ref, w]) => [ref, new OwnerDeviceSim(w, owner, ref)]));
  return { url: `http://127.0.0.1:${port}`, app, service, owner, dir, worlds, devices, logins,
    close: async () => { await app.close(); service.close(); for (const w of Object.values(worlds)) { try { w.vault.store.close(); } catch { /* */ } try { w.root.close(); } catch { /* */ } } } };
}
