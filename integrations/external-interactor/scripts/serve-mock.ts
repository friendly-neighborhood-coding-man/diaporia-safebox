/**
 * Loopback-only manual trial server: MOCK SafeBox account + gateway on 127.0.0.1. Prints the development sign-in secret
 * for the consent page and offers a local owner-device console (stdin) to approve pending requests. Never binds a
 * non-loopback address (mock-loopback mode refuses it). No real NEAR.
 */
import { createInterface } from "node:readline";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { buildWorld, bindingFor, OwnerDeviceSim } from "../harness/mockWorld.js";
import { SafeBoxService } from "../src/safebox/SafeBoxService.js";
import { AccountDirectory } from "../src/auth/accounts.js";
import { createApp } from "../src/http/app.js";

const port = Number(process.env.PORT ?? 8791);
const dir = mkdtempSync(join(tmpdir(), "sbx-serve-")); mkdirSync(join(dir, "alice"));
const w = await buildWorld(join(dir, "alice"));
const service = await SafeBoxService.open(join(dir, "interactor.db"));
service.addAccount(bindingFor("sbx-alice", w));
const accounts = new AccountDirectory(); const login = "login-alice-" + randomBytes(16).toString("hex"); accounts.add(login, "alice", "sbx-alice");
const app = createApp({ mode: "mock-loopback", host: "127.0.0.1", port, baseUrl: `http://127.0.0.1:${port}`, oauthDbPath: join(dir, "oauth.db"), accounts, ai: service.aiPort() });
await app.listen();
const dev = new OwnerDeviceSim(w, service.ownerPort(), "sbx-alice");
console.log(`SafeBox interactor (MOCK) on http://127.0.0.1:${port}/mcp\nconsent sign-in (dev placeholder): ${login}\nowner device console: "approve <requestId>", "decline <requestId>", "settle", "quit"`);
const rl = createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  const [cmd, id] = line.trim().split(/\s+/);
  try {
    if (cmd === "approve" && id) console.log(JSON.stringify(await dev.approve(id, { decide: (t) => { console.log(t); return true; } })));
    else if (cmd === "decline" && id) console.log(JSON.stringify(await dev.approve(id, { decide: () => false })));
    else if (cmd === "settle") { await dev.settle(); console.log("MOCK clock advanced past the settlement buffer"); }
    else if (cmd === "quit") { await app.close(); service.close(); process.exit(0); }
  } catch (e) { console.log("error:", (e as Error).message); }
});
