// Update Fetcher. UNTRUSTED by design: it holds no keys, verifies nothing and cannot authorize anything. It mirrors the
// files a TUF client would request into a spool directory, which the controller later verifies offline.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const CAPS = { root: 512 << 10, timestamp: 64 << 10, snapshot: 512 << 10, targets: 2 << 20, target: 8 << 20 };

async function get(url, cap, timeoutMs) {
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ac.signal });
    if (r.status === 404 || r.status === 403) return { status: r.status };
    if (!r.ok) return { status: r.status };
    const chunks = []; let n = 0;
    for await (const c of r.body) { n += c.length; if (n > cap) return { status: 'TOO_LARGE' }; chunks.push(c); }
    return { status: 200, bytes: Buffer.concat(chunks) };
  } catch (e) { return { status: 'NETWORK_ERROR', error: String(e.cause?.code ?? e.name) }; } finally { clearTimeout(t); }
}

/** Mirror metadata + one target. Returns a report; never throws on server misbehaviour (that is the verifier's job). */
export async function mirror({ baseUrl, spoolDir, targetName, maxRoot = 32, timeoutMs = 5000 }) {
  mkdirSync(join(spoolDir, 'metadata'), { recursive: true }); mkdirSync(join(spoolDir, 'targets'), { recursive: true });
  const report = { files: [], errors: [] };
  const save = (rel, bytes) => { writeFileSync(join(spoolDir, rel), bytes); report.files.push(rel); };
  for (let v = 1; v <= maxRoot; v++) {
    const r = await get(`${baseUrl}/metadata/${v}.root.json`, CAPS.root, timeoutMs);
    if (r.status === 200) save(`metadata/${v}.root.json`, r.bytes); else { if (r.status !== 404) report.errors.push({ file: `${v}.root.json`, status: r.status }); break; }
  }
  for (const role of ['timestamp', 'snapshot', 'targets']) {
    const r = await get(`${baseUrl}/metadata/${role}.json`, CAPS[role], timeoutMs);
    if (r.status === 200) save(`metadata/${role}.json`, r.bytes); else report.errors.push({ file: `${role}.json`, status: r.status, error: r.error });
  }
  if (targetName) {
    const r = await get(`${baseUrl}/targets/${encodeURIComponent(targetName)}`, CAPS.target, timeoutMs);
    if (r.status === 200) save(`targets/${targetName}`, r.bytes); else report.errors.push({ file: targetName, status: r.status, error: r.error });
  }
  return report;
}

// CLI: node fetcher.mjs <baseUrl> <spoolDir> <targetName>
if (import.meta.url === `file://${process.argv[1]}`) {
  const [baseUrl, spoolDir, targetName] = process.argv.slice(2);
  mirror({ baseUrl, spoolDir, targetName }).then(r => { process.stdout.write(JSON.stringify(r) + '\n'); });
}
