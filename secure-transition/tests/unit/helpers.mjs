import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { writeTar } from '../../src/package/tar.mjs';
import { buildManifest, MANIFEST_NAME } from '../../src/package/manifest.mjs';
import { canon } from '../../src/common/crypto.mjs';

export const tmp = (t, p = 'sstp-') => { const d = mkdtempSync(join(tmpdir(), p)); t?.after?.(() => rmSync(d, { recursive: true, force: true })); return d; };

export const APP_FILES = (version, extra = []) => [
  { path: 'main.mjs', mode: 0o644, data: Buffer.from(`export const VERSION = ${version};\nconsole.log(JSON.stringify({ health: 'ok', version: VERSION }));\n`) },
  { path: 'lib/util.mjs', mode: 0o644, data: Buffer.from('export const x = 1;\n') },
  ...extra,
];

/** Build a well-formed package archive. opts.mutate(entries) may alter tar entries after the manifest is computed. */
export function makePackage({ version = 2, files = APP_FILES(version), authoritySchema = { min: 1, max: 1 }, mutate } = {}) {
  const m = buildManifest({ version, files, authoritySchema });
  let entries = [{ name: MANIFEST_NAME, data: canon(m), mode: 0o644 }, ...files.slice().sort((a, b) => (a.path < b.path ? -1 : 1)).map(f => ({ name: f.path, data: f.data, mode: f.mode }))];
  if (mutate) entries = mutate(entries) ?? entries;
  return { bytes: writeTar(entries), manifest: m };
}

/** Static file server over a directory (the untrusted update server). */
export async function serveDir(dir, t) {
  const srv = http.createServer(async (req, res) => {
    try { const b = await readFile(join(dir, decodeURIComponent(new URL(req.url, 'http://x').pathname))); res.writeHead(200); res.end(b); }
    catch { res.writeHead(404); res.end(); }
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  t?.after?.(() => srv.close());
  return `http://127.0.0.1:${srv.address().port}`;
}
