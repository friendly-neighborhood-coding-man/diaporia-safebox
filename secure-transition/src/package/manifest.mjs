// Canonical SSTP package manifest. The archive's first entry must be SSTP-MANIFEST.json, byte-identical to its canonical
// JSON form, listing every other file exactly once with SHA-256, size and mode. Unknown fields are rejected, so a
// package cannot smuggle install hooks, policy changes or verifier code through its manifest.
import { canon, sha256 } from '../common/crypto.mjs';
import { readTar, PackageError } from './tar.mjs';

export const MANIFEST_NAME = 'SSTP-MANIFEST.json';
export const ENTRY = 'main.mjs';
const TOP_KEYS = ['authoritySchema', 'entry', 'files', 'format', 'name', 'version'];
const fail = (code, detail) => { throw new PackageError(code, detail); };

export function buildManifest({ name = 'safebox-app', version, authoritySchema = { min: 1, max: 1 }, files }) {
  return { format: 'sstp-package-v0', name, version, entry: ENTRY, authoritySchema,
    files: files.map(f => ({ path: f.path, sha256: sha256(f.data), size: f.data.length, mode: f.mode ?? 0o644 })).sort((a, b) => (a.path < b.path ? -1 : 1)) };
}

/** Parse + verify a package archive. Returns { manifest, files: [{path, mode, data}], dirs }. */
export function openPackage(buf) {
  const entries = readTar(buf);
  if (!entries.length || entries[0].path !== MANIFEST_NAME || entries[0].type !== 'file') fail('MANIFEST_NOT_FIRST');
  const raw = entries[0].data;
  let m;
  try { m = JSON.parse(raw.toString('utf8')); } catch { fail('MANIFEST_NOT_JSON'); }
  if (!m || typeof m !== 'object' || Array.isArray(m)) fail('MANIFEST_SHAPE');
  if (!Buffer.from(canon(m)).equals(raw)) fail('MANIFEST_NOT_CANONICAL');
  const keys = Object.keys(m).sort();
  if (keys.join() !== TOP_KEYS.join()) fail('MANIFEST_UNKNOWN_OR_MISSING_FIELD', keys.join());
  if (m.format !== 'sstp-package-v0') fail('MANIFEST_FORMAT');
  if (m.name !== 'safebox-app') fail('MANIFEST_NAME');
  if (!Number.isSafeInteger(m.version) || m.version < 1) fail('MANIFEST_VERSION');
  if (m.entry !== ENTRY) fail('MANIFEST_ENTRY');
  const s = m.authoritySchema;
  if (!s || Object.keys(s).sort().join() !== 'max,min' || !Number.isSafeInteger(s.min) || !Number.isSafeInteger(s.max) || s.min < 1 || s.max < s.min) fail('MANIFEST_SCHEMA_RANGE');
  if (!Array.isArray(m.files) || !m.files.length) fail('MANIFEST_FILES');
  const files = entries.slice(1).filter(e => e.type === 'file');
  const dirs = entries.slice(1).filter(e => e.type === 'dir');
  if (files.some(f => f.path === MANIFEST_NAME)) fail('MANIFEST_DUPLICATE');
  const byPath = new Map(files.map(f => [f.path, f]));
  if (byPath.size !== m.files.length) fail('MANIFEST_FILE_SET_MISMATCH', `${byPath.size} vs ${m.files.length}`);
  let prev = '';
  for (const mf of m.files) {
    if (!mf || Object.keys(mf).sort().join() !== 'mode,path,sha256,size') fail('MANIFEST_FILE_SHAPE');
    if (!(mf.path > prev)) fail('MANIFEST_NOT_SORTED'); prev = mf.path;
    const f = byPath.get(mf.path);
    if (!f) fail('MANIFEST_FILE_MISSING', mf.path);
    if (f.data.length !== mf.size || sha256(f.data) !== mf.sha256) fail('MANIFEST_DIGEST_MISMATCH', mf.path);
    if (f.mode !== mf.mode) fail('MANIFEST_MODE_MISMATCH', mf.path);
  }
  if (!byPath.has(ENTRY)) fail('MANIFEST_ENTRY_MISSING');
  return { manifest: m, files, dirs };
}
