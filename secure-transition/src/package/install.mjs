// Install a verified package into an inactive slot. Destination must be one of the allow-listed slot directories, must be
// a real directory (not a symlink) and is emptied first. Files are created with O_EXCL|O_NOFOLLOW so nothing pre-planted
// in the slot can redirect a write, then read back and re-hashed against the manifest.
import { lstatSync, readdirSync, rmSync, mkdirSync, openSync, writeSync, fsyncSync, closeSync, chmodSync, readFileSync, realpathSync, statfsSync, constants as C } from 'node:fs';
import { join, dirname } from 'node:path';
import { sha256 } from '../common/crypto.mjs';
import { fsyncDir } from '../common/fsutil.mjs';
import { crashPoint, ioFault } from '../common/faults.mjs';
import { PackageError } from './tar.mjs';
const fail = (code, detail) => { throw new PackageError(code, detail); };

export function assertAllowedSlot(slotDir, allowList) {
  if (!allowList.includes(slotDir)) fail('SLOT_NOT_ALLOWLISTED', slotDir);
  const st = lstatSync(slotDir);
  if (st.isSymbolicLink() || !st.isDirectory()) fail('SLOT_NOT_A_DIRECTORY', slotDir);
  if (realpathSync(slotDir) !== slotDir) fail('SLOT_PATH_NOT_CANONICAL', slotDir);
}

export function wipeSlot(slotDir) {
  for (const n of readdirSync(slotDir)) rmSync(join(slotDir, n), { recursive: true, force: true });
  fsyncDir(slotDir);
}

export function installToSlot(slotDir, pkg, { allowList, minFreeFactor = 2 }) {
  assertAllowedSlot(slotDir, allowList);
  const total = pkg.files.reduce((a, f) => a + f.data.length, 0);
  const fs = statfsSync(slotDir);
  if (Number(fs.bavail) * Number(fs.bsize) < total * minFreeFactor + (1 << 20)) fail('INSUFFICIENT_STORAGE');
  wipeSlot(slotDir);
  crashPoint('install.after-wipe');
  const made = new Set();
  const mkParents = (rel) => {
    const segs = rel.split('/').slice(0, -1); let cur = slotDir;
    for (const s of segs) {
      cur = join(cur, s);
      if (made.has(cur)) continue;
      mkdirSync(cur, { mode: 0o755 });
      const st = lstatSync(cur); if (!st.isDirectory() || st.isSymbolicLink()) fail('SLOT_ESCAPE', cur);
      made.add(cur);
    }
  };
  let n = 0;
  for (const f of pkg.files) {
    const dest = join(slotDir, f.path);
    if (!dest.startsWith(slotDir + '/')) fail('SLOT_ESCAPE', f.path);
    mkParents(f.path);
    if (realpathSync(dirname(dest)) !== dirname(dest)) fail('SLOT_ESCAPE', f.path);
    const fd = openSync(dest, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    try { ioFault('install.write'); writeSync(fd, f.data); fsyncSync(fd); } finally { closeSync(fd); }
    chmodSync(dest, f.mode);
    if (++n === 1) crashPoint('install.mid-files');
  }
  for (const d of [...made].reverse()) fsyncDir(d);
  fsyncDir(slotDir);
  return verifySlot(slotDir, pkg.manifest);
}

/** Re-read a slot and compare it to the manifest: exact file set, digests, modes, no symlinks, nothing app-writable. */
export function verifySlot(slotDir, manifest, { expectUid } = {}) {
  const found = new Map();
  const walk = (dir, rel) => {
    for (const n of readdirSync(dir)) {
      const p = join(dir, n); const r = rel ? `${rel}/${n}` : n; const st = lstatSync(p);
      if (st.isSymbolicLink()) fail('SLOT_CONTAINS_SYMLINK', r);
      if (st.mode & 0o022) fail('SLOT_WRITABLE_BY_OTHERS', r);
      if (expectUid !== undefined && st.uid !== expectUid) fail('SLOT_WRONG_OWNER', r);
      if (st.isDirectory()) walk(p, r);
      else if (st.isFile()) found.set(r, { mode: st.mode & 0o7777, data: readFileSync(p) });
      else fail('SLOT_SPECIAL_FILE', r);
    }
  };
  walk(slotDir, '');
  if (found.size !== manifest.files.length) fail('SLOT_FILE_SET_MISMATCH', `${found.size} vs ${manifest.files.length}`);
  for (const mf of manifest.files) {
    const f = found.get(mf.path);
    if (!f) fail('SLOT_FILE_MISSING', mf.path);
    if (sha256(f.data) !== mf.sha256) fail('SLOT_DIGEST_MISMATCH', mf.path);
    if (f.mode !== mf.mode) fail('SLOT_MODE_MISMATCH', mf.path);
  }
  return { files: found.size };
}
