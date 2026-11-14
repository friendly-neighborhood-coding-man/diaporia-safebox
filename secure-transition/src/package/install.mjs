// Install a verified package into an inactive slot. Destination must be one of the allow-listed slot directories, must be
// a real directory (not a symlink) and is emptied first. Files are created with O_EXCL|O_NOFOLLOW so nothing pre-planted
// in the slot can redirect a write, then read back and re-hashed against the manifest.
import { lstatSync, statSync, fstatSync, readdirSync, rmSync, mkdirSync, openSync, writeSync, fsyncSync, closeSync, chmodSync, readFileSync, realpathSync, statfsSync, constants as C } from 'node:fs';
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

/**
 * Read a file that walk() has just lstat-checked, WITHOUT a second lookup by path (CodeQL js/file-system-race,
 * submission-freeze triage). The file is opened once with O_NOFOLLOW (a symlink swapped in after the lstat fails with
 * ELOOP) and O_NONBLOCK (a FIFO swapped in cannot hang the verifier); the descriptor is then fstat-ed and must be the
 * SAME inode on the same device as the lstat result, still a regular file, with the same mode / owner checks. The
 * bytes are read from that descriptor, so the digest is computed over exactly the object whose metadata was checked.
 */
export function readCheckedFile(p, r, lst, { expectUid } = {}) {
  let fd;
  try { fd = openSync(p, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); }
  catch (e) { if (e.code === 'ELOOP') fail('SLOT_CONTAINS_SYMLINK', r); fail('SLOT_CHANGED_DURING_VERIFY', `${r}: ${e.code}`); }
  try {
    const st = fstatSync(fd);
    if (st.dev !== lst.dev || st.ino !== lst.ino) fail('SLOT_CHANGED_DURING_VERIFY', r);
    if (!st.isFile()) fail('SLOT_SPECIAL_FILE', r);
    if (st.mode & 0o022) fail('SLOT_WRITABLE_BY_OTHERS', r);
    if (expectUid !== undefined && st.uid !== expectUid) fail('SLOT_WRONG_OWNER', r);
    return { mode: st.mode & 0o7777, data: readFileSync(fd) };
  } finally { closeSync(fd); }
}

// ---- Descriptor-relative slot verification (post-video hardening, Mission 1; replaces the PR #27 path-recheck walk) ----
// Node has no openat()/fdopendir(). On Linux, /proc/self/fd/<N> is a kernel "magic link": resolving <N>/<name> jumps to
// the directory object that descriptor N holds and looks <name> up INSIDE it, without re-resolving the directory's
// path. So the walk below holds a descriptor for every directory it enters and reaches every child through its
// parent's descriptor. A directory renamed away or swapped in after it was opened cannot redirect the walk.
// After the walk, a final pass (all descriptors still held) re-checks every name in every directory: same name set,
// same dev/inode for each entry, unchanged ctime/size for files and unchanged mtime/ctime for directories (a rename in
// or out of a directory, including swap-and-swap-back, changes that directory's mtime/ctime), and the slot path still
// names the root directory that was walked. This refuses renames, swaps (including swap-and-swap-back), symlinks and
// new entries that happen during the walk. It gives NO content guarantee against anyone who can write a slot file:
// a write through a shared memory mapping changes the bytes without changing any metadata (independent review F1),
// and in-place writes are otherwise detected only through ctime, i.e. only on filesystems with fine-grained
// timestamps. Nor does it bind anything after verifySlot returns (verify-then-use). Both need the slot to be
// unwritable by the attacker, which only OS separation provides; assertProtectedPath() checks that precondition
// when expectUid is given. The /proc/self/fd traversal is defence in depth: the mutation run shows it is not what
// carries the measured protection (the identity re-checks over held descriptors are).
const FD_DIR = '/proc/self/fd';
const MAX_DIRS = 4096;
const at = (dfd, name) => `${FD_DIR}/${dfd}/${name}`;
const sameObj = (a, b) => a.dev === b.dev && a.ino === b.ino;

/** true when /proc/self/fd/<N> resolves to the object descriptor N holds (Linux procfs). Checked on every call. */
export function fdRelativeSupported() {
  if (process.platform !== 'linux') return false;
  let fd;
  try {
    fd = openSync('/', C.O_RDONLY | C.O_DIRECTORY);
    return sameObj(statSync(`${FD_DIR}/${fd}`, { bigint: true }), fstatSync(fd, { bigint: true }));
  } catch { return false; } finally { if (fd !== undefined) closeSync(fd); }
}

/**
 * OS precondition for any claim beyond the verifySlot call itself: the slot and every ancestor directory must be
 * unwritable by anyone except root and expectUid (an ancestor may be group/other-writable only with the sticky bit,
 * like /tmp, where others cannot rename entries they do not own). Path components are checked with lstat and must be
 * real directories. Without this, an attacker with write access anywhere on the path can rename the slot after it
 * was verified. This checks permissions only; it is not evidence that a separate uid actually runs the attacker.
 */
export function assertProtectedPath(slotDir, expectUid) {
  const okOwner = (st) => st.uid === 0 || st.uid === expectUid;
  let cur = slotDir;
  for (;;) {
    const st = lstatSync(cur);
    if (st.isSymbolicLink() || !st.isDirectory()) fail('SLOT_PATH_NOT_PROTECTED', `${cur}: not a directory`);
    if (!okOwner(st)) fail('SLOT_PATH_NOT_PROTECTED', `${cur}: owner ${st.uid}`);
    const sticky = (st.mode & 0o1000) !== 0;
    if ((st.mode & 0o022) && (cur === slotDir || !sticky)) fail('SLOT_PATH_NOT_PROTECTED', `${cur}: mode ${(st.mode & 0o7777).toString(8)}`);
    const up = dirname(cur); if (up === cur) break; cur = up;
  }
}

/** Re-read a slot and compare it to the manifest: exact file set, digests, modes, no symlinks, nothing app-writable. */
export function verifySlot(slotDir, manifest, { expectUid } = {}) {
  if (!fdRelativeSupported()) fail('VERIFIER_FD_RELATIVE_UNAVAILABLE', process.platform);
  const top = lstatSync(slotDir, { bigint: true });
  if (top.isSymbolicLink() || !top.isDirectory()) fail('SLOT_NOT_A_DIRECTORY', slotDir);
  if (realpathSync(slotDir) !== slotDir) fail('SLOT_PATH_NOT_CANONICAL', slotDir);
  if (expectUid !== undefined) assertProtectedPath(slotDir, expectUid);
  const meta = (st, r) => {
    if (Number(st.mode) & 0o022) fail('SLOT_WRITABLE_BY_OTHERS', r);
    if (expectUid !== undefined && Number(st.uid) !== expectUid) fail('SLOT_WRONG_OWNER', r);
  };
  const fds = [], dirs = [], entries = [], found = new Map();
  const listed = new Map(manifest.files.map(f => [f.path, f]));
  const openDir = (p, r, lst) => {
    let fd;
    try { fd = openSync(p, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW); }
    catch (e) { if (e.code === 'ELOOP' || e.code === 'ENOTDIR') fail('SLOT_CONTAINS_SYMLINK', r || '.'); fail('SLOT_CHANGED_DURING_VERIFY', `${r || '.'}: ${e.code}`); }
    fds.push(fd);
    const st = fstatSync(fd, { bigint: true });
    if (!sameObj(st, lst) || !st.isDirectory()) fail('SLOT_CHANGED_DURING_VERIFY', r || '.');
    return { fd, st };
  };
  const readAt = (p, r, lst) => {
    let fd;
    try { fd = openSync(p, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); }
    catch (e) { if (e.code === 'ELOOP') fail('SLOT_CONTAINS_SYMLINK', r); fail('SLOT_CHANGED_DURING_VERIFY', `${r}: ${e.code}`); }
    try {
      const st = fstatSync(fd, { bigint: true });
      if (!sameObj(st, lst)) fail('SLOT_CHANGED_DURING_VERIFY', r);
      if (!st.isFile()) fail('SLOT_SPECIAL_FILE', r);
      meta(st, r);
      const data = readFileSync(fd);
      const post = fstatSync(fd, { bigint: true });
      if (post.size !== st.size || post.ctimeNs !== st.ctimeNs || BigInt(data.length) !== st.size) fail('SLOT_CHANGED_DURING_VERIFY', r);
      return { mode: Number(st.mode) & 0o7777, data, st };
    } finally { closeSync(fd); }
  };
  const walk = (dfd, dst, rel) => {
    const names = readdirSync(`${FD_DIR}/${dfd}`).sort();
    dirs.push({ dfd, rel, names, st: dst });
    if (dirs.length > MAX_DIRS) fail('SLOT_TOO_MANY_DIRECTORIES', String(MAX_DIRS));
    for (const n of names) {
      const r = rel ? `${rel}/${n}` : n; const p = at(dfd, n);
      let st; try { st = lstatSync(p, { bigint: true }); } catch (e) { fail('SLOT_CHANGED_DURING_VERIFY', `${r}: ${e.code}`); }
      if (st.isSymbolicLink()) fail('SLOT_CONTAINS_SYMLINK', r);
      meta(st, r);
      if (st.isDirectory()) { const c = openDir(p, r, st); entries.push({ dfd, n, r, st: c.st, dir: true }); walk(c.fd, c.st, r); }
      else if (st.isFile()) {
        const mf = listed.get(r); if (!mf) fail('SLOT_FILE_SET_MISMATCH', `unlisted ${r}`);
        if (mf.size !== undefined && BigInt(mf.size) !== st.size) fail('SLOT_DIGEST_MISMATCH', r);
        const f = readAt(p, r, st); found.set(r, f); entries.push({ dfd, n, r, st: f.st, dir: false }); }
      else fail('SLOT_SPECIAL_FILE', r);
    }
  };
  try {
    const root = openDir(slotDir, '', top);
    walk(root.fd, root.st, '');
    // Final pass, every descriptor still held. Entries first; then every non-root directory, deepest first; then the
    // slot path (an ancestor rename changes no directory we hold, so this must come after everything but the root);
    // the root directory last. Renames into, out of or within a held directory change its mtime/ctime.
    for (const e of entries) {
      let now; try { now = lstatSync(at(e.dfd, e.n), { bigint: true }); } catch (x) { fail('SLOT_CHANGED_DURING_VERIFY', `${e.r}: ${x.code}`); }
      if (!sameObj(now, e.st) || now.isSymbolicLink() || now.ctimeNs !== e.st.ctimeNs || (!e.dir && now.size !== e.st.size)) fail('SLOT_CHANGED_DURING_VERIFY', e.r);
    }
    const dirCheck = (d) => {
      if (readdirSync(`${FD_DIR}/${d.dfd}`).sort().join('/') !== d.names.join('/')) fail('SLOT_CHANGED_DURING_VERIFY', d.rel || '.');
      const now = fstatSync(d.dfd, { bigint: true });
      if (now.mtimeNs !== d.st.mtimeNs || now.ctimeNs !== d.st.ctimeNs) fail('SLOT_CHANGED_DURING_VERIFY', d.rel || '.');
    };
    for (const d of [...dirs].reverse()) if (d.rel !== '') dirCheck(d);
    let rp; try { rp = realpathSync(slotDir); } catch (x) { fail('SLOT_CHANGED_DURING_VERIFY', `.: ${x.code}`); }
    if (rp !== slotDir) fail('SLOT_CONTAINS_SYMLINK', '.');
    const nowTop = lstatSync(slotDir, { bigint: true });
    if (!sameObj(nowTop, top) || nowTop.isSymbolicLink()) fail('SLOT_CHANGED_DURING_VERIFY', '.');
    dirCheck(dirs[0]);
  } finally { for (const fd of fds) closeSync(fd); }
  if (found.size !== manifest.files.length) fail('SLOT_FILE_SET_MISMATCH', `${found.size} vs ${manifest.files.length}`);
  for (const mf of manifest.files) {
    const f = found.get(mf.path);
    if (!f) fail('SLOT_FILE_MISSING', mf.path);
    if (sha256(f.data) !== mf.sha256) fail('SLOT_DIGEST_MISMATCH', mf.path);
    if (f.mode !== mf.mode) fail('SLOT_MODE_MISMATCH', mf.path);
  }
  return { files: found.size };
}
