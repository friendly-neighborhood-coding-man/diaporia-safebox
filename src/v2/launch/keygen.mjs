// Runs as the owning principal: generates SYNTHETIC keys inside its own 0700 directory and
// publishes only public keys. Usage: node keygen.mjs <base> sens|sup <t0>
//
// Private keys are created by writing a complete temp file and linking it into place, so a
// concurrent caller either creates the file or reads the complete file that won. Paths are
// opened with O_NOFOLLOW. Public files are replaced by rename, which replaces a symlink
// instead of writing through it.
import { openSync, closeSync, readSync, writeSync, fsyncSync, fstatSync, linkSync, unlinkSync, renameSync, constants as C } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { layout } from './layout.mjs';
import { generatePrivateKey, exportPkcs8, importPkcs8, keyIdOf } from '../common/crypto.mjs';

const OPEN_NEW = C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW;

function fail(code, detail) {
  const e = new Error(detail ? `${code}: ${detail}` : code);
  e.code = code;
  throw e;
}

function writeNew(path, data, mode) {
  const fd = openSync(path, OPEN_NEW, mode);
  try {
    const buf = Buffer.from(data);
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off, null);
    fsyncSync(fd);
    const st = fstatSync(fd);
    if (!st.isFile()) fail('KEY_PATH_NOT_A_FILE', path);
    if (mode === 0o600 && (st.mode & 0o077) !== 0) fail('KEY_FILE_TOO_PERMISSIVE', path);
  } finally { closeSync(fd); }
}

function readPrivate(path) {
  let fd;
  try { fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW); }
  catch (e) {
    if (e.code === 'ENOENT') return null;
    if (e.code === 'ELOOP') fail('KEY_PATH_SYMLINK', path);
    throw e;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) fail('KEY_PATH_NOT_A_FILE', path);
    if ((st.mode & 0o077) !== 0) fail('KEY_FILE_TOO_PERMISSIVE', path);
    if (st.size > (1 << 20)) fail('KEY_FILE_TOO_LARGE', path);
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, null);
      if (n === 0) break;
      off += n;
    }
    if (off !== buf.length) fail('KEY_READ_SHORT', path);
    return buf.toString('utf8');
  } finally { closeSync(fd); }
}

function createExclusive(path, data, mode) {
  const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
  try {
    writeNew(tmp, data, mode);
    try { linkSync(tmp, path); }
    catch (e) {
      if (e.code === 'EEXIST') fail('KEY_FILE_EXISTS', path);
      throw e;
    }
  } finally {
    try { unlinkSync(tmp); } catch { /* the exclusive name remains */ }
  }
}

/** Replace `path` with a regular file. A symlink at `path` is removed, not followed. */
function publishPublic(path, text) {
  const tmp = join(dirname(path), `.pub-${randomBytes(6).toString('hex')}`);
  writeNew(tmp, text, 0o644);
  try { unlinkSync(path); }
  catch (e) {
    if (e.code !== 'ENOENT') { try { unlinkSync(tmp); } catch { /* keep the original error */ } throw e; }
  }
  try { renameSync(tmp, path); }
  catch (e) { try { unlinkSync(tmp); } catch { /* keep the original error */ } throw e; }
}

function ensureAppendFile(path) {
  try {
    const fd = openSync(path, C.O_WRONLY | C.O_APPEND | C.O_CREAT | C.O_NOFOLLOW, 0o600);
    closeSync(fd);
  } catch (e) {
    if (e.code === 'ELOOP') fail('KEY_PATH_SYMLINK', path);
    throw e;
  }
}

function sensRecord(k) {
  return JSON.stringify({ v: 'sbx2.executor-key', synthetic: true, canary: 'SBX2-CANARY-' + randomBytes(12).toString('hex'), pkcs8: exportPkcs8(k) });
}

export function generateZoneKeys(base, who, t0) {
  const L = layout(base);
  if (who === 'sens') {
    let raw = readPrivate(L.sensKey);
    let k;
    if (raw == null) {
      k = generatePrivateKey();
      try { createExclusive(L.sensKey, sensRecord(k), 0o600); }
      catch (e) {
        if (e.code !== 'KEY_FILE_EXISTS') throw e;
        raw = readPrivate(L.sensKey);
        if (raw == null) throw e;
        k = importPkcs8(JSON.parse(raw).pkcs8);
      }
    } else k = importPkcs8(JSON.parse(raw).pkcs8);
    const id = keyIdOf(k);
    publishPublic(L.executorPub, id + '\n');
    return { who, publicKey: id };
  }
  if (who === 'sup') {
    let raw = readPrivate(L.ownerKeys);
    let keys;
    if (raw == null) {
      const generated = { owner_alice: generatePrivateKey(), owner_bob: generatePrivateKey(), __operator: generatePrivateKey() };
      const body = JSON.stringify({ v: 'sbx2.owner-keys', synthetic: true, canary: 'SBX2-CANARY-' + randomBytes(12).toString('hex'), keys: Object.fromEntries(Object.entries(generated).map(([name, key]) => [name, exportPkcs8(key)])) });
      try { createExclusive(L.ownerKeys, body, 0o600); keys = generated; }
      catch (e) {
        if (e.code !== 'KEY_FILE_EXISTS') throw e;
        raw = readPrivate(L.ownerKeys);
        if (raw == null) throw e;
        keys = Object.fromEntries(Object.entries(JSON.parse(raw).keys).map(([name, b64]) => [name, importPkcs8(b64)]));
      }
    } else keys = Object.fromEntries(Object.entries(JSON.parse(raw).keys).map(([name, b64]) => [name, importPkcs8(b64)]));
    publishPublic(L.ownerPub, JSON.stringify({ trustedOwnerKeys: { owner_alice: keyIdOf(keys.owner_alice), owner_bob: keyIdOf(keys.owner_bob) }, operatorKey: keyIdOf(keys.__operator) }) + '\n');
    publishPublic(L.clock, String(t0));
    for (const f of [L.labels, L.freeze, L.ownerLog]) ensureAppendFile(f);
    return { who, operatorKey: keyIdOf(keys.__operator) };
  }
  fail('KEYGEN_USAGE');
}

function invokedDirectly() {
  const argv = process.argv[1];
  return !!argv && import.meta.url === pathToFileURL(argv).href;
}

if (invokedDirectly()) {
  const [base, who, t0] = process.argv.slice(2);
  try { generateZoneKeys(base, who, t0); }
  catch (e) { console.error(e.code || e.message); process.exit(1); }
}
