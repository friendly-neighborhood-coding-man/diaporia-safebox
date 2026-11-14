// Strict, bounded ustar reader for SSTP packages, plus a permissive writer used only to build test fixtures (including
// hostile archives). The reader accepts regular files and directories only and rejects everything else.
export const LIMITS = Object.freeze({ maxArchiveBytes: 8 << 20, maxEntries: 256, maxFileBytes: 4 << 20, maxTotalBytes: 16 << 20, maxPathLen: 200, maxDepth: 8 });
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ALLOWED_MODES = new Set([0o644, 0o755]);

export class PackageError extends Error { constructor(code, detail) { super(`${code}${detail ? ': ' + detail : ''}`); this.code = code; this.detail = detail; } }
const fail = (code, detail) => { throw new PackageError(code, detail); };

const str = (b, off, len) => { const s = b.subarray(off, off + len); const z = s.indexOf(0); return s.subarray(0, z < 0 ? len : z).toString('latin1'); };
function octal(b, off, len, what) {
  const s = str(b, off, len).trim();
  if (!/^[0-7]{1,12}$/.test(s)) fail('TAR_BAD_NUMBER', what);
  return parseInt(s, 8);
}

export function validatePath(p) {
  if (typeof p !== 'string' || !p.length) fail('PATH_EMPTY');
  if (p.length > LIMITS.maxPathLen) fail('PATH_TOO_LONG', p);
  if (p.includes('\\') || p.includes('\0')) fail('PATH_BAD_CHAR', p);
  if (p.startsWith('/')) fail('PATH_ABSOLUTE', p);
  const segs = p.replace(/\/$/, '').split('/');
  if (segs.length > LIMITS.maxDepth) fail('PATH_TOO_DEEP', p);
  for (const s of segs) {
    if (s === '..') fail('PATH_TRAVERSAL', p);
    if (s === '.' || s === '') fail('PATH_NOT_NORMALIZED', p);
    if (!SEGMENT.test(s)) fail('PATH_BAD_CHAR', p);
  }
  return segs.join('/');
}

/** Parse a tar buffer. Returns [{ path, type: 'file'|'dir', mode, data }]. Throws PackageError on anything unexpected. */
export function readTar(buf) {
  if (!Buffer.isBuffer(buf)) fail('TAR_NOT_BUFFER');
  if (buf.length > LIMITS.maxArchiveBytes) fail('ARCHIVE_TOO_LARGE', String(buf.length));
  if (buf.length % 512 !== 0) fail('TAR_MISALIGNED');
  const out = []; const seen = new Set(); let off = 0; let total = 0; let ended = false;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every(x => x === 0)) {
      if (off + 1024 <= buf.length && buf.subarray(off + 512, off + 1024).every(x => x === 0)) { ended = true; off += 1024; break; }
      fail('TAR_BAD_END');
    }
    const sum = octal(h, 148, 8, 'chksum');
    let calc = 0; for (let i = 0; i < 512; i++) calc += (i >= 148 && i < 156) ? 32 : h[i];
    if (sum !== calc) fail('TAR_BAD_CHECKSUM');
    if (str(h, 257, 6) !== 'ustar') fail('TAR_NOT_USTAR');
    const type = String.fromCharCode(h[156] || 48);
    const name = str(h, 0, 100); const prefix = str(h, 345, 155);
    const full = prefix ? `${prefix}/${name}` : name;
    const size = octal(h, 124, 12, 'size');
    const mode = octal(h, 100, 8, 'mode') & 0o7777;
    if (type === '2') fail('ENTRY_SYMLINK', full);
    if (type === '1') fail('ENTRY_HARDLINK', full);
    if (type !== '0' && type !== '5') fail('ENTRY_TYPE_FORBIDDEN', `${type} ${full}`);
    const path = validatePath(full);
    const key = path.toLowerCase();
    if (seen.has(key)) fail('ENTRY_DUPLICATE', path);
    seen.add(key);
    if (out.length >= LIMITS.maxEntries) fail('TOO_MANY_ENTRIES');
    off += 512;
    if (type === '5') { if (size !== 0) fail('TAR_DIR_WITH_DATA', path); if (mode !== 0o755) fail('MODE_FORBIDDEN', `${path} ${mode.toString(8)}`); out.push({ path, type: 'dir', mode, data: Buffer.alloc(0) }); continue; }
    if (!ALLOWED_MODES.has(mode)) fail('MODE_FORBIDDEN', `${path} ${mode.toString(8)}`);
    if (size > LIMITS.maxFileBytes) fail('FILE_TOO_LARGE', path);
    total += size; if (total > LIMITS.maxTotalBytes) fail('PACKAGE_TOO_LARGE');
    if (off + size > buf.length) fail('TAR_TRUNCATED', path);
    out.push({ path, type: 'file', mode, data: Buffer.from(buf.subarray(off, off + size)) });
    off += Math.ceil(size / 512) * 512;
  }
  if (!ended) fail('TAR_TRUNCATED', 'no end marker');
  if (buf.subarray(off).some(x => x !== 0)) fail('TAR_TRAILING_DATA');
  // A file must not also be used as a directory prefix of another entry.
  const files = new Set(out.filter(e => e.type === 'file').map(e => e.path.toLowerCase()));
  for (const e of out) { const segs = e.path.toLowerCase().split('/'); for (let i = 1; i < segs.length; i++) if (files.has(segs.slice(0, i).join('/'))) fail('PATH_FILE_AS_DIR', e.path); }
  return out;
}

/** Test-fixture writer. entries: [{ name, type?: '0'|'1'|'2'|'5'|..., data?, mode?, linkname?, prefix? }] */
export function writeTar(entries) {
  const blocks = [];
  for (const e of entries) {
    const data = Buffer.from(e.data ?? '');
    const h = Buffer.alloc(512);
    h.write(e.name, 0, 100, 'latin1');
    h.write(((e.mode ?? 0o644)).toString(8).padStart(7, '0') + '\0', 100, 8, 'latin1');
    h.write('0000000\0', 108, 8); h.write('0000000\0', 116, 8);
    h.write((e.type === '5' || e.type === '2' || e.type === '1' ? 0 : data.length).toString(8).padStart(11, '0') + '\0', 124, 12, 'latin1');
    h.write('00000000000\0', 136, 12);
    h.write('        ', 148, 8);
    h[156] = (e.type ?? '0').charCodeAt(0);
    if (e.linkname) h.write(e.linkname, 157, 100, 'latin1');
    h.write('ustar\0', 257, 6, 'latin1'); h.write('00', 263, 2, 'latin1');
    if (e.prefix) h.write(e.prefix, 345, 155, 'latin1');
    let sum = 0; for (let i = 0; i < 512; i++) sum += h[i];
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'latin1');
    blocks.push(h);
    if (!(e.type === '5' || e.type === '2' || e.type === '1') && data.length) { blocks.push(data); const pad = (512 - (data.length % 512)) % 512; if (pad) blocks.push(Buffer.alloc(pad)); }
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}
