// Minimal bounded IPC: newline-delimited JSON over a Unix domain socket.
// Authentication of the CALLER is done by the kernel: each socket lives in a directory whose
// owner/group/mode decide which OS principals may connect (workload identity by filesystem ACL,
// in the spirit of SPIFFE workload attestation). Every endpoint is deny-by-default:
// unknown ops, unknown fields, non-string values and oversized frames are rejected.
import net from 'node:net';
import { chmodSync, existsSync, unlinkSync } from 'node:fs';
import { SafeBoxError, isPlainObject } from '../../v1/canonical.mjs';

export const MAX_FRAME = 16 * 1024;
const OP_RE = /^[A-Z][A-Z0-9_]{1,39}$/;

/** Validates a request envelope and the op's exact argument field list. */
export function checkEnvelope(msg, ops) {
  if (!isPlainObject(msg)) throw new SafeBoxError('BAD_ENVELOPE');
  const keys = Object.keys(msg).sort().join(',');
  if (keys !== 'args,op,rid') throw new SafeBoxError('BAD_ENVELOPE', keys.slice(0, 40));
  if (typeof msg.op !== 'string' || !OP_RE.test(msg.op)) throw new SafeBoxError('BAD_OP');
  if (typeof msg.rid !== 'string' || msg.rid.length > 64) throw new SafeBoxError('BAD_RID');
  const spec = Object.prototype.hasOwnProperty.call(ops, msg.op) ? ops[msg.op] : null;
  if (!spec) throw new SafeBoxError('OP_DENIED', msg.op); // deny by default
  if (!isPlainObject(msg.args)) throw new SafeBoxError('BAD_ARGS');
  const got = Object.keys(msg.args).sort(), want = [...spec.fields].sort();
  if (got.join(',') !== want.join(',')) throw new SafeBoxError('BAD_ARGS', `expected ${want.join(',')}`);
  for (const k of got) {
    const v = msg.args[k], t = spec.types?.[k] ?? 'string';
    if (t === 'string' && (typeof v !== 'string' || v.length > (spec.maxLen?.[k] ?? 4096))) throw new SafeBoxError('BAD_ARG', k);
    if (t === 'signed' && !(isPlainObject(v) && Object.keys(v).sort().join(',') === 'signature,statement' &&
      typeof v.statement === 'string' && v.statement.length <= 4096 && typeof v.signature === 'string' && v.signature.length <= 128)) throw new SafeBoxError('BAD_ARG', k);
  }
  return spec;
}

export async function dispatch(ops, line, ctx) {
  let msg, rid = null;
  try {
    if (Buffer.byteLength(line) > MAX_FRAME) throw new SafeBoxError('FRAME_TOO_LARGE');
    try { msg = JSON.parse(line); } catch { throw new SafeBoxError('BAD_JSON'); }
    if (isPlainObject(msg) && typeof msg.rid === 'string') rid = msg.rid.slice(0, 64);
    const spec = checkEnvelope(msg, ops);
    const result = await spec.handler(msg.args, ctx);
    return { rid, ok: true, result: result ?? null };
  } catch (e) {
    const code = e instanceof SafeBoxError ? e.code : 'INTERNAL_ERROR';
    if (!(e instanceof SafeBoxError) && process.env.SBX2_DEBUG) console.error(e);
    ctx?.onDenied?.(msg?.op ?? null, code);
    return { rid, ok: false, error: { code } };
  }
}

/** Starts a Unix-socket server. The socket's directory permissions are the access control. */
export function serveUnix(path, ops, { mode = 0o660, ctx = {} } = {}) {
  if (existsSync(path)) unlinkSync(path);
  const server = net.createServer((sock) => {
    let buf = '';
    let chain = Promise.resolve();
    sock.setEncoding('utf8');
    sock.on('data', (d) => {
      buf += d;
      if (buf.length > MAX_FRAME * 2 && !buf.includes('\n')) { sock.end(JSON.stringify({ rid: null, ok: false, error: { code: 'FRAME_TOO_LARGE' } }) + '\n'); sock.destroy(); return; }
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        chain = chain.then(async () => { const r = await dispatch(ops, line, ctx); if (!sock.destroyed) sock.write(JSON.stringify(r) + '\n'); });
      }
    });
    sock.on('error', () => {});
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(path, () => { chmodSync(path, mode); resolve(server); });
  });
}

let ridSeq = 0;
/** Persistent client over a Unix socket. */
export class UnixClient {
  constructor(path, { timeoutMs = 10_000 } = {}) { this.path = path; this.timeoutMs = timeoutMs; this.sock = null; this.pending = new Map(); this.buf = ''; }
  #connect() {
    if (this.sock && !this.sock.destroyed) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const s = net.createConnection(this.path);
      s.setEncoding('utf8');
      s.once('connect', () => { this.sock = s; resolve(); });
      s.once('error', (e) => { reject(Object.assign(new SafeBoxError('IPC_CONNECT_FAILED', e.code), { sysCode: e.code })); for (const p of this.pending.values()) p.reject(new SafeBoxError('IPC_CLOSED')); this.pending.clear(); });
      s.on('data', (d) => {
        this.buf += d; let i;
        while ((i = this.buf.indexOf('\n')) >= 0) {
          const line = this.buf.slice(0, i); this.buf = this.buf.slice(i + 1);
          let r; try { r = JSON.parse(line); } catch { continue; }
          const key = r.rid ?? '__null__';
          const p = this.pending.get(key) ?? (this.pending.size === 1 ? [...this.pending.entries()][0][1] : null);
          if (p) { for (const [k, v] of this.pending) if (v === p) this.pending.delete(k); p.resolve(r); }
        }
      });
      s.on('close', () => { for (const p of this.pending.values()) p.reject(new SafeBoxError('IPC_CLOSED')); this.pending.clear(); });
    });
  }
  async raw(line, rid = null) {
    rid = rid ?? '__null__';
    await this.#connect();
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.pending.delete(rid); reject(new SafeBoxError('IPC_TIMEOUT')); }, this.timeoutMs);
      this.pending.set(rid, { resolve: (r) => { clearTimeout(t); resolve(r); }, reject: (e) => { clearTimeout(t); reject(e); } });
      this.sock.write(line + '\n');
    });
  }
  async request(op, args = {}) { const rid = 'r' + (++ridSeq); return this.raw(JSON.stringify({ op, args, rid }), rid); }
  async call(op, args = {}) { const r = await this.request(op, args); if (!r.ok) throw new SafeBoxError(r.error.code); return r.result; }
  close() { this.sock?.destroy(); }
}

/** In-process transport with the same JSON round-trip and validation semantics (unit tests). */
export class DirectClient {
  constructor(ops, ctx = {}) { this.ops = ops; this.ctx = ctx; }
  async raw(line) { const r = await dispatch(this.ops, line, this.ctx); return JSON.parse(JSON.stringify(r)); }
  async request(op, args = {}) { const rid = 'd' + (++ridSeq); return this.raw(JSON.stringify({ op, args, rid })); }
  async call(op, args = {}) { const r = await this.request(op, args); if (!r.ok) throw new SafeBoxError(r.error.code); return r.result; }
  close() {}
}
