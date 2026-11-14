// JSON-lines request/response over Unix domain sockets. Transport only: authority over who may connect comes from the
// socket's filesystem permissions (OS boundary), and every security-relevant payload is signature-checked by the receiver.
import net from 'node:net';
import { chmodSync, chownSync, rmSync } from 'node:fs';

const MAX_LINE = 1 << 20;

export function serve(path, handler, { mode = 0o600, uid, gid } = {}) {
  rmSync(path, { force: true });
  const server = net.createServer((sock) => {
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', async (chunk) => {
      buf += chunk;
      if (buf.length > MAX_LINE) { sock.destroy(); return; }
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        let req;
        try { req = JSON.parse(line); } catch { sock.write(JSON.stringify({ ok: false, error: 'BAD_JSON' }) + '\n'); continue; }
        let res;
        try { res = await handler(req.method, req.params ?? {}, req); } catch (e) { res = { ok: false, error: e.code ?? 'INTERNAL', detail: String(e.message ?? e) }; }
        if (!sock.destroyed) sock.write(JSON.stringify({ id: req.id, ...res }) + '\n');
      }
    });
    sock.on('error', () => {});
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(path, () => {
      chmodSync(path, mode);
      if (uid !== undefined || gid !== undefined) chownSync(path, uid ?? -1, gid ?? -1);
      resolve(server);
    });
  });
}

export function call(path, method, params = {}, { timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(path);
    let buf = '';
    const t = setTimeout(() => { sock.destroy(); reject(Object.assign(new Error('IPC_TIMEOUT'), { code: 'IPC_TIMEOUT' })); }, timeoutMs);
    sock.setEncoding('utf8');
    sock.on('connect', () => sock.write(JSON.stringify({ id: 1, method, params }) + '\n'));
    sock.on('data', (d) => {
      buf += d;
      const i = buf.indexOf('\n');
      if (i >= 0) { clearTimeout(t); sock.end(); try { resolve(JSON.parse(buf.slice(0, i))); } catch (e) { reject(e); } }
    });
    sock.on('error', (e) => { clearTimeout(t); reject(e); });
  });
}
