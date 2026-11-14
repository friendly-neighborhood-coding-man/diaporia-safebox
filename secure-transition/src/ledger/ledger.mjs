// MOCK ledger ("the chain"). Authoritative for balances, account nonces and settlement. It keeps settling while the local
// SafeBox is offline or in maintenance. Accepts any correctly signed tx from anyone (a public chain does not care which
// software signed). Admin socket (root only) drives settlement ticks deterministically. No real funds.
import net from 'node:net';
import { readJson, writeJsonDurable } from '../common/fsutil.mjs';
import { verifyEnvelope, DOMAINS, digestObj } from '../common/crypto.mjs';
import { serve } from '../common/ipc.mjs';
import { join } from 'node:path';

export class Ledger {
  constructor(dir) {
    this.path = join(dir, 'ledger.json');
    this.s = readJson(this.path, null);
  }
  init({ accounts }) {
    // accounts: { id: { balance, publicPem? } }
    this.s = { accounts: Object.fromEntries(Object.entries(accounts).map(([id, a]) => [id, { balance: String(a.balance), nonce: 0, keys: a.publicPem ? [a.publicPem] : [] }])), mempool: [], txs: {}, height: 0 };
    this.save();
  }
  save() { writeJsonDurable(this.path, this.s); }
  submit(env) {
    const tx = env?.payload;
    if (!tx || typeof tx !== 'object') return { ok: false, error: 'BAD_TX' };
    const txid = digestObj(env.payload);
    if (this.s.txs[txid] || this.s.mempool.some(m => m.txid === txid)) return { ok: true, txid, duplicate: true, status: this.status(txid).status };
    const acct = this.s.accounts[tx.from];
    if (!acct) return { ok: false, error: 'UNKNOWN_ACCOUNT' };
    if (!verifyEnvelope(env, DOMAINS.LEDGER_TX, acct.keys)) return { ok: false, error: 'BAD_SIGNATURE' };
    if (!Number.isSafeInteger(tx.nonce) || tx.nonce <= acct.nonce) return { ok: false, error: 'NONCE_TOO_LOW' };
    this.s.mempool.push({ txid, env });
    this.save();
    return { ok: true, txid, status: 'PENDING' };
  }
  /** Settle up to n pending txs in nonce order (per account). */
  tick(n = 1000) {
    const settled = [];
    this.s.mempool.sort((a, b) => a.env.payload.nonce - b.env.payload.nonce);
    const keep = [];
    for (const m of this.s.mempool) {
      if (settled.length >= n) { keep.push(m); continue; }
      const tx = m.env.payload; const a = this.s.accounts[tx.from];
      let result = 'SETTLED';
      if (tx.nonce <= a.nonce) result = 'FAILED_NONCE';
      else if (BigInt(a.balance) < BigInt(tx.amount)) result = 'FAILED_FUNDS';
      if (result === 'SETTLED') {
        a.balance = (BigInt(a.balance) - BigInt(tx.amount)).toString();
        const to = this.s.accounts[tx.to] ?? (this.s.accounts[tx.to] = { balance: '0', nonce: 0, keys: [] });
        to.balance = (BigInt(to.balance) + BigInt(tx.amount)).toString();
      }
      if (tx.nonce > a.nonce) a.nonce = tx.nonce;
      this.s.txs[m.txid] = { status: result, height: ++this.s.height, tx };
      settled.push({ txid: m.txid, status: result });
    }
    this.s.mempool = keep; this.save();
    return settled;
  }
  status(txid) {
    if (this.s.txs[txid]) return { status: this.s.txs[txid].status, height: this.s.txs[txid].height };
    if (this.s.mempool.some(m => m.txid === txid)) return { status: 'PENDING' };
    return { status: 'UNKNOWN' };
  }
  account(id) { const a = this.s.accounts[id]; return a ? { balance: a.balance, nonce: a.nonce } : null; }
  /** Every settled tx from `from` (what an explorer would show). */
  history(from) { return Object.entries(this.s.txs).filter(([, t]) => t.tx.from === from).map(([txid, t]) => ({ txid, ...t })); }
  dump() { return this.s; }
}

const handle = (L) => async (method, p) => {
  switch (method) {
    case 'submit': return L.submit(p.env);
    case 'status': return { ok: true, ...L.status(p.txid) };
    case 'account': return { ok: true, account: L.account(p.id) };
    case 'history': return { ok: true, history: L.history(p.from) };
    default: return { ok: false, error: 'METHOD_NOT_ALLOWED' };
  }
};

/** Public API on TCP (the "network"); admin (init/tick/dump) on a root-only Unix socket. */
export async function startLedgerDaemon({ dir, port, host = '127.0.0.1', adminSock }) {
  const L = new Ledger(dir);
  const pub = handle(L);
  const server = net.createServer((sock) => {
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', async (c) => {
      buf += c; let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        let req; try { req = JSON.parse(line); } catch { sock.write('{"ok":false,"error":"BAD_JSON"}\n'); continue; }
        const res = await pub(req.method, req.params ?? {});
        sock.write(JSON.stringify({ id: req.id, ...res }) + '\n');
      }
    });
    sock.on('error', () => {});
  });
  await new Promise((r) => server.listen(port, host, r));
  await serve(adminSock, async (method, p) => {
    if (method === 'init') { L.init(p); return { ok: true }; }
    if (method === 'tick') return { ok: true, settled: L.tick(p.n) };
    if (method === 'dump') return { ok: true, state: L.dump() };
    return pub(method, p);
  }, { mode: 0o600 });
  return { server, L };
}

/** TCP client for the public ledger API. */
export function ledgerCall({ host = '127.0.0.1', port }, method, params = {}, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({ host, port });
    let buf = ''; const t = setTimeout(() => { s.destroy(); reject(Object.assign(new Error('LEDGER_TIMEOUT'), { code: 'LEDGER_TIMEOUT' })); }, timeoutMs);
    s.setEncoding('utf8');
    s.on('connect', () => s.write(JSON.stringify({ id: 1, method, params }) + '\n'));
    s.on('data', (d) => { buf += d; const i = buf.indexOf('\n'); if (i >= 0) { clearTimeout(t); s.end(); resolve(JSON.parse(buf.slice(0, i))); } });
    s.on('error', (e) => { clearTimeout(t); reject(e); });
  });
}
