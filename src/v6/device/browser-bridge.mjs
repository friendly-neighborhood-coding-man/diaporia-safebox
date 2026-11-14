// REAL platform authenticator bridge (owner-run, local only). The SafeBox owner kit calls authenticators
// synchronously (register / assert); a real authenticator (Windows Hello, a security key) lives in the browser and is
// asynchronous. This bridge runs an HTTP server in a worker thread on the RP origin (http://localhost:<port>); the main
// thread posts a WebAuthn request and blocks (Atomics.wait) until the owner, on the bridge page, reads WHAT is being
// approved and performs the real navigator.credentials ceremony. Nothing is faked: the returned attestation /
// assertion are the browser's, verified later by the unchanged RP code. Every other path on the same origin is
// forwarded to the main thread (the Owner Console), which is never blocked while the console is in use.
import { Worker, MessageChannel, receiveMessageOnPort } from 'node:worker_threads';
import { randomBytes } from 'node:crypto';
import { fail, b64u } from '../../v3/common/canon.mjs';

const WORKER = `
const { workerData, parentPort } = require('node:worker_threads');
const http = require('node:http');
const { port, sab, reply, page } = workerData; const flag = new Int32Array(sab);
let pending = null; let lastPoll = 0; const waiting = new Map(); let n = 0;
parentPort.on('message', (m) => {
  if (m.type === 'webauthn') { pending = m; }
  else if (m.type === 'http-res') { const r = waiting.get(m.id); if (r) { waiting.delete(m.id); r.writeHead(m.res.status, m.res.headers); r.end(m.res.body); } }
  else if (m.type === 'status') parentPort.postMessage({ type: 'status', lastPoll });
});
const finish = (msg) => { pending = null; reply.postMessage(msg); Atomics.store(flag, 0, 1); Atomics.notify(flag, 0); };
http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'); const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    if (u.pathname === '/bridge') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); return res.end(page); }
    if (u.pathname === '/bridge/next') { lastPoll = Date.now(); res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); return res.end(JSON.stringify(pending ? { id: pending.id, op: pending.op, options: pending.options, display: pending.display } : { none: true })); }
    if (u.pathname === '/bridge/result' && req.method === 'POST') {
      if (req.headers.origin !== workerData.origin) { res.writeHead(403); return res.end('{"ok":false}'); }
      let m; try { m = JSON.parse(body); } catch { res.writeHead(400); return res.end('{}'); }
      if (!pending || m.id !== pending.id) { res.writeHead(409); return res.end('{"ok":false,"code":"NO_SUCH_REQUEST"}'); }
      finish({ id: m.id, ok: !!m.ok, data: m.data ?? null, error: m.error ?? null });
      res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"ok":true}');
    }
    const id = ++n; waiting.set(id, res);
    parentPort.postMessage({ type: 'http', id, req: { method: req.method, path: req.url, headers: req.headers, body } });
  });
}).listen(port, '127.0.0.1', () => parentPort.postMessage({ type: 'listening' }));
`;

const PAGE = (origin) => `<!DOCTYPE html><html><head><meta charset="utf-8"><title>SafeBox device bridge</title><style>
body{font:16px/1.45 system-ui,sans-serif;max-width:760px;margin:30px auto;padding:0 16px;background:#f6f7f9;color:#1d232b}
.card{background:#fff;border:1px solid #d9dee5;border-radius:10px;padding:16px;margin:12px 0}pre{white-space:pre-wrap;background:#f1f3f6;padding:10px;border-radius:6px;font-size:14px}
button{font:inherit;padding:9px 16px;border-radius:7px;border:1px solid #8893a1;background:#fff;margin-right:8px}button.go{background:#1f6feb;color:#fff;border-color:#1f6feb}</style></head><body>
<h1>SafeBox owner device bridge (${origin})</h1>
<p>Keep this tab open. When SafeBox needs this laptop's enrolled passkey, the exact request appears below. Approving opens the
<b>real Windows Hello prompt</b>; Windows Hello may accept a fingerprint, face or PIN (SafeBox cannot tell which: a separate fingerprint gate does).</p>
<div class="card" id="c"><i>Waiting for a request...</i></div><div id="log"></div>
<script>
"use strict";
const b64u=(b)=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const fromB64u=(s)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((s.length+3)%4)),c=>c.charCodeAt(0));
let cur=null;
async function send(r){await fetch('/bridge/result',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(r)});}
function txt(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
async function act(){
  const q=cur; const o=q.options; document.getElementById('c').innerHTML='<i>Windows Hello prompt open...</i>';
  try{
    if(q.op==='create'){
      const c=await navigator.credentials.create({publicKey:{rp:{id:o.rpId,name:'SafeBox'},user:{id:fromB64u(o.userId),name:o.userName,displayName:o.userName},challenge:fromB64u(o.challenge),
        pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{authenticatorAttachment:'platform',userVerification:'required',residentKey:'discouraged'},attestation:'none',timeout:180000}});
      await send({id:q.id,ok:true,data:{credentialId:b64u(c.rawId),attestationObject:b64u(c.response.attestationObject),clientDataJSON:b64u(c.response.clientDataJSON)}});
    } else {
      const c=await navigator.credentials.get({publicKey:{rpId:o.rpId,challenge:fromB64u(o.challenge),allowCredentials:[{type:'public-key',id:fromB64u(o.credentialId)}],userVerification:'required',timeout:180000}});
      await send({id:q.id,ok:true,data:{credentialId:b64u(c.rawId),authenticatorData:b64u(c.response.authenticatorData),clientDataJSON:b64u(c.response.clientDataJSON),signature:b64u(c.response.signature)}});
    }
    document.getElementById('log').insertAdjacentHTML('afterbegin','<div>&#10003; '+txt(q.title)+'</div>');
  }catch(e){await send({id:q.id,ok:false,error:e.name+': '+e.message});document.getElementById('log').insertAdjacentHTML('afterbegin','<div>&#10007; '+txt(q.title)+': '+txt(e.name)+'</div>');}
  cur=null; document.getElementById('c').innerHTML='<i>Waiting for a request...</i>';
}
async function decline(){const q=cur;cur=null;await send({id:q.id,ok:false,error:'DECLINED_BY_OWNER'});document.getElementById('c').innerHTML='<i>Declined. Waiting...</i>';}
async function poll(){
  try{const r=await fetch('/bridge/next').then(r=>r.json());
    if(!r.none&&(!cur||cur.id!==r.id)){cur={...r,title:r.display.split('\\n')[0]};
      document.getElementById('c').innerHTML='<b>'+txt(cur.title)+'</b><pre>'+txt(r.display)+'</pre><button class="go" id="go">Approve with Windows Hello</button><button id="no">Decline</button>';
      document.getElementById('go').onclick=act;document.getElementById('no').onclick=decline;}}catch(e){}
  setTimeout(poll,500);}
poll();
</script></body></html>`;

export class BrowserBridge {
  /** handler(req) -> Promise<{status, headers, body}> for every non-bridge path (the Owner Console). */
  constructor({ port, origin, handler = async () => ({ status: 503, headers: {}, body: 'not ready' }), timeoutMs = 300_000 }) {
    this.port = port; this.origin = origin; this.handler = handler; this.timeoutMs = timeoutMs; this.display = 'SafeBox request';
    this.readyP = new Promise((r) => { this.onListening = r; });
    this.sab = new SharedArrayBuffer(4); this.flag = new Int32Array(this.sab);
    const { port1, port2 } = new MessageChannel(); this.reply = port1;
    this.worker = new Worker(WORKER, { eval: true, workerData: { port, sab: this.sab, reply: port2, page: PAGE(origin), origin }, transferList: [port2] });
    this.worker.on('message', async (m) => {
      if (m.type === 'http') { let res; try { res = await this.handler(m.req); } catch (e) { res = { status: 500, headers: {}, body: String(e.message) }; } this.worker.postMessage({ type: 'http-res', id: m.id, res }); }
      if (m.type === 'listening') this.onListening?.();
      if (m.type === 'status') this.onStatus?.(m);
    });
  }
  ready() { return this.readyP; }
  lastPoll() { return new Promise((r) => { this.onStatus = (m) => r(m.lastPoll); this.worker.postMessage({ type: 'status' }); }); }
  /** Synchronous round trip to the owner's browser (blocks this thread; the worker keeps serving). */
  call(op, options, display) {
    const id = randomBytes(8).toString('hex');
    Atomics.store(this.flag, 0, 0);
    // a step that needs several signatures (enrollment signs one record per genesis layer) numbers each request, so a
    // repeated title is visibly a NEW request, not a loop
    const text = String(display ?? this.display); const [title, ...rest] = text.split('\n');
    this.counts ??= new Map(); const k = (this.counts.get(title) ?? 0) + 1; this.counts.set(title, k);
    const shown = [title + (k > 1 || this.expected?.[title] ? ` (request ${k}${this.expected?.[title] ? ' of ' + this.expected[title] : ''}, new challenge)` : ''), ...rest].join('\n');
    this.worker.postMessage({ type: 'webauthn', id, op, options, display: shown });
    const w = Atomics.wait(this.flag, 0, 0, this.timeoutMs);
    if (w === 'timed-out') fail('REAL_AUTHENTICATOR_TIMEOUT');
    const m = receiveMessageOnPort(this.reply)?.message;
    if (!m || m.id !== id) fail('REAL_AUTHENTICATOR_PROTOCOL');
    if (!m.ok) fail('REAL_AUTHENTICATOR_REFUSED', String(m.error).slice(0, 120));
    return m.data;
  }
  close() { return this.worker.terminate(); }
}

/** Authenticator with the SoftAuthenticator interface, backed by the owner's REAL platform authenticator. */
export class RealAuthenticator {
  constructor({ bridge, label }) { this.bridge = bridge; this.label = label; this.credentialIdB64u = null; this.kind = 'REAL_PLATFORM_AUTHENTICATOR'; this.ceremonies = []; }
  register({ rpId, challenge }) {
    const d = this.bridge.call('create', { rpId, challenge: b64u(challenge), userId: b64u(randomBytes(16)), userName: 'SafeBox ' + this.label }, this.bridge.display);
    this.credentialIdB64u = d.credentialId; this.ceremonies.push({ op: 'create', at: new Date().toISOString(), what: this.bridge.display.split('\n')[0] });
    return { attestationObject: d.attestationObject, clientDataJSON: d.clientDataJSON };
  }
  assert({ rpId, challenge }) {
    if (!this.credentialIdB64u) fail('REAL_AUTHENTICATOR_NOT_REGISTERED');
    const d = this.bridge.call('get', { rpId, challenge: b64u(challenge), credentialId: this.credentialIdB64u }, this.bridge.display);
    this.ceremonies.push({ op: 'get', at: new Date().toISOString(), what: this.bridge.display.split('\n')[0] });
    return { credentialId: d.credentialId, authenticatorData: d.authenticatorData, clientDataJSON: d.clientDataJSON, signature: d.signature };
  }
  get credentialId() { return this.credentialIdB64u ? Buffer.from(this.credentialIdB64u, 'base64url') : null; }
  toJSON() { return { label: this.label, credentialId: this.credentialIdB64u, kind: this.kind }; }
}
