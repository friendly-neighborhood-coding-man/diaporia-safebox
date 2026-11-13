// General Zone process (runs as sbx2-gen, inside its own network namespace). FULLY UNTRUSTED.
// It can reach exactly two sockets: the Sensitive Zone's public gz.sock and the controller's task.sock.
import net from 'node:net';
import { layout } from './layout.mjs';
import { UnixClient } from '../common/wire.mjs';
import { GeneralZone } from '../general/zone.mjs';

const L = layout(process.argv[2]);
const mode = process.argv[3] ?? 'B';
let clockNow = 0;
let zone = null;
const sock = net.createConnection(L.supTask);
sock.setEncoding('utf8');
let buf = '';
const send = (o) => sock.write(JSON.stringify(o) + '\n');
sock.on('connect', () => send({ kind: 'READY', pid: process.pid, uid: process.getuid() }));
sock.on('data', (d) => {
  buf += d; let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const m = JSON.parse(line);
    (async () => {
      clockNow = m.now ?? clockNow;
      if (m.kind === 'CONFIG') {
        zone = new GeneralZone({ gz: new UnixClient(L.sensGz), mode, os: m.payload, now: () => clockNow, extraClients: (n) => Array.from({ length: n }, () => new UnixClient(L.sensGz)) });
        return send({ id: m.id, result: { ok: true } });
      }
      if (m.kind === 'TASK') return send({ id: m.id, result: await zone.handleTask(m.payload) });
      if (m.kind === 'ATTACK') return send({ id: m.id, result: await zone.runAttack(m.payload) });
      if (m.kind === 'REPLAY') return send({ id: m.id, result: await zone.replay(m.payload.eventId) });
      if (m.kind === 'EXIT') { send({ id: m.id, result: { bye: true } }); setTimeout(() => process.exit(0), 50); }
    })().catch(e => send({ id: m.id, result: { kind: 'ERROR', error: String(e.message).slice(0, 200) } }));
  }
});
sock.on('error', (e) => { console.error('general: task socket error', e.code); process.exit(3); });
