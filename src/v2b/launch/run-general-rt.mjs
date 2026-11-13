// V2-B General Zone process (runs as sbx2-gen inside an empty network namespace). FULLY UNTRUSTED.
// Hosts the honest (gullible) agent for owner tasks and the red-team actuator. Reachable sockets: gz.sock, task.sock.
import net from 'node:net';
import { layout } from '../../v2/launch/layout.mjs';
import { UnixClient } from '../../v2/common/wire.mjs';
import { RedTeamZone } from '../actuator.mjs';

const L = layout(process.argv[2]);
let clockNow = 0, zone = null;
const sock = net.createConnection(L.supTask); sock.setEncoding('utf8');
let buf = '';
const send = (o) => sock.write(JSON.stringify(o) + '\n');
sock.on('connect', () => send({ kind: 'READY', pid: process.pid, uid: process.getuid() }));
sock.on('data', (d) => {
  buf += d; let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
    (async () => {
      clockNow = m.now ?? clockNow;
      if (m.kind === 'CONFIG') { zone = new RedTeamZone({ gz: new UnixClient(L.sensGz), now: () => clockNow, makeClient: () => new UnixClient(L.sensGz) }); return send({ id: m.id, result: { ok: true } }); }
      if (m.kind === 'TASK') return send({ id: m.id, result: await zone.handleTask(m.payload) });
      if (m.kind === 'SLOT') return send({ id: m.id, result: zone.receiveSlotTask(m.payload) });
      if (m.kind === 'ACT') return send({ id: m.id, result: await zone.act(m.payload) });
      if (m.kind === 'REPLAY') return send({ id: m.id, result: await zone.replay(m.payload.eventId) });
      if (m.kind === 'HOOKLOG') return send({ id: m.id, result: zone.hookLog });
      if (m.kind === 'EXIT') { send({ id: m.id, result: { bye: true } }); setTimeout(() => process.exit(0), 50); }
    })().catch(e => send({ id: m.id, result: { kind: 'ERROR', error: String(e.message).slice(0, 200) } }));
  }
});
sock.on('error', (e) => { console.error('general: task socket error', e.code); process.exit(3); });
