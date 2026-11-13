// Independent watchdog (runs as sbx2-sup). Own wall-clock loop + on-demand SCAN from the controller.
import { readFileSync, appendFileSync } from 'node:fs';
import { layout } from './layout.mjs';
import { Watchdog, FreezeStore } from '../supervisor/watchdog.mjs';
import { OwnerSimulator } from '../supervisor/owner.mjs';
import { FileClockReader } from '../common/clock.mjs';
import { serveUnix, UnixClient } from '../common/wire.mjs';
import { importPkcs8 } from '../common/crypto.mjs';

const L = layout(process.argv[2]);
const run = JSON.parse(readFileSync(L.runConf, 'utf8'));
const clock = new FileClockReader(L.clock);
const now = () => clock.now();
const keys = JSON.parse(readFileSync(L.ownerKeys, 'utf8')).keys;
const signerOwner = OwnerSimulator.fromPrivateKeys(Object.fromEntries(Object.entries(keys).map(([k, v]) => [k, importPkcs8(v)])), now);
const view = OwnerSimulator.view(L.ownerLog);
// The watchdog verifies against the controller's owner issuance LOG (file), and signs unfreeze with the operator key.
const owner = new Proxy(signerOwner, { get(t, p) { if (p === 'issued' || p === 'revoked' || p === 'policies') { view.refresh(); return view[p]; } const v = t[p]; return typeof v === 'function' ? v.bind(t) : v; } });
const wd = new Watchdog({ ledgerRead: new UnixClient(L.ledgerRead), ledgerAdmin: new UnixClient(L.ledgerAdmin), sensCtl: new UnixClient(L.sensCtl),
  owner, freezeStore: new FreezeStore(L.freeze), now, executorKey: readFileSync(L.executorPub, 'utf8').trim(), genesisTotalYocto: run.genesisTotal,
  preReleaseAudit: run.preReleaseAudit !== false, drillHideFlawFlag: !!run.drillHideFlawFlag });
let busy = Promise.resolve();
const scan = () => (busy = busy.then(async () => { const r = await wd.scan(); if (r.breaches.length || r.anomalies.length || r.actions.some(a => a !== 'HEARTBEAT')) appendFileSync(L.wdEvents, JSON.stringify(r) + '\n'); return r; }).catch(e => ({ error: e.code ?? e.message })));
await serveUnix(L.supWd, {
  SCAN: { fields: [], handler: () => scan().then(r => ({ actions: r.actions?.map(a => typeof a === 'string' ? a : a.id) ?? [], breaches: r.breaches?.length ?? 0, anomalies: r.anomalies ?? [] })) },
  RECOVER: { fields: ['reviewRef', 'diagnosis'], handler: (a) => (busy = busy.then(() => wd.recover(a))) },
  STATE: { fields: [], handler: () => ({ scans: wd.scans, frozen: wd.freezeStore.isFrozen(), events: wd.events.length }) },
}, { mode: 0o600 });
setInterval(scan, 500).unref?.();
setInterval(() => {}, 1 << 30);
console.log(JSON.stringify({ ready: 'watchdog', pid: process.pid, uid: process.getuid() }));
