// Sensitive Zone service (runs as sbx2-sens). Holds the only copy of the executor key.
import { readFileSync } from 'node:fs';
import { layout } from './layout.mjs';
import { SensitiveZone, SensitiveStore, sensitiveOps } from '../sensitive/service.mjs';
import { FileClockReader } from '../common/clock.mjs';
import { serveUnix, UnixClient } from '../common/wire.mjs';
import { makeSigner, importPkcs8 } from '../common/crypto.mjs';

const L = layout(process.argv[2]);
const conf = JSON.parse(readFileSync(L.sensConf, 'utf8'));
const clock = new FileClockReader(L.clock);
const keyFile = JSON.parse(readFileSync(L.sensKey, 'utf8'));
const executorSigner = makeSigner(importPkcs8(keyFile.pkcs8), 'executor');
const store = new SensitiveStore(L.sensDb, { now: () => clock.now() });
const zone = new SensitiveZone(conf, { store, now: () => clock.now(), executorSigner, ledger: new UnixClient(L.ledgerExec) });
const ops = sensitiveOps(zone);
await serveUnix(L.sensGz, ops.gz);
await serveUnix(L.sensCtl, ops.ctl);
// Crash recovery on start: in-flight transfers are reconciled (never re-signed blindly).
console.log(JSON.stringify({ ready: 'sensitive', pid: process.pid, uid: process.getuid(), injectFlaw: conf.injectFlaw ?? null }));
