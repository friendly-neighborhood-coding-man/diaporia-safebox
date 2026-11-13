// Mock ledger service (runs as sbx2-ledger). Reads only root-owned trusted config.
import { readFileSync } from 'node:fs';
import { layout } from './layout.mjs';
import { MockLedger, ledgerOps } from '../mock-ledger/ledger.mjs';
import { FileClockReader } from '../common/clock.mjs';
import { serveUnix } from '../common/wire.mjs';

const L = layout(process.argv[2]);
const conf = JSON.parse(readFileSync(L.ledgerConf, 'utf8'));
const clock = new FileClockReader(L.clock);
const ledger = new MockLedger(L.ledgerDb, { now: () => clock.now() });
ledger.genesis(conf.genesis);
const ops = ledgerOps(ledger);
await serveUnix(L.ledgerExec, ops.exec);
await serveUnix(L.ledgerRead, ops.read);
await serveUnix(L.ledgerAdmin, ops.admin);
process.send?.({ ready: 'ledger', pid: process.pid });
console.log(JSON.stringify({ ready: 'ledger', pid: process.pid, uid: process.getuid() }));
