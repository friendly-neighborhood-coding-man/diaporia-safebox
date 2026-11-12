// Child process for multi-process race tests: tries to reserve each given intent once.
import { SafeBoxStore } from '../../src/v1/store.mjs';
import { parseSealedIntent } from '../../src/v1/intent.mjs';
const [dbPath, startAt, maxTotal, ...ids] = process.argv.slice(2);
const store = new SafeBoxStore(dbPath);
while (Date.now() < Number(startAt)) { /* spin to align start */ }
const results = [];
for (const id of ids) {
  try {
    store.transition(id, 'AUTHORIZED', 'RESERVED', { actor: `pid:${process.pid}`, guard: (r, db) => {
      SafeBoxStore.reserveMandateSpend(db, r.mandate_id, parseSealedIntent(r.canonical).intent.amountYocto, maxTotal);
    } });
    results.push({ id, ok: true });
  } catch (e) { results.push({ id, ok: false, code: e.code ?? String(e.message).slice(0, 60) }); }
}
store.close();
process.stdout.write(JSON.stringify(results));
