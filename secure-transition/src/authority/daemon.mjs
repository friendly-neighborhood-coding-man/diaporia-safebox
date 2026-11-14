// Authority daemon: app socket (payments, status, signed owner commands) and controller socket (maintenance protocol).
// Which socket a caller can open is decided by the OS (file permissions); the Authority still checks every argument.
import { readFileSync } from 'node:fs';
import { serve } from '../common/ipc.mjs';
import { Authority } from './authority.mjs';
import { ledgerCall } from '../ledger/ledger.mjs';

const cfg = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const A = new Authority({ dir: cfg.dir, ledger: (m, p) => ledgerCall({ port: cfg.ledgerPort }, m, p) });

const APP = { status: () => ({ ok: true, status: A.status() }), pay: (p) => A.pay(p), ownerCommand: (p) => A.ownerCommand(p.cmd) };
const CTL = {
  ...APP,
  beginMaintenance: (p) => A.beginMaintenance(p), enterSafeHold: (p) => A.enterSafeHold(p), reconcile: (p) => A.reconcile(p),
  completeTransition: (p) => A.completeTransition(p), refusals: (p) => ({ ok: true, refusals: A.refusalsSince(p.transitionId) }),
};
const wrap = (table, source) => async (method, params) => {
  const f = Object.hasOwn(table, method) ? table[method] : null;
  if (!f) { A.refuse(source, method, 'METHOD_NOT_ALLOWED'); return { ok: false, error: 'METHOD_NOT_ALLOWED' }; }
  try { return await f(params); } catch (e) {
    const code = e.code ?? 'INTERNAL';
    if (method !== 'status') A.refuse(source, method, code);
    return { ok: false, error: code, detail: String(e.message) };
  }
};
await serve(cfg.appSock, wrap(APP, 'app'), { mode: 0o666 });
await serve(cfg.ctlSock, wrap(CTL, 'ctl'), { mode: 0o660, gid: cfg.ctlGid });
process.stdout.write('AUTHORITY_READY\n');
