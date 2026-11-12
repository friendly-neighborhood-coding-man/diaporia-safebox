#!/usr/bin/env node
// SafeBox operator CLI (trusted service side). Holds the executor key reference via config; never the owner key.
import { readFileSync, writeFileSync } from 'node:fs';
import { openRuntime } from '../src/v1/runtime.mjs';
import { parseArgs, need } from '../src/v1/cli-args.mjs';

const USAGE = `usage: safebox <command> --config <safebox.config.json> [...]
  register-mandate --file <mandate.json>
  propose          --file <proposal.json> --request-out <request.json>   (untrusted input: proposal only)
  authorize        --file <authorization.json>                          (owner-signed statement)
  revoke           --file <revocation.json>
  execute          --intent <id>
  reconcile        --intent <id> [--rebroadcast]
  recover
  status           --intent <id>
  journal          [--intent <id>]`;

async function main() {
  const a = parseArgs(process.argv.slice(2), { flags: ['rebroadcast'] });
  if (!a._cmd || a._cmd === 'help') { console.error(USAGE); process.exitCode = 64; return; }
  need(a, 'config');
  const needsExecutor = ['execute', 'reconcile', 'recover'].includes(a._cmd);
  const { service, store } = openRuntime(a.config, { withExecutor: needsExecutor });
  const out = (o) => console.log(JSON.stringify(o, null, 2));
  switch (a._cmd) {
    case 'register-mandate': { need(a, 'file'); const m = service.registerMandate(JSON.parse(readFileSync(a.file, 'utf8'))); out({ registered: m.mandateId }); break; }
    case 'propose': {
      need(a, 'file', 'request-out');
      const r = service.propose(readFileSync(a.file, 'utf8'));
      writeFileSync(a['request-out'], JSON.stringify(service.authorizationRequest(r.intentId), null, 2) + '\n');
      console.error(r.display); out({ intentId: r.intentId, digest: r.digest, state: 'PREPARED', ownerRequest: a['request-out'] }); break;
    }
    case 'authorize': { need(a, 'file'); const f = JSON.parse(readFileSync(a.file, 'utf8')); service.authorize(f.intentId, f); out(service.publicStatus(f.intentId)); break; }
    case 'revoke': { need(a, 'file'); const f = JSON.parse(readFileSync(a.file, 'utf8')); service.revoke(f.intentId, f); out(service.publicStatus(f.intentId)); break; }
    case 'execute': { need(a, 'intent'); out(await service.execute(a.intent, { actor: 'operator' })); break; }
    case 'reconcile': { need(a, 'intent'); out(await service.reconcile(a.intent, { rebroadcast: !!a.rebroadcast })); break; }
    case 'recover': out(await service.recover()); break;
    case 'status': need(a, 'intent'); out(service.publicStatus(a.intent)); break;
    case 'journal': out({ chain: store.verifyJournalChain(), entries: store.journal(a.intent) }); break;
    default: console.error(USAGE); process.exitCode = 64;
  }
}
main().catch(e => { console.error('ERROR:', e.code ?? '', e.message); process.exitCode = 1; });
