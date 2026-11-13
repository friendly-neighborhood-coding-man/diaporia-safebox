// Filesystem layout of an OS-isolated V2 deployment. Directory ownership/modes ARE the access policy.
import { join } from 'node:path';

export const USERS = Object.freeze({ ledger: 'sbx2-ledger', sens: 'sbx2-sens', sup: 'sbx2-sup', gen: 'sbx2-gen' });
export const GROUPS = Object.freeze(['sbx2-gzipc', 'sbx2-ctl', 'sbx2-lexec', 'sbx2-lread', 'sbx2-ladmin', 'sbx2-gtask']);
// Supplementary groups each principal runs with (decides which sockets it can reach).
export const PRINCIPAL_GROUPS = Object.freeze({
  ledger: [], sens: ['sbx2-lexec'], sup: ['sbx2-ctl', 'sbx2-lread', 'sbx2-ladmin', 'sbx2-gzipc'], gen: ['sbx2-gzipc', 'sbx2-gtask'],
});

export function layout(base) {
  const d = (...p) => join(base, ...p);
  return {
    base,
    dirs: [
      // [path, user, group, mode]
      [d('ledger'), USERS.ledger, USERS.ledger, 0o700],
      [d('sens'), USERS.sens, USERS.sens, 0o700],
      [d('sup'), USERS.sup, USERS.sup, 0o700],
      [d('gen'), USERS.gen, USERS.gen, 0o700],
      [d('pub'), 'root', 'root', 0o755],
      [d('pub', 'sens'), USERS.sens, USERS.sens, 0o755],
      [d('pub', 'sup'), USERS.sup, USERS.sup, 0o755],
      [d('conf'), 'root', 'root', 0o755],
      [d('sock'), 'root', 'root', 0o755],
      [d('sock', 'sens-gz'), USERS.sens, 'sbx2-gzipc', 0o2750],
      [d('sock', 'sens-ctl'), USERS.sens, 'sbx2-ctl', 0o2750],
      [d('sock', 'ledger-exec'), USERS.ledger, 'sbx2-lexec', 0o2750],
      [d('sock', 'ledger-read'), USERS.ledger, 'sbx2-lread', 0o2750],
      [d('sock', 'ledger-admin'), USERS.ledger, 'sbx2-ladmin', 0o2750],
      [d('sock', 'sup-task'), USERS.sup, 'sbx2-gtask', 0o2750],
      [d('sock', 'sup-wd'), USERS.sup, USERS.sup, 0o700],
    ],
    sensGz: d('sock', 'sens-gz', 'gz.sock'), sensCtl: d('sock', 'sens-ctl', 'ctl.sock'),
    ledgerExec: d('sock', 'ledger-exec', 'exec.sock'), ledgerRead: d('sock', 'ledger-read', 'read.sock'), ledgerAdmin: d('sock', 'ledger-admin', 'admin.sock'),
    supTask: d('sock', 'sup-task', 'task.sock'), supWd: d('sock', 'sup-wd', 'wd.sock'),
    ledgerDb: d('ledger', 'ledger.db'), sensDb: d('sens', 'sensitive.db'), sensKey: d('sens', 'executor.key'),
    ownerKeys: d('sup', 'owner.keys'), ownerLog: d('sup', 'owner-log.jsonl'), labels: d('sup', 'labels.jsonl'), freeze: d('sup', 'freeze.jsonl'),
    results: d('sup', 'results.json'), wdEvents: d('sup', 'watchdog-events.jsonl'),
    executorPub: d('pub', 'sens', 'executor.pub'), ownerPub: d('pub', 'sup', 'owner.pub.json'), clock: d('pub', 'sup', 'clock'),
    sensConf: d('conf', 'sensitive.json'), ledgerConf: d('conf', 'ledger.json'), runConf: d('conf', 'run.json'),
  };
}
