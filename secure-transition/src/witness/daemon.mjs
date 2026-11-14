import { readFileSync } from 'node:fs';
import { serve, call } from '../common/ipc.mjs';
import { Witness } from './witness.mjs';
const cfg = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const W = new Witness({ dir: cfg.dir, paths: cfg.paths, authorityStatus: async () => { const r = await call(cfg.authAppSock, 'status'); if (!r.ok) throw new Error('AUTHORITY_STATUS'); return r.status; } });
const T = { baseline: (p) => W.baseline(p), checkCandidate: (p) => W.checkCandidate(p), attestReady: (p) => W.attestReady(p), log: () => ({ ok: true, records: W.log.records.length }) };
await serve(cfg.sock, async (m, p) => (Object.hasOwn(T, m) ? T[m](p) : { ok: false, error: 'METHOD_NOT_ALLOWED' }), { mode: 0o660, gid: cfg.ctlGid });
process.stdout.write('WITNESS_READY\n');
