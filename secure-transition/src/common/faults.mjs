// Fault injection for the transition experiment (Adversary D). Only active when the env var is set by the harness.
//   SSTP_CRASH_AT=<point>        SIGKILL this process at that named point (process crash / power-loss model)
//   SSTP_FAULT=<point>:<CODE>    throw an fs-style error (EIO, ENOSPC) at that point
import { appendFileSync } from 'node:fs';
export function crashPoint(name) {
  if (process.env.SSTP_CRASH_AT === name) {
    if (process.env.SSTP_CRASH_LOG) try { appendFileSync(process.env.SSTP_CRASH_LOG, name + '\n'); } catch { /* best effort */ }
    process.kill(process.pid, 'SIGKILL');
  }
}
export function ioFault(name) {
  const f = process.env.SSTP_FAULT;
  if (f && f.split(':')[0] === name) { const e = new Error(`injected ${f}`); e.code = f.split(':')[1] || 'EIO'; e.injected = true; throw e; }
}
