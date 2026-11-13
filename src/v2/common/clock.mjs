// Virtual clocks. The authoritative experiment clock is written ONLY by the supervisor
// (a file in a supervisor-owned directory); every other zone may read it but not write it.
// Readers refuse a clock that moves backwards (fail closed).
import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import { fail } from '../../v1/canonical.mjs';

export class MemoryClock {
  constructor(t0) { this.t = t0; }
  now() { return this.t; }
  advance(ms) { if (!(ms >= 0)) fail('CLOCK_BACKWARDS'); this.t += ms; return this.t; }
  set(t) { if (t < this.t) fail('CLOCK_BACKWARDS'); this.t = t; }
}

export class FileClockWriter {
  constructor(path, t0) { this.path = path; this.t = t0; this.#write(); }
  #write() { const tmp = this.path + '.tmp'; writeFileSync(tmp, String(this.t), { mode: 0o644 }); renameSync(tmp, this.path); }
  now() { return this.t; }
  advance(ms) { if (!(ms >= 0)) fail('CLOCK_BACKWARDS'); this.t += ms; this.#write(); return this.t; }
}

export class FileClockReader {
  constructor(path) { this.path = path; this.last = -Infinity; }
  now() {
    let t;
    try { t = Number(readFileSync(this.path, 'utf8')); } catch { fail('CLOCK_UNAVAILABLE'); }
    if (!Number.isSafeInteger(t) || t <= 0) fail('CLOCK_INVALID');
    if (t < this.last) fail('CLOCK_BACKWARDS');
    this.last = t;
    return t;
  }
}
