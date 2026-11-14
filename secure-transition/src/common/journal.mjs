// Append-only, hash-chained, fsync'd journal. A torn last line (power loss mid-write) is dropped and reported; a broken
// link anywhere before the tail is tampering and makes read() report `tampered`, which the controller maps to SAFE_HOLD.
import { openSync, writeSync, fsyncSync, closeSync, readFileSync, existsSync, truncateSync } from 'node:fs';
import { digestObj } from './crypto.mjs';
import { ioFault } from './faults.mjs';

const GENESIS = '0'.repeat(64);

export function readJournal(path) {
  if (!existsSync(path)) return { records: [], torn: false, tampered: false };
  const raw = readFileSync(path, 'utf8');
  const lines = raw.split('\n');
  const records = []; let prev = GENESIS; let offset = 0; let torn = false; let tampered = false; let goodBytes = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isLast = i === lines.length - 1;
    if (line === '' && isLast) break;
    let rec = null;
    try { rec = JSON.parse(line); } catch { /* torn or garbage */ }
    const ok = rec && rec.prev === prev && rec.seq === records.length && rec.h === digestObj({ seq: rec.seq, prev: rec.prev, state: rec.state, data: rec.data, at: rec.at });
    if (!ok) {
      // Torn tail: the bad line is the last non-empty line and (raw does not end with \n there, or it is unparsable).
      const restNonEmpty = lines.slice(i + 1).some(l => l !== '');
      if (!restNonEmpty && (rec === null || isLast)) torn = true; else tampered = true;
      break;
    }
    records.push(rec); prev = rec.h; offset += line.length + 1; goodBytes = offset;
  }
  return { records, torn, tampered, goodBytes };
}

export class Journal {
  constructor(path) {
    this.path = path;
    const r = readJournal(path);
    if (r.torn) truncateSync(path, r.goodBytes);
    this.records = r.records; this.tornOnOpen = r.torn; this.tampered = r.tampered;
  }
  get last() { return this.records.at(-1) ?? null; }
  append(state, data = {}, { faultPoint } = {}) {
    if (this.tampered) throw Object.assign(new Error('JOURNAL_TAMPERED'), { code: 'JOURNAL_TAMPERED' });
    const seq = this.records.length; const prev = this.last?.h ?? GENESIS; const at = new Date().toISOString();
    const rec = { seq, prev, state, data, at, h: digestObj({ seq, prev, state, data, at }) };
    const fd = openSync(this.path, 'a', 0o600);
    try {
      if (faultPoint) ioFault(faultPoint);
      writeSync(fd, JSON.stringify(rec) + '\n');
      fsyncSync(fd);
    } finally { closeSync(fd); }
    this.records.push(rec);
    return rec;
  }
}
