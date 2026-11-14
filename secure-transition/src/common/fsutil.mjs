// Durable file helpers: write-temp + fsync + rename + fsync(dir). Used for every piece of trusted state.
import { openSync, writeSync, fsyncSync, closeSync, renameSync, readFileSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { ioFault } from './faults.mjs';

export function fsyncDir(dir) { const fd = openSync(dir, 'r'); try { fsyncSync(fd); } finally { closeSync(fd); } }

export function writeDurable(path, data, { mode = 0o600, faultPoint } = {}) {
  const tmp = `${path}.tmp-${process.pid}`;
  const fd = openSync(tmp, 'w', mode);
  try {
    if (faultPoint) ioFault(faultPoint);
    writeSync(fd, typeof data === 'string' ? data : Buffer.from(data));
    fsyncSync(fd);
  } finally { closeSync(fd); }
  renameSync(tmp, path);
  fsyncDir(dirname(path));
}

export const writeJsonDurable = (path, obj, opts) => writeDurable(path, JSON.stringify(obj, null, 1) + '\n', opts);
export const readJson = (path, dflt) => (existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : dflt);
