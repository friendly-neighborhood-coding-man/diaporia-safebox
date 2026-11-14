// Publisher-side TUF repository builder (test fixture AND adversary tool: Adversary B holds all of these keys).
// Metadata objects and signatures are produced through @tufjs/models, so the signed bytes are exactly what tuf-js checks.
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { sign as edSign, createPrivateKey } from 'node:crypto';
import { newKeyPair, canon, sha256 } from '../common/crypto.mjs';
const require = createRequire(import.meta.url);
const { Metadata, Signature, MetadataKind } = require('@tufjs/models');

const ROLES = ['root', 'targets', 'snapshot', 'timestamp'];
const DAY = 86400_000;
export const iso = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');

export function tufKey() {
  const kp = newKeyPair();
  const json = { keytype: 'ed25519', scheme: 'ed25519', keyval: { public: kp.publicRawHex } };
  return { ...kp, keyId: sha256(canon(json)), json };
}

function signMd(kind, signedJson, keys) {
  const md = Metadata.fromJSON(kind, { signed: signedJson, signatures: [] });
  for (const k of keys) md.sign((data) => new Signature({ keyID: k.keyId, sig: edSign(null, data, createPrivateKey(k.privatePem)).toString('hex') }), true);
  return Buffer.from(JSON.stringify(md.toJSON()));
}

/**
 * A TUF repository with consistent_snapshot=false, laid out as served over HTTP:
 *   <dir>/metadata/{N.root.json, timestamp.json, snapshot.json, targets.json}, <dir>/targets/<name>
 * thresholds: e.g. { root: 2, targets: 2, snapshot: 1, timestamp: 1 }.
 */
export class TufRepo {
  constructor(dir, { thresholds = { root: 1, targets: 1, snapshot: 1, timestamp: 1 }, keysPerRole = { root: 1, targets: 1, snapshot: 1, timestamp: 1 }, now = Date.now() } = {}) {
    this.dir = dir; this.now = now; this.thresholds = { ...thresholds };
    mkdirSync(join(dir, 'metadata'), { recursive: true }); mkdirSync(join(dir, 'targets'), { recursive: true });
    this.keys = Object.fromEntries(ROLES.map(r => [r, Array.from({ length: keysPerRole[r] ?? 1 }, tufKey)]));
    this.versions = { root: 0, targets: 0, snapshot: 0, timestamp: 0 };
    this.targets = {};
    this.history = []; // every published metadata byte string, for replay/mix-and-match attacks
    this.writeRoot();
  }
  rootSigned(version, expires) {
    const keys = {}; const roles = {};
    for (const r of ROLES) { for (const k of this.keys[r]) keys[k.keyId] = k.json; roles[r] = { keyids: this.keys[r].map(k => k.keyId), threshold: this.thresholds[r] }; }
    return { _type: 'root', spec_version: '1.0.31', version, expires: iso(expires), consistent_snapshot: false, keys, roles };
  }
  /** Write N.root.json signed by `signers` (default: current root keys; rotation passes old+new). */
  writeRoot({ expires = this.now + 365 * DAY, signers } = {}) {
    const v = ++this.versions.root;
    const bytes = signMd(MetadataKind.Root, this.rootSigned(v, expires), (signers ?? this.keys.root).slice(0, Math.max(this.thresholds.root, (signers ?? this.keys.root).length)));
    writeFileSync(join(this.dir, 'metadata', `${v}.root.json`), bytes);
    this.history.push({ role: 'root', version: v, bytes });
    if (v === 1) this.initialRoot = bytes;
    return bytes;
  }
  /** Rotate root (and optionally other roles') keys. New root is signed by the old root keys and the new ones (TUF 5.3.4). */
  rotateRoot(newRoles = ['root']) {
    const oldRootKeys = this.keys.root;
    for (const r of newRoles) this.keys[r] = this.keys[r].map(() => tufKey());
    return this.writeRoot({ signers: [...oldRootKeys, ...this.keys.root] });
  }
  addTarget(name, bytes, custom) {
    writeFileSync(join(this.dir, 'targets', name), bytes);
    this.targets[name] = { length: bytes.length, hashes: { sha256: sha256(bytes) }, ...(custom ? { custom } : {}) };
  }
  removeTarget(name) { delete this.targets[name]; }
  /** Publish targets -> snapshot -> timestamp. expires: { targets, snapshot, timestamp } absolute ms. */
  publish({ expires = {}, signWith = {} } = {}) {
    const e = { targets: this.now + 30 * DAY, snapshot: this.now + 7 * DAY, timestamp: this.now + DAY, ...expires };
    const tv = ++this.versions.targets;
    const t = signMd(MetadataKind.Targets, { _type: 'targets', spec_version: '1.0.31', version: tv, expires: iso(e.targets), targets: structuredClone(this.targets) }, signWith.targets ?? this.keys.targets);
    const sv = ++this.versions.snapshot;
    const s = signMd(MetadataKind.Snapshot, { _type: 'snapshot', spec_version: '1.0.31', version: sv, expires: iso(e.snapshot), meta: { 'targets.json': { version: tv } } }, signWith.snapshot ?? this.keys.snapshot);
    const tsv = ++this.versions.timestamp;
    const ts = signMd(MetadataKind.Timestamp, { _type: 'timestamp', spec_version: '1.0.31', version: tsv, expires: iso(e.timestamp), meta: { 'snapshot.json': { version: sv, length: s.length, hashes: { sha256: sha256(s) } } } }, signWith.timestamp ?? this.keys.timestamp);
    const md = join(this.dir, 'metadata');
    writeFileSync(join(md, 'targets.json'), t); writeFileSync(join(md, 'snapshot.json'), s); writeFileSync(join(md, 'timestamp.json'), ts);
    const snap = { targets: t, snapshot: s, timestamp: ts, versions: { targets: tv, snapshot: sv, timestamp: tsv } };
    this.history.push({ role: 'release', ...snap });
    return snap;
  }
  /** Overwrite served files directly (compromised server / replay). */
  serveRaw(rel, bytes) { writeFileSync(join(this.dir, rel), bytes); }
  readServed(rel) { return existsSync(join(this.dir, rel)) ? readFileSync(join(this.dir, rel)) : null; }
}
