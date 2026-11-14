// Release Metadata Verifier against a real tuf-js client, using publisher-built repositories served over HTTP and
// mirrored by the untrusted Fetcher. Covers U01-U05 and U15 at the verifier layer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, copyFileSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { TufRepo } from '../../src/publisher/repo.mjs';
import { mirror } from '../../src/fetcher/fetcher.mjs';
import { verifyRelease, VerifyError } from '../../src/verifier/tuf.mjs';
import { sha256 } from '../../src/common/crypto.mjs';
import { makePackage, tmp, serveDir } from './helpers.mjs';

const DAY = 86400_000;
async function setup(t, opts = {}) {
  const d = tmp(t); const repo = new TufRepo(join(d, 'repo'), opts);
  const trust = join(d, 'trust'); mkdirSync(trust);
  writeFileSync(join(trust, 'root.json'), repo.initialRoot);                    // pinned at install time (out of band)
  const url = await serveDir(join(d, 'repo'), t);
  let n = 0;
  const run = async (name, extra = {}) => {
    const spool = join(d, `spool${n++}`);
    await mirror({ baseUrl: url, spoolDir: spool, targetName: name });
    return verifyRelease({ metadataDir: trust, spoolDir: spool, targetName: name, targetOut: join(d, `out-${n}`), ...extra });
  };
  return { d, repo, trust, run };
}
const release = (repo, v, pkg = makePackage({ version: v }).bytes) => { repo.addTarget(`app-${v}.tar`, pkg, { sstp: { version: v } }); return repo.publish(); };
const code = async (p, c) => { try { await p; assert.fail(`expected ${c}`); } catch (e) { assert.ok(e instanceof VerifyError, String(e)); assert.equal(e.code, c, e.message); } };

test('valid release verifies (threshold 2-of-3 targets)', async (t) => {
  const { repo, run } = await setup(t, { thresholds: { root: 2, targets: 2, snapshot: 1, timestamp: 1 }, keysPerRole: { root: 3, targets: 3, snapshot: 1, timestamp: 1 } });
  release(repo, 2);
  const r = await run('app-2.tar');
  assert.equal(r.version, 2); assert.equal(r.sha256, sha256(repo.readServed('targets/app-2.tar')));
});

test('U01 unsigned / wrong-key metadata is rejected', async (t) => {
  const { repo, run } = await setup(t);
  release(repo, 2);
  const ts = JSON.parse(repo.readServed('metadata/timestamp.json')); ts.signatures = [];
  repo.serveRaw('metadata/timestamp.json', Buffer.from(JSON.stringify(ts)));
  await code(run('app-2.tar'), 'TUF_BAD_SIGNATURE');
});

test('U01 targets signed below threshold is rejected', async (t) => {
  const { repo, run } = await setup(t, { thresholds: { root: 1, targets: 2, snapshot: 1, timestamp: 1 }, keysPerRole: { root: 1, targets: 2, snapshot: 1, timestamp: 1 } });
  repo.addTarget('app-2.tar', makePackage({ version: 2 }).bytes, { sstp: { version: 2 } });
  repo.publish({ signWith: { targets: repo.keys.targets.slice(0, 1) } });
  await code(run('app-2.tar'), 'TUF_BAD_SIGNATURE');
});

test('U02 signed metadata with tampered package bytes is rejected', async (t) => {
  const { repo, run } = await setup(t);
  release(repo, 2);
  const b = Buffer.from(repo.readServed('targets/app-2.tar')); b[600] ^= 1; repo.serveRaw('targets/app-2.tar', b);
  await code(run('app-2.tar'), 'TUF_HASH_MISMATCH');
  const longer = Buffer.concat([repo.readServed('targets/app-2.tar'), Buffer.alloc(512)]); repo.serveRaw('targets/app-2.tar', longer);
  await code(run('app-2.tar'), 'TUF_LENGTH_MISMATCH');
});

test('U03/U05 replay of older signed metadata after a newer one was seen is rejected (rollback)', async (t) => {
  const { repo, run } = await setup(t);
  const old = release(repo, 2);
  release(repo, 3);
  await run('app-3.tar');
  repo.serveRaw('metadata/timestamp.json', old.timestamp); repo.serveRaw('metadata/snapshot.json', old.snapshot); repo.serveRaw('metadata/targets.json', old.targets);
  await code(run('app-2.tar'), 'TUF_ROLLBACK');
});

test('U04 expired timestamp is rejected even when the client is offline (no exemption)', async (t) => {
  const { repo, run } = await setup(t);
  repo.addTarget('app-2.tar', makePackage({ version: 2 }).bytes, { sstp: { version: 2 } });
  repo.publish({ expires: { timestamp: Date.now() - DAY } });
  await code(run('app-2.tar'), 'TUF_EXPIRED');
});

test('U04 expired targets metadata is rejected', async (t) => {
  const { repo, run } = await setup(t);
  repo.addTarget('app-2.tar', makePackage({ version: 2 }).bytes, { sstp: { version: 2 } });
  repo.publish({ expires: { targets: Date.now() - DAY } });
  await code(run('app-2.tar'), 'TUF_EXPIRED');
});

test('U04 mix-and-match: new timestamp+snapshot with targets from another release is rejected', async (t) => {
  const { repo, run } = await setup(t);
  const a = release(repo, 2);
  release(repo, 3);
  repo.serveRaw('metadata/targets.json', a.targets);
  await code(run('app-2.tar'), 'TUF_ROLLBACK_OR_MIX');
});

test('U05 withheld metadata / target and freeze (server stops updating) are rejected', async (t) => {
  const { d, repo, run } = await setup(t);
  release(repo, 2);
  await code(run('app-9.tar'), 'TARGET_NOT_LISTED');
  // Withheld snapshot on a client that has none cached yet.
  const w = await setup(t); release(w.repo, 2); writeFileSync(join(w.d, 'repo/metadata/snapshot.json'), '');
  await code(w.run('app-2.tar'), 'TUF_HASH_MISMATCH');
  // Freeze: the server keeps serving a timestamp that has since expired.
  const fresh = await setup(t); fresh.repo.addTarget('app-2.tar', makePackage({ version: 2 }).bytes, { sstp: { version: 2 } });
  fresh.repo.publish({ expires: { timestamp: Date.now() + 1500 } });
  await fresh.run('app-2.tar');
  await new Promise(r => setTimeout(r, 2100));
  await code(fresh.run('app-2.tar'), 'TUF_EXPIRED');
});

test('target without sstp version is rejected', async (t) => {
  const { repo, run } = await setup(t);
  repo.addTarget('app-2.tar', makePackage({ version: 2 }).bytes); repo.publish();
  await code(run('app-2.tar'), 'TARGET_NO_VERSION');
});

test('U15 root rotation: accepted by plain TUF, refused by SSTP unless the owner approved that exact root digest', async (t) => {
  const { repo, run } = await setup(t);
  release(repo, 2);
  await run('app-2.tar');
  const newRoot = repo.rotateRoot(['root', 'targets', 'snapshot', 'timestamp']);   // publisher (or thief of root keys) rotates
  release(repo, 3);
  await code(run('app-3.tar'), 'ROOT_ROTATION_NOT_OWNER_APPROVED');
  const ok = await run('app-3.tar', { approvedRootDigests: [sha256(newRoot)] });
  assert.equal(ok.rootVersion, 2);
  // Baseline A (plain TUF, approvedRootDigests = null) accepts any correctly cross-signed rotation.
  const other = await setup(t); release(other.repo, 2); await other.run('app-2.tar');
  other.repo.rotateRoot(['root', 'targets', 'snapshot', 'timestamp']); release(other.repo, 3);
  assert.equal((await other.run('app-3.tar', { approvedRootDigests: null })).rootVersion, 2);
});

test('rotation not cross-signed by the old root keys is rejected even by plain TUF', async (t) => {
  const { repo, run } = await setup(t);
  release(repo, 2); await run('app-2.tar');
  const ownKeys = repo.keys.root; repo.keys.root = repo.keys.root.map(() => repo.constructor.prototype.constructor && ownKeys[0]);
  // Forge: new root 2 signed only by fresh keys.
  const { tufKey } = await import('../../src/publisher/repo.mjs');
  repo.keys.root = [tufKey()];
  repo.writeRoot({ signers: repo.keys.root });
  await code(run('app-2.tar', { approvedRootDigests: null }), 'TUF_BAD_SIGNATURE');
});
