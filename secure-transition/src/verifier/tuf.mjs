// Release Metadata Verifier. Runs the tuf-js client (TUF client workflow 5.x) OFFLINE against the fetched spool, using
// the controller's locally persisted trust state (metadataDir). It never executes package-supplied code.
// SSTP additions on top of TUF: (1) any new N.root.json must have an owner-approved digest (rootGate), (2) the target's
// custom.sstp.version must be present. Expiry is checked against the real clock; offline is never an exemption.
import { createRequire } from 'node:module';
import { existsSync, readFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { sha256 } from '../common/crypto.mjs';
const require = createRequire(import.meta.url);
const { Updater, BaseFetcher } = require('tuf-js');
const tufErrors = require('tuf-js/dist/error.js');

const BASE = 'http://spool.invalid';

class SpoolFetcher extends BaseFetcher {
  constructor(spoolDir, rootGate) { super(); this.spoolDir = spoolDir; this.rootGate = rootGate; this.served = []; }
  async fetch(url) {
    const u = new URL(url);
    if (u.host !== 'spool.invalid') throw new tufErrors.DownloadHTTPError('foreign url', 403);
    const rel = decodeURIComponent(u.pathname).replace(/^\//, '');
    if (!/^(metadata\/[0-9]+\.root\.json|metadata\/(timestamp|snapshot|targets)\.json|targets\/[A-Za-z0-9._-]+)$/.test(rel)) throw new tufErrors.DownloadHTTPError('bad path', 403);
    const p = join(this.spoolDir, rel);
    if (!existsSync(p)) throw new tufErrors.DownloadHTTPError('not in spool', 404);
    const bytes = readFileSync(p);
    if (/\.root\.json$/.test(rel) && this.rootGate) this.rootGate(rel, bytes);
    this.served.push(rel);
    return new Blob([bytes]).stream();
  }
}

export class VerifyError extends Error { constructor(code, detail) { super(`${code}: ${detail}`); this.code = code; this.detail = detail; } }

function classify(e) {
  if (e instanceof VerifyError) return e;
  const n = e?.constructor?.name ?? 'Error';
  const map = { ExpiredMetadataError: 'TUF_EXPIRED', EqualVersionError: 'TUF_ROLLBACK', BadVersionError: 'TUF_ROLLBACK', UnsignedMetadataError: 'TUF_BAD_SIGNATURE', LengthOrHashMismatchError: 'TUF_HASH_MISMATCH', DownloadLengthMismatchError: 'TUF_LENGTH_MISMATCH', DownloadHTTPError: 'TUF_MISSING_FILE', RepositoryError: 'TUF_REPOSITORY_ERROR' };
  const m = String(e?.message ?? '');
  const byMsg = /expired/i.test(m) ? 'TUF_EXPIRED' : /version/i.test(m) ? 'TUF_ROLLBACK_OR_MIX' : /signature|threshold|signed by/i.test(m) ? 'TUF_BAD_SIGNATURE' : /hash|length/i.test(m) ? 'TUF_HASH_MISMATCH' : /not in spool|not found/i.test(m) ? 'TUF_MISSING_FILE' : null;
  return new VerifyError(map[n] && n !== 'RuntimeError' ? map[n] : (byMsg ?? map[n] ?? 'TUF_ERROR'), `${n}: ${m}`);
}

/**
 * opts: { metadataDir (trusted, must contain root.json), spoolDir, targetName, targetOut, approvedRootDigests?: string[] | null }
 * approvedRootDigests === null disables the owner root pin (Baseline A = plain TUF).
 */
export async function verifyRelease({ metadataDir, spoolDir, targetName, targetOut, approvedRootDigests = [] }) {
  if (!existsSync(join(metadataDir, 'root.json'))) throw new VerifyError('NO_TRUST_ANCHOR', metadataDir);
  const rootGate = approvedRootDigests === null ? null : (rel, bytes) => {
    const d = sha256(bytes);
    if (!approvedRootDigests.includes(d)) throw new VerifyError('ROOT_ROTATION_NOT_OWNER_APPROVED', `${rel} ${d}`);
  };
  const fetcher = new SpoolFetcher(spoolDir, rootGate);
  mkdirSync(metadataDir, { recursive: true });
  const up = new Updater({ metadataDir, metadataBaseUrl: `${BASE}/metadata/`, targetBaseUrl: `${BASE}/targets/`, fetcher, config: { maxRootRotations: 8 } });
  let info;
  try {
    await up.refresh();
    info = await up.getTargetInfo(targetName);
    if (!info) throw new VerifyError('TARGET_NOT_LISTED', targetName);
    const ver = info.custom?.sstp?.version;
    if (!Number.isSafeInteger(ver)) throw new VerifyError('TARGET_NO_VERSION', targetName);
    if (targetOut) await up.downloadTarget(info, targetOut);
  } catch (e) { throw classify(e); }
  const rootVersion = JSON.parse(readFileSync(join(metadataDir, 'root.json'), 'utf8')).signed.version;
  return { targetName, version: info.custom.sstp.version, sha256: info.hashes.sha256, length: info.length, rootVersion, served: fetcher.served };
}
