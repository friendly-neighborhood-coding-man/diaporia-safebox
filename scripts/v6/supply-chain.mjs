// V6 hardening P1.9 (issue #14): offline supply-chain checks. Local tool, not CI, and not a substitute for a maintained
// scanner (gitleaks / npm audit need tools or network this environment does not have).
//   node scripts/v6/supply-chain.mjs [outDir]
// 1. lockfiles: v3, every installed package carries an integrity hash, direct dependencies pinned to exact versions.
// 2. secret scan of git-tracked files: private keys, Google OAuth client secrets / tokens, GitHub / AWS / Slack tokens.
// 3. CycloneDX SBOMs from both lockfiles (npm sbom --package-lock-only), plus their SHA-256.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

export const SECRET_PATTERNS = [
  ['PRIVATE_KEY_BLOCK', /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/],
  ['GOOGLE_OAUTH_CLIENT_SECRET', /GOCSPX-[A-Za-z0-9_-]{20,}/],
  ['GOOGLE_ACCESS_TOKEN', /ya29\.[A-Za-z0-9_-]{20,}/],
  ['GOOGLE_REFRESH_TOKEN', /\b1\/\/0[A-Za-z0-9_-]{30,}/],
  ['GITHUB_TOKEN', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}/],
  ['AWS_ACCESS_KEY', /\bAKIA[0-9A-Z]{16}\b/],
  ['SLACK_TOKEN', /\bxox[abpors]-[A-Za-z0-9-]{10,}/],
  ['JSON_CLIENT_SECRET', /"client_secret"\s*:\s*"[^"]{8,}"/],
  ['JSON_REFRESH_TOKEN', /"refresh_token"\s*:\s*"[^"]{8,}"/],
  ['JWK_PRIVATE_KEY', /"d"\s*:\s*"[A-Za-z0-9_-]{32,}"/],
];
// Strip the wrappers key material appears in inside source and config: quotes, escaped newlines, '+' concatenation,
// commas, indentation. Then require base64 (40+ chars) or a legacy encryption header within the next lines.
const unwrap = (l) => l.replace(/\\[nr]/g, '').replace(/^[\s'"`+,]+|[\s'"`+,;]+$/g, '');
function keyMaterialFollows(ls, i) {
  const after = ls[i].split(/PRIVATE KEY(?: BLOCK)?-----/)[1] ?? '';
  if (/[A-Za-z0-9+/=]{40,}/.test(after.replace(/\\[nr]/g, ''))) return true; // single-line (escaped \n) form
  for (const l of ls.slice(i + 1, i + 6).map(unwrap)) { if (/^[A-Za-z0-9+/=]{40,}$/.test(l) || /^Proc-Type:\s*4,ENCRYPTED/.test(l)) return true; }
  return false;
}
/** Scan text; returns [{rule, line}] (the matched value itself is never returned or printed). */
export function scanText(text) {
  const out = [];
  const ls = text.split(/\r?\n/);
  ls.forEach((l, i) => { for (const [rule, re] of SECRET_PATTERNS) {
    if (!re.test(l)) continue;
    // a key header only counts with key material after it (tests legitimately mention the header string)
    if (rule === 'PRIVATE_KEY_BLOCK' && !keyMaterialFollows(ls, i)) continue;
    out.push({ rule, line: i + 1 });
  } });
  return out;
}
export function checkLock(path) {
  const l = JSON.parse(readFileSync(path, 'utf8')); const problems = [];
  if (l.lockfileVersion !== 3) problems.push('lockfileVersion ' + l.lockfileVersion);
  const pk = Object.entries(l.packages ?? {}).filter(([k]) => k);
  for (const [k, v] of pk) if (!v.integrity && !v.link) problems.push('no integrity: ' + k);
  const root = l.packages?.[''] ?? {};
  for (const [n, r] of Object.entries({ ...(root.dependencies ?? {}), ...(root.devDependencies ?? {}) })) if (!/^\d+\.\d+\.\d+$/.test(r)) problems.push(`not pinned: ${n}@${r}`);
  return { path, packages: pk.length, problems };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const out = process.argv[2] ?? 'docs/evidence/v6-hardening/supply-chain';
  mkdirSync(out, { recursive: true });
  const locks = ['package-lock.json', 'integrations/external-interactor/package-lock.json'].filter(existsSync).map(checkLock);
  const files = execFileSync('git', ['ls-files', '-z']).toString().split('\0').filter(Boolean).filter((f) => !/\.(png|jpg|mp4|webm|gif|ico)$/i.test(f));
  const findings = [];
  for (const f of files) { let t; try { t = readFileSync(f, 'utf8'); } catch { continue; } for (const x of scanText(t)) findings.push({ file: f, ...x }); }
  const sbomOf = (cwd) => execFileSync('npm', ['sbom', '--sbom-format', 'cyclonedx', '--package-lock-only'], { cwd, maxBuffer: 64 << 20 }).toString();
  const sbom = sbomOf('.'); writeFileSync(join(out, 'sbom.cdx.json'), sbom);
  const ix = 'integrations/external-interactor';
  const sbomIx = existsSync(join(ix, 'package-lock.json')) ? sbomOf(ix) : null; if (sbomIx) writeFileSync(join(out, 'sbom-external-interactor.cdx.json'), sbomIx);
  const report = { generatedBy: 'scripts/v6/supply-chain.mjs', commit: execFileSync('git', ['rev-parse', 'HEAD']).toString().trim(), scope: 'LOCAL run (not CI)',
    locks, secretScan: { files: files.length, findings }, sbom: { file: 'sbom.cdx.json', sha256: createHash('sha256').update(sbom).digest('hex'), components: JSON.parse(sbom).components?.length ?? 0,
      externalInteractor: sbomIx && { file: 'sbom-external-interactor.cdx.json', sha256: createHash('sha256').update(sbomIx).digest('hex'), components: JSON.parse(sbomIx).components?.length ?? 0 } },
    notRun: ['npm audit / advisory database (needs network)', 'build provenance / reproducible build attestation (no CI runner)'] };
  writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 1) + '\n');
  console.log(JSON.stringify({ locks: locks.map((l) => [l.path, l.packages, l.problems.length]), secretFindings: findings.length, sbomComponents: report.sbom.components }));
  process.exit(findings.length || locks.some((l) => l.problems.length) ? 1 : 0);
}
