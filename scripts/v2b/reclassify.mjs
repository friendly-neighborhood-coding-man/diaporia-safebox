#!/usr/bin/env node
// Re-runs ONLY the independent classifier on preserved campaign evidence (no attacker, no model, no re-execution),
// e.g. after a classifier correction. Writes classification-<tag>.json next to the original, which stays unchanged.
// Usage: sudo node scripts/v2b/reclassify.mjs <campaignDir> <tag>
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { layout } from '../../src/v2/launch/layout.mjs';
import { classify } from '../../src/v2b/classify.mjs';
const [dir, tag] = process.argv.slice(2);
const run = JSON.parse(readFileSync(join(dir, 'run.json'), 'utf8'));
const res = JSON.parse(readFileSync(join(dir, 'controller-results.json'), 'utf8'));
const trajectory = readFileSync(join(dir, 'trajectory.jsonl'), 'utf8').split('\n').filter(Boolean).map(JSON.parse);
const transcript = readFileSync(join(dir, 'transcript.jsonl'), 'utf8').split('\n').filter(Boolean).map(JSON.parse);
const L = layout(`/var/lib/sbx2/${run.runId}`);
if (!existsSync(L.sensKey)) { console.error('deployment directory with synthetic keys no longer exists'); process.exit(2); }
const secrets = { executorPrivateKey: JSON.parse(readFileSync(L.sensKey, 'utf8')).pkcs8,
  ...Object.fromEntries(Object.entries(JSON.parse(readFileSync(L.ownerKeys, 'utf8')).keys).map(([k, v]) => ['ownerPrivateKey:' + k, v])),
  fakeMetadataToken: 'SBX2-FAKE-ADMIN-TOKEN-' + run.runId.slice(-6), labelsFileLine: readFileSync(L.labels, 'utf8').split('\n')[0] };
const cap = readFileSync(L.ownerLog, 'utf8').split('\n').find(l => l.includes('"issuedAtMs"')); if (cap) secrets.ownerLogIssuedAtMs = '"issuedAtMs":' + JSON.parse(cap).issuedAtMs + '}';
const obs = [...trajectory.flatMap(t => (t.observations ?? []).map(o => o.result)), ...transcript.map(t => t.input)];
const cls = classify({ evaluation: res.result, decisions: res.decisions, trajectory, freezeRecords: res.freezeRecords, secrets, observationTexts: obs });
writeFileSync(join(dir, `classification-${tag}.json`), JSON.stringify({ reclassifiedAt: new Date().toISOString(), reason: process.argv[4] ?? null, ...cls }, null, 1));
console.log(JSON.stringify({ counts: cls.counts, credentialExposure: cls.credentialExposure }));
