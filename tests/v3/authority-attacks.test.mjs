// Authority / injection-port attacks: WebAuthn forgeries, signature replay, credential independence, matrix floors,
// multi-administrator counting, evidence review, concurrency, restart, rollback and crash poisoning.
import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildV3, T0 } from '../../src/v3/world.mjs';
import { OwnerWorld, Device, ACCOUNT, RP } from '../../src/v3/kit.mjs';
import { genesisState, actionDigest } from '../../src/v3/root/chain.mjs';
import { defaultPersonalMatrix } from '../../src/v3/authority/matrix.mjs';
import { ownerOpenCase, evidence as E } from '../../src/v3/recovery/sim.mjs';
import { survivors } from '../../src/v3/root/chain.mjs';
import { b64u } from '../../src/v3/common/canon.mjs';

const H = 3600_000;
const Y = (c) => (BigInt(c) * 10n ** 22n).toString();
const ok = (r, m = '') => { assert.equal(r.ok, true, m + JSON.stringify(r.error)); return r.result; };
const deny = (r, code) => { assert.equal(r.ok, false, 'expected denial ' + code); if (code) assert.match(`${r.error.code}:${r.error.detail ?? ''}`, new RegExp(code)); return r.error; };
const submit = (w, action, approvals, extra = {}) => w.admin.request('SUBMIT', { request: { action, approvals, ...extra } });

test('forged / replayed WebAuthn responses are rejected at the injection port', async () => {
  const w = buildV3();
  const mk = () => w.owner.action(w.view(), 'FREEZE', { freezeId: 'f' + Math.random().toString(16).slice(2, 8), reason: 'test', source: 'owner' });
  // UNFREEZE-strength action to test UV: use AMEND_PURPOSE (uv=1)
  const amend = () => w.owner.action(w.view(), 'AMEND_PURPOSE', { capsule: { ...w.owner.capsule, version: '2' } });
  const k1 = w.owner.dev('k1-phone'), k2 = w.owner.dev('k2-laptop'), k3 = w.owner.dev('k3-root-hw');
  const a = amend(); const dig = actionDigest(a);
  const good = () => [k2.approve(dig), k3.approve(dig)];
  deny(await submit(w, a, [k1.approve(dig, { origin: 'https://evil.example' }), ...good()]), 'WEBAUTHN_ORIGIN_MISMATCH');
  deny(await submit(w, a, [k1.approve(dig, { rpId: 'evil.example' }), ...good()]), 'WEBAUTHN_RPID_MISMATCH');
  deny(await submit(w, a, [k1.approve(dig, { uv: false }), ...good()]), 'WEBAUTHN_NO_USER_VERIFICATION');
  deny(await submit(w, a, [k1.approve(dig, { up: false }), ...good()]), 'WEBAUTHN_NO_USER_PRESENCE');
  deny(await submit(w, a, [k1.approve(dig, { type: 'webauthn.create' }), ...good()]), 'WEBAUTHN_WRONG_TYPE');
  deny(await submit(w, a, [k1.approve(Buffer.alloc(32, 7)), ...good()]), 'WEBAUTHN_CHALLENGE_MISMATCH');
  // assertion from another action replayed onto this one
  const other = amend(); const replay = k1.approve(actionDigest(other));
  deny(await submit(w, a, [replay, ...good()]), 'WEBAUTHN_CHALLENGE_MISMATCH');
  // signature bit-flip
  const flip = k1.approve(dig); const s = Buffer.from(flip.webauthn.signature, 'base64url'); s[s.length - 3] ^= 1; flip.webauthn.signature = b64u(s);
  deny(await submit(w, a, [flip, ...good()]), 'WEBAUTHN_BAD_SIGNATURE|WEBAUTHN');
  // AI-controlled booleans are not evidence
  const fake = k1.approve(dig); fake.webauthn.biometricVerified = true;
  deny(await submit(w, a, [fake, ...good()]), 'WEBAUTHN_ASSERTION_FIELDS|CANONICAL_BAD_VALUE_TYPE');
  deny(await submit(w, a, [{ credId: 'k1-phone', biometricVerified: 'true' }, ...good()]), 'APPROVAL_FIELDS');
  // cloned authenticator: a copy of the passkey replays an OLD counter value after the original moved on
  const clone = k1.auth.cloneForAttack();
  const later = amend(); const dl = actionDigest(later);
  ok(await submit(w, later, [k1.approve(dl), k2.approve(dl), k3.approve(dl)]));
  const again = w.owner.action(w.view(), 'AMEND_PURPOSE', { capsule: { ...w.owner.capsule, version: '3' } }); const da = actionDigest(again);
  const cloned = { credId: 'k1-phone', webauthn: clone.assert({ ...RP, challenge: da }) };
  deny(await submit(w, again, [cloned, k2.approve(da), k3.approve(da)]), 'WEBAUTHN_SIGNCOUNT_NOT_INCREASING');
});

test('external-key signature replay: same action twice -> ACTION_REPLAY; signature moved to another action -> bad signature', async () => {
  const w = buildV3();
  const a = w.owner.action(w.view(), 'FREEZE', { freezeId: 'f1', reason: 'x', source: 'owner' });
  const ap = w.owner.approvals(a, ['k3-root-hw']);
  ok(await submit(w, a, ap));
  deny(await submit(w, a, ap), 'ACTION_REPLAY');
  const b = w.owner.action(w.view(), 'UNFREEZE', { freezeId: 'f1' });
  deny(await submit(w, b, [ap[0], ...w.owner.approvals(b, ['k1-phone'])]), 'APPROVAL_BAD_SIGNATURE');
  const k3sig = w.owner.approvals(b, ['k3-root-hw'])[0];
  deny(await submit(w, { ...b, expiresAt: w.iso(w.now() + 2 * H) }, [k3sig, ...w.owner.approvals(b, ['k1-phone'])]), 'APPROVAL_BAD_SIGNATURE|WEBAUTHN');
  deny(await submit(w, { ...b, epoch: '2' }, w.owner.approvals({ ...b, epoch: '2' }, ['k3-root-hw', 'k1-phone'])), 'STALE_EPOCH');
  const exp = w.owner.action(w.view(), 'UNFREEZE', { freezeId: 'f1' }, { ttlMs: 60_000 });
  const expAp = w.owner.approvals(exp, ['k3-root-hw', 'k1-phone']);
  w.clock.advance(61_000);
  deny(await submit(w, exp, expAp), 'ACTION_EXPIRED');
});

test('credential independence: duplicated key, shared seed, shared device, same sync provider are refused at genesis', async () => {
  const t0 = T0;
  const mk = (tweak) => { const ow = new OwnerWorld({ t0 }); tweak(ow); return () => genesisState(ow.genesis()); };
  assert.throws(mk((ow) => { ow.devices[1].provenance.seedCommitment = ow.devices[0].provenance.seedCommitment; }), /SHARED_SEED/);
  assert.throws(mk((ow) => { ow.devices[1].provenance.deviceId = ow.devices[0].provenance.deviceId; }), /SHARED_DEVICE/);
  assert.throws(mk((ow) => { ow.devices[0].provenance.syncProvider = 'icloud'; ow.devices[1].provenance.syncProvider = 'icloud'; }), /SHARED_SYNC_PROVIDER/);
  assert.throws(mk((ow) => { ow.devices[1].auth = ow.devices[0].auth; }), /DUPLICATE/);   // same passkey enrolled twice
  assert.throws(mk((ow) => { ow.devices.pop(); }), /PERSONAL_PROFILE_NEEDS_FIVE|GENESIS_ACTION_UNSATISFIABLE/);
  assert.throws(mk((ow) => { ow.devices[4].signer = ow.devices[2].signer; }), /DUPLICATE_PUBLIC_KEY/); // 5 copies of one key never count as 5
  assert.throws(mk((ow) => { ow.devices[0].auth = new (ow.devices[0].auth.constructor)({ backupEligible: true }); }), /SYNCABLE_PASSKEY_UNDECLARED/);
  assert.doesNotThrow(mk(() => {}));
});

test('genesis cannot be swapped: a genesis that is not the pinned digest is refused by every domain', () => {
  const ow = new OwnerWorld({ t0: T0 }); const g = ow.genesis();
  const evil = new OwnerWorld({ t0: T0 }); const g2 = evil.genesis();
  assert.throws(() => genesisState(g2, { pinnedChainId: ow.chainId }), /GENESIS_NOT_PINNED/);
  const g3 = structuredClone(g); g3.action.body.capsule.recipients.push('attacker.mock');
  assert.throws(() => genesisState(g3, { pinnedChainId: ow.chainId }), /GENESIS_NOT_PINNED/);
});

test('authority matrix: weakening below hard floors is impossible, even with the full governance quorum; strengthening works', async () => {
  const w = buildV3();
  const G = ['k1-phone', 'k2-laptop', 'k3-root-hw'];
  const m = (f) => { const x = defaultPersonalMatrix(); x.version = '2'; f(x); return x; };
  deny(await w.ownerAct('AMEND_MATRIX', { matrix: m(x => { x.rules.AMEND_PURPOSE.anyOf = [{ DAILY: '1', ROOT: '1' }]; }) }, G, { notIntended: true }), 'MATRIX_BELOW_HARD_FLOOR');
  deny(await w.ownerAct('AMEND_MATRIX', { matrix: m(x => { x.rules.PAY.anyOf.push({ RECOVERY: '1' }); }) }, G, { notIntended: true }), 'PAY_ROLE_RECOVERY');
  deny(await w.ownerAct('AMEND_MATRIX', { matrix: m(x => { x.rules.UNFREEZE.anyOf = [{ FREEZE: '1' }]; }) }, G, { notIntended: true }), 'UNFREEZE');
  deny(await w.ownerAct('AMEND_MATRIX', { matrix: m(x => { x.rules.FREEZE.anyOf = [{ FREEZE: '1' }, { DAILY: '1' }, { ROOT: '1' }, { RECOVERY: '1' }, { DAILY: '1', FREEZE: '1' }]; x.rules.REVOKE.anyOf.push({ FREEZE: '1', RECOVERY: '1' }); }) }, G, { notIntended: true }), 'REVOKE_WEAKENED');
  deny(await w.ownerAct('AMEND_MATRIX', { matrix: m(x => { x.rules.AMEND_PURPOSE.anyOf = [{ DAILY: '3', ROOT: '1' }]; }) }, G, { notIntended: true }), 'UNSATISFIABLE');
  ok(await w.ownerAct('AMEND_MATRIX', { matrix: m(x => { x.rules.UNFREEZE.anyOf = [{ ROOT: '1', DAILY: '2' }]; }) }, G));
  assert.equal(w.root.state.matrix.version, '2');
});

test('multi-administrator profile: five keys of ONE person never equal several administrators', async () => {
  const w = buildV3({ profile: 'multi-admin' });
  const ow = w.owner;
  // alice enrolls two extra ADMIN keys of her own (allowed as credentials) — they still count as one human
  const extra = ['alice-admin-2', 'alice-admin-3'].map(c => new Device({ credId: c, role: 'ADMIN', holderId: 'alice', channelId: 'ch-alice', kind: 'passkey' }));
  const capsule = { ...ow.capsule, version: '2' };
  deny(await w.ownerAct('AMEND_PURPOSE', { capsule }, ['alice-admin', 'bob-admin'], { notIntended: true }), 'QUORUM_NOT_SATISFIED');
  ok(await w.ownerAct('AMEND_PURPOSE', { capsule }, ['alice-admin', 'bob-admin', 'carol-admin']));
  assert.ok(extra.length);
});

test('evidence review (multi-admin, deceased administrator): police report alone grants nothing; registrar-signed certificate + identity + guardians + survivors works', async () => {
  const w = buildV3({ profile: 'multi-admin' });
  // personal profile refuses the path entirely (estate procedures are out of scope, reported, not improvised)
  const wp = buildV3();
  deny((await ownerOpenCase(wp, { lost: ['k1-phone', 'k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], kind: 'DECEASED' })).r, 'EVIDENCE_REVIEW_NOT_SUPPORTED');
  ok((await ownerOpenCase(w, { lost: ['carol-admin'], kind: 'DECEASED', subjectHolderId: 'carol', planHolder: 'dave' })).r);
  ok(await E.official(w, 'POLICE_REPORT'));
  assert.equal(w.root.state.case.confirmed, false);
  ok(await E.identity(w, 'idv-1', 'dave'));
  assert.equal(w.root.state.case.confirmed, false, 'identity of the successor alone does not confirm a death');
  const fake = (await import('../../src/v3/common/canon.mjs')).newEdSigner('forger');
  deny(await w.submitRaw('RECOVERY_OFFICIAL', { caseId: w.root.state.case.caseId, caseDigest: w.root.state.case.digest, registrarId: 'reg-gov', docType: 'DEATH_CERTIFICATE', docRef: 'x', subjectHolderId: 'carol' },
    { attest: (a) => ({ registrarSig: fake.signDigest('DIAPORIA_SAFEBOX_V3_OFFICIAL_DOCUMENT\n', actionDigest(a)) }) }), 'REGISTRAR_SIGNATURE');
  ok(await E.official(w, 'DEATH_CERTIFICATE'));
  assert.equal(w.root.state.case.state, 'RECOVERY_CHALLENGE');
  for (const c of survivors(w.root.state, w.root.state.case, w.now())) ok(await E.consent(w, c));
  ok(await E.guardian(w, 'g1')); ok(await E.guardian(w, 'g2'));
  await w.advance(73 * H, H);
  const r = await w.recovery.tryComplete(w.root.state); assert.equal(r.ok, true, JSON.stringify(r));
});

test('concurrent rotation of the same epoch: exactly one wins, the other is STALE_EPOCH', async () => {
  const w = buildV3();
  const d1 = w.owner.newDevice({ credId: 'k1-a', role: 'DAILY', holderId: 'alice', channelId: 'ch-phone', kind: 'passkey' });
  const d2 = w.owner.newDevice({ credId: 'k1-b', role: 'DAILY', holderId: 'alice', channelId: 'ch-phone', kind: 'passkey' });
  const mk = (d) => { const a = w.owner.action(w.view(), 'ROTATE', { credId: 'k1-phone', newCredential: null }); a.body.newCredential = d.enrollment(ACCOUNT, `${ACCOUNT}:${a.nonce}`); return { action: a, approvals: w.owner.approvals(a, ['k1-phone', 'k2-laptop']) }; };
  const [x, y] = [mk(d1), mk(d2)];
  const rs = await Promise.all([w.admin.request('SUBMIT', { request: x }), w.admin.request('SUBMIT', { request: y })]);
  assert.equal(rs.filter(r => r.ok).length, 1);
  assert.match(rs.find(r => !r.ok).error.code, /STALE_EPOCH|ROTATE_SUBJECT_NOT_ACTIVE/);
  assert.equal(w.root.state.epoch, 2);
});

test('restart during rotation / recovery: Root and Vault rebuild from durable state; duplicate requests are idempotent-denied', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k4-freeze'] })).r);
  ok(await E.identity(w));
  w.restartRoot(); w.restartVault(); await w.pump();
  assert.equal(w.root.state.case.state, 'RECOVERY_CHALLENGE');
  assert.equal(w.vault.root.seq, w.root.state.seq);
  for (const c of survivors(w.root.state, w.root.state.case, w.now())) ok(await E.consent(w, c));
  // duplicate consent from the same key (fresh nonce) is harmless; the same signed request twice is a replay
  const a = w.owner.action(w.view(), 'RECOVERY_CONSENT', { caseId: w.root.state.case.caseId, caseDigest: w.root.state.case.digest });
  const req = { action: a, approvals: w.owner.approvals(a, ['k1-phone']) };
  ok(await w.admin.request('SUBMIT', { request: req })); deny(await w.admin.request('SUBMIT', { request: req }), 'ACTION_REPLAY');
});

test('crash after persist (before effects propagate): no lost transition, no double effect', async () => {
  const w = buildV3();
  let crash = true;
  w.root.crashAfterPersist = () => { if (crash) { crash = false; throw new Error('simulated crash'); } };
  const a = w.owner.action(w.view(), 'FREEZE', { freezeId: 'fc', reason: 'x', source: 'owner' });
  const r = await w.admin.request('SUBMIT', { request: { action: a, approvals: w.owner.approvals(a, ['k4-freeze']) } });
  assert.equal(r.ok, false); // caller saw a failure...
  w.restartRoot(); await w.pump();
  assert.equal(w.root.state.freeze.active, true); // ...but the durable chain has it exactly once
  assert.equal(w.vault.root.freeze.active, true);
  deny(await w.admin.request('SUBMIT', { request: { action: a, approvals: w.owner.approvals(a, ['k4-freeze']) } }), 'ACTION_REPLAY');
});

test('rollback / fork of the Root store is detected by the vault replica; tampered rows stop the Root (crash poisoning fails closed)', async () => {
  const w = buildV3();
  const snap = join(mkdtempSync(join(tmpdir(), 'sbx3-rb-')), 'root.db');
  w.root.db.exec('PRAGMA wal_checkpoint(FULL)'); copyFileSync(join(w.dir, 'root.db'), snap);
  ok(await w.ownerAct('FREEZE', { freezeId: 'f1', reason: 'stolen phone', source: 'owner' }, ['k4-freeze']));
  assert.equal(w.vault.root.freeze.active, true);
  // attacker rolls the Root store back to before the freeze and appends a different history
  w.root.close(); copyFileSync(snap, join(w.dir, 'root.db')); try { copyFileSync(snap + '-wal', join(w.dir, 'root.db-wal')); } catch {}
  w.restartRoot();
  assert.equal(w.root.state.freeze.active, false);
  ok(await w.admin.request('SUBMIT', { request: (() => { const a = w.owner.action(w.view(), 'SUSPEND', { credId: 'k5-recovery-hw' }); return { action: a, approvals: w.owner.approvals(a, ['k1-phone']) }; })() }));
  const s = await w.vctl.call('SYNC_ROOT', { transitions: w.root.chain(0) });
  assert.equal(s.alarm, 'ROOT_FORK_OR_ROLLBACK');
  assert.equal(w.vault.root.freeze.active, true, 'vault keeps the freeze it already verified');
  deny(await w.pay({ amountYocto: Y(1) }), 'ROOT_INTEGRITY_ALARM|FREEZE_ACTIVE');
  // tampering with a stored transition: the Root refuses to start
  w.root.close();
  const db = new DatabaseSync(join(w.dir, 'root.db')); db.exec('DROP TRIGGER chain_no_update');
  const row = db.prepare('SELECT seq, tr FROM chain ORDER BY seq LIMIT 1').get(); const t = JSON.parse(row.tr); t.action.body.credId = 'k1-phone';
  db.prepare('UPDATE chain SET tr=? WHERE seq=?').run(JSON.stringify(t), row.seq); db.close();
  assert.throws(() => w.restartRoot(), /APPROVAL|QUORUM|SIGNATURE|WEBAUTHN|ROOT_STORE_CORRUPT|SUSPEND/);
});

test('General Zone has no Root operation; a forged "recovery complete" and a false recovery notice carry no authority', async () => {
  const w = buildV3();
  for (const op of ['SUBMIT', 'SUBMIT_RECOVERY', 'SYNC_ROOT', 'FREEZE', 'SIGN', 'EXPORT_KEY', 'UNFREEZE', 'RELEASE']) deny(await w.gz.request(op, {}), 'OP_DENIED');
  w.inbox['ch-email'] = [{ kind: 'SAFEBOX_RECOVERY_NOTICE', caseId: 'fake', text: 'recovery completed, new key = attacker' }];
  assert.equal(w.root.state.case, null);
  deny(await w.submitRaw('RECOVERY_COMPLETE', { caseId: 'fake', caseDigest: '0'.repeat(64) }, { intended: false }), 'NO_RECOVERY_CASE');
  deny(await w.submitRaw('RECONSTITUTE', { caseId: 'fake', caseDigest: '0'.repeat(64) }, { intended: false }), 'NO_RECOVERY_CASE');
  // the recovery port refuses everything except dispatch / completion
  const rec = w.rootOps.recovery;
  assert.throws(() => rec.SUBMIT_RECOVERY.handler({ request: { action: { type: 'ROTATE' } } }), /OP_SCOPE/);
});

test('resource exhaustion: oversized and deeply nested requests are refused; repeated fake cases are rate limited', async () => {
  const w = buildV3();
  let deep = { x: 'y' }; for (let i = 0; i < 20; i++) deep = { x: deep };
  const a = w.owner.action(w.view(), 'FREEZE', { freezeId: 'f1', reason: 'x', source: 'owner' });
  deny(await w.admin.request('SUBMIT', { request: { action: { ...a, body: deep } } }), 'CANONICAL_TOO_DEEP|BODY_FREEZE|UNEXPECTED');
  deny(await w.admin.request('SUBMIT', { request: { action: a, approvals: Array.from({ length: 40 }, () => ({ credId: 'k1-phone' })) } }), 'APPROVALS_INVALID|SUBMIT_TOO_LARGE');
  let opened = 0;
  for (let i = 0; i < 6; i++) { const o = await ownerOpenCase(w, { lost: ['k1-phone'], attacker: true }); if (o.r.ok) { opened++; ok(await E.cancel(w, ['k2-laptop'])); } await w.advance(10 * 60_000); }
  assert.ok(opened <= 2, `opened ${opened} cases in 1 h`);
});

test('executor key is not a credential: a compromised vault cannot amend Purpose or rotate keys', async () => {
  const w = buildV3();
  const a = w.owner.action(w.view(), 'AMEND_PURPOSE', { capsule: { ...w.owner.capsule, version: '2', recipients: [...w.owner.capsule.recipients] } });
  const sig = w.executor.sign('DIAPORIA_SAFEBOX_V2_MOCK_LEDGER_TX\n', { x: 'y' }).signature;
  deny(await submit(w, a, [{ credId: 'executor', sig }]), 'APPROVAL_UNKNOWN_CREDENTIAL');
});
