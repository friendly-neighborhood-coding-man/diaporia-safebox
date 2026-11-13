// Credential enrollment and independence checks.
// A credential = (identity: credId + public key) + (role) + (holder: the human) + (notification channel) + provenance.
// Independence: five copies of one private key, or five keys from one seed, must not count as five credentials.
// What is checked cryptographically: distinct public keys, distinct WebAuthn credential ids, proof of possession of each
// key bound to this account + enrollment context. What is checked by declaration only (cannot be proven without
// hardware attestation chains): distinct device ids, distinct seed commitments, one active credential per sync provider.
import { fail, exactFields, id, digest, V3_DOMAINS, edVerifyDigest, ED_PREFIX } from '../common/canon.mjs';
import { verifyRegistration } from '../webauthn/verify.mjs';

const PROV = ['deviceId', 'seedCommitment', 'syncProvider'];

export function enrollmentChallenge(accountId, e, context) {
  return digest(V3_DOMAINS.ENROLL, { accountId, credId: e.credId, role: e.role, holderId: e.holderId, channelId: e.channelId, kind: e.kind,
    deviceId: e.provenance.deviceId, seedCommitment: e.provenance.seedCommitment, syncProvider: e.provenance.syncProvider, context });
}

/** Verifies one enrollment; returns the credential record to pin. */
export function verifyEnrollment(e, { accountId, rp, context, roles }) {
  exactFields(e, ['credId', 'role', 'holderId', 'channelId', 'kind', 'provenance'], ['registration', 'publicKey', 'pop'], 'ENROLLMENT_FIELDS');
  id(e.credId, 'credId'); id(e.holderId, 'holderId'); id(e.channelId, 'channelId');
  if (!roles.includes(e.role)) fail('ENROLLMENT_ROLE');
  exactFields(e.provenance, PROV, [], 'ENROLLMENT_PROVENANCE');
  id(e.provenance.deviceId, 'deviceId'); if (!/^[0-9a-f]{64}$/.test(e.provenance.seedCommitment)) fail('ENROLLMENT_SEED_COMMITMENT');
  if (!/^(none|[a-z0-9][a-z0-9-]{1,31})$/.test(e.provenance.syncProvider)) fail('ENROLLMENT_SYNC_PROVIDER');
  const ch = enrollmentChallenge(accountId, e, context);
  const base = { credId: e.credId, role: e.role, holderId: e.holderId, channelId: e.channelId, kind: e.kind, provenance: { ...e.provenance } };
  if (e.kind === 'passkey') {
    if (!e.registration || 'publicKey' in e || 'pop' in e) fail('ENROLLMENT_FIELDS');
    exactFields(e.registration, ['attestationObject', 'clientDataJSON'], [], 'ENROLLMENT_REGISTRATION');
    const r = verifyRegistration(e.registration, { rp, expectedChallenge: ch, requireUV: true });
    if (r.backupEligible && e.provenance.syncProvider === 'none') fail('ENROLLMENT_SYNCABLE_PASSKEY_UNDECLARED');
    return { ...base, publicKey: 'spki:' + r.spki, webauthn: { credentialId: r.credentialId, alg: r.alg, spki: r.spki, aaguid: r.aaguid, backupEligible: r.backupEligible, attestation: r.attestation }, signCount: r.signCount };
  }
  if (e.kind === 'ed25519') {
    if ('registration' in e || typeof e.publicKey !== 'string' || !e.publicKey.startsWith(ED_PREFIX) || typeof e.pop !== 'string') fail('ENROLLMENT_FIELDS');
    if (!edVerifyDigest(V3_DOMAINS.ENROLL, ch, e.pop, e.publicKey)) fail('ENROLLMENT_POP_INVALID');
    return { ...base, publicKey: e.publicKey, signCount: 0 };
  }
  fail('ENROLLMENT_KIND');
}

/** Independence of a new credential against every credential ever pinned (and against the other new ones). */
export function independenceViolations(newCred, existing) {
  const v = [];
  for (const c of existing) {
    if (c.credId === newCred.credId) v.push('DUPLICATE_CRED_ID');
    if (c.publicKey === newCred.publicKey) v.push('DUPLICATE_PUBLIC_KEY');
    if (c.webauthn && newCred.webauthn && c.webauthn.credentialId === newCred.webauthn.credentialId) v.push('DUPLICATE_WEBAUTHN_CREDENTIAL_ID');
    if (c.provenance.seedCommitment === newCred.provenance.seedCommitment) v.push('SHARED_SEED');
    const live = c.status === 'active' || c.status === 'suspended' || c.status === undefined;
    if (live && c.provenance.deviceId === newCred.provenance.deviceId) v.push('SHARED_DEVICE');
    if (live && newCred.provenance.syncProvider !== 'none' && c.provenance.syncProvider === newCred.provenance.syncProvider) v.push('SHARED_SYNC_PROVIDER');
  }
  return [...new Set(v)];
}
