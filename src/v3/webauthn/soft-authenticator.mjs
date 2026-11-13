// Software WebAuthn authenticator for tests and simulations ONLY. It produces byte-exact WebAuthn registration and
// assertion responses (real P-256 ECDSA signatures, real authenticatorData and clientDataJSON). It is NOT a secure
// authenticator: the "user verification" it reports is a test parameter. Production uses a platform/roaming
// authenticator through navigator.credentials; the relying-party verification code is identical.
import { generateKeyPairSync, sign, randomBytes, createHash } from 'node:crypto';
import { encodeCbor } from './cbor.mjs';
import { b64u } from '../common/canon.mjs';

const sha = (b) => createHash('sha256').update(b).digest();

export class SoftAuthenticator {
  constructor({ label = 'passkey', aaguid = randomBytes(16), backupEligible = false, counter = true } = {}) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.label = label; this.aaguid = Buffer.from(aaguid); this.be = backupEligible; this.useCounter = counter;
    this.credentialId = randomBytes(32); this.counter = 0;
    Object.defineProperty(this, 'priv', { value: privateKey, enumerable: false });
    const j = publicKey.export({ format: 'jwk' });
    this.cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(j.x, 'base64url')], [-3, Buffer.from(j.y, 'base64url')]]);
  }
  get credentialIdB64u() { return b64u(this.credentialId); }
  #authData(rpId, { uv = true, up = true, attested = false } = {}) {
    if (this.useCounter) this.counter++;
    const flags = (up ? 1 : 0) | (uv ? 4 : 0) | (this.be ? 8 : 0) | (attested ? 0x40 : 0);
    const head = Buffer.concat([sha(Buffer.from(rpId)), Buffer.from([flags]), Buffer.alloc(4)]);
    head.writeUInt32BE(this.counter, 33);
    if (!attested) return head;
    const len = Buffer.alloc(2); len.writeUInt16BE(this.credentialId.length);
    return Buffer.concat([head, this.aaguid, len, this.credentialId, encodeCbor(this.cose)]);
  }
  register({ rpId, origin, challenge, uv = true, fmt = 'none' }) {
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: b64u(challenge), origin, crossOrigin: false }));
    const authData = this.#authData(rpId, { uv, attested: true });
    const attStmt = fmt === 'packed' ? new Map([['alg', -7], ['sig', sign('sha256', Buffer.concat([authData, sha(clientData)]), { key: this.priv, dsaEncoding: 'der' })]]) : new Map();
    return { attestationObject: b64u(encodeCbor(new Map([['fmt', fmt], ['attStmt', attStmt], ['authData', authData]]))), clientDataJSON: b64u(clientData) };
  }
  /** Signs exactly one challenge (the action digest). Options let tests forge bad variants. */
  assert({ rpId, origin, challenge, uv = true, up = true, type = 'webauthn.get', crossOrigin = false }) {
    const clientData = Buffer.from(JSON.stringify({ type, challenge: b64u(challenge), origin, crossOrigin }));
    const authData = this.#authData(rpId, { uv, up });
    const signature = sign('sha256', Buffer.concat([authData, sha(clientData)]), { key: this.priv, dsaEncoding: 'der' });
    return { credentialId: this.credentialIdB64u, authenticatorData: b64u(authData), clientDataJSON: b64u(clientData), signature: b64u(signature) };
  }
  toJSON() { return { label: this.label, credentialId: this.credentialIdB64u }; }
}
