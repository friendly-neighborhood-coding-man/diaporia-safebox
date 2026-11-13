// Confidential-ballot model for sensitive Guardian / identity-verifier replacement votes.
//
// WHAT THIS IS: each eligible voter (a pinned Guardian or identity-verifier key) submits ONE sealed ballot per case:
//   commitment = SHA-256(domain || canon{gcaseDigest, voterId, choice, salt})       (public, binding)
//   sealed     = X25519-ECDH(ephemeral, tallyKey) -> HKDF-SHA-256 -> AES-256-GCM(choice, salt)   (only the tally can open)
//   voterSig   = Ed25519 by the voter's pinned key over {gcaseDigest, voterId, commitment, sealedDigest}  (eligibility)
// The tally service opens the sealed ballots and publishes a signed result.
//   * APPROVED (the only result that changes authority) must come with the opening of EVERY ballot; the Root and any
//     verifier re-check each commitment, so a dishonest tally cannot fabricate an approval.
//   * REJECTED publishes no openings: who dissented stays confidential to the tally service.
// WHAT THIS IS NOT: anonymity. Voters are identified (eligibility is public); under the unanimity rule an APPROVED result
// reveals that every eligible voter approved, and with a single eligible voter any result reveals that voter's choice.
// Dissent confidentiality relies on the tally service keeping its X25519 key and the openings secret. No zero-knowledge
// protocol is used or claimed.
import { generateKeyPairSync, createPublicKey, createPrivateKey, diffieHellman, hkdfSync, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { fail, exactFields, b64u, fromB64u, canon } from '../../v3/common/canon.mjs';
import { V4_DOMAINS, d4, d4hex, sha256hex, verifyDigest, newSigner4 } from '../common/v4.mjs';

export const CHOICES = Object.freeze(['APPROVE', 'REJECT']);
export const commitmentOf = ({ gcaseDigest, voterId, choice, salt }) => d4hex(V4_DOMAINS.BALLOT_COMMIT, { gcaseDigest, voterId, choice, salt });
export const eligibilityDigest = ({ gcaseDigest, voterId, commitment, sealed }) => d4(V4_DOMAINS.BALLOT_ELIG, { gcaseDigest, voterId, commitment, sealedDigest: sha256hex(Buffer.from(canon(sealed))) });

function aad(gcaseDigest, voterId) { return Buffer.from(`${gcaseDigest}|${voterId}`); }
function kdf(shared, epkRaw) { return Buffer.from(hkdfSync('sha256', shared, epkRaw, Buffer.from('safebox.v4.ballot'), 32)); }
const rawX = (pubObj) => Buffer.from(pubObj.export({ format: 'jwk' }).x, 'base64url');
const xPub = (raw) => createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64u(raw) }, format: 'jwk' });

/** Seals {choice, salt} to the tally's X25519 public key (b64u raw). */
export function sealBallot({ gcaseDigest, voterId, choice, salt }, tallyPubB64u) {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const epk = rawX(publicKey);
  const key = kdf(diffieHellman({ privateKey, publicKey: xPub(fromB64u(tallyPubB64u)) }), epk);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv); c.setAAD(aad(gcaseDigest, voterId));
  const ct = Buffer.concat([c.update(Buffer.from(canon({ choice, salt }))), c.final(), c.getAuthTag()]);
  return { epk: b64u(epk), iv: b64u(iv), ct: b64u(ct) };
}

/** A voter (Guardian / IDV) casting one ballot with its pinned V3 Ed25519 signer. */
export function castBallot({ gcaseId, gcaseDigest, voterId, signer, choice, tallyPublicKey }) {
  if (!CHOICES.includes(choice)) fail('BALLOT_CHOICE');
  const salt = randomBytes(16).toString('hex');
  const commitment = commitmentOf({ gcaseDigest, voterId, choice, salt });
  const sealed = sealBallot({ gcaseDigest, voterId, choice, salt }, tallyPublicKey);
  const body = { gcaseId, gcaseDigest, voterId, commitment, sealed };
  const voterSig = signer.signDigest(V4_DOMAINS.BALLOT_ELIG, eligibilityDigest(body));
  return { body, voterSig, opening: { voterId, choice, salt } };
}

export function verifyBallotEligibility(body, voterSig, voterPub) { return verifyDigest(V4_DOMAINS.BALLOT_ELIG, eligibilityDigest(body), voterSig, voterPub); }

/** The tally service: holds the X25519 opening key and its Ed25519 result-signing key (separate OS principal in deployment). */
export class TallyService {
  constructor({ id = 'tally-1' } = {}) {
    const { privateKey, publicKey } = generateKeyPairSync('x25519');
    Object.defineProperty(this, 'x', { value: privateKey, enumerable: false });
    this.id = id; this.publicKey = b64u(rawX(publicKey)); this.signer = newSigner4('tally');
  }
  open(ballot) {
    const s = exactFields(ballot.body.sealed, ['epk', 'iv', 'ct'], [], 'SEALED_FIELDS');
    const epk = fromB64u(s.epk); const key = kdf(diffieHellman({ privateKey: this.x, publicKey: xPub(epk) }), epk);
    const raw = fromB64u(s.ct); if (raw.length < 17) fail('SEALED_TOO_SHORT');
    const d = createDecipheriv('aes-256-gcm', key, fromB64u(s.iv)); d.setAAD(aad(ballot.body.gcaseDigest, ballot.body.voterId)); d.setAuthTag(raw.subarray(raw.length - 16));
    let pt; try { pt = Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]); } catch { fail('SEALED_BALLOT_UNOPENABLE'); }
    const o = JSON.parse(pt.toString());
    if (commitmentOf({ gcaseDigest: ballot.body.gcaseDigest, voterId: ballot.body.voterId, choice: o.choice, salt: o.salt }) !== ballot.body.commitment) fail('BALLOT_COMMITMENT_MISMATCH');
    return { voterId: ballot.body.voterId, choice: o.choice, salt: o.salt };
  }
  /** Tallies the ballots recorded on the Root for a governance case. Unanimity of the electorate is required. */
  tally(gcase) {
    const openings = Object.values(gcase.ballots).map(b => this.open({ body: b }));
    const allIn = gcase.electorate.every(v => gcase.ballots[v]);
    const unanimous = allIn && openings.length === gcase.electorate.length && openings.every(o => o.choice === 'APPROVE');
    const result = unanimous ? 'APPROVED' : 'REJECTED';
    const statement = { gcaseId: gcase.gcaseId, gcaseDigest: gcase.digest, result, ballots: String(openings.length), electorate: String(gcase.electorate.length),
      openings: unanimous ? openings.map(o => ({ voterId: o.voterId, choice: o.choice, salt: o.salt })).sort((a, b) => a.voterId < b.voterId ? -1 : 1) : [] };
    return { statement, sig: this.signer.signObj(V4_DOMAINS.TALLY, statement) };
  }
}
