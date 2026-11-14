// V4 owner-side world: the V3 devices plus an Owner Recovery Credential (ORC: offline hardware key with its own trusted
// display), simulated protected-confirmation keys on the phone passkeys, three adjudicators, the tally service and the
// challenge issuer. Everything here runs outside SafeBox (owner devices, independent parties); the AI never holds it.
//
// The trusted confirmation ceremony (`authorize`) models what the owner's devices do:
//   1. ask the challenge service for a one-time grant bound to (action digest, credential);
//   2. build the intent + summary from a VERIFIED replica of the Root state (never from AI-provided text);
//   3. the device shows the deterministic summary (hardware display / protected confirmation prompt);
//   4. the human decides (callback `decide(summary, text)`); only then does the device sign the intent digest.
import { OwnerWorld, Device, ACCOUNT, RP } from '../v3/kit.mjs';
import { iso, nonce as mkNonce } from '../v3/common/canon.mjs';
import { actionDigest } from '../v3/root/chain.mjs';
import { V4_DOMAINS, d4, newSigner4, signDigestWith, signObjWith } from './common/v4.mjs';
import { EXT_V, V4_DEFAULT_CONFIG, VERDICT_V, WITHDRAWAL_V } from './root/chain.mjs';
import { buildIntent, intentDigest, ChallengeService } from './intent/intent.mjs';
import { renderText, renderScreen, screenDigestHex } from './intent/summary.mjs';
import { TallyService, castBallot } from './ballot/ballot.mjs';
import { newEdSigner } from '../v3/common/canon.mjs';

export { ACCOUNT, RP, Device };

/** Simulated Android-Protected-Confirmation-style key living next to a phone passkey (labelled SIMULATED everywhere). */
export class SimulatedProtectedConfirmation {
  constructor(credId) { this.credId = credId; this.signer = newSigner4('apc-' + credId); this.publicKey = this.signer.publicKey; }
  pop(accountId, v3ChainId) { return this.signer.signObj(V4_DOMAINS.CONFIRM_POP, { accountId, v3ChainId, credId: this.credId, publicKey: this.publicKey }); }
  /** The secure UI shows `prompt`; the key signs {prompt, extraData} only after the user confirms on that UI. */
  confirm(prompt, extraDataHex) { return this.signer.signObj(V4_DOMAINS.CONFIRM, { prompt: prompt.split('\n'), extraData: extraDataHex }); }
}

export class OwnerWorldV4 extends OwnerWorld {
  constructor(opts = {}) {
    super(opts);
    this.config4 = { ...V4_DEFAULT_CONFIG, ...(opts.config4 ?? {}) };
    this.orcs = { 'orc-1': newEdSigner('orc-1') };              // ORC: offline hardware key with its own display
    this.lostOrcs = new Set();
    this.apc = {}; for (const c of opts.apcCreds ?? ['k1-phone', 'k4-freeze']) this.apc[c] = new SimulatedProtectedConfirmation(c);
    this.displays = opts.displays ?? ['k3-root-hw', 'k5-recovery-hw'];
    this.adjudicatorKeys = { 'adj-1': newSigner4('adj-1'), 'adj-2': newSigner4('adj-2'), 'adj-3': newSigner4('adj-3') };
    this.tally = new TallyService();
    this.issuerSigner = newSigner4('challenge-issuer');
    this.metrics = { prompts: 0, gestures: 0, signatures: 0, declined: 0, byCred: {} };
    this.decide = () => true; // the human's decision on what the trusted display shows (tests replace it)
  }
  challengeService(now) { this.challenge ??= new ChallengeService({ signer: this.issuerSigner, now }); return this.challenge; }
  genesis4() {
    const gen3 = this.genesis();
    const v3ChainId = this.chainId;
    const action = { v: EXT_V, v3ChainId, accountId: ACCOUNT, nonce: mkNonce(), issuedAt: iso(this.t0), body: {
      config: this.config4,
      orcs: Object.fromEntries(Object.entries(this.orcs).map(([k, s]) => [k, { publicKey: s.publicKey, holderId: 'alice' }])),
      displays: Object.fromEntries(this.displays.filter(c => this.devices.some(d => d.credId === c)).map(c => [c, 'TRUSTED_DISPLAY'])),
      confirmers: Object.fromEntries(Object.entries(this.apc).filter(([c]) => this.devices.some(d => d.credId === c)).map(([c, k]) => [c, { publicKey: k.publicKey, pop: k.pop(ACCOUNT, v3ChainId) }])),
      adjudicators: Object.fromEntries(Object.entries(this.adjudicatorKeys).map(([k, s]) => [k, { publicKey: s.publicKey, holderId: 'arbiter-' + k }])),
      tally: { id: this.tally.id, publicKey: this.tally.publicKey, sigKey: this.tally.signer.publicKey },
      challengeIssuer: { id: 'challenge-svc', publicKey: this.issuerSigner.publicKey },
    } };
    const dig = d4(V4_DOMAINS.GENESIS_EXT, action);
    const approvals = this.devices.map(d => d.kind === 'passkey' ? { credId: d.credId, webauthn: d.auth.assert({ ...this.rp, challenge: dig, uv: true }) } : { credId: d.credId, sig: signDigestWith(d.signer, V4_DOMAINS.GENESIS_EXT, dig) });
    for (const [k, s] of Object.entries(this.orcs)) approvals.push({ credId: k, sig: signDigestWith(s, V4_DOMAINS.ORC_POP, dig) });
    this.genesis4Record = { v3: gen3, ext: { action, approvals } };
    this.chainId4 = d4(V4_DOMAINS.GENESIS, { v3ChainId, ext: dig.toString('hex') }).toString('hex');
    return this.genesis4Record;
  }
  orcSigner(id) { const s = this.orcs[id]; if (!s || this.lostOrcs.has(id)) throw new Error('ORC not available: ' + id); return s; }
  isOrc(id) { return !!this.orcs[id]; }

  /**
   * One credential's part of a trusted confirmation ceremony. Returns the approval or null if the human declined.
   * opts: { screen (attach screen evidence), apc (default: use the enrolled confirmer), decide, tamper(intent, summary) }
   */
  approveIntent(state, action, credId, { screen = false, apc = true, decide = this.decide, challenge = null, tamperGrant = null } = {}) {
    const svc = challenge ?? this.challenge;
    const grant = svc.issue({ accountId: state.accountId, chainId: state.chainId, actionType: action.type, actionDigestHex: actionDigest(action).toString('hex'), credId });
    if (tamperGrant) tamperGrant(grant);
    let screenDigest = '-', sc = null;
    const pre = buildIntent(state, action, grant.statement);
    if (screen) { const fb = renderScreen(pre.summary, 48); screenDigest = screenDigestHex(fb); sc = { region: fb.region, renderer: fb.renderer, width: fb.width, digest: screenDigest, challengeNonce: grant.statement.challengeNonce, caseId: pre.intent.caseId }; }
    const { intent, summary } = buildIntent(state, action, grant.statement, { screenDigest });
    const text = renderText(summary);
    const m = this.metrics; m.prompts++; m.byCred[credId] = (m.byCred[credId] ?? 0) + 1;
    if (!decide(summary, text, { credId, action })) { m.declined++; return null; }
    m.gestures++; m.signatures++;
    const dig = intentDigest(intent);
    const ap = { credId, intent, grant };
    if (this.orcs[credId]) ap.sig = signDigestWith(this.orcSigner(credId), V4_DOMAINS.INTENT, dig);
    else {
      const d = this.dev(credId);
      if (d.kind === 'passkey') { ap.webauthn = d.auth.assert({ ...this.rp, challenge: dig, uv: true }); if (apc && this.apc[credId]) ap.apc = { sig: this.apc[credId].confirm(text, dig.toString('hex')) }; }
      else ap.sig = signDigestWith(d.signer, V4_DOMAINS.INTENT, dig);
    }
    if (sc) ap.screen = sc;
    return ap;
  }
  /** Approvals for several credentials (each its own grant / prompt). Declined approvals are dropped. */
  authorize(state, action, credIds, opts = {}) { return credIds.map(c => this.approveIntent(state, action, c, opts)).filter(Boolean); }

  // ---------------------------------------------- independent parties
  verdict(adjId, { subjectKind, subjectId, subjectKey, finding, at, ttlMs = 7 * 86_400_000, accountId = ACCOUNT, chainId = this.chainId4 }) {
    const statement = { v: VERDICT_V, accountId, chainId, subjectKind, subjectId, subjectKey, finding, evidenceRef: 'case-file-' + subjectId, issuedAt: iso(at), expiresAt: iso(at + ttlMs) };
    return { kind: 'VERDICT', subjectId, adjudicatorId: adjId, statement, sig: this.adjudicatorKeys[adjId].signObj(V4_DOMAINS.VERDICT, statement) };
  }
  participantKey(id) { return this.guardianKeys[id] ?? this.idvKeys[id]; }
  /** A new independent guardian / identity verifier (fresh key, its own holder) with proof of possession for a case. */
  newParticipant(kind, id, holderId, gcaseId = '-') {
    const k = newEdSigner('participant-' + id);
    if (kind === 'guardian') this.guardianKeys[id] = k; else this.idvKeys[id] = k;
    return { id, holderId, publicKey: k.publicKey, pop: signObjWith(k, V4_DOMAINS.PARTICIPANT_POP, { accountId: ACCOUNT, chainId: this.chainId4, gcaseId, id, holderId, publicKey: k.publicKey }) };
  }
  /** F-V4-02: a withdrawal statement is bound to ONE governance case (a statement signed once is not a standing resignation). */
  withdrawal(id, gcaseId) { const k = this.participantKey(id); return { kind: 'WITHDRAWAL', subjectId: id, sig: signObjWith(k, V4_DOMAINS.WITHDRAWAL, { v: WITHDRAWAL_V, accountId: ACCOUNT, chainId: this.chainId4, gcaseId: String(gcaseId), subjectId: id, subjectKey: k.publicKey }) }; }
  ballot(gcase, voterId, choice) { return castBallot({ gcaseId: gcase.gcaseId, gcaseDigest: gcase.digest, voterId, signer: this.participantKey(voterId), choice, tallyPublicKey: this.tally.publicKey }); }
  livenessSign(action, id) { return signDigestWith(this.participantKey(id), V4_DOMAINS.LIVENESS, actionDigest(action)); }
  withdrawalSign(action, id) { return signDigestWith(this.participantKey(id), V4_DOMAINS.WITHDRAWAL, actionDigest(action)); }
  orcPop(id, signer, chainId, nonce) { return signObjWith(signer, V4_DOMAINS.ORC_POP, { accountId: ACCOUNT, chainId, id, publicKey: signer.publicKey, nonce }); }
}
