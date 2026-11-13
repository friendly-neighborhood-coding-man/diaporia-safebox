//! DIAPORIA SafeBox V4 on-chain vault (LOCAL SANDBOX ONLY — not deployed to any network).
//!
//! V4 keeps every V3 on-chain rule (payments, hard-coded governance matrix, recovery evidence) and adds:
//! * R-1 closure: a majority-loss RECONSTITUTION completes only with an explicit authorization by a pre-enrolled Owner
//!   Recovery Credential (ORC) bound to the exact case digest (which commits to the replacement plan). Channel silence,
//!   elapsed time, guardians and identity verifiers never substitute for it. At the deadline an unapproved case can be
//!   expired by anyone (no authority transfer, lockdown released). A failed claim starts a 12 h per-account reattempt
//!   cooldown, counts against a 3-per-30-days claim budget and burns its plan keys; an ORC-attested open is exempt.
//! * Intent-bound governance messages: a 256-bit nonce, issuedAt / expiresAt with a lifetime of at most 120 s,
//!   single use, checked against block time.
//! * R-3 closure: guardian / identity-verifier emergency replacement. Opened by an owner quorum of two DISTINCT owner
//!   roles (DAILY / ROOT / RECOVERY / ORC); each accused member needs two independent adjudicator verdicts; the accused
//!   are excluded from the electorate; every remaining eligible member submits a hiding commitment; approval requires
//!   the opening of EVERY commitment to APPROVE; 24 h delay; atomic 1:1 replacement with proof of possession; epoch bump.
//!   Ballot sealing (encryption to the tally) is off-chain; the chain only ever sees commitments and, on approval,
//!   openings. A rejection reveals no individual choice. This is confidentiality, not anonymity.
//! * The ORC is never a payment, Purpose or freeze authority. There is NO owner/admin method, NO upgrade method and NO
//!   withdraw-all (deployment invariant: no FullAccess key, checked off-chain).
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::{IterableMap, LookupSet};
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

const PAY_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V4_ONCHAIN_PAY\n";
const GOV_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V4_ONCHAIN_GOV\n";
const REC_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V4_ONCHAIN_RECOVERY\n";
const ORC_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V4_ONCHAIN_ORC_INTENT\n";
const PART_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V4_ONCHAIN_PARTICIPANT\n";
const VERDICT_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V4_ONCHAIN_VERDICT\n";
const SEC: u64 = 1_000_000_000;
const HOUR: u64 = 3600 * SEC;
const DAY: u64 = 24 * HOUR;
const CHALLENGE_TTL: u64 = 120 * SEC;
const SKEW: u64 = 60 * SEC;
const REATTEMPT_COOLDOWN: u64 = 12 * HOUR;
const COMPLETION_GRACE: u64 = 7 * DAY;
const CLAIM_BUDGET_30D: usize = 3;
const GOV_VOTE: u64 = 72 * HOUR;
const GOV_DELAY: u64 = 24 * HOUR;
const ADJUDICATOR_QUORUM: usize = 2;

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role { Daily, Root, Freeze, Recovery }

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Cred { pub id: String, pub role: Role, pub pk: String, pub active: bool }

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Purpose { pub version: u64, pub recipients: Vec<AccountId>, pub per_payment_max: U128, pub cumulative_limit: U128, pub expires_at_ns: u64 }

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Pending { pub recipient: AccountId, pub amount: U128, pub release_at_ns: u64, pub epoch: u64, pub purpose_version: u64, pub cred_id: String }

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Case { pub case_id: String, pub lost: Vec<String>, pub plan: Vec<Cred>, pub opened_at_ns: u64, pub consents: Vec<String>, pub guardians: Vec<u32>,
  pub identities: Vec<u32>, pub disputes: Vec<String>, pub reconstitution: bool, pub digest: String,
  pub deadline_ns: u64, pub owner_auth: Option<String>, pub orc_attested: bool }

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct GCase { pub gcase_id: String, pub guardian_proc: bool, pub accused: Vec<u32>, pub replacements: Vec<String>, pub electorate: Vec<String>,
  pub commitments: Vec<(String, String)>, pub opened_at_ns: u64, pub vote_deadline_ns: u64, pub execute_after_ns: Option<u64>, pub digest: String }

#[near(serializers = [json])]
pub struct Init { pub creds: Vec<Cred>, pub guardians: Vec<String>, pub idvs: Vec<String>, pub purpose: Purpose, pub buffer_ns: u64, pub window_ns: u64,
  pub guardian_quorum: u32, pub recon_guardian_quorum: u32, pub orcs: Vec<String>, pub adjudicators: Vec<String> }

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SafeBoxV4 {
  epoch: u64, creds: Vec<Cred>, baseline: Vec<String>, guardians: Vec<String>, idvs: Vec<String>, purpose: Purpose, spent: u128,
  frozen: bool, lockdown: bool, buffer_ns: u64, window_ns: u64, guardian_quorum: u32, recon_guardian_quorum: u32,
  lost_since_baseline: u32, used: LookupSet<String>, pending: IterableMap<u64, Pending>, next_id: u64, case: Option<Case>,
  orcs: Vec<String>, adjudicators: Vec<String>, failed_claims: Vec<u64>, burned: LookupSet<String>, gcase: Option<GCase>, disqualified: Vec<String>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields, rename_all = "camelCase")]
struct PayMsg { v: String, epoch: u64, purpose_version: u64, nonce: String, recipient: AccountId, amount: U128, expires_at_ns: u64 }

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields, rename_all = "camelCase")]
struct GovMsg { v: String, epoch: u64, nonce: String, issued_at_ns: u64, expires_at_ns: u64, op: String, #[serde(default)] subject: Option<String>,
  #[serde(default)] new_cred: Option<Cred>, #[serde(default)] purpose: Option<Purpose> }

/// ORC intent: {v, op, caseRef, nonce (256-bit hex), issuedAtNs, expiresAtNs}; caseRef = case digest (or plan ref for OPEN).
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields, rename_all = "camelCase")]
struct OrcMsg { v: String, op: String, case_ref: String, nonce: String, issued_at_ns: u64, expires_at_ns: u64 }

/// Adjudicator verdict: {v, subjectPk, finding, expiresAtNs}.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields, rename_all = "camelCase")]
struct VerdictMsg { v: String, subject_pk: String, finding: String, expires_at_ns: u64 }

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Approval { pub cred_id: String, pub sig: Base64VecU8 }
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct OrcApproval { pub index: u32, pub msg: String, pub sig: Base64VecU8 }
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Verdict { pub adjudicator: u32, pub msg: String, pub sig: Base64VecU8 }
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Replacement { pub pk: String, pub pop: Base64VecU8 }

fn pk32(s: &str) -> [u8; 32] { let v = hex::decode(s).unwrap_or_else(|_| env::panic_str("BAD_PUBLIC_KEY")); v.try_into().unwrap_or_else(|_| env::panic_str("BAD_PUBLIC_KEY")) }
fn sig64(s: &Base64VecU8) -> [u8; 64] { s.0.clone().try_into().unwrap_or_else(|_| env::panic_str("BAD_SIGNATURE_LENGTH")) }
fn signed(domain: &[u8], msg: &[u8]) -> Vec<u8> { [domain, msg].concat() }

#[near]
impl SafeBoxV4 {
  /// Self-initialised at deployment. The account must afterwards hold no FullAccess key.
  #[init]
  pub fn new(init: Init) -> Self {
    require!(env::predecessor_account_id() == env::current_account_id(), "INIT_ONLY_BY_SELF");
    let count = |r: Role| init.creds.iter().filter(|c| c.role == r).count();
    require!(init.creds.len() >= 5 && count(Role::Daily) >= 2 && count(Role::Root) >= 1 && count(Role::Freeze) >= 1 && count(Role::Recovery) >= 1, "NEEDS_FIVE_INDEPENDENT_CREDENTIALS");
    let mut pks: Vec<&String> = init.creds.iter().map(|c| &c.pk).collect(); pks.sort(); pks.dedup();
    require!(pks.len() == init.creds.len(), "DUPLICATE_PUBLIC_KEY");
    for c in &init.creds { pk32(&c.pk); require!(!init.guardians.contains(&c.pk), "GUARDIAN_IS_CREDENTIAL"); }
    require!(init.guardian_quorum >= 2 && init.recon_guardian_quorum >= init.guardian_quorum && init.recon_guardian_quorum as usize <= init.guardians.len(), "GUARDIAN_QUORUM");
    require!(init.window_ns <= 72 * 3600 * 1_000_000_000 && init.buffer_ns >= 600 * 1_000_000_000, "WINDOW_OR_BUFFER");
    // V4: at least one ORC; ORCs and adjudicators independent of every other key; adjudicator quorum satisfiable
    require!(!init.orcs.is_empty(), "V4_NEEDS_OWNER_RECOVERY_CREDENTIAL");
    require!(init.adjudicators.len() >= ADJUDICATOR_QUORUM, "ADJUDICATORS");
    let mut all: Vec<&String> = init.creds.iter().map(|c| &c.pk).chain(init.guardians.iter()).chain(init.idvs.iter()).chain(init.orcs.iter()).chain(init.adjudicators.iter()).collect();
    for k in &all { pk32(k); }
    let n = all.len(); all.sort(); all.dedup(); require!(all.len() == n, "KEYS_NOT_INDEPENDENT");
    Self { epoch: 1, baseline: init.creds.iter().map(|c| c.id.clone()).collect(), creds: init.creds, guardians: init.guardians, idvs: init.idvs, purpose: init.purpose, spent: 0,
      frozen: false, lockdown: false, buffer_ns: init.buffer_ns, window_ns: init.window_ns, guardian_quorum: init.guardian_quorum, recon_guardian_quorum: init.recon_guardian_quorum,
      lost_since_baseline: 0, used: LookupSet::new(b"u"), pending: IterableMap::new(b"p"), next_id: 1, case: None,
      orcs: init.orcs, adjudicators: init.adjudicators, failed_claims: vec![], burned: LookupSet::new(b"b"), gcase: None, disqualified: vec![] }
  }

  fn cred(&self, id: &str) -> &Cred { self.creds.iter().find(|c| c.id == id && c.active).unwrap_or_else(|| env::panic_str("CREDENTIAL_NOT_ACTIVE")) }
  fn verify(&self, domain: &[u8], msg: &[u8], cred_id: &str, sig: &Base64VecU8) -> Role {
    let c = self.cred(cred_id);
    require!(env::ed25519_verify(&sig64(sig), &signed(domain, msg), &pk32(&c.pk)), "BAD_SIGNATURE");
    c.role
  }
  fn use_nonce(&mut self, n: &str) { require!(n.len() == 32 && n.chars().all(|c| c.is_ascii_hexdigit()), "NONCE"); require!(self.used.insert(n.to_string()), "REPLAY"); }
  /// V4 high-risk challenge: 256-bit nonce, issuedAt <= now (+skew) < expiresAt, lifetime <= 120 s, single use.
  fn use_challenge(&mut self, n: &str, issued: u64, expires: u64) {
    require!(n.len() == 64 && n.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "CHALLENGE_NONCE_256");
    require!(issued < expires && expires - issued <= CHALLENGE_TTL, "CHALLENGE_LIFETIME");
    let now = env::block_timestamp();
    require!(issued <= now + SKEW, "CHALLENGE_FROM_FUTURE");
    require!(now < expires, "CHALLENGE_EXPIRED");
    require!(self.used.insert(format!("c:{}", n)), "CHALLENGE_ALREADY_CONSUMED");
  }
  /// Verifies an ORC intent for (op, case_ref); returns the ORC index. Never a V3 credential.
  fn verify_orc(&mut self, o: &OrcApproval, op: &str, case_ref: &str) -> u32 {
    let pk = self.orcs.get(o.index as usize).cloned().unwrap_or_else(|| env::panic_str("ORC_UNKNOWN"));
    require!(env::ed25519_verify(&sig64(&o.sig), &signed(ORC_DOMAIN, o.msg.as_bytes()), &pk32(&pk)), "ORC_BAD_SIGNATURE");
    let m: OrcMsg = near_sdk::serde_json::from_str(&o.msg).unwrap_or_else(|_| env::panic_str("BAD_ORC_MSG"));
    require!(m.v == "safebox.v4.onchain.orc", "ORC_VERSION");
    require!(m.op == op, "ORC_INTENT_WRONG_OPERATION");
    require!(m.case_ref == case_ref, "ORC_INTENT_WRONG_CASE");
    self.use_challenge(&m.nonce, m.issued_at_ns, m.expires_at_ns);
    o.index
  }
  fn close_failed(&mut self, c: &Case) {
    self.failed_claims.push(env::block_timestamp());
    for p in &c.plan { self.burned.insert(p.pk.clone()); }
    self.lockdown = false; self.case = None;
  }
  /// Reference that an ORC-attested OPEN commits to (case id, lost set, plan keys).
  pub fn open_ref(case_id: String, lost: Vec<String>, plan: Vec<Cred>) -> String {
    hex::encode(env::sha256(near_sdk::serde_json::to_string(&(&case_id, &lost, &plan.iter().map(|p| (&p.id, &p.pk)).collect::<Vec<_>>())).unwrap().as_bytes()))
  }

  // ------------------------------------------------ payments
  pub fn propose_payment(&mut self, msg: String, cred_id: String, sig: Base64VecU8) -> u64 {
    require!(!self.frozen, "FROZEN"); require!(!self.lockdown, "LOCKDOWN");
    let role = self.verify(PAY_DOMAIN, msg.as_bytes(), &cred_id, &sig);
    require!(role == Role::Daily, "ROLE_CANNOT_PAY");
    let m: PayMsg = near_sdk::serde_json::from_str(&msg).unwrap_or_else(|_| env::panic_str("BAD_PAY_MSG"));
    require!(m.v == "safebox.v4.onchain.pay", "PAY_VERSION");
    require!(m.epoch == self.epoch, "STALE_EPOCH");
    require!(m.purpose_version == self.purpose.version, "STALE_PURPOSE_VERSION");
    require!(env::block_timestamp() < m.expires_at_ns && env::block_timestamp() < self.purpose.expires_at_ns, "EXPIRED");
    require!(self.purpose.recipients.contains(&m.recipient), "RECIPIENT_NOT_IN_PURPOSE");
    require!(m.amount.0 > 0 && m.amount.0 <= self.purpose.per_payment_max.0, "OVER_PER_PAYMENT_LIMIT");
    require!(self.spent + m.amount.0 <= self.purpose.cumulative_limit.0, "OVER_CUMULATIVE_LIMIT");
    self.use_nonce(&m.nonce);
    self.spent += m.amount.0; // reserved now, released on cancel
    let id = self.next_id; self.next_id += 1;
    self.pending.insert(id, Pending { recipient: m.recipient, amount: m.amount, release_at_ns: env::block_timestamp() + self.buffer_ns, epoch: self.epoch, purpose_version: self.purpose.version, cred_id });
    id
  }
  /// Anyone may trigger a release; the contract decides. Returns true if a transfer was made.
  pub fn release(&mut self, id: u64) -> bool {
    let p = self.pending.get(&id).cloned().unwrap_or_else(|| env::panic_str("NO_PENDING"));
    require!(!self.frozen && !self.lockdown, "FROZEN_OR_LOCKDOWN");
    require!(env::block_timestamp() >= p.release_at_ns, "BUFFER_NOT_ELAPSED");
    let approver_ok = self.creds.iter().any(|c| c.id == p.cred_id && c.active);
    self.pending.remove(&id);
    if p.epoch != self.epoch || p.purpose_version != self.purpose.version || !approver_ok { self.spent -= p.amount.0; return false; }
    Promise::new(p.recipient).transfer(NearToken::from_yoctonear(p.amount.0)).detach();
    true
  }

  // ------------------------------------------------ governance (hard-coded matrix)
  fn count_roles(&self, msg: &[u8], approvals: &[Approval], exclude: Option<&str>) -> (u32, u32, u32, u32, bool) {
    let (mut d, mut r, mut f, mut rc) = (0, 0, 0, 0); let mut seen: Vec<&str> = vec![]; let mut self_signed = false;
    for a in approvals {
      require!(!seen.contains(&a.cred_id.as_str()), "DUPLICATE_APPROVAL"); seen.push(&a.cred_id);
      let role = self.verify(GOV_DOMAIN, msg, &a.cred_id, &a.sig);
      if Some(a.cred_id.as_str()) == exclude { self_signed = true; continue; }
      match role { Role::Daily => d += 1, Role::Root => r += 1, Role::Freeze => f += 1, Role::Recovery => rc += 1 }
    }
    (d, r, f, rc, self_signed)
  }
  pub fn govern(&mut self, msg: String, approvals: Vec<Approval>) {
    let m: GovMsg = near_sdk::serde_json::from_str(&msg).unwrap_or_else(|_| env::panic_str("BAD_GOV_MSG"));
    require!(m.v == "safebox.v4.onchain.gov", "GOV_VERSION");
    require!(m.epoch == self.epoch, "STALE_EPOCH");
    require!(self.gcase.is_none() || m.op == "FREEZE", "GOVERNANCE_CASE_OPEN");
    let subject = m.subject.clone();
    let (d, r, f, rc, self_signed) = self.count_roles(msg.as_bytes(), &approvals, subject.as_deref());
    self.use_challenge(&m.nonce, m.issued_at_ns, m.expires_at_ns);
    match m.op.as_str() {
      "FREEZE" => { require!(d + r + f + rc >= 1, "QUORUM"); self.frozen = true; }
      "UNFREEZE" => { require!(r >= 1 && d >= 1, "QUORUM"); self.frozen = false; }
      "AMEND_PURPOSE" => {
        require!(self.case.is_none() && !self.lockdown, "RECOVERY_IN_PROGRESS");
        require!(d >= 2 && r >= 1, "QUORUM");
        let p = m.purpose.unwrap_or_else(|| env::panic_str("NO_PURPOSE"));
        require!(p.version == self.purpose.version + 1, "PURPOSE_VERSION");
        self.purpose = p;
      }
      "REVOKE" => {
        require!(self.case.is_none(), "RECOVERY_IN_PROGRESS");
        let s = subject.unwrap_or_else(|| env::panic_str("NO_SUBJECT"));
        require!(!self_signed, "REVOKE_SELF_APPROVAL");
        require!((d >= 1 && r >= 1) || d >= 2, "QUORUM");
        let c = self.creds.iter_mut().find(|c| c.id == s && c.active).unwrap_or_else(|| env::panic_str("NO_SUBJECT"));
        c.active = false; self.epoch += 1;
      }
      "ROTATE" => {
        require!(self.case.is_none() && !self.lockdown, "RECOVERY_IN_PROGRESS");
        let s = subject.unwrap_or_else(|| env::panic_str("NO_SUBJECT"));
        let nc = m.new_cred.unwrap_or_else(|| env::panic_str("NO_NEW_CRED"));
        let old_role = self.cred(&s).role;
        require!(self_signed, "ROTATION_NEEDS_OLD_KEY");
        require!(nc.role == old_role, "ROLE_MUST_BE_PRESERVED");
        let ok = match old_role { Role::Daily => d >= 1 || r >= 1, Role::Root => d >= 2, Role::Freeze => r >= 1, Role::Recovery => r >= 1 && d >= 1 };
        require!(ok, "QUORUM");
        require!(!self.creds.iter().any(|c| c.pk == nc.pk || c.id == nc.id), "NOT_INDEPENDENT"); pk32(&nc.pk);
        for c in self.creds.iter_mut() { if c.id == s { c.active = false; } }
        self.baseline.iter_mut().for_each(|b| if *b == s { *b = nc.id.clone(); });
        self.creds.push(Cred { active: true, ..nc }); self.epoch += 1;
      }
      _ => env::panic_str("UNKNOWN_OP"),
    }
  }

  // ------------------------------------------------ recovery
  fn survivors(&self, c: &Case) -> Vec<String> { self.creds.iter().filter(|x| x.active && !c.lost.contains(&x.id)).map(|x| x.id.clone()).collect() }
  /// A claim: needs no authority and changes no authority.
  pub fn recovery_open(&mut self, case_id: String, lost: Vec<String>, plan: Vec<Cred>, orc: Option<OrcApproval>) {
    require!(self.case.is_none(), "CASE_OPEN");
    require!(self.gcase.is_none(), "GOVERNANCE_CASE_OPEN");
    require!(!lost.is_empty(), "LOST_EMPTY");
    for l in &lost { self.cred(l); }
    for p in &plan { pk32(&p.pk); require!(!self.creds.iter().any(|c| c.pk == p.pk || c.id == p.id), "NOT_INDEPENDENT"); require!(!self.burned.contains(&p.pk), "PLAN_KEY_PREVIOUSLY_REJECTED");
      require!(!self.orcs.contains(&p.pk) && !self.guardians.contains(&p.pk) && !self.idvs.contains(&p.pk) && !self.adjudicators.contains(&p.pk), "NOT_INDEPENDENT"); }
    let now = env::block_timestamp();
    let attested = match &orc { Some(o) => { let r = Self::open_ref(case_id.clone(), lost.clone(), plan.clone()); self.verify_orc(o, "RECOVERY_OPEN", &r); true } None => false };
    if !attested {
      if let Some(last) = self.failed_claims.last() { require!(now >= last + REATTEMPT_COOLDOWN, "RECOVERY_REATTEMPT_COOLDOWN"); }
      require!(self.failed_claims.iter().filter(|t| **t + 30 * DAY > now).count() < CLAIM_BUDGET_30D, "RECOVERY_CLAIM_BUDGET_EXHAUSTED");
    }
    // denominator = baseline (never reset by partial recoveries); earlier recovered-away keys still count as lost
    let recon = (self.lost_since_baseline as usize + lost.len()) * 2 > self.baseline.len();
    let digest = hex::encode(env::sha256(near_sdk::serde_json::to_string(&(&case_id, &lost, &plan, env::block_timestamp())).unwrap().as_bytes()));
    self.case = Some(Case { case_id, lost, plan, opened_at_ns: now, consents: vec![], guardians: vec![], identities: vec![], disputes: vec![], reconstitution: recon, digest,
      deadline_ns: now + self.window_ns, owner_auth: None, orc_attested: attested });
  }
  /// R-1: the owner's explicit, independent authorization of THIS case digest (which commits to the plan).
  pub fn recovery_owner_authorize(&mut self, orc: OrcApproval) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    require!(env::block_timestamp() < c.deadline_ns, "OWNER_AUTHORIZATION_AFTER_DEADLINE");
    self.verify_orc(&orc, "RECOVERY_OWNER_AUTHORIZE", &c.digest);
    self.case.as_mut().unwrap().owner_auth = Some(c.digest);
  }
  /// The ORC cancels any case at once, including during lockdown.
  pub fn recovery_orc_cancel(&mut self, orc: OrcApproval) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    self.verify_orc(&orc, "RECOVERY_ORC_CANCEL", &c.digest);
    self.close_failed(&c);
  }
  /// Anyone may call. An unapproved case ends at its deadline (an approved one at deadline + grace) with NO authority
  /// transfer; the lockdown is released.
  pub fn recovery_expire(&mut self) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    let now = env::block_timestamp();
    let unapproved = c.owner_auth.as_deref() != Some(c.digest.as_str());
    let minority_ready = !c.reconstitution && c.disputes.is_empty() && !c.identities.is_empty();
    require!(now >= c.deadline_ns + COMPLETION_GRACE || (now >= c.deadline_ns && unapproved && (c.reconstitution || !minority_ready)), "RECOVERY_NOT_EXPIRED");
    self.close_failed(&c);
  }
  pub fn case_digest(&self) -> Option<String> { self.case.as_ref().map(|c| c.digest.clone()) }
  pub fn recovery_consent(&mut self, cred_id: String, sig: Base64VecU8) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    require!(self.survivors(&c).contains(&cred_id), "NOT_A_SURVIVOR");
    self.verify(REC_DOMAIN, format!("CONSENT:{}", c.digest).as_bytes(), &cred_id, &sig);
    let cs = self.case.as_mut().unwrap(); if !cs.consents.contains(&cred_id) { cs.consents.push(cred_id); }
  }
  pub fn recovery_object(&mut self, cred_id: String, sig: Base64VecU8) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    self.verify(REC_DOMAIN, format!("OBJECT:{}", c.digest).as_bytes(), &cred_id, &sig);
    let cs = self.case.as_mut().unwrap(); if !cs.disputes.contains(&cred_id) { cs.disputes.push(cred_id); }
  }
  pub fn recovery_withdraw(&mut self, cred_id: String, sig: Base64VecU8) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    self.verify(REC_DOMAIN, format!("WITHDRAW:{}", c.digest).as_bytes(), &cred_id, &sig);
    self.case.as_mut().unwrap().disputes.retain(|d| *d != cred_id);
  }
  pub fn recovery_guardian(&mut self, index: u32, sig: Base64VecU8) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    let pk = self.guardians.get(index as usize).unwrap_or_else(|| env::panic_str("NO_GUARDIAN"));
    require!(env::ed25519_verify(&sig64(&sig), &signed(REC_DOMAIN, format!("GUARDIAN:{}", c.digest).as_bytes()), &pk32(pk)), "BAD_SIGNATURE");
    let cs = self.case.as_mut().unwrap(); if !cs.guardians.contains(&index) { cs.guardians.push(index); }
  }
  pub fn recovery_identity(&mut self, index: u32, sig: Base64VecU8) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    let pk = self.idvs.get(index as usize).unwrap_or_else(|| env::panic_str("NO_IDV"));
    require!(env::ed25519_verify(&sig64(&sig), &signed(REC_DOMAIN, format!("IDENTITY:{}", c.digest).as_bytes()), &pk32(pk)), "BAD_SIGNATURE");
    let cs = self.case.as_mut().unwrap(); if !cs.identities.contains(&index) { cs.identities.push(index); }
    if cs.reconstitution { self.lockdown = true; } // confirmed loss of more than half: emergency lockdown
  }
  pub fn recovery_cancel(&mut self, cred_id: String, sig: Base64VecU8) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    require!(self.survivors(&c).contains(&cred_id), "NOT_A_SURVIVOR");
    self.verify(REC_DOMAIN, format!("CANCEL:{}", c.digest).as_bytes(), &cred_id, &sig);
    require!(!self.lockdown, "LOCKDOWN_CANCEL_NEEDS_ORC"); // during lockdown only the ORC cancels (recovery_orc_cancel)
    self.close_failed(&c);
  }
  /// F-V3-02 (ported): on the minority-loss path, objections signed by an allegedly LOST key (possibly a thief) can be
  /// overridden only by the full evidence set: every survivor consented, the guardian quorum, identity, and the survivors
  /// strictly outnumber the objecting lost keys. A surviving key's objection is never overridable; reconstitution never.
  pub fn recovery_override(&mut self) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    require!(!c.reconstitution, "OVERRIDE_NOT_ALLOWED_IN_RECONSTITUTION");
    require!(!c.disputes.is_empty(), "NOTHING_TO_OVERRIDE");
    require!(c.disputes.iter().all(|d| c.lost.contains(d)), "SURVIVOR_OBJECTION_NOT_OVERRIDABLE");
    let surv = self.survivors(&c);
    require!(!surv.is_empty() && surv.iter().all(|s| c.consents.contains(s)), "OVERRIDE_NEEDS_ALL_SURVIVOR_CONSENTS");
    require!(c.guardians.len() as u32 >= self.guardian_quorum, "OVERRIDE_NEEDS_GUARDIAN_QUORUM");
    require!(!c.identities.is_empty(), "OVERRIDE_NEEDS_IDENTITY");
    require!(surv.len() > c.disputes.len(), "OVERRIDE_OUTNUMBERED_BY_OBJECTING_KEYS");
    self.case.as_mut().unwrap().disputes.clear();
  }
  /// Anyone may call; the contract checks every requirement. The timer alone never completes anything.
  pub fn recovery_complete(&mut self) {
    let c = self.case.clone().unwrap_or_else(|| env::panic_str("NO_CASE"));
    require!(env::block_timestamp() < c.deadline_ns + COMPLETION_GRACE, "RECOVERY_CASE_EXPIRED");
    require!(c.disputes.is_empty(), "DISPUTED");
    require!(!c.identities.is_empty(), "NO_IDENTITY");
    let surv = self.survivors(&c);
    require!(!surv.is_empty(), "RECOVERY_IMPOSSIBLE");
    require!(surv.iter().all(|s| c.consents.contains(s)), "SURVIVOR_CONSENT_MISSING");
    let need = if c.reconstitution { self.recon_guardian_quorum } else { self.guardian_quorum };
    require!(c.guardians.len() as u32 >= need, "GUARDIAN_QUORUM");
    if c.reconstitution { require!(c.identities.len() >= 2, "RECON_NEEDS_TWO_IDENTITY_ATTESTATIONS"); }
    require!(env::block_timestamp() >= c.opened_at_ns + self.window_ns, "WINDOW_OPEN");
    // INV-V4-01/02: silence, elapsed time, guardians, identity verifiers and survivor consents never authorize a
    // reconstitution. Only an ORC authorization bound to THIS digest does.
    if c.reconstitution { require!(c.owner_auth.as_deref() == Some(c.digest.as_str()), "OWNER_AUTHORIZATION_REQUIRED"); }
    let lost_roles: Vec<Role> = c.lost.iter().map(|l| self.cred(l).role).collect();
    if c.reconstitution {
      let n = |r: Role| c.plan.iter().filter(|p| p.role == r).count();
      require!(c.plan.len() >= 5 && n(Role::Daily) >= 2 && n(Role::Root) >= 1 && n(Role::Freeze) >= 1 && n(Role::Recovery) >= 1, "RECON_PLAN_NEEDS_FULL_ROLE_SET");
      for x in self.creds.iter_mut() { x.active = false; }
      self.baseline = c.plan.iter().map(|p| p.id.clone()).collect();
      self.lockdown = false; self.lost_since_baseline = 0;
    } else {
      self.lost_since_baseline += c.lost.len() as u32;
      let mut pr: Vec<Role> = c.plan.iter().map(|p| p.role).collect(); let mut lr = lost_roles.clone();
      let key = |r: &Role| *r as u8; pr.sort_by_key(key); lr.sort_by_key(key);
      require!(pr == lr, "REPLACEMENT_ROLES_MISMATCH");
      for x in self.creds.iter_mut() { if c.lost.contains(&x.id) { x.active = false; } }
    }
    for p in c.plan { self.creds.push(Cred { active: true, ..p }); }
    self.epoch += 1; self.case = None;
  }

  // ------------------------------------------------ R-3: guardian / identity-verifier emergency replacement
  fn voter_pk(&self, v: &str) -> Option<String> {
    let (k, i) = v.split_once(':')?; let i: usize = i.parse().ok()?;
    match k { "g" => self.guardians.get(i).cloned(), "i" => self.idvs.get(i).cloned(), _ => None }
  }
  fn all_keys(&self) -> Vec<String> {
    self.creds.iter().map(|c| c.pk.clone()).chain(self.guardians.iter().cloned()).chain(self.idvs.iter().cloned()).chain(self.orcs.iter().cloned())
      .chain(self.adjudicators.iter().cloned()).chain(self.disqualified.iter().cloned()).collect()
  }
  /// Statement the owner quorum signs (GOV_DOMAIN, with challenge fields) to open a case.
  pub fn gov_open_statement(gcase_id: String, guardian_proc: bool, accused: Vec<u32>, replacements: Vec<String>, epoch: u64, nonce: String, issued_at_ns: u64, expires_at_ns: u64) -> String {
    near_sdk::serde_json::json!({ "v": "safebox.v4.onchain.govcase", "gcaseId": gcase_id, "guardianProc": guardian_proc, "accused": accused, "replacements": replacements,
      "epoch": epoch, "nonce": nonce, "issuedAtNs": issued_at_ns, "expiresAtNs": expires_at_ns }).to_string()
  }
  pub fn gov_case_open(&mut self, gcase_id: String, guardian_proc: bool, accused: Vec<u32>, verdicts: Vec<Verdict>, replacements: Vec<Replacement>,
    nonce: String, issued_at_ns: u64, expires_at_ns: u64, owners: Vec<Approval>) {
    require!(self.case.is_none() && !self.lockdown, "RECOVERY_CASE_OPEN");
    require!(self.gcase.is_none(), "GOVERNANCE_CASE_ALREADY_OPEN");
    let now = env::block_timestamp();
    let rep_pks: Vec<String> = replacements.iter().map(|r| r.pk.clone()).collect();
    let stmt = Self::gov_open_statement(gcase_id.clone(), guardian_proc, accused.clone(), rep_pks.clone(), self.epoch, nonce.clone(), issued_at_ns, expires_at_ns);
    // owner quorum: >= 2 distinct roles among DAILY / ROOT / RECOVERY / ORC (FREEZE excluded); no key counted twice
    require!(owners.len() >= 2 && owners.len() <= 6, "EMERGENCY_OWNER_QUORUM_SHAPE");
    let mut seen: Vec<String> = vec![]; let mut roles: Vec<u8> = vec![];
    for a in &owners {
      require!(!seen.contains(&a.cred_id), "DUPLICATE_APPROVAL"); seen.push(a.cred_id.clone());
      let role = if let Some(ix) = a.cred_id.strip_prefix("orc:") {
        let pk = self.orcs.get(ix.parse::<usize>().unwrap_or(usize::MAX)).cloned().unwrap_or_else(|| env::panic_str("ORC_UNKNOWN"));
        require!(env::ed25519_verify(&sig64(&a.sig), &signed(GOV_DOMAIN, stmt.as_bytes()), &pk32(&pk)), "BAD_SIGNATURE"); 9u8
      } else { let r = self.verify(GOV_DOMAIN, stmt.as_bytes(), &a.cred_id, &a.sig); require!(r != Role::Freeze, "ROLE_NOT_IN_EMERGENCY_OWNER_QUORUM"); r as u8 };
      if !roles.contains(&role) { roles.push(role); }
    }
    require!(roles.len() >= 2, "EMERGENCY_OWNER_QUORUM_NOT_MET");
    self.use_challenge(&nonce, issued_at_ns, expires_at_ns);
    let pool: Vec<String> = if guardian_proc { self.guardians.clone() } else { self.idvs.clone() };
    require!(!accused.is_empty(), "GOV_ACCUSED_SET");
    let mut acc = accused.clone(); acc.sort(); acc.dedup(); require!(acc.len() == accused.len(), "GOV_ACCUSED_SET");
    // an accusation alone proves nothing: >= ADJUDICATOR_QUORUM distinct, current, correctly bound verdicts per accused key
    for ix in &accused {
      let subject = pool.get(*ix as usize).cloned().unwrap_or_else(|| env::panic_str("GOV_ACCUSED_NOT_MEMBER"));
      let mut by: Vec<u32> = vec![];
      for v in verdicts.iter() {
        let m: VerdictMsg = near_sdk::serde_json::from_str(&v.msg).unwrap_or_else(|_| env::panic_str("BAD_VERDICT"));
        if m.subject_pk != subject { continue; }
        let apk = self.adjudicators.get(v.adjudicator as usize).cloned().unwrap_or_else(|| env::panic_str("VERDICT_UNKNOWN_ADJUDICATOR"));
        require!(env::ed25519_verify(&sig64(&v.sig), &signed(VERDICT_DOMAIN, v.msg.as_bytes()), &pk32(&apk)), "VERDICT_SIGNATURE");
        require!(m.v == "safebox.v4.onchain.verdict" && (m.finding == "COMPROMISED" || m.finding == "MISCONDUCT"), "VERDICT_FINDING");
        require!(now < m.expires_at_ns && m.expires_at_ns <= now + 30 * DAY, "VERDICT_NOT_CURRENT");
        if !by.contains(&v.adjudicator) { by.push(v.adjudicator); }
      }
      require!(by.len() >= ADJUDICATOR_QUORUM, "ACCUSATION_NOT_ESTABLISHED");
    }
    // atomic 1:1 replacement with proof of possession, independent of every existing key
    require!(replacements.len() == accused.len(), "REMOVAL_WITHOUT_REPLACEMENT");
    let mut keys = self.all_keys();
    for r in &replacements {
      pk32(&r.pk); require!(!keys.contains(&r.pk), "REPLACEMENT_KEY_NOT_INDEPENDENT"); keys.push(r.pk.clone());
      require!(env::ed25519_verify(&sig64(&r.pop), &signed(PART_DOMAIN, format!("POP:{}:{}", gcase_id, r.pk).as_bytes()), &pk32(&r.pk)), "REPLACEMENT_POP_INVALID");
    }
    // electorate: every guardian and identity verifier, minus the accused, minus disqualified keys; never empty
    let mut electorate: Vec<String> = vec![];
    for (i, g) in self.guardians.iter().enumerate() { if !(guardian_proc && accused.contains(&(i as u32))) && !self.disqualified.contains(g) { electorate.push(format!("g:{}", i)); } }
    for (i, d) in self.idvs.iter().enumerate() { if !(!guardian_proc && accused.contains(&(i as u32))) && !self.disqualified.contains(d) { electorate.push(format!("i:{}", i)); } }
    require!(!electorate.is_empty(), "EMERGENCY_ELECTORATE_EMPTY");
    let digest = hex::encode(env::sha256(format!("GCASE:{}:{}", stmt, now).as_bytes()));
    self.gcase = Some(GCase { gcase_id, guardian_proc, accused, replacements: rep_pks, electorate, commitments: vec![], opened_at_ns: now, vote_deadline_ns: now + GOV_VOTE, execute_after_ns: None, digest });
  }
  pub fn gcase_digest(&self) -> Option<String> { self.gcase.as_ref().map(|g| g.digest.clone()) }
  /// One hiding commitment per eligible voter: sha256("APPROVE|REJECT" | digest | voter | salt), signed by the voter key.
  pub fn gov_ballot(&mut self, voter: String, commitment: String, sig: Base64VecU8) {
    let g = self.gcase.clone().unwrap_or_else(|| env::panic_str("NO_GOVERNANCE_CASE"));
    require!(g.execute_after_ns.is_none() && env::block_timestamp() < g.vote_deadline_ns, "BALLOT_VOTING_CLOSED");
    require!(g.electorate.contains(&voter), "BALLOT_VOTER_NOT_ELIGIBLE");
    require!(!g.commitments.iter().any(|(v, _)| *v == voter), "BALLOT_DUPLICATE_VOTE");
    require!(commitment.len() == 64 && commitment.chars().all(|c| c.is_ascii_hexdigit()), "BALLOT_COMMITMENT");
    let pk = self.voter_pk(&voter).unwrap_or_else(|| env::panic_str("BALLOT_VOTER_NOT_ELIGIBLE"));
    require!(env::ed25519_verify(&sig64(&sig), &signed(PART_DOMAIN, format!("BALLOT:{}:{}:{}", g.digest, voter, commitment).as_bytes()), &pk32(&pk)), "BALLOT_ELIGIBILITY_SIGNATURE");
    self.gcase.as_mut().unwrap().commitments.push((voter, commitment));
  }
  pub fn commitment_of(choice: String, digest: String, voter: String, salt: String) -> String { hex::encode(env::sha256(format!("{}|{}|{}|{}", choice, digest, voter, salt).as_bytes())) }
  /// Approval is verifiable without trusting any tally: every eligible voter committed and every commitment opens to APPROVE.
  pub fn gov_tally_approve(&mut self, openings: Vec<(String, String)>) {
    let g = self.gcase.clone().unwrap_or_else(|| env::panic_str("NO_GOVERNANCE_CASE"));
    require!(g.execute_after_ns.is_none(), "ALREADY_APPROVED");
    require!(g.electorate.iter().all(|v| g.commitments.iter().any(|(x, _)| x == v)), "TALLY_APPROVAL_INCOMPLETE");
    require!(openings.len() == g.electorate.len(), "TALLY_OPENINGS_MISSING");
    let mut seen: Vec<&String> = vec![];
    for (voter, salt) in &openings {
      require!(!seen.contains(&voter), "TALLY_OPENING_VOTER"); seen.push(voter);
      let c = g.commitments.iter().find(|(x, _)| x == voter).map(|(_, c)| c.clone()).unwrap_or_else(|| env::panic_str("TALLY_OPENING_VOTER"));
      require!(Self::commitment_of("APPROVE".into(), g.digest.clone(), voter.clone(), salt.clone()) == c, "TALLY_OPENING_MISMATCH");
    }
    self.gcase.as_mut().unwrap().execute_after_ns = Some(env::block_timestamp() + GOV_DELAY);
  }
  pub fn gov_execute(&mut self) {
    let g = self.gcase.clone().unwrap_or_else(|| env::panic_str("NO_GOVERNANCE_CASE"));
    let ea = g.execute_after_ns.unwrap_or_else(|| env::panic_str("GOV_NOT_APPROVED"));
    require!(env::block_timestamp() >= ea, "GOV_SECURITY_DELAY_OPEN");
    require!(env::block_timestamp() < ea + COMPLETION_GRACE, "GOV_EXPIRED");
    require!(self.case.is_none() && !self.lockdown, "RECOVERY_CASE_OPEN");
    let before = if g.guardian_proc { self.guardians.len() } else { self.idvs.len() };
    for (k, ix) in g.accused.iter().enumerate() {
      let list = if g.guardian_proc { &mut self.guardians } else { &mut self.idvs };
      let old = std::mem::replace(&mut list[*ix as usize], g.replacements[k].clone());
      self.disqualified.push(old);
    }
    let after = if g.guardian_proc { self.guardians.len() } else { self.idvs.len() };
    require!(before == after && (self.guardians.len() as u32) >= self.recon_guardian_quorum, "QUORUM_FLOOR_CHANGED");
    self.epoch += 1; self.gcase = None;
  }
  /// Anyone may call after the vote window (unapproved) or after the execution grace.
  pub fn gov_expire(&mut self) {
    let g = self.gcase.clone().unwrap_or_else(|| env::panic_str("NO_GOVERNANCE_CASE"));
    let now = env::block_timestamp();
    let ok = match g.execute_after_ns { None => now >= g.vote_deadline_ns, Some(ea) => now >= ea + COMPLETION_GRACE };
    require!(ok, "GOV_NOT_EXPIRED"); self.gcase = None;
  }
  pub fn gov_orc_cancel(&mut self, orc: OrcApproval) {
    let g = self.gcase.clone().unwrap_or_else(|| env::panic_str("NO_GOVERNANCE_CASE"));
    self.verify_orc(&orc, "GOV_CASE_CANCEL", &g.digest); self.gcase = None;
  }

  // ------------------------------------------------ views
  pub fn view_state(&self) -> near_sdk::serde_json::Value {
    near_sdk::serde_json::json!({ "epoch": self.epoch, "frozen": self.frozen, "lockdown": self.lockdown, "purposeVersion": self.purpose.version, "spent": U128(self.spent),
      "creds": self.creds.iter().map(|c| (c.id.clone(), format!("{:?}", c.role), c.active)).collect::<Vec<_>>(), "case": self.case.as_ref().map(|c| c.case_id.clone()),
      "ownerAuthorized": self.case.as_ref().map(|c| c.owner_auth.as_deref() == Some(c.digest.as_str())), "gcase": self.gcase.as_ref().map(|g| g.gcase_id.clone()),
      "guardians": self.guardians.clone(), "idvs": self.idvs.clone(), "failedClaims": self.failed_claims.len() })
  }
}

#[cfg(test)]
mod tests;
