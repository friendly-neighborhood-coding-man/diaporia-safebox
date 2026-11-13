//! DIAPORIA SafeBox V3 on-chain vault (LOCAL SANDBOX ONLY — not deployed to any network).
//!
//! The contract is the on-chain half of the Purpose Root: it holds the funds and re-enforces, with its OWN signature
//! checks, the same authority rules as the off-chain Root, so that a compromised off-chain executor cannot move funds
//! beyond the owner's Purpose and a compromised recovery service cannot install keys.
//!
//! * Payments: a DAILY credential's Ed25519 signature over an exact payment message bound to (epoch, purpose version,
//!   nonce, recipient, amount, expiry); recipient allow-list, per-payment and cumulative limits; buffered two-phase
//!   release; freeze / lockdown block release; stale epoch / purpose / revoked approver cancel at release.
//! * Governance: hard-coded authority matrix (not amendable on-chain): purpose amendment = 2 DAILY + 1 ROOT;
//!   unfreeze = ROOT + DAILY (FREEZE key cannot unfreeze); rotation = old key + role-specific others; revocation = two
//!   other keys. Every authority change bumps the epoch.
//! * Recovery: a claim changes nothing; completion needs consents of ALL surviving credentials, a guardian quorum, an
//!   identity attestation and the protected window (block time), and no objection. > 50 % lost => lockdown and the
//!   stricter reconstitution quorum; claimed-lost keys objecting cannot be overridden on-chain.
//! * There is NO owner/admin method, NO upgrade method and NO withdraw-all. Privileged bypass then depends on the
//!   ACCOUNT having no FullAccess key (deployment invariant checked off-chain: scripts/v3/check-deployment.mjs).
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::{IterableMap, LookupSet};
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

const PAY_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V3_ONCHAIN_PAY\n";
const GOV_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V3_ONCHAIN_GOV\n";
const REC_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_V3_ONCHAIN_RECOVERY\n";

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
  pub identities: Vec<u32>, pub disputes: Vec<String>, pub reconstitution: bool, pub digest: String }

#[near(serializers = [json])]
pub struct Init { pub creds: Vec<Cred>, pub guardians: Vec<String>, pub idvs: Vec<String>, pub purpose: Purpose, pub buffer_ns: u64, pub window_ns: u64,
  pub guardian_quorum: u32, pub recon_guardian_quorum: u32 }

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SafeBoxV3 {
  epoch: u64, creds: Vec<Cred>, baseline: Vec<String>, guardians: Vec<String>, idvs: Vec<String>, purpose: Purpose, spent: u128,
  frozen: bool, lockdown: bool, buffer_ns: u64, window_ns: u64, guardian_quorum: u32, recon_guardian_quorum: u32,
  lost_since_baseline: u32, used: LookupSet<String>, pending: IterableMap<u64, Pending>, next_id: u64, case: Option<Case>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields, rename_all = "camelCase")]
struct PayMsg { v: String, epoch: u64, purpose_version: u64, nonce: String, recipient: AccountId, amount: U128, expires_at_ns: u64 }

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields, rename_all = "camelCase")]
struct GovMsg { v: String, epoch: u64, nonce: String, expires_at_ns: u64, op: String, #[serde(default)] subject: Option<String>,
  #[serde(default)] new_cred: Option<Cred>, #[serde(default)] purpose: Option<Purpose> }

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Approval { pub cred_id: String, pub sig: Base64VecU8 }

fn pk32(s: &str) -> [u8; 32] { let v = hex::decode(s).unwrap_or_else(|_| env::panic_str("BAD_PUBLIC_KEY")); v.try_into().unwrap_or_else(|_| env::panic_str("BAD_PUBLIC_KEY")) }
fn sig64(s: &Base64VecU8) -> [u8; 64] { s.0.clone().try_into().unwrap_or_else(|_| env::panic_str("BAD_SIGNATURE_LENGTH")) }
fn signed(domain: &[u8], msg: &[u8]) -> Vec<u8> { [domain, msg].concat() }

#[near]
impl SafeBoxV3 {
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
    Self { epoch: 1, baseline: init.creds.iter().map(|c| c.id.clone()).collect(), creds: init.creds, guardians: init.guardians, idvs: init.idvs, purpose: init.purpose, spent: 0,
      frozen: false, lockdown: false, buffer_ns: init.buffer_ns, window_ns: init.window_ns, guardian_quorum: init.guardian_quorum, recon_guardian_quorum: init.recon_guardian_quorum,
      lost_since_baseline: 0, used: LookupSet::new(b"u"), pending: IterableMap::new(b"p"), next_id: 1, case: None }
  }

  fn cred(&self, id: &str) -> &Cred { self.creds.iter().find(|c| c.id == id && c.active).unwrap_or_else(|| env::panic_str("CREDENTIAL_NOT_ACTIVE")) }
  fn verify(&self, domain: &[u8], msg: &[u8], cred_id: &str, sig: &Base64VecU8) -> Role {
    let c = self.cred(cred_id);
    require!(env::ed25519_verify(&sig64(sig), &signed(domain, msg), &pk32(&c.pk)), "BAD_SIGNATURE");
    c.role
  }
  fn use_nonce(&mut self, n: &str) { require!(n.len() == 32 && n.chars().all(|c| c.is_ascii_hexdigit()), "NONCE"); require!(self.used.insert(n.to_string()), "REPLAY"); }

  // ------------------------------------------------ payments
  pub fn propose_payment(&mut self, msg: String, cred_id: String, sig: Base64VecU8) -> u64 {
    require!(!self.frozen, "FROZEN"); require!(!self.lockdown, "LOCKDOWN");
    let role = self.verify(PAY_DOMAIN, msg.as_bytes(), &cred_id, &sig);
    require!(role == Role::Daily, "ROLE_CANNOT_PAY");
    let m: PayMsg = near_sdk::serde_json::from_str(&msg).unwrap_or_else(|_| env::panic_str("BAD_PAY_MSG"));
    require!(m.v == "safebox.v3.onchain.pay", "PAY_VERSION");
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
    require!(m.v == "safebox.v3.onchain.gov", "GOV_VERSION");
    require!(m.epoch == self.epoch, "STALE_EPOCH");
    require!(env::block_timestamp() < m.expires_at_ns, "EXPIRED");
    let subject = m.subject.clone();
    let (d, r, f, rc, self_signed) = self.count_roles(msg.as_bytes(), &approvals, subject.as_deref());
    self.use_nonce(&m.nonce);
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
  pub fn recovery_open(&mut self, case_id: String, lost: Vec<String>, plan: Vec<Cred>) {
    require!(self.case.is_none(), "CASE_OPEN");
    require!(!lost.is_empty(), "LOST_EMPTY");
    for l in &lost { self.cred(l); }
    for p in &plan { pk32(&p.pk); require!(!self.creds.iter().any(|c| c.pk == p.pk || c.id == p.id), "NOT_INDEPENDENT"); }
    // denominator = baseline (never reset by partial recoveries); earlier recovered-away keys still count as lost
    let recon = (self.lost_since_baseline as usize + lost.len()) * 2 > self.baseline.len();
    let digest = hex::encode(env::sha256(near_sdk::serde_json::to_string(&(&case_id, &lost, &plan, env::block_timestamp())).unwrap().as_bytes()));
    self.case = Some(Case { case_id, lost, plan, opened_at_ns: env::block_timestamp(), consents: vec![], guardians: vec![], identities: vec![], disputes: vec![], reconstitution: recon, digest });
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
    require!(!self.lockdown, "LOCKDOWN_CANCEL_NEEDS_GOVERNANCE_QUORUM_OFFCHAIN_ROOT"); // conservative on-chain
    self.case = None;
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
    require!(c.disputes.is_empty(), "DISPUTED");
    require!(!c.identities.is_empty(), "NO_IDENTITY");
    let surv = self.survivors(&c);
    require!(!surv.is_empty(), "RECOVERY_IMPOSSIBLE");
    require!(surv.iter().all(|s| c.consents.contains(s)), "SURVIVOR_CONSENT_MISSING");
    let need = if c.reconstitution { self.recon_guardian_quorum } else { self.guardian_quorum };
    require!(c.guardians.len() as u32 >= need, "GUARDIAN_QUORUM");
    if c.reconstitution { require!(c.identities.len() >= 2, "RECON_NEEDS_TWO_IDENTITY_ATTESTATIONS"); }
    require!(env::block_timestamp() >= c.opened_at_ns + self.window_ns, "WINDOW_OPEN");
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

  // ------------------------------------------------ views
  pub fn view_state(&self) -> near_sdk::serde_json::Value {
    near_sdk::serde_json::json!({ "epoch": self.epoch, "frozen": self.frozen, "lockdown": self.lockdown, "purposeVersion": self.purpose.version, "spent": U128(self.spent),
      "creds": self.creds.iter().map(|c| (c.id.clone(), format!("{:?}", c.role), c.active)).collect::<Vec<_>>(), "case": self.case.as_ref().map(|c| c.case_id.clone()) })
  }
}

#[cfg(test)]
mod tests;
