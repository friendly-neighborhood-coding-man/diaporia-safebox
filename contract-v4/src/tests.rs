// SafeBox V4 on-chain vault (V3 tests ported + V4 tests at the end): authority, payment, recovery and epoch tests in the near-sdk unit-test VM.
// Every signature is a real Ed25519 signature (ed25519-dalek) verified by the contract through env::ed25519_verify.
// NOTE: the unit-test VM does not roll back in-memory state after a panic the way a real receipt would; failure
// tests therefore only assert the panic reason and later steps always use fresh nonces.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

const SEC: u64 = 1_000_000_000;
const HOUR: u64 = 3600 * SEC;
const T0: u64 = 1_800_000_000 * SEC;

struct H { c: SafeBoxV4, keys: Vec<(String, SigningKey)>, guardians: Vec<SigningKey>, idvs: Vec<SigningKey>, orcs: Vec<SigningKey>, adjs: Vec<SigningKey>, now: u64, n: u64 }

fn key(seed: u8) -> SigningKey { SigningKey::from_bytes(&[seed; 32]) }
fn pkh(k: &SigningKey) -> String { hex::encode(k.verifying_key().to_bytes()) }
fn ctx(now: u64) {
  let mut b = VMContextBuilder::new();
  b.current_account_id("vault-alice.test.near".parse().unwrap()).predecessor_account_id("vault-alice.test.near".parse().unwrap())
    .block_timestamp(now).account_balance(NearToken::from_near(100));
  testing_env!(b.build());
}
fn acct(s: &str) -> AccountId { s.parse().unwrap() }
fn cred(id: &str, role: Role, k: &SigningKey) -> Cred { Cred { id: id.into(), role, pk: pkh(k), active: true } }

impl H {
  fn new() -> Self {
    ctx(T0);
    let keys: Vec<(String, SigningKey)> = vec![("k1".into(), key(1)), ("k2".into(), key(2)), ("k3".into(), key(3)), ("k4".into(), key(4)), ("k5".into(), key(5))];
    let roles = [Role::Daily, Role::Daily, Role::Root, Role::Freeze, Role::Recovery];
    let creds = keys.iter().zip(roles).map(|((id, k), r)| cred(id, r, k)).collect();
    let guardians = vec![key(31), key(32), key(33)];
    let idvs = vec![key(41), key(42)];
    let c = SafeBoxV4::new(Init { creds, guardians: guardians.iter().map(pkh).collect(), idvs: idvs.iter().map(pkh).collect(),
      purpose: Purpose { version: 1, recipients: vec![acct("shop.test.near")], per_payment_max: U128(10), cumulative_limit: U128(30), expires_at_ns: T0 + 1000 * HOUR },
      buffer_ns: 600 * SEC, window_ns: 72 * HOUR, guardian_quorum: 2, recon_guardian_quorum: 3, orcs: vec![pkh(&key(111))], adjudicators: vec![pkh(&key(101)), pkh(&key(102)), pkh(&key(103))] });
    H { c, keys, guardians, idvs, orcs: vec![key(111)], adjs: vec![key(101), key(102), key(103)], now: T0, n: 0 }
  }
  fn sk(&self, id: &str) -> &SigningKey { &self.keys.iter().rev().find(|(i, _)| i == id).unwrap().1 }
  fn at(&mut self, dt: u64) { self.now += dt; ctx(self.now); }
  fn nonce(&mut self) -> String { self.n += 1; format!("{:032x}", self.n) }
  fn nonce256(&mut self) -> String { self.n += 1; format!("{:064x}", self.n) }
  fn s(k: &SigningKey, dom: &[u8], m: &[u8]) -> Base64VecU8 { Base64VecU8(k.sign(&signed(dom, m)).to_bytes().to_vec()) }
  fn epoch(&self) -> u64 { self.c.epoch }
  fn pay_msg(&mut self, to: &str, amount: u128) -> String {
    let n = self.nonce();
    format!(r#"{{"v":"safebox.v4.onchain.pay","epoch":{},"purposeVersion":{},"nonce":"{}","recipient":"{}","amount":"{}","expiresAtNs":{}}}"#,
      self.c.epoch, self.c.purpose.version, n, to, amount, self.now + HOUR)
  }
  fn propose(&mut self, by: &str, to: &str, amount: u128) -> u64 {
    let m = self.pay_msg(to, amount); let sig = H::s(self.sk(by), PAY_DOMAIN, m.as_bytes()); self.c.propose_payment(m, by.into(), sig)
  }
  fn gov_msg(&mut self, op: &str, extra: &str) -> String {
    let n = self.nonce256();
    format!(r#"{{"v":"safebox.v4.onchain.gov","epoch":{},"nonce":"{}","issuedAtNs":{},"expiresAtNs":{},"op":"{}"{}}}"#, self.c.epoch, n, self.now, self.now + 120 * SEC, op, extra)
  }
  fn approvals(&self, m: &str, by: &[&str]) -> Vec<Approval> { by.iter().map(|i| Approval { cred_id: (*i).into(), sig: H::s(self.sk(i), GOV_DOMAIN, m.as_bytes()) }).collect() }
  fn govern(&mut self, op: &str, extra: &str, by: &[&str]) { let m = self.gov_msg(op, extra); let a = self.approvals(&m, by); self.c.govern(m, a); }
  fn rec(&self, word: &str, k: &SigningKey) -> Base64VecU8 { H::s(k, REC_DOMAIN, format!("{}:{}", word, self.c.case_digest().unwrap()).as_bytes()) }
  fn orc_msg(&mut self, op: &str, case_ref: &str, ttl: u64) -> String {
    let n = self.nonce256();
    format!(r#"{{"v":"safebox.v4.onchain.orc","op":"{}","caseRef":"{}","nonce":"{}","issuedAtNs":{},"expiresAtNs":{}}}"#, op, case_ref, n, self.now, self.now + ttl)
  }
  fn orc(&mut self, op: &str, case_ref: &str) -> OrcApproval { let m = self.orc_msg(op, case_ref, 120 * SEC); OrcApproval { index: 0, sig: H::s(&self.orcs[0], ORC_DOMAIN, m.as_bytes()), msg: m } }
  fn orc_authorize(&mut self) { let d = self.c.case_digest().unwrap(); let o = self.orc("RECOVERY_OWNER_AUTHORIZE", &d); self.c.recovery_owner_authorize(o); }
  fn consent(&mut self, id: &str) { let s = self.rec("CONSENT", self.sk(id)); self.c.recovery_consent(id.into(), s); }
  fn object(&mut self, id: &str) { let s = self.rec("OBJECT", self.sk(id)); self.c.recovery_object(id.into(), s); }
  fn guardian(&mut self, i: u32) { let s = self.rec("GUARDIAN", &self.guardians[i as usize]); self.c.recovery_guardian(i, s); }
  fn identity(&mut self, i: u32) { let s = self.rec("IDENTITY", &self.idvs[i as usize]); self.c.recovery_identity(i, s); }
  fn active(&self, id: &str) -> bool { self.c.creds.iter().any(|c| c.id == id && c.active) }
  fn add_key(&mut self, id: &str, seed: u8) -> Cred { let k = key(seed); self.keys.push((id.into(), k.clone())); Cred { id: id.into(), role: Role::Daily, pk: pkh(&k), active: true } }
}

fn fails<F: FnOnce()>(f: F) -> String {
  let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
  match r { Ok(_) => "NO_PANIC".into(), Err(e) => e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default() }
}
macro_rules! assert_fails { ($e:expr, $code:expr) => {{ let m = $e; assert!(m.contains($code), "expected {} got {}", $code, m); }}; }

// ---------------------------------------------------------------- init / independence
#[test]
fn init_requires_self_five_roles_and_distinct_keys() {
  let mut b = VMContextBuilder::new();
  b.current_account_id(acct("vault.test.near")).predecessor_account_id(acct("attacker.test.near"));
  testing_env!(b.build());
  let k = key(9);
  let mk = |creds: Vec<Cred>| Init { creds, guardians: vec![pkh(&key(31)), pkh(&key(32)), pkh(&key(33))], idvs: vec![pkh(&key(41))],
    purpose: Purpose { version: 1, recipients: vec![], per_payment_max: U128(1), cumulative_limit: U128(1), expires_at_ns: 1 }, buffer_ns: 600 * SEC, window_ns: 72 * HOUR, guardian_quorum: 2, recon_guardian_quorum: 3, orcs: vec![pkh(&key(111))], adjudicators: vec![pkh(&key(101)), pkh(&key(102))] };
  let five = || vec![cred("a", Role::Daily, &key(1)), cred("b", Role::Daily, &key(2)), cred("c", Role::Root, &key(3)), cred("d", Role::Freeze, &key(4)), cred("e", Role::Recovery, &key(5))];
  assert_fails!(fails(|| { SafeBoxV4::new(mk(five())); }), "INIT_ONLY_BY_SELF");
  ctx(T0);
  assert_fails!(fails(|| { SafeBoxV4::new(mk(five()[..4].to_vec())); }), "NEEDS_FIVE_INDEPENDENT_CREDENTIALS");
  let mut dup = five(); dup[1].pk = pkh(&key(1));
  assert_fails!(fails(|| { SafeBoxV4::new(mk(dup)); }), "DUPLICATE_PUBLIC_KEY");
  let mut g = five(); g[0] = cred("a", Role::Daily, &key(31));
  assert_fails!(fails(|| { SafeBoxV4::new(mk(g)); }), "GUARDIAN_IS_CREDENTIAL");
  let _ = k;
}

// ---------------------------------------------------------------- payments
#[test]
fn daily_key_pays_exactly_within_purpose_after_buffer() {
  let mut h = H::new();
  let id = h.propose("k1", "shop.test.near", 7);
  assert_fails!(fails(|| { h.c.release(id); }), "BUFFER_NOT_ELAPSED");
  h.at(600 * SEC);
  assert!(h.c.release(id));
  assert_eq!(h.c.spent, 7);
}

#[test]
fn payment_checks_role_recipient_limits_signature_and_replay() {
  let mut h = H::new();
  for (by, code) in [("k3", "ROLE_CANNOT_PAY"), ("k4", "ROLE_CANNOT_PAY"), ("k5", "ROLE_CANNOT_PAY")] {
    let m = h.pay_msg("shop.test.near", 1); let s = H::s(h.sk(by), PAY_DOMAIN, m.as_bytes());
    assert_fails!(fails(|| { h.c.propose_payment(m, by.into(), s); }), code);
  }
  assert_fails!(fails(|| { h.propose("k1", "attacker.test.near", 1); }), "RECIPIENT_NOT_IN_PURPOSE");
  assert_fails!(fails(|| { h.propose("k1", "shop.test.near", 11); }), "OVER_PER_PAYMENT_LIMIT");
  // signature by k2 presented as k1
  let m = h.pay_msg("shop.test.near", 1); let s = H::s(h.sk("k2"), PAY_DOMAIN, m.as_bytes());
  assert_fails!(fails(|| { h.c.propose_payment(m, "k1".into(), s); }), "BAD_SIGNATURE");
  // wrong domain (a governance signature replayed as a payment)
  let m = h.pay_msg("shop.test.near", 1); let s = H::s(h.sk("k1"), GOV_DOMAIN, m.as_bytes());
  assert_fails!(fails(|| { h.c.propose_payment(m, "k1".into(), s); }), "BAD_SIGNATURE");
  // tampered amount after signing
  let m = h.pay_msg("shop.test.near", 1); let s = H::s(h.sk("k1"), PAY_DOMAIN, m.as_bytes());
  let m2 = m.replace(r#""amount":"1""#, r#""amount":"9""#);
  assert_fails!(fails(|| { h.c.propose_payment(m2, "k1".into(), s); }), "BAD_SIGNATURE");
  // exact replay
  let m = h.pay_msg("shop.test.near", 1); let s = H::s(h.sk("k1"), PAY_DOMAIN, m.as_bytes());
  h.c.propose_payment(m.clone(), "k1".into(), s.clone());
  assert_fails!(fails(|| { h.c.propose_payment(m, "k1".into(), s); }), "REPLAY");
  // unknown field smuggling
  let n = h.nonce();
  let m = format!(r#"{{"v":"safebox.v4.onchain.pay","epoch":1,"purposeVersion":1,"nonce":"{}","recipient":"shop.test.near","amount":"1","expiresAtNs":{},"memo":"x"}}"#, n, h.now + HOUR);
  let s = H::s(h.sk("k1"), PAY_DOMAIN, m.as_bytes());
  assert_fails!(fails(|| { h.c.propose_payment(m, "k1".into(), s); }), "BAD_PAY_MSG");
}

#[test]
fn cumulative_limit_counts_pending_and_cancelled_release_refunds() {
  let mut h = H::new();
  h.propose("k1", "shop.test.near", 10); h.propose("k2", "shop.test.near", 10); let p3 = h.propose("k1", "shop.test.near", 10);
  assert_fails!(fails(|| { h.propose("k1", "shop.test.near", 1); }), "OVER_CUMULATIVE_LIMIT");
  // revoke k1 (k2 + k3) -> epoch bump; k1's pending release is cancelled and its reservation refunded
  h.govern("REVOKE", r#","subject":"k1""#, &["k2", "k3"]);
  h.at(600 * SEC);
  assert!(!h.c.release(p3));
  assert_eq!(h.c.spent, 20);
}

#[test]
fn expired_purpose_or_message_rejected() {
  let mut h = H::new();
  let n = h.nonce();
  let m = format!(r#"{{"v":"safebox.v4.onchain.pay","epoch":1,"purposeVersion":1,"nonce":"{}","recipient":"shop.test.near","amount":"1","expiresAtNs":{}}}"#, n, h.now);
  let s = H::s(h.sk("k1"), PAY_DOMAIN, m.as_bytes());
  assert_fails!(fails(|| { h.c.propose_payment(m, "k1".into(), s); }), "EXPIRED");
  h.at(1001 * HOUR);
  assert_fails!(fails(|| { h.propose("k1", "shop.test.near", 1); }), "EXPIRED");
}

// ---------------------------------------------------------------- freeze / governance
#[test]
fn freeze_key_freezes_alone_but_cannot_unfreeze() {
  let mut h = H::new();
  let id = h.propose("k1", "shop.test.near", 5);
  h.govern("FREEZE", "", &["k4"]);
  h.at(600 * SEC);
  assert_fails!(fails(|| { h.c.release(id); }), "FROZEN_OR_LOCKDOWN");
  assert_fails!(fails(|| { h.propose("k1", "shop.test.near", 1); }), "FROZEN");
  assert_fails!(fails(|| { h.govern("UNFREEZE", "", &["k4"]); }), "QUORUM");
  assert_fails!(fails(|| { h.govern("UNFREEZE", "", &["k4", "k1", "k2"]); }), "QUORUM"); // no ROOT
  h.govern("UNFREEZE", "", &["k3", "k1"]);
  assert!(h.c.release(id));
}

#[test]
fn purpose_amendment_needs_two_daily_plus_root_and_invalidates_pending() {
  let mut h = H::new();
  let id = h.propose("k1", "shop.test.near", 5);
  let p = r#","purpose":{"version":2,"recipients":["attacker.test.near"],"per_payment_max":"1000","cumulative_limit":"1000","expires_at_ns":99999999999999999999}"#;
  let p = p.replace("99999999999999999999", &(T0 + 2000 * HOUR).to_string());
  assert_fails!(fails(|| { h.govern("AMEND_PURPOSE", &p, &["k1", "k3"]); }), "QUORUM");
  assert_fails!(fails(|| { h.govern("AMEND_PURPOSE", &p, &["k1", "k2", "k4", "k5"]); }), "QUORUM");
  h.govern("AMEND_PURPOSE", &p, &["k1", "k2", "k3"]);
  assert_eq!(h.c.purpose.version, 2);
  h.at(600 * SEC);
  assert!(!h.c.release(id), "pending payment under the old purpose version must not release");
}

#[test]
fn governance_signature_is_bound_to_message_and_duplicates_rejected() {
  let mut h = H::new();
  let m = h.gov_msg("UNFREEZE", ""); let a = h.approvals(&m, &["k3", "k1"]);
  let m2 = m.replace("UNFREEZE", "FREEZE\u{0}").replace("\u{0}", "");
  assert_fails!(fails(|| h.c.govern(m2, a)), "BAD_SIGNATURE");
  let m = h.gov_msg("UNFREEZE", ""); let mut a = h.approvals(&m, &["k3", "k1"]); a.push(Approval { cred_id: "k1".into(), sig: a[1].sig.clone() });
  assert_fails!(fails(|| h.c.govern(m, a)), "DUPLICATE_APPROVAL");
}

#[test]
fn revocation_cannot_be_self_approved_and_bumps_epoch() {
  let mut h = H::new();
  let e = h.epoch();
  assert_fails!(fails(|| { h.govern("REVOKE", r#","subject":"k2""#, &["k2", "k1"]); }), "REVOKE_SELF_APPROVAL");
  assert_fails!(fails(|| { h.govern("REVOKE", r#","subject":"k2""#, &["k4"]); }), "QUORUM");
  h.govern("REVOKE", r#","subject":"k2""#, &["k1", "k3"]);
  assert!(!h.active("k2")); assert_eq!(h.epoch(), e + 1);
  assert_fails!(fails(|| { h.propose("k2", "shop.test.near", 1); }), "CREDENTIAL_NOT_ACTIVE");
}

#[test]
fn rotation_needs_old_key_preserves_role_and_stales_old_epoch() {
  let mut h = H::new();
  let old = h.pay_msg("shop.test.near", 1); let old_sig = H::s(h.sk("k1"), PAY_DOMAIN, old.as_bytes());
  let nc = h.add_key("k1b", 61);
  let extra = format!(r#","subject":"k1","newCred":{{"id":"k1b","role":"Daily","pk":"{}","active":true}}"#, nc.pk);
  assert_fails!(fails(|| { h.govern("ROTATE", &extra, &["k2"]); }), "ROTATION_NEEDS_OLD_KEY");
  let bad = extra.replace(r#""role":"Daily""#, r#""role":"Root""#);
  assert_fails!(fails(|| { h.govern("ROTATE", &bad, &["k1", "k2"]); }), "ROLE_MUST_BE_PRESERVED");
  let dup = extra.replace(&nc.pk, &pkh(h.sk("k2")));
  assert_fails!(fails(|| { h.govern("ROTATE", &dup, &["k1", "k2"]); }), "NOT_INDEPENDENT");
  h.govern("ROTATE", &extra, &["k1", "k2"]);
  assert!(!h.active("k1") && h.active("k1b"));
  // a payment message signed at the old epoch by the rotated-out key is dead (credential and epoch)
  assert_fails!(fails(|| { h.c.propose_payment(old, "k1".into(), old_sig); }), "CREDENTIAL_NOT_ACTIVE");
  h.propose("k1b", "shop.test.near", 1);
  // an old-epoch governance message is stale
  let m = format!(r#"{{"v":"safebox.v4.onchain.gov","epoch":1,"nonce":"{:064x}","issuedAtNs":{},"expiresAtNs":{},"op":"FREEZE"}}"#, 999, h.now, h.now + 100 * SEC);
  let a = h.approvals(&m, &["k4"]);
  assert_fails!(fails(|| h.c.govern(m, a)), "STALE_EPOCH");
}

#[test]
fn root_rotation_needs_two_daily() {
  let mut h = H::new();
  let k = key(62); h.keys.push(("k3b".into(), k.clone()));
  let extra = format!(r#","subject":"k3","newCred":{{"id":"k3b","role":"Root","pk":"{}","active":true}}"#, pkh(&k));
  assert_fails!(fails(|| { h.govern("ROTATE", &extra, &["k3", "k1"]); }), "QUORUM");
  h.govern("ROTATE", &extra, &["k3", "k1", "k2"]);
  assert!(h.active("k3b"));
}

// ---------------------------------------------------------------- recovery
fn plan(h: &mut H, ids: &[(&str, Role, u8)]) -> Vec<Cred> {
  ids.iter().map(|(id, r, seed)| { let k = key(*seed); h.keys.push((id.to_string(), k.clone())); cred(id, *r, &k) }).collect()
}

#[test]
fn claim_alone_changes_nothing_and_timer_alone_completes_nothing() {
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 71)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  assert!(h.active("k1") && !h.active("n1"));
  h.propose("k1", "shop.test.near", 1); // the (allegedly lost) key keeps working until completion
  h.at(70 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "NO_IDENTITY");
  h.at(430 * HOUR); // V4: long after the deadline + grace the case can only expire (V3 asserted NO_IDENTITY here)
  assert_fails!(fails(|| h.c.recovery_complete()), "RECOVERY_CASE_EXPIRED");
  h.c.recovery_expire(); assert!(h.c.case.is_none() && h.active("k1"));
}

#[test]
fn partial_loss_recovery_needs_all_survivors_guardians_identity_and_window() {
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 71)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  h.identity(0);
  for s in ["k2", "k3", "k4"] { h.consent(s); }
  assert_fails!(fails(|| { h.consent("k1"); }), "NOT_A_SURVIVOR");
  h.guardian(0); h.guardian(1);
  assert_fails!(fails(|| h.c.recovery_complete()), "SURVIVOR_CONSENT_MISSING"); // k5 missing
  h.consent("k5");
  assert_fails!(fails(|| h.c.recovery_complete()), "WINDOW_OPEN");
  h.at(72 * HOUR);
  let e = h.epoch();
  h.c.recovery_complete();
  assert!(!h.active("k1") && h.active("n1")); assert_eq!(h.epoch(), e + 1);
  h.propose("n1", "shop.test.near", 1);
}

#[test]
fn objection_by_any_key_including_claimed_lost_blocks_completion() {
  let mut h = H::new();
  let p = plan(&mut h, &[("evil", Role::Daily, 72)]);
  h.c.recovery_open("c1".into(), vec!["k2".into()], p, None);
  h.identity(0); for s in ["k1", "k3", "k4", "k5"] { h.consent(s); } h.guardian(0); h.guardian(1);
  h.object("k2"); // the "lost" key is actually with the owner
  h.at(72 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "DISPUTED");
  assert!(h.active("k2"));
}

#[test]
fn guardians_and_identity_alone_cannot_recover_and_forged_guardian_rejected() {
  let mut h = H::new();
  let p = plan(&mut h, &[("evil", Role::Daily, 73)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  h.identity(0); h.identity(1); h.guardian(0); h.guardian(1); h.guardian(2);
  h.at(72 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "SURVIVOR_CONSENT_MISSING");
  let forged = H::s(&key(99), REC_DOMAIN, format!("GUARDIAN:{}", h.c.case_digest().unwrap()).as_bytes());
  assert_fails!(fails(|| h.c.recovery_guardian(0, forged)), "BAD_SIGNATURE");
  // a guardian signature for a different case does not transfer
  let other = H::s(&h.guardians[2], REC_DOMAIN, b"GUARDIAN:deadbeef");
  assert_fails!(fails(|| h.c.recovery_guardian(2, other)), "BAD_SIGNATURE");
}

#[test]
fn replacement_roles_must_match_lost_roles() {
  let mut h = H::new();
  let p = plan(&mut h, &[("evilroot", Role::Root, 74)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  h.identity(0); for s in ["k2", "k3", "k4", "k5"] { h.consent(s); } h.guardian(0); h.guardian(1);
  h.at(72 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "REPLACEMENT_ROLES_MISMATCH");
}

#[test]
fn survivor_cancels_claim() {
  let mut h = H::new();
  let p = plan(&mut h, &[("evil", Role::Daily, 75)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  let s = h.rec("CANCEL", &key(2)); h.c.recovery_cancel("k2".into(), s);
  assert!(h.c.case.is_none());
}

#[test]
fn majority_loss_goes_to_lockdown_and_stricter_reconstitution() {
  let mut h = H::new();
  let p = plan(&mut h, &[("r1", Role::Daily, 81), ("r2", Role::Daily, 82), ("r3", Role::Root, 83), ("r4", Role::Freeze, 84), ("r5", Role::Recovery, 85)]);
  h.c.recovery_open("c1".into(), vec!["k1".into(), "k2".into(), "k3".into()], p, None);
  assert!(h.c.case.as_ref().unwrap().reconstitution);
  h.identity(0);
  assert!(h.c.lockdown, "confirmed majority loss => emergency lockdown");
  assert_fails!(fails(|| { h.propose("k1", "shop.test.near", 1); }), "LOCKDOWN");
  h.consent("k4"); h.consent("k5"); h.guardian(0); h.guardian(1);
  h.orc_authorize(); // V4: the owner's ORC authorizes THIS case digest within the window
  h.at(72 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "GUARDIAN_QUORUM");
  h.guardian(2);
  assert_fails!(fails(|| h.c.recovery_complete()), "RECON_NEEDS_TWO_IDENTITY_ATTESTATIONS");
  h.identity(1);
  let e = h.epoch();
  h.c.recovery_complete();
  assert!(!h.c.lockdown && h.epoch() == e + 1);
  for k in ["k1", "k2", "k3", "k4", "k5"] { assert!(!h.active(k), "old {k} must be retired by reconstitution"); }
  h.propose("r1", "shop.test.near", 1);
}

#[test]
fn reconstitution_plan_must_be_a_full_role_set() {
  let mut h = H::new();
  let p = plan(&mut h, &[("r1", Role::Daily, 86)]);
  h.c.recovery_open("c1".into(), vec!["k1".into(), "k2".into(), "k3".into()], p, None);
  h.identity(0); h.identity(1); h.consent("k4"); h.consent("k5"); for g in 0..3 { h.guardian(g); }
  h.orc_authorize();
  h.at(72 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "RECON_PLAN_NEEDS_FULL_ROLE_SET");
}

#[test]
fn denominator_laundering_by_sequential_small_claims_is_blocked() {
  // Two successive "minority" recoveries must not let an attacker replace a majority without the reconstitution quorum.
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 91)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  h.identity(0); for s in ["k2", "k3", "k4", "k5"] { h.consent(s); } h.guardian(0); h.guardian(1);
  h.at(72 * HOUR); h.c.recovery_complete();
  let p = plan(&mut h, &[("n2", Role::Daily, 92)]);
  h.c.recovery_open("c2".into(), vec!["k2".into()], p, None);
  assert!(!h.c.case.as_ref().unwrap().reconstitution, "2/5 lost since baseline is still a minority");
  let s = h.rec("CANCEL", &key(3)); h.c.recovery_cancel("k3".into(), s);
  // V4: the cancelled claim burned key 92 and started the 12 h reattempt cooldown
  let p = plan(&mut h, &[("n2", Role::Daily, 92), ("n3", Role::Root, 93)]);
  assert_fails!(fails(|| { h.c.recovery_open("c3".into(), vec!["k2".into(), "k3".into()], p.clone(), None); }), "PLAN_KEY_PREVIOUSLY_REJECTED");
  let p = plan(&mut h, &[("n2", Role::Daily, 94), ("n3", Role::Root, 93)]);
  assert_fails!(fails(|| { h.c.recovery_open("c3".into(), vec!["k2".into(), "k3".into()], p.clone(), None); }), "RECOVERY_REATTEMPT_COOLDOWN");
  h.at(12 * HOUR);
  h.c.recovery_open("c3".into(), vec!["k2".into(), "k3".into()], p, None);
  assert!(h.c.case.as_ref().unwrap().reconstitution, "1 earlier + 2 now = 3/5 since baseline => reconstitution path");
}

#[test]
fn recovery_blocks_concurrent_authority_changes() {
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 94)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  let pp = format!(r#","purpose":{{"version":2,"recipients":["shop.test.near"],"per_payment_max":"1","cumulative_limit":"1","expires_at_ns":{}}}"#, T0 + HOUR);
  assert_fails!(fails(|| { h.govern("AMEND_PURPOSE", &pp, &["k1", "k2", "k3"]); }), "RECOVERY_IN_PROGRESS");
  assert_fails!(fails(|| { h.govern("REVOKE", r#","subject":"k2""#, &["k1", "k3"]); }), "RECOVERY_IN_PROGRESS");
  assert_fails!(fails(|| { h.c.recovery_open("c2".into(), vec!["k2".into()], vec![], None); }), "CASE_OPEN");
}

#[test]
fn recovery_plan_keys_must_be_independent() {
  let mut h = H::new();
  let k2pk = pkh(h.sk("k2"));
  assert_fails!(fails(|| { h.c.recovery_open("c1".into(), vec!["k1".into()], vec![Cred { id: "n1".into(), role: Role::Daily, pk: k2pk, active: true }], None); }), "NOT_INDEPENDENT");
}

#[test]
fn f_v3_02_stolen_lost_key_objection_overridable_only_with_full_evidence() {
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 95)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  h.object("k1"); // thief holding the lost key objects
  assert_fails!(fails(|| h.c.recovery_override()), "OVERRIDE_NEEDS_ALL_SURVIVOR_CONSENTS");
  for s in ["k2", "k3", "k4", "k5"] { h.consent(s); }
  assert_fails!(fails(|| h.c.recovery_override()), "OVERRIDE_NEEDS_GUARDIAN_QUORUM");
  h.guardian(1); h.guardian(2);
  assert_fails!(fails(|| h.c.recovery_override()), "OVERRIDE_NEEDS_IDENTITY");
  h.identity(0);
  h.c.recovery_override();
  h.at(72 * HOUR); h.c.recovery_complete();
  assert!(!h.active("k1") && h.active("n1"));
}

#[test]
fn f_v3_02_survivor_objection_and_reconstitution_never_overridable() {
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 96)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p, None);
  for s in ["k2", "k3", "k4", "k5"] { h.consent(s); } h.guardian(0); h.guardian(1); h.identity(0);
  h.object("k2");
  assert_fails!(fails(|| h.c.recovery_override()), "SURVIVOR_OBJECTION_NOT_OVERRIDABLE");
  let mut h = H::new();
  let p = plan(&mut h, &[("r1", Role::Daily, 97)]);
  h.c.recovery_open("c1".into(), vec!["k1".into(), "k2".into(), "k3".into()], p, None);
  h.object("k1");
  assert_fails!(fails(|| h.c.recovery_override()), "OVERRIDE_NOT_ALLOWED_IN_RECONSTITUTION");
}

// ================================================================ V4: R-1 closure (ORC), challenges, R-3 replacement
fn majority_case(h: &mut H, seeds: [u8; 5]) {
  let p = plan(h, &[("r1", Role::Daily, seeds[0]), ("r2", Role::Daily, seeds[1]), ("r3", Role::Root, seeds[2]), ("r4", Role::Freeze, seeds[3]), ("r5", Role::Recovery, seeds[4])]);
  h.c.recovery_open("c1".into(), vec!["k2".into(), "k3".into(), "k4".into(), "k5".into()], p, None);
}

#[test]
fn v4_r1_collusion_without_orc_is_denied_and_expires_without_transfer() {
  let mut h = H::new();
  majority_case(&mut h, [121, 122, 123, 124, 125]);
  h.identity(0); h.identity(1); h.consent("k1"); for g in 0..3 { h.guardian(g); }
  h.at(73 * HOUR);
  let e = h.epoch();
  assert_fails!(fails(|| h.c.recovery_complete()), "OWNER_AUTHORIZATION_REQUIRED");
  h.c.recovery_expire();
  assert!(h.c.case.is_none() && !h.c.lockdown && h.epoch() == e);
  for k in ["k1", "k2", "k3", "k4", "k5"] { assert!(h.active(k), "{k} untouched"); }
  h.propose("k1", "shop.test.near", 1);
  // the same plan keys are burned; a fresh plan is refused for 12 h (keyed on the account, not the case id)
  let p = plan(&mut h, &[("x1", Role::Daily, 121)]);
  assert_fails!(fails(|| { h.c.recovery_open("zz".into(), vec!["k2".into()], p.clone(), None); }), "PLAN_KEY_PREVIOUSLY_REJECTED");
  let p = plan(&mut h, &[("x1", Role::Daily, 126)]);
  assert_fails!(fails(|| { h.c.recovery_open("zz".into(), vec!["k2".into()], p.clone(), None); }), "RECOVERY_REATTEMPT_COOLDOWN");
}

#[test]
fn v4_expire_refused_before_deadline_and_for_authorized_case_until_grace() {
  let mut h = H::new();
  majority_case(&mut h, [131, 132, 133, 134, 135]);
  h.identity(0); h.identity(1);
  assert_fails!(fails(|| h.c.recovery_expire()), "RECOVERY_NOT_EXPIRED");
  h.orc_authorize();
  h.at(73 * HOUR);
  assert_fails!(fails(|| h.c.recovery_expire()), "RECOVERY_NOT_EXPIRED");
  h.at(7 * 24 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "RECOVERY_CASE_EXPIRED");
  h.c.recovery_expire();
  assert!(h.c.case.is_none());
}

#[test]
fn v4_orc_intent_bound_to_operation_case_time_key_and_single_use() {
  let mut h = H::new();
  majority_case(&mut h, [141, 142, 143, 144, 145]);
  h.identity(0);
  let d = h.c.case_digest().unwrap();
  let o = h.orc("RECOVERY_ORC_CANCEL", &d);
  assert_fails!(fails(|| h.c.recovery_owner_authorize(o)), "ORC_INTENT_WRONG_OPERATION");
  let o = h.orc("RECOVERY_OWNER_AUTHORIZE", &"0".repeat(64));
  assert_fails!(fails(|| h.c.recovery_owner_authorize(o)), "ORC_INTENT_WRONG_CASE");
  let m = h.orc_msg("RECOVERY_OWNER_AUTHORIZE", &d, 600 * SEC);
  let o = OrcApproval { index: 0, sig: H::s(&h.orcs[0], ORC_DOMAIN, m.as_bytes()), msg: m };
  assert_fails!(fails(|| h.c.recovery_owner_authorize(o)), "CHALLENGE_LIFETIME");
  let m = h.orc_msg("RECOVERY_OWNER_AUTHORIZE", &d, 120 * SEC);
  let late = OrcApproval { index: 0, sig: H::s(&h.orcs[0], ORC_DOMAIN, m.as_bytes()), msg: m.clone() };
  let stolen = OrcApproval { index: 0, sig: H::s(h.sk("k1"), ORC_DOMAIN, m.as_bytes()), msg: m };
  assert_fails!(fails(|| h.c.recovery_owner_authorize(stolen)), "ORC_BAD_SIGNATURE");
  h.at(121 * SEC);
  assert_fails!(fails(|| h.c.recovery_owner_authorize(late)), "CHALLENGE_EXPIRED");
  let short = format!(r#"{{"v":"safebox.v4.onchain.orc","op":"RECOVERY_OWNER_AUTHORIZE","caseRef":"{}","nonce":"{:032x}","issuedAtNs":{},"expiresAtNs":{}}}"#, d, 7, h.now, h.now + 60 * SEC);
  let o = OrcApproval { index: 0, sig: H::s(&h.orcs[0], ORC_DOMAIN, short.as_bytes()), msg: short };
  assert_fails!(fails(|| h.c.recovery_owner_authorize(o)), "CHALLENGE_NONCE_256");
  let o = h.orc("RECOVERY_OWNER_AUTHORIZE", &d); let replay = OrcApproval { index: 0, msg: o.msg.clone(), sig: o.sig.clone() };
  h.c.recovery_owner_authorize(o);
  assert_fails!(fails(|| h.c.recovery_owner_authorize(replay)), "CHALLENGE_ALREADY_CONSUMED");
  h.at(72 * HOUR);
  let o = h.orc("RECOVERY_OWNER_AUTHORIZE", &d);
  assert_fails!(fails(|| h.c.recovery_owner_authorize(o)), "OWNER_AUTHORIZATION_AFTER_DEADLINE");
}

#[test]
fn v4_orc_is_never_a_payment_or_governance_authority() {
  let mut h = H::new();
  let m = h.pay_msg("shop.test.near", 1); let sig = H::s(&h.orcs[0], PAY_DOMAIN, m.as_bytes());
  assert_fails!(fails(|| { h.c.propose_payment(m, "orc:0".into(), sig); }), "CREDENTIAL_NOT_ACTIVE");
  let m = h.gov_msg("UNFREEZE", ""); let a = vec![Approval { cred_id: "orc:0".into(), sig: H::s(&h.orcs[0], GOV_DOMAIN, m.as_bytes()) }];
  assert_fails!(fails(|| h.c.govern(m, a)), "CREDENTIAL_NOT_ACTIVE");
}

#[test]
fn v4_orc_cancel_releases_lockdown_and_survivor_cannot_cancel_in_lockdown() {
  let mut h = H::new();
  majority_case(&mut h, [151, 152, 153, 154, 155]);
  h.identity(0); assert!(h.c.lockdown);
  let s = h.rec("CANCEL", &key(1));
  assert_fails!(fails(|| h.c.recovery_cancel("k1".into(), s)), "LOCKDOWN_CANCEL_NEEDS_ORC");
  let d = h.c.case_digest().unwrap(); let o = h.orc("RECOVERY_ORC_CANCEL", &d);
  h.c.recovery_orc_cancel(o);
  assert!(h.c.case.is_none() && !h.c.lockdown);
  h.propose("k1", "shop.test.near", 1);
}

#[test]
fn v4_claim_budget_and_orc_attested_open() {
  let mut h = H::new();
  for i in 0..3u8 {
    let p = plan(&mut h, &[("y1", Role::Daily, 160 + i)]);
    h.c.recovery_open(format!("b{i}"), vec!["k2".into()], p, None);
    h.at(73 * HOUR); h.c.recovery_expire(); h.at(12 * HOUR);
  }
  let p = plan(&mut h, &[("y1", Role::Daily, 170)]);
  assert_fails!(fails(|| { h.c.recovery_open("b9".into(), vec!["k2".into()], p.clone(), None); }), "RECOVERY_CLAIM_BUDGET_EXHAUSTED");
  let r = SafeBoxV4::open_ref("b9".into(), vec!["k2".into()], p.clone());
  let o = h.orc("RECOVERY_OPEN", &r);
  h.c.recovery_open("b9".into(), vec!["k2".into()], p, Some(o));
  assert!(h.c.case.as_ref().unwrap().orc_attested);
}

#[test]
fn v4_governance_challenge_needs_256_bit_nonce_short_lifetime_not_future() {
  let mut h = H::new();
  let bad = |h: &H, n: &str, iss: u64, exp: u64| format!(r#"{{"v":"safebox.v4.onchain.gov","epoch":1,"nonce":"{}","issuedAtNs":{},"expiresAtNs":{},"op":"FREEZE"}}"#, n, iss, exp).replace("{}", &h.now.to_string());
  for (n, iss, exp, code) in [(format!("{:032x}", 5), h.now, h.now + 60 * SEC, "CHALLENGE_NONCE_256"), (format!("{:064x}", 5), h.now, h.now + 300 * SEC, "CHALLENGE_LIFETIME"),
    (format!("{:064x}", 6), h.now + HOUR, h.now + HOUR + 60 * SEC, "CHALLENGE_FROM_FUTURE"), (format!("{:064x}", 7), h.now - 200 * SEC, h.now - 100 * SEC, "CHALLENGE_EXPIRED")] {
    let m = bad(&h, &n, iss, exp); let a = h.approvals(&m, &["k4"]);
    assert_fails!(fails(|| h.c.govern(m, a)), code);
  }
}

// ---------------------------------------------------------------- R-3 emergency replacement
fn verdict(h: &H, adj: u32, subject: &str, finding: &str) -> Verdict {
  let m = format!(r#"{{"v":"safebox.v4.onchain.verdict","subjectPk":"{}","finding":"{}","expiresAtNs":{}}}"#, subject, finding, h.now + 24 * HOUR);
  Verdict { adjudicator: adj, sig: H::s(&h.adjs[adj as usize], VERDICT_DOMAIN, m.as_bytes()), msg: m }
}
fn replacement(gid: &str, k: &SigningKey) -> Replacement { let pk = pkh(k); Replacement { pop: H::s(k, PART_DOMAIN, format!("POP:{}:{}", gid, pk).as_bytes()), pk } }
fn gov_open(h: &mut H, gid: &str, gproc: bool, accused: Vec<u32>, verdicts: Vec<Verdict>, reps: Vec<Replacement>, owners: &[&str]) {
  let n = h.nonce256(); let (iss, exp) = (h.now, h.now + 120 * SEC);
  let stmt = SafeBoxV4::gov_open_statement(gid.into(), gproc, accused.clone(), reps.iter().map(|r| r.pk.clone()).collect(), h.c.epoch, n.clone(), iss, exp);
  let a: Vec<Approval> = owners.iter().map(|o| if *o == "orc:0" { Approval { cred_id: "orc:0".into(), sig: H::s(&h.orcs[0], GOV_DOMAIN, stmt.as_bytes()) } } else { Approval { cred_id: (*o).into(), sig: H::s(h.sk(o), GOV_DOMAIN, stmt.as_bytes()) } }).collect();
  h.c.gov_case_open(gid.into(), gproc, accused, verdicts, reps, n, iss, exp, a);
}
fn vote(h: &mut H, voter: &str, choice: &str, k: &SigningKey) -> String {
  let d = h.c.gcase_digest().unwrap(); let salt = format!("salt-{voter}");
  let c = SafeBoxV4::commitment_of(choice.into(), d.clone(), voter.into(), salt.clone());
  h.c.gov_ballot(voter.into(), c.clone(), H::s(k, PART_DOMAIN, format!("BALLOT:{}:{}:{}", d, voter, c).as_bytes())); salt
}

#[test]
fn v4_guardian_emergency_replacement_two_of_three_with_k2_k3_and_k2_k3_k5() {
  for (it, owners) in [vec!["k2", "k3"], vec!["k2", "k3", "k5"]].into_iter().enumerate() {
    let mut h = H::new(); h.n += 10_000 * it as u64; // the unit-test VM keeps storage across instances: fresh nonces
    let (g0, g1) = (pkh(&h.guardians[0]), pkh(&h.guardians[1]));
    let vs = vec![verdict(&h, 0, &g0, "COMPROMISED"), verdict(&h, 1, &g0, "COMPROMISED"), verdict(&h, 1, &g1, "COMPROMISED"), verdict(&h, 2, &g1, "COMPROMISED")];
    let (n0, n1) = (key(171), key(172));
    gov_open(&mut h, "gc1", true, vec![0, 1], vs, vec![replacement("gc1", &n0), replacement("gc1", &n1)], &owners);
    let el = h.c.gcase.as_ref().unwrap().electorate.clone();
    assert_eq!(el, vec!["g:2".to_string(), "i:0".to_string(), "i:1".to_string()], "accused excluded");
    let (gk, i0, i1) = (h.guardians[2].clone(), h.idvs[0].clone(), h.idvs[1].clone());
    let s2 = vote(&mut h, "g:2", "APPROVE", &gk); let s3 = vote(&mut h, "i:0", "APPROVE", &i0); let s4 = vote(&mut h, "i:1", "APPROVE", &i1);
    h.c.gov_tally_approve(vec![("g:2".into(), s2), ("i:0".into(), s3), ("i:1".into(), s4)]);
    assert_fails!(fails(|| h.c.gov_execute()), "GOV_SECURITY_DELAY_OPEN");
    h.at(24 * HOUR);
    let e = h.epoch();
    h.c.gov_execute();
    assert!(h.epoch() == e + 1 && h.c.guardians[0] == pkh(&n0) && h.c.guardians[1] == pkh(&n1) && h.c.guardians.len() == 3);
    // the removed guardian key can no longer contribute to a recovery
    let p = plan(&mut h, &[("z1", Role::Daily, 173)]); h.c.recovery_open("cz".into(), vec!["k2".into()], p, None);
    let d = h.c.case_digest().unwrap(); let old = key(31);
    let s = H::s(&old, REC_DOMAIN, format!("GUARDIAN:{}", d).as_bytes());
    assert_fails!(fails(|| h.c.recovery_guardian(0, s)), "BAD_SIGNATURE");
  }
}

#[test]
fn v4_governance_negative_cases() {
  let mut h = H::new();
  let g0 = pkh(&h.guardians[0]);
  let two = |h: &H| vec![verdict(h, 0, &g0, "COMPROMISED"), verdict(h, 1, &g0, "COMPROMISED")];
  let r = |s: u8| replacement("gx", &key(s));
  let (one, dupv, wrongf) = (vec![verdict(&h, 0, &g0, "COMPROMISED")], vec![verdict(&h, 0, &g0, "COMPROMISED"), verdict(&h, 0, &g0, "COMPROMISED")], vec![verdict(&h, 0, &g0, "INNOCENT"), verdict(&h, 1, &g0, "COMPROMISED")]);
  assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], one, vec![r(181)], &["k1", "k3"])), "ACCUSATION_NOT_ESTABLISHED");
  assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], dupv, vec![r(181)], &["k1", "k3"])), "ACCUSATION_NOT_ESTABLISHED");
  assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], wrongf, vec![r(181)], &["k1", "k3"])), "VERDICT_FINDING");
  let v = two(&h); assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], v, vec![r(181)], &["k1", "k2"])), "EMERGENCY_OWNER_QUORUM_NOT_MET");
  let v = two(&h); assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], v, vec![r(181)], &["k4", "k3"])), "ROLE_NOT_IN_EMERGENCY_OWNER_QUORUM");
  let v = two(&h); assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], v, vec![r(181)], &["k3", "k3"])), "DUPLICATE_APPROVAL");
  let v = two(&h); assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], v, vec![], &["k1", "k3"])), "REMOVAL_WITHOUT_REPLACEMENT");
  let gk1 = h.guardians[1].clone();
  let dup = Replacement { pk: pkh(&gk1), pop: H::s(&gk1, PART_DOMAIN, format!("POP:gx:{}", pkh(&gk1)).as_bytes()) };
  let v = two(&h); assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], v, vec![dup], &["k1", "k3"])), "REPLACEMENT_KEY_NOT_INDEPENDENT");
  let badpop = Replacement { pk: pkh(&key(182)), pop: H::s(&key(183), PART_DOMAIN, b"x") };
  let v = two(&h); assert_fails!(fails(|| gov_open(&mut h, "gx", true, vec![0], v, vec![badpop], &["k1", "k3"])), "REPLACEMENT_POP_INVALID");
  // valid open with K1 + ORC; then electorate attacks
  let v = two(&h); gov_open(&mut h, "gx", true, vec![0], v, vec![r(184)], &["k1", "orc:0"]);
  let g0k = h.guardians[0].clone(); let g1k = h.guardians[1].clone(); let g2k = h.guardians[2].clone(); let i0 = h.idvs[0].clone(); let i1 = h.idvs[1].clone();
  assert_fails!(fails(|| { vote(&mut h, "g:0", "APPROVE", &g0k); }), "BALLOT_VOTER_NOT_ELIGIBLE");
  assert_fails!(fails(|| { vote(&mut h, "g:1", "APPROVE", &g2k); }), "BALLOT_ELIGIBILITY_SIGNATURE");
  let s1 = vote(&mut h, "g:1", "APPROVE", &g1k);
  assert_fails!(fails(|| { vote(&mut h, "g:1", "APPROVE", &g1k); }), "BALLOT_DUPLICATE_VOTE");
  let s2 = vote(&mut h, "g:2", "APPROVE", &g2k); let s3 = vote(&mut h, "i:0", "APPROVE", &i0);
  assert_fails!(fails(|| h.c.gov_tally_approve(vec![("g:1".into(), s1.clone()), ("g:2".into(), s2.clone()), ("i:0".into(), s3.clone())])), "TALLY_APPROVAL_INCOMPLETE");
  let s4 = vote(&mut h, "i:1", "REJECT", &i1);
  assert_fails!(fails(|| h.c.gov_tally_approve(vec![("g:1".into(), s1), ("g:2".into(), s2), ("i:0".into(), s3), ("i:1".into(), s4)])), "TALLY_OPENING_MISMATCH");
  let p = plan(&mut h, &[("w1", Role::Daily, 185)]);
  assert_fails!(fails(|| { h.c.recovery_open("cw".into(), vec!["k2".into()], p, None); }), "GOVERNANCE_CASE_OPEN");
  h.at(73 * HOUR); h.c.gov_expire();
  assert!(h.c.gcase.is_none() && h.c.guardians[0] == g0, "rejected case changes nothing");
}

#[test]
fn v4_identity_verifier_replacement_and_orc_cancel_of_governance_case() {
  let mut h = H::new();
  let (i0, i1) = (pkh(&h.idvs[0]), pkh(&h.idvs[1]));
  let vs = vec![verdict(&h, 0, &i0, "MISCONDUCT"), verdict(&h, 2, &i0, "MISCONDUCT"), verdict(&h, 0, &i1, "COMPROMISED"), verdict(&h, 1, &i1, "COMPROMISED")];
  gov_open(&mut h, "gi", false, vec![0, 1], vs, vec![replacement("gi", &key(191)), replacement("gi", &key(192))], &["k3", "k5"]);
  assert_eq!(h.c.gcase.as_ref().unwrap().electorate, vec!["g:0".to_string(), "g:1".to_string(), "g:2".to_string()]);
  let d = h.c.gcase_digest().unwrap(); let o = h.orc("GOV_CASE_CANCEL", &d);
  h.c.gov_orc_cancel(o);
  assert!(h.c.gcase.is_none() && h.c.idvs[0] == i0);
}
