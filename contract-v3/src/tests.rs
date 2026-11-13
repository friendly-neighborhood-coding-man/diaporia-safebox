// SafeBox V3 on-chain vault: authority, payment, recovery and epoch tests in the near-sdk unit-test VM.
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

struct H { c: SafeBoxV3, keys: Vec<(String, SigningKey)>, guardians: Vec<SigningKey>, idvs: Vec<SigningKey>, now: u64, n: u64 }

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
    let c = SafeBoxV3::new(Init { creds, guardians: guardians.iter().map(pkh).collect(), idvs: idvs.iter().map(pkh).collect(),
      purpose: Purpose { version: 1, recipients: vec![acct("shop.test.near")], per_payment_max: U128(10), cumulative_limit: U128(30), expires_at_ns: T0 + 1000 * HOUR },
      buffer_ns: 600 * SEC, window_ns: 72 * HOUR, guardian_quorum: 2, recon_guardian_quorum: 3 });
    H { c, keys, guardians, idvs, now: T0, n: 0 }
  }
  fn sk(&self, id: &str) -> &SigningKey { &self.keys.iter().rev().find(|(i, _)| i == id).unwrap().1 }
  fn at(&mut self, dt: u64) { self.now += dt; ctx(self.now); }
  fn nonce(&mut self) -> String { self.n += 1; format!("{:032x}", self.n) }
  fn s(k: &SigningKey, dom: &[u8], m: &[u8]) -> Base64VecU8 { Base64VecU8(k.sign(&signed(dom, m)).to_bytes().to_vec()) }
  fn epoch(&self) -> u64 { self.c.epoch }
  fn pay_msg(&mut self, to: &str, amount: u128) -> String {
    let n = self.nonce();
    format!(r#"{{"v":"safebox.v3.onchain.pay","epoch":{},"purposeVersion":{},"nonce":"{}","recipient":"{}","amount":"{}","expiresAtNs":{}}}"#,
      self.c.epoch, self.c.purpose.version, n, to, amount, self.now + HOUR)
  }
  fn propose(&mut self, by: &str, to: &str, amount: u128) -> u64 {
    let m = self.pay_msg(to, amount); let sig = H::s(self.sk(by), PAY_DOMAIN, m.as_bytes()); self.c.propose_payment(m, by.into(), sig)
  }
  fn gov_msg(&mut self, op: &str, extra: &str) -> String {
    let n = self.nonce();
    format!(r#"{{"v":"safebox.v3.onchain.gov","epoch":{},"nonce":"{}","expiresAtNs":{},"op":"{}"{}}}"#, self.c.epoch, n, self.now + HOUR, op, extra)
  }
  fn approvals(&self, m: &str, by: &[&str]) -> Vec<Approval> { by.iter().map(|i| Approval { cred_id: (*i).into(), sig: H::s(self.sk(i), GOV_DOMAIN, m.as_bytes()) }).collect() }
  fn govern(&mut self, op: &str, extra: &str, by: &[&str]) { let m = self.gov_msg(op, extra); let a = self.approvals(&m, by); self.c.govern(m, a); }
  fn rec(&self, word: &str, k: &SigningKey) -> Base64VecU8 { H::s(k, REC_DOMAIN, format!("{}:{}", word, self.c.case_digest().unwrap()).as_bytes()) }
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
    purpose: Purpose { version: 1, recipients: vec![], per_payment_max: U128(1), cumulative_limit: U128(1), expires_at_ns: 1 }, buffer_ns: 600 * SEC, window_ns: 72 * HOUR, guardian_quorum: 2, recon_guardian_quorum: 3 };
  let five = || vec![cred("a", Role::Daily, &key(1)), cred("b", Role::Daily, &key(2)), cred("c", Role::Root, &key(3)), cred("d", Role::Freeze, &key(4)), cred("e", Role::Recovery, &key(5))];
  assert_fails!(fails(|| { SafeBoxV3::new(mk(five())); }), "INIT_ONLY_BY_SELF");
  ctx(T0);
  assert_fails!(fails(|| { SafeBoxV3::new(mk(five()[..4].to_vec())); }), "NEEDS_FIVE_INDEPENDENT_CREDENTIALS");
  let mut dup = five(); dup[1].pk = pkh(&key(1));
  assert_fails!(fails(|| { SafeBoxV3::new(mk(dup)); }), "DUPLICATE_PUBLIC_KEY");
  let mut g = five(); g[0] = cred("a", Role::Daily, &key(31));
  assert_fails!(fails(|| { SafeBoxV3::new(mk(g)); }), "GUARDIAN_IS_CREDENTIAL");
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
  let m = format!(r#"{{"v":"safebox.v3.onchain.pay","epoch":1,"purposeVersion":1,"nonce":"{}","recipient":"shop.test.near","amount":"1","expiresAtNs":{},"memo":"x"}}"#, n, h.now + HOUR);
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
  let m = format!(r#"{{"v":"safebox.v3.onchain.pay","epoch":1,"purposeVersion":1,"nonce":"{}","recipient":"shop.test.near","amount":"1","expiresAtNs":{}}}"#, n, h.now);
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
  let m = format!(r#"{{"v":"safebox.v3.onchain.gov","epoch":1,"nonce":"{:032x}","expiresAtNs":{},"op":"FREEZE"}}"#, 999, h.now + HOUR);
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
  h.c.recovery_open("c1".into(), vec!["k1".into()], p);
  assert!(h.active("k1") && !h.active("n1"));
  h.propose("k1", "shop.test.near", 1); // the (allegedly lost) key keeps working until completion
  h.at(500 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "NO_IDENTITY");
}

#[test]
fn partial_loss_recovery_needs_all_survivors_guardians_identity_and_window() {
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 71)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p);
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
  h.c.recovery_open("c1".into(), vec!["k2".into()], p);
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
  h.c.recovery_open("c1".into(), vec!["k1".into()], p);
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
  h.c.recovery_open("c1".into(), vec!["k1".into()], p);
  h.identity(0); for s in ["k2", "k3", "k4", "k5"] { h.consent(s); } h.guardian(0); h.guardian(1);
  h.at(72 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "REPLACEMENT_ROLES_MISMATCH");
}

#[test]
fn survivor_cancels_claim() {
  let mut h = H::new();
  let p = plan(&mut h, &[("evil", Role::Daily, 75)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p);
  let s = h.rec("CANCEL", &key(2)); h.c.recovery_cancel("k2".into(), s);
  assert!(h.c.case.is_none());
}

#[test]
fn majority_loss_goes_to_lockdown_and_stricter_reconstitution() {
  let mut h = H::new();
  let p = plan(&mut h, &[("r1", Role::Daily, 81), ("r2", Role::Daily, 82), ("r3", Role::Root, 83), ("r4", Role::Freeze, 84), ("r5", Role::Recovery, 85)]);
  h.c.recovery_open("c1".into(), vec!["k1".into(), "k2".into(), "k3".into()], p);
  assert!(h.c.case.as_ref().unwrap().reconstitution);
  h.identity(0);
  assert!(h.c.lockdown, "confirmed majority loss => emergency lockdown");
  assert_fails!(fails(|| { h.propose("k1", "shop.test.near", 1); }), "LOCKDOWN");
  h.consent("k4"); h.consent("k5"); h.guardian(0); h.guardian(1);
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
  h.c.recovery_open("c1".into(), vec!["k1".into(), "k2".into(), "k3".into()], p);
  h.identity(0); h.identity(1); h.consent("k4"); h.consent("k5"); for g in 0..3 { h.guardian(g); }
  h.at(72 * HOUR);
  assert_fails!(fails(|| h.c.recovery_complete()), "RECON_PLAN_NEEDS_FULL_ROLE_SET");
}

#[test]
fn denominator_laundering_by_sequential_small_claims_is_blocked() {
  // Two successive "minority" recoveries must not let an attacker replace a majority without the reconstitution quorum.
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 91)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p);
  h.identity(0); for s in ["k2", "k3", "k4", "k5"] { h.consent(s); } h.guardian(0); h.guardian(1);
  h.at(72 * HOUR); h.c.recovery_complete();
  let p = plan(&mut h, &[("n2", Role::Daily, 92)]);
  h.c.recovery_open("c2".into(), vec!["k2".into()], p);
  assert!(!h.c.case.as_ref().unwrap().reconstitution, "2/5 lost since baseline is still a minority");
  let s = h.rec("CANCEL", &key(3)); h.c.recovery_cancel("k3".into(), s);
  let p = plan(&mut h, &[("n2", Role::Daily, 92), ("n3", Role::Root, 93)]);
  h.c.recovery_open("c3".into(), vec!["k2".into(), "k3".into()], p);
  assert!(h.c.case.as_ref().unwrap().reconstitution, "1 earlier + 2 now = 3/5 since baseline => reconstitution path");
}

#[test]
fn recovery_blocks_concurrent_authority_changes() {
  let mut h = H::new();
  let p = plan(&mut h, &[("n1", Role::Daily, 94)]);
  h.c.recovery_open("c1".into(), vec!["k1".into()], p);
  let pp = format!(r#","purpose":{{"version":2,"recipients":["shop.test.near"],"per_payment_max":"1","cumulative_limit":"1","expires_at_ns":{}}}"#, T0 + HOUR);
  assert_fails!(fails(|| { h.govern("AMEND_PURPOSE", &pp, &["k1", "k2", "k3"]); }), "RECOVERY_IN_PROGRESS");
  assert_fails!(fails(|| { h.govern("REVOKE", r#","subject":"k2""#, &["k1", "k3"]); }), "RECOVERY_IN_PROGRESS");
  assert_fails!(fails(|| { h.c.recovery_open("c2".into(), vec!["k2".into()], vec![]); }), "CASE_OPEN");
}

#[test]
fn recovery_plan_keys_must_be_independent() {
  let mut h = H::new();
  let k2pk = pkh(h.sk("k2"));
  assert_fails!(fails(|| { h.c.recovery_open("c1".into(), vec!["k1".into()], vec![Cred { id: "n1".into(), role: Role::Daily, pk: k2pk, active: true }]); }), "NOT_INDEPENDENT");
}
