// Runs the shared cross-implementation vectors (tests/vectors/contract-vectors.json)
// against the real contract code in the near-sdk unit-test VM.
use super::*;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

const VECTORS: &str = include_str!("../../tests/vectors/contract-vectors.json");

fn vectors() -> serde_json::Value { serde_json::from_str(VECTORS).unwrap() }

fn setup(v: &serde_json::Value, predecessor: &str, ts_ms: u64) -> SafeBoxPayment {
    let balance: u128 = v["contractBalanceYocto"].as_str().unwrap().parse().unwrap();
    let ctx = VMContextBuilder::new()
        .current_account_id(v["contractId"].as_str().unwrap().parse().unwrap())
        .predecessor_account_id(predecessor.parse().unwrap())
        .block_timestamp(ts_ms * 1_000_000)
        .account_balance(NearToken::from_yoctonear(balance))
        .build();
    testing_env!(ctx);
    SafeBoxPayment::new(
        v["ownerId"].as_str().unwrap().parse().unwrap(),
        v["ownerPrincipalId"].as_str().unwrap().to_string(),
        v["ownerAuthKey"].as_str().unwrap().to_string(),
        v["executorId"].as_str().unwrap().parse().unwrap(),
        U128(v["maxPaymentYocto"].as_str().unwrap().parse().unwrap()),
    )
}

fn sig(c: &serde_json::Value) -> Base64VecU8 {
    use near_sdk::serde_json::json;
    serde_json::from_value(json!(c["signature"].as_str().unwrap())).unwrap()
}

fn run_case(v: &serde_json::Value, c: &serde_json::Value) -> Result<(), String> {
    let mut contract = setup(v, c["predecessor"].as_str().unwrap(), c["blockTimestampMs"].as_u64().unwrap());
    let intent = c["intent"].as_str().unwrap().to_string();
    let authz = c["authorization"].as_str().unwrap().to_string();
    let s = sig(c);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        contract.execute_payment(intent, authz, s);
    }))
    .map_err(|e| {
        e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
    })
}

#[test]
fn shared_vectors_match_expected_outcomes() {
    let v = vectors();
    let mut checked = 0;
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let expect = c["expect"].as_str().unwrap();
        let r = run_case(&v, c);
        match (expect, &r) {
            ("OK", Ok(())) => {}
            ("OK", Err(e)) => panic!("{name}: expected OK, got panic {e}"),
            (code, Err(e)) => assert!(e.contains(code), "{name}: expected {code}, got {e}"),
            (code, Ok(())) => panic!("{name}: expected {code}, but payment was released"),
        }
        checked += 1;
    }
    assert!(checked >= 15);
}

#[test]
fn valid_payment_emits_event_and_consumes_nonce_once() {
    let v = vectors();
    let c = &v["cases"][0];
    assert_eq!(c["name"], "valid");
    let mut contract = setup(&v, c["predecessor"].as_str().unwrap(), c["blockTimestampMs"].as_u64().unwrap());
    let nonce = "0123456789abcdef0123456789abcdef".to_string();
    assert!(!contract.is_nonce_used(nonce.clone()));
    contract.execute_payment(c["intent"].as_str().unwrap().into(), c["authorization"].as_str().unwrap().into(), sig(c));
    assert!(contract.is_nonce_used(nonce.clone()));
    let logs = near_sdk::test_utils::get_logs();
    assert!(logs.iter().any(|l| l.starts_with("EVENT_JSON:") && l.contains("payment_executed") && l.contains(&nonce)));
    // Replay of the identical authorization is rejected on-chain.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        contract.execute_payment(c["intent"].as_str().unwrap().into(), c["authorization"].as_str().unwrap().into(), sig(c));
    }));
    let msg = r.err().and_then(|e| e.downcast_ref::<String>().cloned()).unwrap_or_default();
    assert!(msg.contains("ERR_NONCE_USED"), "{msg}");
}

#[test]
fn owner_revocation_blocks_execution() {
    let v = vectors();
    let c = &v["cases"][0];
    let mut contract = setup(&v, v["ownerId"].as_str().unwrap(), c["blockTimestampMs"].as_u64().unwrap());
    contract.revoke_nonce("0123456789abcdef0123456789abcdef".into());
    let mut ctx = VMContextBuilder::new();
    ctx.current_account_id(v["contractId"].as_str().unwrap().parse().unwrap())
        .predecessor_account_id(c["predecessor"].as_str().unwrap().parse().unwrap())
        .block_timestamp(c["blockTimestampMs"].as_u64().unwrap() * 1_000_000)
        .account_balance(NearToken::from_near(50));
    testing_env!(ctx.build());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        contract.execute_payment(c["intent"].as_str().unwrap().into(), c["authorization"].as_str().unwrap().into(), sig(c));
    }));
    let msg = r.err().and_then(|e| e.downcast_ref::<String>().cloned()).unwrap_or_default();
    assert!(msg.contains("ERR_REVOKED"), "{msg}");
}

#[test]
fn non_owner_cannot_revoke_or_withdraw() {
    let v = vectors();
    let mut contract = setup(&v, "safebox-exec.testnet", 1);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| contract.revoke_nonce("0123456789abcdef0123456789abcdef".into())));
    assert!(r.is_err());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { contract.withdraw(U128(1)); }));
    assert!(r.is_err());
}

#[test]
fn iso_parser_matches_unix_ms() {
    assert_eq!(iso_ms("1970-01-01T00:00:00.000Z"), 0);
    assert_eq!(iso_ms("2026-11-13T00:00:00.000Z"), 1_794_528_000_000);
    assert_eq!(iso_ms("2000-02-29T12:34:56.789Z"), 951_827_696_789);
}
