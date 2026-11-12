//! DIAPORIA SafeBox V1 payment contract (NEAR testnet only).
//!
//! The contract holds testnet NEAR deposited by the owner and releases it only for a
//! payment that the owner has signed with an Ed25519 *authorization key* (separate from any
//! NEAR access key). It enforces on-chain: owner signature, exact intent bytes (digest
//! binding), fixed action/method/asset, this contract as receiver, the configured executor
//! as caller, network = testnet, expiry against block time, a one-use intent nonce,
//! owner revocation of a nonce, and a per-payment maximum.
//!
//! It does NOT enforce cumulative spending limits or recipient allow-lists; those are the
//! SafeBox service's mandate checks (off-chain). Mirror: src/v1/sim/contract-model.mjs.
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::LookupSet;
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

const INTENT_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_INTENT_V1\n";
const AUTHZ_DOMAIN: &[u8] = b"DIAPORIA_SAFEBOX_AUTHZ_V1\n";

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields, rename_all = "camelCase")]
#[allow(dead_code)]
struct Intent {
    v: String,
    intent_id: String,
    principal_id: String,
    mandate_id: String,
    chain_id: String,
    network_id: String,
    action: String,
    signer_account_id: String,
    receiver_id: String,
    recipient_id: String,
    asset: String,
    amount_yocto: String,
    nonce: String,
    created_at: String,
    expires_at: String,
    method: String,
    gas: String,
    attached_deposit_yocto: String,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields, rename_all = "camelCase")]
#[allow(dead_code)]
struct Authorization {
    v: String,
    intent_id: String,
    intent_digest: String,
    principal_id: String,
    owner_key: String,
    challenge: String,
    issued_at: String,
    expires_at: String,
}

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ConfigView {
    pub owner_id: AccountId,
    pub owner_principal_id: String,
    pub owner_auth_key: String,
    pub executor_id: AccountId,
    pub max_payment_yocto: U128,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SafeBoxPayment {
    owner_id: AccountId,
    owner_principal_id: String,
    owner_auth_key: String,
    owner_auth_key_raw: Vec<u8>,
    executor_id: AccountId,
    max_payment_yocto: u128,
    used: LookupSet<String>,
    revoked: LookupSet<String>,
}

fn strict<T: for<'de> Deserialize<'de>>(text: &str) -> T {
    match serde_json::from_str::<T>(text) {
        Ok(v) => v,
        Err(e) if e.is_syntax() || e.is_eof() => env::panic_str("ERR_BAD_JSON"),
        Err(_) => env::panic_str("ERR_FIELDS"),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Parses exactly "YYYY-MM-DDTHH:MM:SS.mmmZ" into Unix milliseconds.
pub fn iso_ms(s: &str) -> u64 {
    let b = s.as_bytes();
    require!(
        b.len() == 24 && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':' && b[19] == b'.' && b[23] == b'Z',
        "ERR_TIME_FORMAT"
    );
    let num = |a: usize, n: usize| -> u64 {
        let mut v = 0u64;
        for c in &b[a..a + n] {
            require!(c.is_ascii_digit(), "ERR_TIME_FORMAT");
            v = v * 10 + (c - b'0') as u64;
        }
        v
    };
    let (y, mo, d, h, mi, se, ms) = (num(0, 4), num(5, 2), num(8, 2), num(11, 2), num(14, 2), num(17, 2), num(20, 3));
    require!(y >= 1970 && (1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && se < 60, "ERR_TIME_FORMAT");
    let yy = if mo <= 2 { y as i64 - 1 } else { y as i64 };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (days as u64) * 86_400_000 + h * 3_600_000 + mi * 60_000 + se * 1000 + ms
}

#[near]
impl SafeBoxPayment {
    #[init]
    pub fn new(owner_id: AccountId, owner_principal_id: String, owner_auth_key: String, executor_id: AccountId, max_payment_yocto: U128) -> Self {
        require!(owner_auth_key.starts_with("ed25519:"), "ERR_KEY_FORMAT");
        let raw = bs58::decode(&owner_auth_key[8..]).into_vec().unwrap_or_else(|_| env::panic_str("ERR_KEY_FORMAT"));
        require!(raw.len() == 32, "ERR_KEY_FORMAT");
        require!(max_payment_yocto.0 > 0, "ERR_MAX");
        Self {
            owner_id,
            owner_principal_id,
            owner_auth_key,
            owner_auth_key_raw: raw,
            executor_id,
            max_payment_yocto: max_payment_yocto.0,
            used: LookupSet::new(b"u"),
            revoked: LookupSet::new(b"r"),
        }
    }

    /// Releases exactly the owner-authorized amount to the owner-authorized recipient, once.
    pub fn execute_payment(&mut self, intent: String, authorization: String, signature: Base64VecU8) -> Promise {
        require!(env::predecessor_account_id() == self.executor_id, "ERR_NOT_EXECUTOR");
        require!(env::attached_deposit().is_zero(), "ERR_DEPOSIT");
        require!(intent.len() <= 4096 && authorization.len() <= 2048, "ERR_TOO_LARGE");
        let i: Intent = strict(&intent);
        let a: Authorization = strict(&authorization);
        // 1. owner signature over the exact authorization statement
        require!(a.v == "safebox.authz.v1", "ERR_AUTHZ_VERSION");
        require!(a.owner_key == self.owner_auth_key, "ERR_OWNER_KEY");
        let sig: [u8; 64] = signature.0.as_slice().try_into().unwrap_or_else(|_| env::panic_str("ERR_SIG_FORMAT"));
        let pk: [u8; 32] = self.owner_auth_key_raw.as_slice().try_into().unwrap_or_else(|_| env::panic_str("ERR_KEY_FORMAT"));
        let mut msg = Vec::with_capacity(AUTHZ_DOMAIN.len() + authorization.len());
        msg.extend_from_slice(AUTHZ_DOMAIN);
        msg.extend_from_slice(authorization.as_bytes());
        require!(env::ed25519_verify(&sig, &msg, &pk), "ERR_BAD_SIGNATURE");
        // 2. authorization bound to these exact intent bytes
        let mut im = Vec::with_capacity(INTENT_DOMAIN.len() + intent.len());
        im.extend_from_slice(INTENT_DOMAIN);
        im.extend_from_slice(intent.as_bytes());
        require!(a.intent_digest == hex_lower(&env::sha256(&im)), "ERR_DIGEST");
        require!(a.intent_id == i.intent_id && a.principal_id == i.principal_id, "ERR_BINDING");
        require!(i.principal_id == self.owner_principal_id, "ERR_PRINCIPAL");
        // 3. fixed-purpose payment fields
        require!(i.v == "safebox.intent.v1" && i.chain_id == "near" && i.network_id == "testnet", "ERR_NETWORK");
        require!(i.action == "SAFEBOX_CONTRACT_PAYMENT" && i.method == "execute_payment", "ERR_ACTION");
        require!(i.receiver_id == env::current_account_id().as_str(), "ERR_WRONG_CONTRACT");
        require!(i.signer_account_id == env::predecessor_account_id().as_str(), "ERR_SIGNER");
        require!(i.asset == "NEAR" && i.attached_deposit_yocto == "0", "ERR_ASSET");
        let digits_ok = !i.amount_yocto.is_empty() && i.amount_yocto.len() <= 39 && i.amount_yocto.bytes().all(|c| c.is_ascii_digit()) && !i.amount_yocto.starts_with('0');
        require!(digits_ok, "ERR_AMOUNT");
        let amount: u128 = i.amount_yocto.parse().unwrap_or_else(|_| env::panic_str("ERR_AMOUNT"));
        require!(amount <= self.max_payment_yocto, "ERR_OVER_MAX");
        require!(i.recipient_id != env::current_account_id().as_str(), "ERR_RECIPIENT");
        let recipient: AccountId = i.recipient_id.parse().unwrap_or_else(|_| env::panic_str("ERR_RECIPIENT"));
        // 4. expiry against block time, one-use nonce, revocation
        let now = env::block_timestamp_ms();
        require!(now < iso_ms(&i.expires_at) && now < iso_ms(&a.expires_at), "ERR_EXPIRED");
        require!(i.nonce.len() == 32 && i.nonce.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "ERR_NONCE_FORMAT");
        require!(!self.revoked.contains(&i.nonce), "ERR_REVOKED");
        require!(!self.used.contains(&i.nonce), "ERR_NONCE_USED");
        let locked = env::storage_byte_cost().saturating_mul(env::storage_usage() as u128 + 200);
        require!(env::account_balance().saturating_sub(locked).as_yoctonear() >= amount, "ERR_BALANCE");
        self.used.insert(i.nonce.clone());
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"diaporia_safebox\",\"version\":\"1.0.0\",\"event\":\"payment_executed\",\"data\":[{{\"intent_id\":\"{}\",\"nonce\":\"{}\",\"recipient\":\"{}\",\"amount\":\"{}\"}}]}}",
            i.intent_id, i.nonce, i.recipient_id, i.amount_yocto
        ));
        Promise::new(recipient).transfer(NearToken::from_yoctonear(amount))
    }

    /// Owner kill-switch for a specific authorization (effective if it lands before execution).
    pub fn revoke_nonce(&mut self, nonce: String) {
        require!(env::predecessor_account_id() == self.owner_id, "ERR_NOT_OWNER");
        require!(nonce.len() == 32, "ERR_NONCE_FORMAT");
        self.revoked.insert(nonce);
    }

    /// Owner withdraws unused testnet funds.
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        require!(env::predecessor_account_id() == self.owner_id, "ERR_NOT_OWNER");
        Promise::new(self.owner_id.clone()).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn is_nonce_used(&self, nonce: String) -> bool { self.used.contains(&nonce) }
    pub fn is_nonce_revoked(&self, nonce: String) -> bool { self.revoked.contains(&nonce) }
    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            owner_id: self.owner_id.clone(),
            owner_principal_id: self.owner_principal_id.clone(),
            owner_auth_key: self.owner_auth_key.clone(),
            executor_id: self.executor_id.clone(),
            max_payment_yocto: U128(self.max_payment_yocto),
        }
    }
}

#[cfg(test)]
mod tests;
