# SafeBox V4 residual risks and unverified boundaries (mission §17, §19.10)

Everything here is reported on purpose. None of it is hidden by a test that "passes because nothing moved".

## A. Residuals by design (accepted, documented)

| ID | Residual | Why it remains | Mitigation in V4 | Evidence |
|---|---|---|---|---|
| R-V4-01 | **A stolen DAILY key pays within the Purpose** until the owner suspends it or recovers. | A DAILY key is the payment authority; V4 does not add a second factor per payment. Inherited from V2-B / V3. | Purpose limits (recipients, per-payment, daily, cumulative), the vault buffer, owner suspension, recovery; the epoch bump cancels pending payments. | Campaign A_r1 (original): 2 attacker payments of 0.02 NEAR to an allowed merchant settled; attempts to the attacker account and over-limit attempts were denied (`RECIPIENT_NOT_IN_PURPOSE`, `OVER_*_LIMIT`). |
| R-V4-02 | **ORC lost together with a majority of owner keys is unrecoverable.** | Without the ORC there is no independent owner intent for a reconstitution; accepting anything weaker reopens R-1. | ORC_REPLACE while the owner still has the governance quorum; a minority loss never needs the ORC. | `tests/v4/r1-closure.test.mjs` "ORC lost", matrix. |
| R-V4-03 | **Losing all five keys is RECOVERY_IMPOSSIBLE.** | Nothing owner-held remains to distinguish the owner from an impostor. | The case still expires and the lockdown is released, so the condition is visible and bounded. | Matrix row `k1..k5`. |
| R-V4-04 | **Two owner roles stolen together with two bribed adjudicators can OPEN a governance case** (one unauthorized governance-case open on the original candidate; distinct from transfers and takeovers, which were 0). | Spec: owner quorum of two distinct roles plus independent evidence. That trust assumption is exceeded in this scenario. | Opening is not replacement: the electorate must still be unanimous (the honest IDVs and guardians reject), there is a 24 h notified delay, and the ORC (or the owner quorum) cancels. | Campaign B2_r3quorum (original): the verifier flagged one `GOV_CASE_OPEN` as `AUTHORITY_CHANGE_NOT_INTENDED_BY_OWNER`; the owner's ORC cancelled it 1 h later; no participant was removed or added. Counted as one unauthorized authority-type transition, not a takeover. |
| R-V4-05 | **The global 1 h case interval of V3 also applies to ORC-attested opens.** | V3 anti-spam rule kept unchanged. | At most 1 h of extra delay for the genuine owner. | Matrix scenario "identity dispute". |
| R-V4-06 | **Availability: repeated false claims can lock the owner's payments for up to 146 h** (observed at a 30-day budget boundary: budget 96 h + one 72 h window, minus what the ORC cancel shortens). | A claim that triggers lockdown must be honoured while it is being checked. | Claim budget (3 / 30 d), 12 h subject cooldown, burned plan keys, lockdown budget, ORC cancel. | Matrix scenario "repeated attempts". |
| R-V4-07 | **Ballot confidentiality depends on the tally service.** | No zero-knowledge tally is implemented or claimed. | The tally cannot fabricate an approval: openings are re-checked by the Root. Rejections publish no openings. | `tests/v4/ballot-integration.test.mjs`. |
| R-V4-08 | **A single stolen key can still SUSPEND the other keys and FREEZE** (one-signature protective actions). | Protective actions must stay one tap for the genuine owner. | After F-V4-01 this is an interruption, not a lockout: the owner recovers with the suspended keys, and the completed recovery lifts every suspension and owner-source freeze imposed only by the revoked keys. Payments are interrupted until then (minority recovery, about 1 h with all acknowledgements). | `tests/v4/f01-suspension-lockout.test.mjs`; fresh campaigns B_r3 and E_avail. |
| R-V4-09 | **After a recovery that replaces both DAILY keys, the new keys are provisional for 30 days (V3 rule)** and cannot co-sign UNFREEZE or UNSUSPEND. | V3 anti-laundering rule kept. | F-V4-01 / 01b drop the attacker's own suspensions and freeze holds at completion, so this only matters for holds the owner placed with keys they still hold (deliberately kept, F-V4-01b). | |
| R-V4-12 | **A freeze the owner placed with a key that is later lost is dropped by an approved recovery.** | The Root cannot tell the owner's K1 freeze from the thief's K1 freeze. | The consent / ORC screen names every hold it would drop; declining keeps it; re-freezing takes one tap. | F-V4-01b HONEST OWNER FREEZE test. |
| R-V4-13 | **UX cost**: losing 1–2 keys still takes 8 physical gestures (5 trusted prompts + 3 channel acknowledgements), majority loss 10–11 gestures and about 72 h. | Each surviving key and each channel must independently confirm. | A unified ceremony would reduce screens, not the number of independent confirmations. | recovery matrix |
| R-V4-10 | **A suspended survivor's single-signer RECOVERY_CANCEL still does not count (V3 behaviour).** | Kept narrow: the ORC cancels any case. | ORC cancel. | |
| R-V4-11 | **An attacker's false claim, once cancelled, starts the 12 h per-subject cooldown and counts against the 3-per-30-days claim budget for the real owner too.** | The cooldown has to be keyed on the subject (not the case ID), otherwise it can be bypassed. | The genuine owner's ORC-attested open is exempt from both. An owner who has also lost the ORC waits up to 12 h, or up to 30 days if the attacker exhausts the budget. | Fresh E_avail on `780e676` (7 × `RECOVERY_REATTEMPT_COOLDOWN` before the harness learned the ORC route); matrix "identity dispute". |
| R-V4-14 | **Guardian-majority refusal plus suspended owner keys is resolved only if two independent adjudicators find the refusal to be misconduct.** | R-3 requires adjudicator evidence for COMPROMISE / MISCONDUCT; a refusal to confirm a genuine recovery is not cryptographically provable. | F-V4-03: ORC + a suspended owner key form the emergency owner quorum; UNAVAILABLE ground after 30 days of no liveness pong if the guardians also stop responding. If no two adjudicators agree and the colluders stay responsive, the owner stays locked out (payments and recovery). | F-V4-03 DEADLOCK test; fresh campaign B_r3 on `705fdbb`. |

## B. Unverified boundaries (simulated or not run)

| Boundary | Status | What is needed |
|---|---|---|
| Hardware trusted display (K3, K5, ORC) | **SIMULATED** (in-process Ed25519 + deterministic renderer) | real signing device firmware rendering the intent, with attestation |
| Android Protected Confirmation (K1, K4) | **SIMULATED** | real APC with key attestation |
| WebAuthn | **software-authenticator verified** only | platform authenticators and FIDO metadata checks |
| Biometrics | never handled; the UV bit is not a biometric | n/a |
| OS isolation | **OS privilege matrix verified locally** (`docs/evidence/v4/os/os-matrix.json`: 8 principals, 360 checks, 0 violations, General Zone without network). The V4 protocol itself was **not** run across those principals. | an OS-separated end-to-end run of the V4 services |
| On-chain | **local contract verified** (`contract-v4`, 34 Rust tests, wasm build). UNAVAILABLE / WITHDRAWAL grounds, sealed ballots and SUSPEND do not exist on-chain. | NEAR Testnet deployment: **not done** (NEAR RPC blocked in this environment, no funded accounts) |
| Testnet / Mainnet | **not done**; no real funds, no live credentials | |
| Independent adjudicators, tally, challenge issuer | in-process keys | separately operated services |
| CI | GitHub check suite on the PR reported no failure (no runner-backed test job evidence beyond that) | |

## C. Harness limitations of the red-team campaigns

- The attacker is an LLM confined to the General Zone tool surface (`src/v4/redteam/actuator.mjs`). It receives the public design, its compromised material and every Root error code. It does not receive owner keys outside the scenario, verifier ground truth or host execution.
- Each campaign is 10 virtual turns × 2 rounds (20 model calls). Some turns were spent on malformed tool calls (for example `BODY_*`, `APPROVAL_FIELDS` and `IDV_METHOD` rejects), so the effective attack depth is lower than 20 attempts.
- The campaign owner is a deterministic simulator with fixed reaction rules (ORC-cancel foreign cases after 1 h, unfreeze, recover on discovery). A real person may react later or not at all. Scenario A uses a silent owner for exactly that reason.
- The original-candidate E_avail and B_r3 owner simulators did not attempt a recovery after the lockout. The repaired simulator notices suspensions of its own keys and recovers with them.
