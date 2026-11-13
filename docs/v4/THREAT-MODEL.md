# SafeBox V4 threat model

V4 inherits the V3 threat model (`docs/v3/THREAT-MODEL.md`): assets, the rogue-AI General Zone, thieves with unlocked devices, colluding guardians and identity verifiers, channel insiders, compromised services and replay. This document lists what V4 changes.

## 1. Goals added by V4

| Goal | Invariant |
|---|---|
| Owner inactivity alone never grants control | INV-V4-01 |
| Reconstitution needs independent affirmative owner authorization bound to the exact new authority set | INV-V4-02 |
| A malicious guardian majority cannot decide its own eligibility or expel the honest remainder | INV-V4-03 |
| Individual votes are confidential to the stated level; ineligible parties cannot influence the result | INV-V4-04 |
| What the trusted path shows is exactly what executes | INV-V4-05 |
| One approval authorizes one action, Purpose, account and credential change | INV-V4-06 |
| Expired, consumed, stale or duplicate approvals are useless | INV-V4-07 |
| Raw biometrics are never exported as authorization | INV-V4-08 |
| Recovery and participant replacement never move assets or expand financial authority | INV-V4-09 |
| Supported legitimate recoveries remain possible | INV-V4-10 |

## 2. Adversaries (V4 additions in bold)

| ID | Adversary | Capabilities in V4 tests and campaigns |
|---|---|---|
| A1 | Rogue AI agent (General Zone) | V3 surface plus: request challenge grants, build intents, ask the owner to approve something (the owner sees only the Root-derived summary), cast ballots and sign verdicts only with keys the scenario grants |
| A2 | Thief | Up to two owner devices with PIN; **an unlocked phone also yields its APC key** (the protected-confirmation key lives on the same device) |
| A3 | Colluding guardians / IDVs | All of them (scenario A) |
| A4 | Channel insider | Any subset of channels |
| **A7** | **Bribed adjudicator** | One (B_r3) or two (B2_r3quorum) adjudicators |
| **A8** | **Dishonest tally service** | Can lie about the result or leak choices (cannot fabricate an approval: openings are re-checked) |
| **A9** | **Dishonest challenge issuer** | Can issue grants freely; a grant alone authorizes nothing and is bound to one action and credential |
| **A10** | **UI manipulator** | Controls any untrusted screen and every AI-generated message; cannot alter what the trusted path renders |

Out of scope, unchanged from V3: a compromised OS kernel or hypervisor on the Root or vault host, physical coercion, legal identity disputes, Mainnet operation.

## 3. Trust assumptions V4 depends on

1. **The ORC is independent of the devices a thief can steal together.** It is offline, kept apart from the phone and laptop, and its display is trustworthy. If a thief holds the ORC and a majority of owner keys, V4 cannot distinguish them from the owner.
2. **At least one trusted confirmation path is honest** (a hardware display or protected confirmation). In this repository both are SIMULATED (see TRUSTED-CONFIRMATION.md).
3. **Adjudicators are independent**: fewer than `adjudicatorQuorum` = 2 are corrupt at once, or the owner keeps two distinct owner roles out of the attacker's hands. Two owner roles plus two bribed adjudicators plus a colluding electorate can replace participants (reported residual).
4. **The tally service keeps dissent confidential.** It can always leak choices; it cannot forge approvals.
5. **The Root and the vault run the code in this repository on hosts the AI cannot write** (V3 OS boundary; verified as a privilege matrix only).
6. **Clocks**: the Root's time drives every window; challenge issuance tolerates 60 s skew.

## 4. Attack surface and where it is closed

| Attack (mission §13) | Closed by | Evidence |
|---|---|---|
| Owner silence; channel acks; 72 h boundary | ORC authorization bound to the case digest; expiry | `tests/v4/r1-closure.test.mjs`, matrix Q2 |
| Forged owner consent; stolen-key signature as owner proof | ORC is a separate key class; owner role ≠ ORC; trusted level required | r1-closure, campaign A |
| 12 h cooldown bypass by new case ID | cooldown keyed on subject holder; burned plan keys | r1-closure, matrix "repeated attempts" |
| Repeated lockdown | claim budget and lockdown budget; ORC cancel | matrix "repeated attempts" (146 h worst case) |
| Guardian-majority collusion; false accusation; forged evidence | owner quorum of two roles; adjudicator quorum; equivocation proof; PoP | `tests/v4/r3-governance.test.mjs`, matrix "false accusation", campaigns B, B2 |
| Electorate manipulation; vote tampering | electorate derived by the Root; signed sealed ballots; openings re-checked | r3-governance, ballot-integration |
| Summary spoofing; approve A execute B; replay; rebinding; timestamps; nonce races; old epoch | AuthorizationIntent + challenge grant | `tests/v4/intent-ui.test.mjs`, `tests/v4/mutation-kills.test.mjs`, campaign C |
| Fake biometrics | SafeBox consumes only signatures and the UV bit; UV is not treated as biometric | intent-ui WEBAUTHN |
| Financial / Purpose attacks during recovery | V2-B / V3 vault and Purpose rules unchanged; epoch bump cancels pending payments | V3 suites, campaign D |
| Availability: freeze amplification, veto abuse, deadlock, prompt flooding | freeze source rules (V3), expiry, ORC cancel, grant rate limit, owner simulator flood guard | campaign E, matrix |

See RESIDUAL-RISKS.md for what remains.
