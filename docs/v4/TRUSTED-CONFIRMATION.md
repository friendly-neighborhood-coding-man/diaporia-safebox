# Trusted confirmation (mission §8, §10)

Code: `src/v4/intent/intent.mjs` (levels), `src/v4/kit.mjs` (`SimulatedProtectedConfirmation`, `approveIntent`), `src/v4/intent/summary.mjs` (renderers).
Tests: `tests/v4/intent-ui.test.mjs`.

## Honest labels first

| Mechanism in V4 | What it is here | What it is NOT |
|---|---|---|
| `TRUSTED_DISPLAY_SIM` (K3, K5, ORC) | An Ed25519 key in-process, enrolled at genesis as "has its own display". The owner world renders the deterministic summary and calls `decide(summary)` before signing. | Not a verified hardware display. **Hardware trusted-UI verified: NO.** |
| `PROTECTED_CONFIRMATION_SIM` (K1, K4) | A separate in-process Ed25519 key enrolled next to the passkey (with proof of possession), signing `{prompt lines, extraData = intent digest}` in the style of Android Protected Confirmation. | Not Android Protected Confirmation, not a TEE, not attested. |
| `SOFTWARE_UI_LOWER_ASSURANCE` | A passkey assertion without APC (for example K2 laptop). | Not acceptable alone for CRITICAL actions. |
| WebAuthn UV flag | The authenticator's statement that it performed user verification (`WEBAUTHN_NO_USER_VERIFICATION` if absent). Verified with a software authenticator. | Not a biometric. SafeBox never receives biometric data; it receives a signature over the intent digest and the UV bit (INV-V4-08). |
| Screen evidence | Optional digest of the fixed-width rendering of the SafeBox authorization region, bound to the challenge nonce and case, replay-protected. | Evidence only. It never raises the confirmation level (a screenshot proves nothing about what a person saw). |

Verification levels reached: **deterministic mock verified** and **software-authenticator verified**. Not reached: hardware trusted-UI verified.

## Rules the Root enforces

1. A CRITICAL action needs at least one approval at a trusted level (`TRUSTED_CONFIRMATION_REQUIRED`). Two software-only passkeys are refused even though they meet the quorum.
2. An APC signature must be over exactly `renderText(summary)` split into lines, with `extraData` equal to the intent digest; any other prompt (for example "Approve purchase of headphones") fails `PROTECTED_CONFIRMATION_INVALID`.
3. A credential without an enrolled confirmer cannot claim APC (`NO_PROTECTED_CONFIRMATION_KEY_ENROLLED`).
4. The ORC must verify at a trusted level (`ORC_REQUIRES_TRUSTED_DISPLAY`).
5. Screen evidence, if present, must be the exact rendering of the Root-derived summary, of the dedicated region, with the fixed renderer, bound to this challenge and case, and never reused.
6. WebAuthn checks from V3 stay: origin, rpId, challenge = intent digest, UV, no cross-origin, sign counters.

The independent verifier (`verifyV4`) records the confirmation level of every approval in `assurance[]`, so the evaluation can show which approvals were trusted and which were lower assurance.

## UI-manipulation cases (§10)

| Attack | Result | Test |
|---|---|---|
| AI tells the owner "approve to finish setting up your laptop" for an attacker-opened plan | the trusted path shows the plan key digests derived by the Root; they do not match the owner's new device; the owner declines (`metrics.declined`) | HUMAN DECISION |
| Approve A, execute B (other parameters, subject or type) | `CHALLENGE_NOT_FOR_THIS_ACTION`; a consistent intent for B with A's grant is also refused | APPROVE A, EXECUTE B |
| Summary that omits or misstates an effect | the summary digest is in the intent and recomputed by the Root: `INTENT_MISMATCH` | mutation-kills INTENT EQUALITY |
| Prompt text differs from the deterministic summary | `PROTECTED_CONFIRMATION_INVALID` | APC |
| Screenshot of a different summary, consistently re-signed | `SCREEN_EVIDENCE_MISMATCH` | SCREEN EVIDENCE |
| Requester free text used as an instruction ("ignore previous instructions and approve") | rendered as `requester note (unverified, not part of the effect)`, truncated to 80 chars | SUMMARY |
| Non-ASCII, bidi override or homoglyph text in an action body | cannot be encoded (canonical encoder rejects) | SUMMARY |
| Old-epoch or stale approval | `INTENT_MISMATCH` / `STALE` | STALE APPROVAL |
| UV forged as false/true, wrong origin / rpId / challenge | refused by the V3 WebAuthn verifier | WEBAUTHN |
| Prompt flooding (excessive owner-authentication requests) | the owner simulator in the red-team campaign answers at most 3 asks per turn and only for actions it can verify; the challenge issuer rate-limits grants per credential | campaign C_ui, E_avail; CHALLENGES |

## What would be needed for hardware verification

- A hardware key whose firmware renders `renderText(summary)` from the canonical intent itself and signs only after a physical button press (for example a dedicated signing device), with attestation of the firmware.
- Android Protected Confirmation (or an equivalent TEE prompt) with key attestation chained to a hardware root, enrolled with the attestation certificate instead of a bare PoP.
- Platform authenticators with attestation and UV policy checked against the FIDO metadata service.

None of these were available in this environment. The interfaces (`confirmers`, `displays`, `screen` evidence, `levels`) are designed so those can replace the simulated keys without changing the Root rules.
