# P0.1: same-user signing and the fingerprint-gate key (issue #14)

Reference: frozen V6 candidate `bf7403d` (Draft PR #13). Branch `claude/v6-security-hardening`.

## Question

Can a process that runs as the owner's Windows user, with no human present, use the gate key or the gate helper to
produce something SafeBox accepts as a fingerprint-only approval?

## What each layer does and does not prove

| Property | V6 gate key / flow | Proves against same-user code? |
|---|---|---|
| Non-exportability (`ExportPolicy=None`) | yes | **No.** The key cannot be copied off the machine, but same-user code can still *use* it in place. |
| TPM backing (Platform Crypto Provider when present) | when available | **No.** TPM keeps the private key off disk; with no auth value, any same-user process can ask the TPM to sign. |
| Protected key use (CNG strong key protection / UI policy) | **none set** | **No.** The helper creates the key with no `UIPolicy`. Even with one, the CNG consent dialog is a password or consent prompt, not a biometric, and it is not on the secure desktop. |
| WinBio result (`WinBioIdentify` MATCH for the current user) | checked by the helper | **Only inside the helper.** The MATCH is not bound to the key: code that opens the key directly skips it. |
| Gate window text (P0.2) | rebuilt from Root | Against a compromised **console**, yes. Against same-user code, **no**: that code can run the helper with any prompt. |
| WebAuthn UV (Windows Hello passkey assertion) | required next to the gate | **A human gesture, yes; a finger, no.** Every assertion needs a Hello gesture, but a PIN is enough. |
| Biometric-bound proof (a key that signs only after an on-device fingerprint match, attested) | **not available** in V6 | That is what fingerprint-only would need. |

## Reproduction

* **Cloud (simulated gate key), `tests/v6/hardening-p0-gatekey.test.mjs`.** Code holding the gate key signs a
  `result: MATCH` statement with no sensor event. Before the fix (`p0-1-prefix.txt`), SafeBox had no way to require
  more than that.
* **Laptop (real CNG key), `tools/winbio-gate/same-user-sign-probe.ps1`.** Opens `SafeBoxGate-k2-laptop` as the same
  user, signs one fixed hash that is not a SafeBox statement, and prints the key's properties plus
  `signedWithoutFingerprint`. It never prints the signature. Status: **RUN 2026-11-14 on the real laptop** (`docs/evidence/v6-hardening/p0-1-laptop-probe.txt`).
  Result: TPM key (Platform Crypto Provider), `exportPolicy=None`, `uiProtectionLevel=None`, `signedWithoutFingerprint=true`,
  `signatureVerified=true`, not elevated. Same-user signing without a finger is CONFIRMED on real hardware.

## Outcome

1. **Fingerprint-only cannot be enforced at signing time against same-user code with the Windows APIs V6 uses.**
   Labelled `INHERENT_RESIDUAL` for the `LOCAL_GATE` mode, and bounded. A forged gate authorizes nothing on its own: it
   still needs the owner's own passkey assertion with UV, which is a human Windows Hello gesture (PIN or finger) for
   that exact digest (test `P0.1-bound`). With that gesture it is accepted (`P0.1-residual`), so the worst case is
   **fingerprint-only degrades to Windows Hello UV**. It never degrades to "no human". The FIXED_600 buffer, holds,
   limits, anomaly delay and Emergency Freeze still apply.
2. **New fail-closed high-assurance mode (`fingerprintAssurance: "HIGH_ASSURANCE"` in the owner-signed genesis policy).**
   Only a gate key kind in `ISOLATED_GATE_KINDS` can satisfy fingerprint-only there. That list is **empty** in V6,
   because SIMULATED, WINBIO_TPM and WINBIO_SOFTWARE_KEY are all same-user keys. Every fingerprint-only payment and
   command is therefore refused with `FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE`:
   * at the Root (commands) and the Vault (payments), honest or forged;
   * on the device and in the console gate service **before** the sensor is prompted.

   UV credentials are unaffected. The field is optional. When it is absent the mode is `LOCAL_GATE` and earlier genesis
   digests are unchanged. The Root view reports `fingerprintAssurance` and `gateKeyProtection: SAME_USER_KEY` for each
   credential. Status: `FIXED_AND_REVIEWED` once the independent review confirms it (pending).
3. **Independent signer requirement**, for anyone who needs real fingerprint-only. Not implemented and not tested:
   `BLOCKED_OPERATOR_HARDWARE`. A gate key kind could only be added to `ISOLATED_GATE_KINDS` if all of these hold:
   * the key lives on hardware that same-user code cannot drive without the biometric (for example a FIDO2 security
     key with an on-key fingerprint sensor and built-in UV, or a phone secure element with a biometric-bound key);
   * the biometric match happens **on that device** and is bound to the key use, with attestation;
   * the device shows the transaction text on its own display, or the text is otherwise bound to what is signed.

   Without such evidence, V6 never claims `CRYPTOGRAPHICALLY_ATTESTED_FINGERPRINT_ONLY`.

## Runs 7 and 8 (unwanted MATCH): root cause

The cloud cannot settle this; it needs the real sensor. Two hypotheses remain, both consistent with the logs:

* **H1, incidental contact.** The sensor is in the power button, and a brush during the capture window is a real match
  of the enrolled finger.
* **H2, queued or stale sample.** WinBio returned a capture taken before the request was made, for example from an
  earlier touch or the Windows Hello unlock.

The final build (cb60433, plus 623d234 logging) counters both:

* the gate can only be started with a mouse click on Start (keyboard cannot arm it);
* there is a 3 s quiet window in which any sensor result is discarded (`quietDiscards`), against H2;
* any capture shorter than 700 ms is discarded (`discarded`);
* after a MATCH the owner must click "Yes, I touched it" (`ownerConfirmed`), against H1.

Runs 8b and 10 (hands off) were refused. Run 9 (deliberate touch, then Yes) approved.

Laptop protocol that can tell H1 from H2 (each run records `elapsedMs`, `quietDiscards`, `discarded` and `armedAfterMs`):

| Step | Action | Expected | Tells us |
|---|---|---|---|
| R1 | Touch the sensor, lift, then click Start within 2 s; hands off | `quietDiscards >= 1`, then TIMEOUT | H2 is reproducible and blocked by the quiet window |
| R2 | Click Start, hands off for 60 s | TIMEOUT, `discarded = 0` | no spontaneous MATCH |
| R3 | Click Start, touch deliberately, answer **No** | `BIOMETRIC_TOUCH_DISOWNED`, nothing signed | the disown path on real hardware |
| R4 | Click Start, touch deliberately, answer **Yes** | MATCH, `ownerConfirmed = true` | honest path still works |

Until these steps run, the root cause stays **unresolved**. The residual also stays: a stray touch followed by a
careless "Yes" still approves.
