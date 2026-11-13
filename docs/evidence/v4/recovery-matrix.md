# V4 recovery matrix (generated)

Level: deterministic mock verified. Q1 owner recovers (final authority set = approved set), Q2 R-1-collusion attacker denied, Q3 case state / lockdown during the case, Q4 surviving DAILY can pay during the case, Q5 owner gestures (physical confirmations; signatures counted separately), Q6 latency, Q7 previously issued capability + intent approval refused afterwards.

| lost | outcome | Q1 | Q2 (stopped by) | Q3 state / lockdown | Q4 | Q5 gestures / prompts | independent signers | chain signatures | Q6 h | Q7 | purpose | verifier |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| none | NO_RECOVERY_NEEDED | yes | yes (NO_CASE) | - / NO | - | 0 / 0 | 0 | 0 | 0 | - | yes | yes |
| k1-phone | RECOVERED | yes | yes (NO_TRUSTED_CONFIRMATION_IN_CASE) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 11 | 1.02 | yes | yes | yes |
| k2-laptop | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 11 | 1.02 | yes | yes | yes |
| k3-root-hw | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 11 | 1.02 | yes | yes | yes |
| k4-freeze | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 11 | 1.02 | yes | yes | yes |
| k5-recovery-hw | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 11 | 1.02 | yes | yes | yes |
| k1-phone+k2-laptop | RECOVERED | yes | yes (NO_TRUSTED_CONFIRMATION_IN_CASE) | RECOVERY_CHALLENGE / NO | - | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k1-phone+k3-root-hw | RECOVERED | yes | yes (NO_TRUSTED_CONFIRMATION_IN_CASE) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k1-phone+k4-freeze | RECOVERED | yes | yes (NO_TRUSTED_CONFIRMATION_IN_CASE) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k1-phone+k5-recovery-hw | RECOVERED | yes | yes (NO_TRUSTED_CONFIRMATION_IN_CASE) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k2-laptop+k3-root-hw | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k2-laptop+k4-freeze | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k2-laptop+k5-recovery-hw | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k3-root-hw+k4-freeze | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k3-root-hw+k5-recovery-hw | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k4-freeze+k5-recovery-hw | RECOVERED | yes | yes (SURVIVOR_CONSENT_MISSING) | RECOVERY_CHALLENGE / NO | yes | 8 / 5 | 3 | 10 | 1.02 | yes | yes | yes |
| k1-phone+k2-laptop+k3-root-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | - | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k1-phone+k2-laptop+k4-freeze | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | - | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k1-phone+k2-laptop+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | - | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k1-phone+k3-root-hw+k4-freeze | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k1-phone+k3-root-hw+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k1-phone+k4-freeze+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k2-laptop+k3-root-hw+k4-freeze | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k2-laptop+k3-root-hw+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k2-laptop+k4-freeze+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k3-root-hw+k4-freeze+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 11 / 8 | 5 | 12 | 72.02 | yes | yes | yes |
| k1-phone+k2-laptop+k3-root-hw+k4-freeze | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | - | 10 / 7 | 5 | 11 | 72.02 | yes | yes | yes |
| k1-phone+k2-laptop+k3-root-hw+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | - | 10 / 7 | 5 | 11 | 72.02 | yes | yes | yes |
| k1-phone+k2-laptop+k4-freeze+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | - | 10 / 7 | 5 | 11 | 72.02 | yes | yes | yes |
| k1-phone+k3-root-hw+k4-freeze+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 10 / 7 | 5 | 11 | 72.02 | yes | yes | yes |
| k2-laptop+k3-root-hw+k4-freeze+k5-recovery-hw | NEW_EPOCH | yes | yes (OWNER_AUTHORIZATION_REQUIRED) | RECONSTITUTION / yes | NO | 10 / 7 | 5 | 11 | 72.02 | yes | yes | yes |
| k1-phone+k2-laptop+k3-root-hw+k4-freeze+k5-recovery-hw | RECOVERY_IMPOSSIBLE | NO | yes (RECOVERY_IMPOSSIBLE) | RECOVERY_IMPOSSIBLE / yes | - | 5 / 5 | 1 | 2 | 72.02 | - | yes | yes |

## Named scenarios

- **stolen DAILY (K1) alone: minority claim + R-1 claim**: `{"Q1":"n/a (no loss)","Q2":true,"detail":["SURVIVOR_CONSENT_MISSING","OWNER_AUTHORIZATION_REQUIRED"]}`
- **compromised Guardians (g1+g2) block the owner: cancel, replace them (R-3), recover**: `{"Q1":true,"Q2":true,"Q3":"HOLD","gov":"done","outcome":"NEW_EPOCH","Q5":11,"Q6":72}`
- **compromised identity verifiers refuse: replace them (R-3), recover**: `{"Q1":true,"gov":"done","outcome":"NEW_EPOCH"}`
- **compromised notification channel objects to the owner's minority recovery (overridable)**: `{"Q3":"HOLD","override":true,"Q1":true}`
- **false accusation against an honest guardian (stolen K1+K3, one bribed adjudicator)**: `{"Q2":true,"code":"ACCUSATION_NOT_ESTABLISHED"}`
- **genuine identity dispute (IDV cannot verify): case expires; owner retries after 12 h or at once with the ORC**: `{"disputed":true,"disputeCode":"IDENTITY_NOT_VERIFIED","expired":"EXPIRED_UNAPPROVED","immediateRetry":"RECOVERY_REATTEMPT_COOLDOWN","Q1":true,"outcome":"RECOVERED","Q6":1}`
- **legitimate owner silence on an attacker case (R-1)**: `{"Q2":true,"code":"OWNER_AUTHORIZATION_REQUIRED"}`
- **device replacement during the 72 h window (new plan device): ORC cancel + ORC-attested reopen**: `{"Q1":true,"outcome":"NEW_EPOCH","Q5":11,"Q6":72}`
- **signed cancellation (ORC) of a fraudulent case**: `{"Q3_lockdownBefore":true,"cancelled":true,"Q4_paymentAfter":true}`
- **repeated reconstitution attempts (cooldown, claim budget, lockdown budget)**: `{"attempts":["opened","immediate:RECOVERY_REATTEMPT_COOLDOWN","opened","immediate:RECOVERY_REATTEMPT_COOLDOWN","opened","immediate:RECOVERY_REATTEMPT_COOLDOWN","RECOVERY_CLAIM_BUDGET_EXHAUSTED","immediate:RECOVERY_CLAIM_BUDGET_EXHAUSTED"],"lockdownHoursTotal":146}`
- **new-Epoch execution after recovery: new keys pay, old capability/approval refused**: `{"Q1":true,"Q7":true,"postRecoveryPayment":true,"authoritySet":true}`
