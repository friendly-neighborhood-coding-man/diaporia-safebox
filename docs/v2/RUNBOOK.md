# SafeBox V2 — Reproduction runbook

All V2 commands are offline and MOCK-only (synthetic keys, Mock NEAR Ledger). They never read V1 keys, never contact
NEAR RPC, and never touch the V1 Testnet contract.

```bash
npm ci
npm test                      # V1 (59) + V2 tests. OS-isolation tests run only as root on Linux, else SKIPPED (= NOT VERIFIED)
npm run v2:test               # V2 only
```

## OS-isolated deployment (Linux, root, util-linux setpriv/unshare, shadow useradd)

The launcher creates system users `sbx2-ledger`, `sbx2-sens`, `sbx2-sup`, `sbx2-gen` and groups `sbx2-*` (idempotent),
a fresh state tree under `/var/lib/sbx2/<runId>/`, and runs every zone under its own uid with no capabilities and
`no_new_privs`; the General Zone runs in an empty network namespace. The repository must be root-owned and not
group/other-writable (the launcher records a check of this in the evidence).

```bash
sudo node scripts/v2/run-isolated.mjs --probe-only                       # access matrix only
sudo node scripts/v2/run-isolated.mjs --suite --mode B                    # 24 attack techniques + interleaved legit payments
sudo node scripts/v2/run-isolated.mjs --seed S --hours 24 --mode A|B|C    # seeded workload (identical across modes)
sudo node scripts/v2/run-isolated.mjs --hours 4 --flaw SKIP_RECIPIENT_BINDING --techniques recipient_substitution  # containment drill, pre-release audit
sudo node scripts/v2/run-isolated.mjs --hours 6 --flaw SKIP_RECIPIENT_BINDING --no-pre-audit --repair            # post-effect detection + automated repair
```

`--flaw` is a **drill-only** injected Sensitive Zone defect (simulated unknown bug); it is reported in every state
dump and evidence file. Evidence is written to `docs/evidence/v2/runs/<runId>/run.json` unless `--out` is given.

## Holdout and final evaluation

```bash
node scripts/v2/holdout.mjs --n 500           # seed = sha256(git HEAD) unless --seed is given
sudo node scripts/v2/evaluate.mjs             # refuses to run on uncommitted src/scripts/tests; writes docs/evidence/v2/final/<commit>/
```

## Modes

* **A** deterministic baseline: no agent; proposals are built from the owner capability.
* **B** AI-assisted General Zone: deterministic *mock* agent parses the instruction and tool output (and obeys injected directives).
* **C** adaptive defense: B + mock diagnosis component that suggests repairs and (as a compromised component would)
  tries to apply them through the boundary; every such escalation must be denied.

No real model is executed in this milestone; results are not real-model security results.
