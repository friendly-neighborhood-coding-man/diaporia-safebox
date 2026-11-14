# Security Analyst (Mission 3)

Source: `src/v5/analyst/analyst.mjs`, intake in `src/v5/risk/engine.mjs` (`intakeFinding`).

## Position

The Analyst is a **read-only** LLM reviewer of the journal's pseudonymous `analyst` view. It has no tools, no write path
except schema-validated findings, and no authority. The model runs through the Claude Code CLI in print mode with
`--tools ""`, no MCP, no settings sources, no session persistence, a scrubbed environment and a scratch HOME
(`src/v5/common/llm.mjs`). Every call records the **requested and served model**. A substitution, safety-classifier
fallback or usage-limit error stops the run.

## Prompt-injection defence

- Event text that may be attacker-controlled (recipient ids of rejected payments, error details) is in the `untrusted`
  field, ASCII-sanitised and length-bounded. Memos are sealed and never reach the analyst. The whole window is wrapped
  in `<evidence>`, and the system prompt states that evidence is never an instruction.
- The model's output is parsed as one JSON object. Anything else is `UNPARSEABLE_OUTPUT`.
- **Schema intake** (`intakeFinding`):
  - exact fields;
  - known kinds;
  - severity `LOW|MEDIUM|HIGH`;
  - bounded lengths;
  - recommendations limited to `NONE | REQUEST_VERIFICATION | OWNER_REVIEW | REPORT_ONLY` (there is no "freeze",
    "release" or "approve").

## Evidence classes

| Class | Assigned by | Meaning |
|---|---|---|
| OBSERVED | model, then checked | must cite existing event ids, and any stated metric must equal the engine's own recomputation; otherwise downgraded to `UNSUPPORTED` |
| INFERRED | model | the model's interpretation; never acted on |
| CORROBORATED | **engine only** | the deterministic detector independently agrees on the flow when `REQUEST_VERIFICATION` asks it to re-run |
| ACTIONED | **engine only** | a predefined deterministic rule actually acted (for example, an incident already exists) |

A model that claims `CORROBORATED` or `ACTIONED` itself gets `REJECTED_CLASS`. A finding never changes Root or vault
state. At most it makes the engine re-run its own checks.

## Reports

`src/v5/report/report.mjs`: DAILY, WEEKLY, MONTHLY and IMMEDIATE reports count events from the journal (auditor view)
and the outbox. They are signed by the report service, and `verifyReport` re-derives every count from the journal rows.
An optional narrative from the Analyst is attached as clearly labelled, non-authoritative text and is not covered by
the counts digest.

## Evidence

- `tests/v5/analyst-report.test.mjs` (7 tests): fabricated event ids or metrics become UNSUPPORTED; a model cannot
  assign CORROBORATED or ACTIONED; unknown recommendation kinds are rejected; reports re-derive; narrative is labelled.
- The Opus 4.8 Analyst run after the `analyst_injection` campaign: see SECURITY-EVALUATION.md.
