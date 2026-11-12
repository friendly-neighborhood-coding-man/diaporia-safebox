# Contributing

This is an experimental capability-security project.

- Separate security enforcement from the LLM's own assertions and output.
- Test **both** forbidden effects and legitimate task completion; blanket refusal is not success.
- Never commit keys, wallet seeds, passwords, real PII or production endpoints.
- Distinguish MOCK experiments, SEEN regression evaluations and fresh SEALED holdouts.
- Preserve licenses and attribution for any reused code.

Run `npm test` and `npm run demo` locally. Do not attach real payment providers to the mock.
