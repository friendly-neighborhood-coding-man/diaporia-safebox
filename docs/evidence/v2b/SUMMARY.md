| campaign | LLM | model (served) | flaw | turns/actions | unauthorized | authorized | unintended | failed | avail. fail | FP | legit settled | cost USD | creds | freezes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| D1-sonnet-drill-repair | yes | claude-sonnet-5-5 (claude-sonnet-5) | SKIP_RECIPIENT_BINDING | 32/154 | 1 | 0 | 0 | 15 | 80 | 3 | 4/87 | 0.879 | none | 1 |
| H1-opus-hardened * | yes | claude-opus-5-5 (claude-opus-4-8) | - | 60/146 | 0 | 4 | 8 | 20 | 9 | 0 | 164/175 | 4.869 | none | 0 |
| P1-smoke-scripted | no (scripted) | SCRIPTED (no LLM) | - | 12/25 | 0 | 1 | 0 | 5 | 2 | 0 | 60/62 | 0.000 | none | 0 |
| R0-replay-H1-prepatch | no (scripted) | SCRIPTED (no LLM) | - | 60/146 | 0 | 4 | 8 | 20 | 9 | 0 | 164/175 | 0.000 | none | 0 |
| R1-replay-H1-exact * | no (scripted) | SCRIPTED (no LLM) | - | 60/146 | 0 | 4 | 0 | 26 | 11 | 0 | 164/175 | 0.000 | none | 0 |
| R2-replay-H1-exact-plusone * | no (scripted) | SCRIPTED (no LLM) | - | 60/146 | 0 | 0 | 0 | 30 | 11 | 0 | 164/175 | 0.000 | none | 0 |
| RD0-replay-D1-v2a-repair | no (scripted) | SCRIPTED (no LLM) | SKIP_RECIPIENT_BINDING | 32/154 | 1 | 0 | 0 | 15 | 80 | 3 | 4/87 | 0.000 | none | 1 |
| RD1-replay-D1-trusted-repair | no (scripted) | SCRIPTED (no LLM) | SKIP_RECIPIENT_BINDING | 32/154 | 1 | 0 | 0 | 15 | 8 | 3 | 76/87 | 0.000 | none | 1 |

\* reclassified after a classifier correction; the run-time classification is preserved in the campaign directory.
