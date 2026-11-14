# Secret and privacy scan of the published repository

Scanned on 2026-11-14 ~21:20Z: every blob reachable from every branch of the public GitHub repository
(174 commits, 1171 unique blobs, all 33 remote branches; no tags), plus commit messages and author fields.

## Method

A Python regex scan over `git cat-file -p` of every reachable blob, for:

- private key blocks (`-----BEGIN ... PRIVATE KEY`), NEAR `ed25519:` secret keys, GitHub tokens (`ghp_`, `github_pat_`, ...),
  Google OAuth access / refresh tokens and client secrets (`ya29.`, `1//0`, `GOCSPX-`), Google API keys, OpenAI /
  Anthropic keys, Slack and AWS keys, and JSON `client_secret` / `refresh_token` / `access_token` / `private_key` values;
- e-mail addresses, Windows user profile paths, host names (`DESKTOP-`, `LAPTOP-`), Windows SIDs, phone-number shapes,
  Unix home paths, IPv4 addresses, the per-run bridge secret (`#t=<hex>`), and personal folder names;
- GitHub issue and pull request text was searched for the owner's personal e-mail domain and address and for the
  private credential folder name (0 hits each). This search uses GitHub's index and is not exhaustive.

## Results

| Finding | Where | Assessment |
|---|---|---|
| Credentials, tokens, private keys | none, except literal `-----BEGIN ... PRIVATE KEY` strings inside tests that check the secret detector and the journal privacy filter (`tests/v6/hardening-p1-supply-chain.test.mjs`, `tests/v5/journal.test.mjs`) | Test fixtures, no key material |
| E-mail addresses | only `example.com` / `example.test` fixtures and the placeholder `sender@gmail.com` | No personal address |
| Owner's real e-mail addresses, OAuth client file, Gmail token | not present | Tokens are stored outside the repository by design |
| Bridge secret | only the redacted form `#t=<hex>` / `<per-run secret, redacted>` | No live secret |
| Laptop model (`LG 16Z90RU`) and folder names on the owner's `D:` drive | `docs/evidence/v6-hardening/*.md`, `docs/v6/*` | Device model and project folder paths only. User name already redacted (`"user":"<redacted>"`). Low sensitivity; disclosed knowingly |
| `C:\Users\...` | runbooks | Already elided |
| Author names | `Eric Lee Kim` (GitHub noreply address), `Claude`, `Cursor Agent` | Public by choice (LICENSE) |
| IPv4 | `127.0.0.1`, `0.0.0.0`, `169.254.169.254` and `1.1.1.1` / `8.8.8.8` in SSRF and egress tests | Test values |
| Media | 11 small MP4 clips under `docs/evidence/v6/showcase/2026-11-14T1011Z-mock/`, rendered headless from the MOCK showcase | Synthetic content |

## Not in the repository (and must stay out)

- The raw OBS recording of Video B and the run 5 to 12 OBS recordings (they show a name, an inbox and chat windows).
- The real-device run folders (`summary.json`, `trace.jsonl`) from the owner's laptop. Only their SHA-256 values are cited.
- The Gmail OAuth client JSON and token, the per-run bridge URL file (`.demo-bridge-url` is deleted at exit), and the
  privacy-scan template crops used to check Video B.

No secret was found that needs rotation.
