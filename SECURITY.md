# Security Policy

DIAPORIA SafeBox is an **experimental research scaffold**, not production financial security software. The mock is intentionally not a real authentication or isolation boundary.

For vulnerabilities, use GitHub's **Report a vulnerability** feature under the Security tab when enabled. Otherwise contact the maintainer privately before disclosing exploit details. Never publish credentials or private user information in GitHub issues.

Only test systems and identities you control. Use synthetic secrets, fake accounts, mock endpoints and NEAR Testnet. Do not probe unrelated third-party infrastructure.

There is no stable production-supported release. A passed unit test does not establish containment security.

V1 (NEAR Testnet execution) boundaries, keys and known limitations are documented in
[docs/near-v1-security.md](docs/near-v1-security.md). Use only Testnet accounts created for this purpose,
keep owner and executor key files outside the repository (mode 0600), and never give an AI runtime access
to the owner authorization key.
