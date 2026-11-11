# Compliance Ledger

[`wallet_core.toml`](requirements/wallet_core.toml) maps Wallet obligations to
owning crates, coverage status, and evidence. `partial` records incomplete
coverage; `not_implemented` records an unsupported requirement. Neither status
establishes certification.

Add a requirement before introducing certification-sensitive behavior. Use
specific source references, put implementation files in `evidence`, and put tests
or fixtures in `test_evidence`. Keep both aligned with the implementation.

Wallet runtime and SDK boundaries use generated protobuf messages. Local
Rust-only traits remain separate. Reference delegated work in SSI, OpenID4VCI,
OpenID4VP, or Identity rather than duplicating it here. Identity owns platform
facades and final binary packaging.

See the [conformance guide](../../conformance/README.md) for pinned sources,
executable requirements, and external evidence limits.
