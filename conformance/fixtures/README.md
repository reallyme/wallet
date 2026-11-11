# Conformance Fixtures

Fixtures are stable, synthetic inputs grouped by Wallet responsibility. They
contain no production identities, credentials, keys, or endpoints. Some describe
expected checks rather than complete wire-valid credentials or executed runs.

| Directory | Contents |
| --- | --- |
| [`credentials`](credentials/README.md) | PID SD-JWT VC and mdoc record inputs |
| [`issuers`](issuers/README.md) | OpenID4VCI metadata and credential offers |
| [`lifecycle`](lifecycle/README.md) | Issuance stages, contact delivery, and Wallet Unit lifecycle evidence |
| [`relying-parties`](relying-parties/README.md) | Presentation requests and registration/entitlement inputs |
| [`trust`](trust/README.md) | QTSP decision and status-list inputs |
| [`wallets`](wallets/README.md) | Wallet unit attestation and SDK ownership inputs |
| [`eudi-reference`](eudi-reference/README.md) | Expected checks for pinned reference-wallet runs |

Shared operation, provider, key-storage, and ProtoJSON wire vectors live in
[`vectors/`](../../vectors/README.md).
