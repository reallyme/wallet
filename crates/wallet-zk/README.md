# ReallyMe Wallet ZK

`reallyme-wallet-zk` connects Wallet presentation derivation to an injected
`reallyme-zk-api` prover. It contains no proving backend, circuit artifacts,
persistent inventory, or consent UI.

## Proving

`PresentationDerivationContext::with_prover` accepts an `Arc<dyn ZkProver>`.
`prove_presentation_derivation` requires the request's session binding to equal
the binding of the verified OpenID4VP request being answered, validates the
circuit and binding, invokes the prover, and checks that the returned circuit,
proof suite, and public inputs match. A context without a prover returns `ProverUnavailable`.
These metadata checks do not replace proof verification by the relying party.

## Encrypted artifacts

`ZkArtifactDescriptor` binds an artifact to credential IDs, a claim-scope digest,
a circuit, expiry, and, for request-specific witnesses and proofs, a session
binding. Storage adapters must use its `aad_digest` as AEAD associated data.

Reusable public-persona issuer-envelope, claim-root, signed-validity,
selected-claim, and current-state packages use `PreparedPublicProof`. Before
disclosure, the presenter must validate decrypted packages against their circuit,
profile, credential join, and proof window, and check current authenticated
issuer status. Artifact metadata alone does not authenticate plaintext proofs.

Private-persona prepared tokens and one-time signing-key handles use
`PresentationCopyStore`. The provider must durably claim a copy before returning
it. Copies bound to a prepared-claim selector require the active-ZK claim policy,
which checks credential state and claims the token in one transaction.

## Presentation support

Published Wallet crates do not expose selected-record OpenID4VP common-root
proving. That composition currently lives in Identity's nonpublishable OIDF
wallet host, which owns operation construction, canonical ZK protobuf exchange,
and provider-response admission. That host path is not a supported Wallet
application or SDK entry point.
