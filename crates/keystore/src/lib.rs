// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key-handle-only WSCD/WSCA boundary.
//!
//! Wallet core never receives private key bytes. Platform secure elements and
//! vault-service clients implement these traits and return signatures or
//! attestation evidence for opaque handles.

mod attest;
mod error;
mod model;
mod sign;
mod validate_boundary;

pub use attest::{
    KeyAttestationEvidence, KEY_ATTESTATION_CHALLENGE_BYTES, MAX_KEY_ATTESTATION_EVIDENCE_BYTES,
};
pub use error::{KeystoreError, KeystoreErrorReason, KeystoreResult};
pub use model::{KeyCustodyKind, KeyHandle, SigningAlgorithm};
pub use sign::{
    sign_wallet_p256_presentation_digest, Signature, SigningInputKind, SigningPurpose,
    SigningRequest, WalletKeystore,
};
pub use validate_boundary::{
    attest_key_with_validated_boundary, require_key_custody, validate_key_attestation_boundary,
    verify_key_attestation_evidence, KeyAttestationEvidenceVerifier, VerifiedKeyAttestationBinding,
    VerifiedKeyAttestationEvidence, WalletKeystoreBackend,
};
