// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet unit attestation operations.

use thiserror::Error;

/// Result type for wallet unit attestation operations.
pub type AttestationResult<T> = Result<T, AttestationError>;

/// Typed attestation error with stable reason codes.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet attestation operation failed: {reason}")]
pub struct AttestationError {
    /// Stable reason code.
    pub reason: AttestationErrorReason,
}

impl AttestationError {
    /// Construct an attestation error from a stable reason.
    #[must_use]
    pub const fn new(reason: AttestationErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable attestation failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AttestationErrorReason {
    /// The attestation evidence was empty or structurally unusable.
    #[error("invalid_attestation_evidence")]
    InvalidAttestationEvidence,
    /// The challenge was absent or the key evidence is too old for issuance.
    #[error("attestation_challenge_stale")]
    AttestationChallengeStale,
    /// The attestation validity window is internally inconsistent.
    #[error("invalid_validity_window")]
    InvalidValidityWindow,
    /// The attestation evidence was issued in the future.
    #[error("wallet_unit_attestation_not_yet_valid")]
    WalletUnitAttestationNotYetValid,
    /// The attestation has expired.
    #[error("wallet_unit_attestation_expired")]
    WalletUnitAttestationExpired,
    /// Rotation was requested before a replacement attestation was available.
    #[error("replacement_not_available")]
    ReplacementNotAvailable,
    /// Provider response did not preserve the requested key evidence and validity.
    #[error("provider_binding_mismatch")]
    ProviderBindingMismatch,
    /// Rotation attempted to change the attested wallet key.
    #[error("key_continuity_mismatch")]
    KeyContinuityMismatch,
    /// The injected trust verifier rejected the issuer signature or chain.
    #[error("attestation_signature_invalid")]
    AttestationSignatureInvalid,
}
