// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet keystore operations.

use thiserror::Error;

/// Result type for keystore operations.
pub type KeystoreResult<T> = Result<T, KeystoreError>;

/// Typed keystore error with no backend exception text.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet keystore operation failed: {reason}")]
pub struct KeystoreError {
    /// Stable reason code.
    pub reason: KeystoreErrorReason,
}

impl KeystoreError {
    /// Construct a keystore error from a stable reason.
    #[must_use]
    pub const fn new(reason: KeystoreErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable keystore failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreErrorReason {
    /// Key handle was not found.
    #[error("key_handle_not_found")]
    KeyHandleNotFound,
    /// Requested algorithm is unsupported by the backend.
    #[error("unsupported_algorithm")]
    UnsupportedAlgorithm,
    /// Backend refused the operation.
    #[error("operation_refused")]
    OperationRefused,
    /// Wallet lifecycle policy does not permit signing.
    #[error("wallet_not_active")]
    WalletNotActive,
    /// Signing input was empty, oversized, or could not be bounded.
    #[error("invalid_signing_input")]
    InvalidSigningInput,
    /// Attestation evidence was missing or invalid.
    #[error("attestation_unavailable")]
    AttestationUnavailable,
    /// Attestation evidence was issued for a different key handle.
    #[error("attestation_key_handle_mismatch")]
    AttestationKeyHandleMismatch,
    /// Authenticated key algorithm differs from the requested handle.
    #[error("attestation_algorithm_mismatch")]
    AttestationAlgorithmMismatch,
    /// Attestation evidence was issued in the future.
    #[error("attestation_issued_in_future")]
    AttestationIssuedInFuture,
    /// Attestation evidence did not authenticate the caller challenge.
    #[error("attestation_challenge_mismatch")]
    AttestationChallengeMismatch,
    /// Attestation evidence is older than the accepted freshness window.
    #[error("attestation_stale")]
    AttestationStale,
}
