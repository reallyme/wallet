// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet inventory operations.

use thiserror::Error;

/// Result type for inventory operations.
pub type InventoryResult<T> = Result<T, InventoryError>;

/// Typed inventory error with stable reason codes.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet inventory operation failed: {reason}")]
pub struct InventoryError {
    /// Stable reason code.
    pub reason: InventoryErrorReason,
}

impl InventoryError {
    /// Construct an inventory error from a stable reason.
    #[must_use]
    pub const fn new(reason: InventoryErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable inventory failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InventoryErrorReason {
    /// No copy is available to claim.
    #[error("batch_pool_exhausted")]
    BatchPoolExhausted,
    /// The batch pool does not belong to the requested credential.
    #[error("credential_mismatch")]
    CredentialMismatch,
    /// A batch pool contains duplicate once-only copy identifiers.
    #[error("duplicate_presentation_copy")]
    DuplicatePresentationCopy,
    /// Status evidence was expired or not yet valid for wallet use.
    #[error("stale_status_evidence")]
    StaleStatusEvidence,
    /// Status evidence had an impossible local lifecycle value.
    #[error("invalid_status_evidence")]
    InvalidStatusEvidence,
    /// Imported credential record was not in the validated active state.
    #[error("invalid_import_status")]
    InvalidImportStatus,
    /// Encrypted credential material was structurally empty.
    #[error("invalid_encrypted_payload")]
    InvalidEncryptedPayload,
    /// Issuer refresh evidence was missing or inconsistent.
    #[error("invalid_refresh_evidence")]
    InvalidRefreshEvidence,
    /// Reissued credential did not come from the same issuer.
    #[error("issuer_mismatch")]
    IssuerMismatch,
    /// Revocation is terminal for local lifecycle transitions.
    #[error("credential_revoked")]
    CredentialRevoked,
    /// Local deletion is terminal and cannot be changed by remote status evidence.
    #[error("credential_deleted")]
    CredentialDeleted,
}
