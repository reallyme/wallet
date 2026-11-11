// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed lifecycle errors.

use thiserror::Error;

/// Result type returned by wallet lifecycle operations.
pub type LifecycleResult<T> = Result<T, LifecycleError>;

/// Error returned when a lifecycle transition or operation is not allowed.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet lifecycle operation failed: {reason}")]
pub struct LifecycleError {
    /// Stable, audit-safe reason code.
    pub reason: LifecycleErrorReason,
}

impl LifecycleError {
    /// Build an error from a stable reason.
    #[must_use]
    pub const fn new(reason: LifecycleErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable lifecycle failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleErrorReason {
    /// The requested event is not valid for the current state.
    #[error("invalid_transition")]
    InvalidTransition,
    /// The supplied timestamp would move the lifecycle record backwards.
    #[error("clock_rollback")]
    ClockRollback,
    /// The wallet is not active enough for the requested operation.
    #[error("wallet_not_active")]
    WalletNotActive,
    /// The wallet has been withdrawn and must not issue, present, or sign.
    #[error("wallet_withdrawn")]
    WalletWithdrawn,
    /// The wallet has been deleted and must not issue, present, or sign.
    #[error("wallet_deleted")]
    WalletDeleted,
    /// A lifecycle evidence record does not match lifecycle policy.
    #[error("invalid_evidence")]
    InvalidEvidence,
    /// A lifecycle evidence digest is missing.
    #[error("evidence_digest_required")]
    EvidenceDigestRequired,
    /// A lifecycle evidence digest exceeds the supported bound.
    #[error("evidence_digest_too_large")]
    EvidenceDigestTooLarge,
}
