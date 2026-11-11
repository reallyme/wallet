// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet logging operations.

use thiserror::Error;

/// Result type for wallet logging operations.
pub type WalletLogResult<T> = Result<T, WalletLogError>;

/// Typed log error with stable reason codes.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet log operation failed: {reason}")]
pub struct WalletLogError {
    /// Stable reason code.
    pub reason: WalletLogErrorReason,
}

impl WalletLogError {
    /// Construct a log error from a stable reason.
    #[must_use]
    pub const fn new(reason: WalletLogErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable log failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WalletLogErrorReason {
    /// Log backend rejected the append operation.
    #[error("append_rejected")]
    AppendRejected,
    /// Presentation entries must identify the relying party.
    #[error("missing_relying_party")]
    MissingRelyingParty,
    /// QTSP decision records must carry a digest of the evaluated artifact.
    #[error("missing_decision_digest")]
    MissingDecisionDigest,
    /// QTSP decision digest exceeded the wallet-core bound.
    #[error("decision_digest_too_long")]
    DecisionDigestTooLong,
    /// QTSP decision digest is not canonical unpadded SHA-256 base64url.
    #[error("invalid_decision_digest")]
    InvalidDecisionDigest,
    /// Transaction log sequence or hash-chain linkage was invalid.
    #[error("invalid_transaction_chain")]
    InvalidTransactionChain,
    /// A canonical transaction transcript length could not be represented safely.
    #[error("transaction_transcript_too_large")]
    TransactionTranscriptTooLarge,
}
