// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for platform-provided wallet storage.

use thiserror::Error;

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Typed storage error with no untrusted payloads.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet storage operation failed: {reason}")]
pub struct StorageError {
    /// Stable reason code.
    pub reason: StorageErrorReason,
}

impl StorageError {
    /// Construct a storage error from a stable reason.
    #[must_use]
    pub const fn new(reason: StorageErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable storage failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StorageErrorReason {
    /// Requested record was not found.
    #[error("record_not_found")]
    RecordNotFound,
    /// Backend rejected the write.
    #[error("write_rejected")]
    WriteRejected,
    /// Backend rejected the read.
    #[error("read_rejected")]
    ReadRejected,
    /// Backend rejected the delete.
    #[error("delete_rejected")]
    DeleteRejected,
    /// A create targeted a record that already exists.
    #[error("record_already_exists")]
    RecordAlreadyExists,
    /// An atomic replacement or delete used a stale revision.
    #[error("revision_conflict")]
    RevisionConflict,
    /// A canonical operation idempotency key had an invalid length or value.
    #[error("invalid_idempotency_key")]
    InvalidIdempotencyKey,
    /// A journal returned the reserved zero capability value.
    #[error("invalid_reservation")]
    InvalidReservation,
    /// An idempotency key was reused for different request bytes.
    #[error("idempotency_conflict")]
    IdempotencyConflict,
    /// A matching operation reservation has not committed a response yet.
    #[error("operation_in_progress")]
    OperationInProgress,
    /// The durable idempotency journal rejected an operation.
    #[error("journal_rejected")]
    JournalRejected,
}
