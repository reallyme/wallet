// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable canonical-operation idempotency journal port.

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{StorageError, StorageErrorReason, StorageResult};

/// Required byte length of a canonical operation idempotency key.
pub const OPERATION_IDEMPOTENCY_KEY_LENGTH: usize = 32;

/// Caller-generated key that identifies one canonical mutating operation.
///
/// Keys are privacy-bearing correlation values. They are fixed-size, omitted
/// from diagnostics and serialization, and wiped with their owner.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct OperationIdempotencyKey([u8; OPERATION_IDEMPOTENCY_KEY_LENGTH]);

impl OperationIdempotencyKey {
    /// Validate and copy a canonical idempotency key.
    pub fn from_slice(value: &[u8]) -> StorageResult<Self> {
        let bytes = <[u8; OPERATION_IDEMPOTENCY_KEY_LENGTH]>::try_from(value)
            .map_err(|_| StorageError::new(StorageErrorReason::InvalidIdempotencyKey))?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(StorageError::new(StorageErrorReason::InvalidIdempotencyKey));
        }
        Ok(Self(bytes))
    }

    /// Borrow the fixed-size key for an injected journal provider.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OPERATION_IDEMPOTENCY_KEY_LENGTH] {
        &self.0
    }
}

/// SHA-256 fingerprint of the complete canonical operation request.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct OperationRequestDigest([u8; OPERATION_IDEMPOTENCY_KEY_LENGTH]);

impl OperationRequestDigest {
    /// Own a request digest produced by the reviewed ReallyMe SHA-256 crate.
    #[must_use]
    pub const fn new(bytes: [u8; OPERATION_IDEMPOTENCY_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed digest for a journal comparison.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OPERATION_IDEMPOTENCY_KEY_LENGTH] {
        &self.0
    }
}

/// Opaque reservation returned when a journal authorizes first execution.
#[derive(PartialEq, Eq)]
pub struct OperationReservation(u64);

impl OperationReservation {
    /// Validate a non-zero capability returned by the trusted journal provider.
    pub fn from_provider_value(value: u64) -> StorageResult<Self> {
        if value == 0 {
            return Err(StorageError::new(StorageErrorReason::InvalidReservation));
        }
        Ok(Self(value))
    }

    /// Return the provider-owned reservation value.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }
}

/// Result of atomically reserving an idempotency key.
pub enum OperationReplayDecision {
    /// This caller owns first execution and must commit its complete response.
    Execute(OperationReservation),
    /// The same request completed earlier; return its canonical response bytes.
    Replay(Zeroizing<Vec<u8>>),
}

/// Durable provider port for whole-operation replay protection.
pub trait OperationJournal {
    /// Reserve a new operation or return its exact committed response.
    fn begin_operation(
        &mut self,
        key: &OperationIdempotencyKey,
        request_digest: &OperationRequestDigest,
    ) -> StorageResult<OperationReplayDecision>;

    /// Commit the exact canonical response for a reservation.
    ///
    /// A failed commit leaves the reservation in progress. Implementations must
    /// never implicitly expire it and authorize the mutation to execute again.
    fn commit_operation(
        &mut self,
        reservation: &OperationReservation,
        response: &[u8],
    ) -> StorageResult<()>;
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
