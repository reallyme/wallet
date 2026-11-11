// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Versioned history metadata. Claim values and backend exception text are excluded.
//!
//! Copies support bounded provider pages; each independently owned record wipes
//! its metadata on drop and does not authorize any wallet operation.
use crate::{
    AttributeName, CredentialRecordId, NonEmptyIdentifier, RelyingPartyId, TransactionLogEntryId,
    UnixTimestamp,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum attributes in each requested or presented scope.
pub const MAX_HISTORY_ATTRIBUTES: usize = 128;
/// Maximum affected inventory records per event.
pub const MAX_HISTORY_CREDENTIALS: usize = 128;
/// Maximum page size, including export pages.
pub const MAX_HISTORY_PAGE_SIZE: u32 = 128;
/// Typed history purpose, independent of the legacy v1 hash transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum HistoryPurpose {
    /// Credential issuance.
    Issuance,
    /// Disclosure or proof.
    Presentation,
    /// Issuer refresh.
    Refresh,
    /// Local deletion.
    Deletion,
    /// Qualified signing.
    QualifiedSignature,
    /// Qualified sealing.
    QualifiedSeal,
}
/// Safe terminal outcome, including attempts that disclosed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum HistoryOutcome {
    /// Confirmed completion.
    Completed,
    /// Holder refusal.
    Refused,
    /// Cancellation before submission.
    Cancelled,
    /// Known failure.
    Failed,
    /// Expired before completion.
    Expired,
    /// Submission may have reached its recipient; never infer no disclosure.
    DeliveryUnknown,
}
/// Stable, non-sensitive explanation for an unsuccessful attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum HistoryFailureReason {
    /// No failure applies.
    None,
    /// User declined.
    UserDecision,
    /// Authorization or policy rejected the operation.
    Policy,
    /// Input validation failed.
    InvalidInput,
    /// A provider failed before delivery.
    Provider,
    /// Transport outcome cannot be established.
    Transport,
    /// Trusted time expired the operation.
    Expiry,
}
/// Version-two event, hashed independently from legacy records.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct TransactionHistoryRecord {
    /// Unique event identity, checked atomically by storage.
    pub id: TransactionLogEntryId,
    /// Purpose of the attempt.
    pub purpose: HistoryPurpose,
    /// Actual outcome.
    pub outcome: HistoryOutcome,
    /// Stable safe reason.
    pub reason: HistoryFailureReason,
    /// Recipient, required for presentations.
    pub relying_party_id: Option<RelyingPartyId>,
    /// Requested names, never values.
    pub requested: Vec<AttributeName>,
    /// Actually presented names; uncertainty retains the attempted disclosure scope.
    pub presented: Vec<AttributeName>,
    /// Affected wallet inventory records.
    pub credential_ids: Vec<CredentialRecordId>,
    /// Exact consent/request context digest, where applicable.
    pub consent_digest: Option<[u8; 32]>,
    /// Flow or operation correlation identity.
    pub operation_id: NonEmptyIdentifier,
    /// Trusted event time.
    pub occurred_at: UnixTimestamp,
    /// One-based sequence continuing an explicitly supplied legacy anchor.
    pub sequence: u64,
    /// Preceding v2 hash, or an authenticated legacy head at migration.
    pub previous_hash: [u8; 32],
    /// Domain-separated canonical v2 hash.
    pub entry_hash: [u8; 32],
}
/// Stable page boundary, pinned to one observed head for a complete export.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct HistoryCursor {
    /// Last verified sequence, zero for an empty log.
    pub after_sequence: u64,
    /// Hash at that sequence.
    pub after_hash: [u8; 32],
    /// Stable last sequence to export.
    pub through_sequence: u64,
    /// Hash of the pinned export head.
    pub through_hash: [u8; 32],
    /// Nonzero bounded page size.
    pub limit: u32,
}
