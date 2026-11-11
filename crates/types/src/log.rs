// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! User-visible transaction and QTSP decision log DTOs.

use crate::{AttributeName, RelyingPartyId, TransactionLogEntryId, UnixTimestamp};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SHA-256 byte length used by the transaction-log hash chain.
pub const TRANSACTION_LOG_HASH_BYTES: usize = 32;

/// Purpose attached to a wallet transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum TransactionPurpose {
    /// Credential issuance.
    Issuance,
    /// Credential presentation to a verifier.
    Presentation,
    /// Credential refresh or re-issuance.
    Refresh,
    /// Credential deletion.
    Deletion,
}

/// Attribute disclosed in a presentation log entry.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct DisclosedAttribute {
    /// Attribute name disclosed to the verifier.
    pub name: AttributeName,
}

/// User-visible transaction log entry.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct TransactionLogEntry {
    /// Stable log entry id.
    pub id: TransactionLogEntryId,
    /// Transaction purpose.
    pub purpose: TransactionPurpose,
    /// Optional relying party for presentations.
    pub relying_party_id: Option<RelyingPartyId>,
    /// Attributes disclosed to the relying party.
    pub disclosed_attributes: Vec<DisclosedAttribute>,
    /// Time of the transaction.
    pub occurred_at: UnixTimestamp,
    /// Monotonic one-based position in the wallet transaction log.
    pub sequence: u64,
    /// Hash of the preceding entry, or all zeroes for the first entry.
    pub previous_entry_hash: [u8; TRANSACTION_LOG_HASH_BYTES],
    /// Hash of this entry's canonical chain transcript.
    pub entry_hash: [u8; TRANSACTION_LOG_HASH_BYTES],
}

/// Audit outcome for trust, status, and QTSP decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum DecisionOutcome {
    /// Decision accepted the input.
    Accept,
    /// Decision rejected the input.
    Reject,
}

/// Kind of QTSP or qualified-trust decision recorded by the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum QtspDecisionKind {
    /// Relying-party registration certificate validation.
    RelyingPartyRegistrationCertificate,
    /// Issuer trust-chain validation.
    IssuerTrustChain,
    /// Credential status or revocation check.
    CredentialStatus,
    /// Qualified electronic signature decision.
    QualifiedElectronicSignature,
    /// Qualified electronic seal decision.
    QualifiedElectronicSeal,
}

/// Storage-agnostic decision record with digests supplied by lower layers.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct QtspDecisionRecord {
    /// Decision kind.
    pub kind: QtspDecisionKind,
    /// Decision outcome.
    pub outcome: DecisionOutcome,
    /// Digest of the evaluated input artifact.
    pub input_sha256_b64url: String,
    /// Time of the decision.
    pub decided_at: UnixTimestamp,
}

#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;
