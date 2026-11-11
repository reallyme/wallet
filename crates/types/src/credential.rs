// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential inventory DTOs.

use core::fmt;

use crate::{
    CredentialRecordId, EncryptedRecord, IssuerId, KeyHandleId, PresentationCopyId,
    SignedCredentialIssuer, UnixTimestamp,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Credential envelope format stored by the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum CredentialFormat {
    /// SD-JWT VC credential.
    SdJwtVc,
    /// ISO mdoc credential.
    Mdoc,
    /// JWT VC credential.
    JwtVc,
    /// Data Integrity proof based credential.
    DataIntegrity,
    /// Issuer-signed common-root credential with a ZK proof binding.
    ReallyMeZkV1,
}

/// User-visible lifecycle status for a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum CredentialStatus {
    /// Credential was imported and validated on receipt.
    Active,
    /// Issuer or status-list check marked the credential suspended.
    Suspended,
    /// Credential is no longer valid.
    Revoked,
    /// Credential was deleted locally.
    Deleted,
}

/// Source method for externally checked credential status evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum CredentialStatusEvidenceMethod {
    /// OAuth token status list or similar token status-list mechanism.
    TokenStatusList,
    /// VC status list with revocation purpose.
    RevocationList,
    /// VC status list with suspension purpose.
    SuspensionList,
    /// Issuer refresh or reissuance flow supplied the status.
    IssuerRefresh,
    /// QTSP or qualified trust decision supplied the status.
    QtspDecision,
}

/// Issuer-authenticated status-list coordinates carried by a credential.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct CredentialStatusReference {
    /// Issuer authenticated from the status reference.
    pub issuer: SignedCredentialIssuer,
    /// Stable status-list identifier.
    pub list_id: [u8; 32],
    /// Credential bit index in that list.
    pub status_index: u64,
    /// Issuance time of the newest authenticated source, used to reject rollback.
    last_source_issued_at: Option<UnixTimestamp>,
}

impl fmt::Debug for CredentialStatusReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialStatusReference(<redacted>)")
    }
}

/// Typed failure returned by wallet-controlled credential mutations.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("credential mutation failed: {reason}")]
pub struct CredentialMutationError {
    /// Stable, audit-safe reason code.
    pub reason: CredentialMutationErrorReason,
}

impl CredentialMutationError {
    const fn new(reason: CredentialMutationErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable reasons why a credential mutation was rejected.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMutationErrorReason {
    /// A status source attempted to move its anti-rollback watermark backwards.
    #[error("status_source_rollback")]
    StatusSourceRollback,
    /// A transition attempted to leave a terminal state or lacked a status reference.
    #[error("invalid_status_transition")]
    InvalidStatusTransition,
    /// Two authenticated observations claimed different states at one source time.
    #[error("conflicting_status_observation")]
    ConflictingStatusObservation,
    /// The status source claims a time later than trusted current time.
    #[error("future_status_source")]
    FutureStatusSource,
}

impl CredentialStatusReference {
    /// Construct issuer-authenticated status-list coordinates.
    #[must_use]
    pub const fn new(
        issuer: SignedCredentialIssuer,
        list_id: [u8; 32],
        status_index: u64,
        last_source_issued_at: Option<UnixTimestamp>,
    ) -> Self {
        Self {
            issuer,
            list_id,
            status_index,
            last_source_issued_at,
        }
    }

    /// Return the newest authenticated source timestamp accepted by the wallet.
    #[must_use]
    pub const fn last_source_issued_at(&self) -> Option<UnixTimestamp> {
        self.last_source_issued_at
    }

    fn advance_watermark(
        &mut self,
        source_issued_at: UnixTimestamp,
    ) -> Result<bool, CredentialMutationError> {
        match self.last_source_issued_at {
            Some(current) if source_issued_at < current => Err(CredentialMutationError::new(
                CredentialMutationErrorReason::StatusSourceRollback,
            )),
            Some(current) if source_issued_at == current => Ok(false),
            _ => {
                self.last_source_issued_at = Some(source_issued_at);
                Ok(true)
            }
        }
    }
}

/// Checked credential status evidence supplied by protocol/identity layers.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct CredentialStatusEvidence {
    /// Credential id this evidence binds to.
    pub credential_id: CredentialRecordId,
    /// Observed lifecycle status.
    pub observed_status: CredentialStatus,
    /// Evidence method.
    pub method: CredentialStatusEvidenceMethod,
    /// Authenticated issuer of the evidence source.
    pub source_issuer: SignedCredentialIssuer,
    /// Stable identifier of the checked list or equivalent source.
    pub source_list_id: [u8; 32],
    /// Credential index checked in the source.
    pub status_index: u64,
    /// Authenticated issuance time of the evidence source.
    pub source_issued_at: UnixTimestamp,
    /// Time when the evidence was checked.
    pub checked_at: UnixTimestamp,
    /// Time until which this evidence may update local inventory state.
    pub valid_until: UnixTimestamp,
}

impl fmt::Debug for CredentialStatusEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialStatusEvidence(<redacted>)")
    }
}

/// Result of applying status evidence to an inventory record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStatusUpdate {
    /// Status before evidence was applied.
    pub previous_status: CredentialStatus,
    /// Status after evidence was applied.
    pub current_status: CredentialStatus,
    /// Whether the inventory record changed.
    pub changed: bool,
}

/// State for a once-only presentation copy in a batch pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum BatchCopyState {
    /// Copy is available for a future presentation.
    Available,
    /// Copy has been consumed and must not be reused.
    Claimed,
}

/// Wallet inventory record for an encrypted credential.
///
/// `Clone` supports atomic storage snapshots. The cloned payload remains
/// ciphertext and each owned copy zeroizes its buffers on drop.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct CredentialRecord {
    /// Stable local credential id.
    pub id: CredentialRecordId,
    /// Issuer identifier after trust validation.
    pub issuer_id: IssuerId,
    /// Exact issuer claim authenticated from the signed credential, when the
    /// credential format defines one. This must never be synthesized from the
    /// Credential Issuer metadata identifier.
    pub signed_issuer: Option<SignedCredentialIssuer>,
    /// Opaque holder/device key handle selected during receipt validation.
    /// Records written before this field may omit it; presentation fails closed on `None`.
    pub holder_key_handle_id: Option<KeyHandleId>,
    /// Issuer-authenticated coordinates for status checks, when supported.
    status_reference: Option<CredentialStatusReference>,
    /// Envelope format for protocol selection.
    pub format: CredentialFormat,
    /// Current lifecycle status.
    status: CredentialStatus,
    /// Timestamp when validation-on-receipt succeeded.
    pub received_at: UnixTimestamp,
    /// The encrypted credential payload and metadata.
    pub encrypted_payload: EncryptedRecord,
}

impl CredentialRecord {
    /// Construct a credential inventory record after receipt validation.
    ///
    /// Construction does not authenticate anything: status and the
    /// anti-rollback watermark are taken as given. Build records only from
    /// receipt-validated input or from authenticated storage. Inventory import
    /// accepts only active records, and later status changes go through
    /// `commit_authenticated_status`, which enforces terminal states and
    /// rollback protection.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        id: CredentialRecordId,
        issuer_id: IssuerId,
        signed_issuer: Option<SignedCredentialIssuer>,
        holder_key_handle_id: Option<KeyHandleId>,
        status_reference: Option<CredentialStatusReference>,
        format: CredentialFormat,
        status: CredentialStatus,
        received_at: UnixTimestamp,
        encrypted_payload: EncryptedRecord,
    ) -> Self {
        Self {
            id,
            issuer_id,
            signed_issuer,
            holder_key_handle_id,
            status_reference,
            format,
            status,
            received_at,
            encrypted_payload,
        }
    }

    /// Return the wallet-controlled credential lifecycle status.
    #[must_use]
    pub const fn status(&self) -> CredentialStatus {
        self.status
    }

    /// Return issuer-authenticated status-list coordinates, if present.
    #[must_use]
    pub const fn status_reference(&self) -> Option<&CredentialStatusReference> {
        self.status_reference.as_ref()
    }

    /// Commit a status observation after the caller has authenticated its evidence.
    ///
    /// This method does not authenticate anything. Use the inventory crate's
    /// status-evidence functions, which check issuer, list, index, and
    /// validity before calling it. It does enforce terminal states,
    /// anti-rollback, and that `source_issued_at` is not later than the
    /// trusted `now`, so a future-dated source cannot pin the watermark and
    /// block every later revocation.
    pub fn commit_authenticated_status(
        &mut self,
        observed_status: CredentialStatus,
        source_issued_at: UnixTimestamp,
        now: UnixTimestamp,
    ) -> Result<CredentialStatusUpdate, CredentialMutationError> {
        if source_issued_at > now {
            return Err(CredentialMutationError::new(
                CredentialMutationErrorReason::FutureStatusSource,
            ));
        }
        if observed_status == CredentialStatus::Deleted || self.status == CredentialStatus::Deleted
        {
            return Err(CredentialMutationError::new(
                CredentialMutationErrorReason::InvalidStatusTransition,
            ));
        }

        let same_source_time = self
            .status_reference
            .as_ref()
            .and_then(CredentialStatusReference::last_source_issued_at)
            == Some(source_issued_at);
        let same_time_more_restrictive = same_source_time
            && matches!(
                (self.status, observed_status),
                (
                    CredentialStatus::Active,
                    CredentialStatus::Suspended | CredentialStatus::Revoked
                ) | (CredentialStatus::Suspended, CredentialStatus::Revoked)
            );
        if same_source_time && observed_status != self.status && !same_time_more_restrictive {
            return Err(CredentialMutationError::new(
                CredentialMutationErrorReason::ConflictingStatusObservation,
            ));
        }

        let watermark_changed = match self.status_reference.as_mut() {
            Some(reference) => reference.advance_watermark(source_issued_at)?,
            None => {
                return Err(CredentialMutationError::new(
                    CredentialMutationErrorReason::InvalidStatusTransition,
                ));
            }
        };
        let previous_status = self.status;
        let current_status = match previous_status {
            CredentialStatus::Revoked => CredentialStatus::Revoked,
            CredentialStatus::Active | CredentialStatus::Suspended => observed_status,
            CredentialStatus::Deleted => {
                return Err(CredentialMutationError::new(
                    CredentialMutationErrorReason::InvalidStatusTransition,
                ));
            }
        };
        if watermark_changed || same_time_more_restrictive {
            self.status = current_status;
        }

        Ok(CredentialStatusUpdate {
            previous_status,
            current_status: self.status,
            changed: previous_status != self.status,
        })
    }

    /// Mark this local credential deleted. Deletion is terminal.
    #[must_use]
    pub fn mark_deleted(&mut self) -> CredentialStatusUpdate {
        let previous_status = self.status;
        self.status = CredentialStatus::Deleted;
        CredentialStatusUpdate {
            previous_status,
            current_status: self.status,
            changed: previous_status != self.status,
        }
    }
}

/// DTO for a once-only presentation copy.
///
/// `Clone` is required by the atomic claim interface so a backend can return an
/// owned claimed snapshot. Each encrypted payload copy zeroizes independently.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct OnceOnlyPresentationCopy {
    /// Copy id used to prevent verifier-linkable reuse.
    pub id: PresentationCopyId,
    /// Credential this unlinkable copy was derived from.
    pub credential_id: CredentialRecordId,
    /// Copy-scoped prepared claim selector, protected with the inventory row.
    pub prepared_claim_selector_digest: Option<[u8; 32]>,
    /// Current copy state.
    pub state: BatchCopyState,
    /// Encrypted copy payload.
    pub encrypted_payload: EncryptedRecord,
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod tests;
