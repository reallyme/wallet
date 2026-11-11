// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Apply checked credential status evidence to inventory records.

use reallyme_wallet_types::{
    CredentialRecord, CredentialStatus, CredentialStatusEvidence, CredentialStatusUpdate,
    UnixTimestamp,
};

use crate::{InventoryError, InventoryErrorReason, InventoryResult};

/// Apply externally checked status evidence to a credential record.
///
/// Wallet-core does not parse token status lists or fetch revocation data. It
/// receives evidence from the protocol/identity layer and owns the local
/// lifecycle transition rules so deleted and revoked states remain safe.
pub(crate) fn apply_status_evidence(
    record: &mut CredentialRecord,
    evidence: &CredentialStatusEvidence,
    now: UnixTimestamp,
) -> InventoryResult<CredentialStatusUpdate> {
    validate_status_evidence(record, evidence, now)?;

    record
        .commit_authenticated_status(evidence.observed_status, evidence.source_issued_at, now)
        .map_err(|_| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))
}

pub(crate) fn validate_status_evidence(
    record: &CredentialRecord,
    evidence: &CredentialStatusEvidence,
    now: UnixTimestamp,
) -> InventoryResult<()> {
    if record.id != evidence.credential_id {
        return Err(InventoryError::new(
            InventoryErrorReason::CredentialMismatch,
        ));
    }
    let reference = record
        .status_reference()
        .ok_or_else(|| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?;
    if reference.issuer != evidence.source_issuer
        || reference.list_id != evidence.source_list_id
        || reference.status_index != evidence.status_index
        || reference
            .last_source_issued_at()
            .is_some_and(|last_issued| evidence.source_issued_at < last_issued)
    {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidStatusEvidence,
        ));
    }
    if evidence.source_issued_at > evidence.checked_at
        || evidence.source_issued_at >= evidence.valid_until
        || evidence.checked_at > now
        || now > evidence.valid_until
    {
        return Err(InventoryError::new(
            InventoryErrorReason::StaleStatusEvidence,
        ));
    }
    if evidence.observed_status == CredentialStatus::Deleted {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidStatusEvidence,
        ));
    }
    if record.status() == CredentialStatus::Deleted {
        return Err(InventoryError::new(InventoryErrorReason::CredentialDeleted));
    }

    Ok(())
}

#[cfg(test)]
#[path = "update_status_tests.rs"]
mod tests;
