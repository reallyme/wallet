// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Refresh encrypted credential payloads after issuer-checked evidence.

use reallyme_wallet_types::{
    CredentialRecord, CredentialStatus, CredentialStatusEvidence, CredentialStatusEvidenceMethod,
    CredentialStatusUpdate, EncryptedRecord, UnixTimestamp,
};

use crate::{
    update_status::validate_status_evidence, validate_record::validate_encrypted_record,
    InventoryError, InventoryErrorReason, InventoryResult,
};

/// Apply an issuer refresh only after the format layer authenticates it.
///
/// This remains crate-private: a public caller can construct the evidence DTO,
/// and this package has no signed issuer response to verify at this boundary.
#[allow(dead_code)]
pub(crate) fn apply_verified_refresh(
    record: &mut CredentialRecord,
    replacement_payload: EncryptedRecord,
    evidence: &CredentialStatusEvidence,
    now: UnixTimestamp,
) -> InventoryResult<CredentialStatusUpdate> {
    validate_refresh_evidence(record, evidence, now)?;
    validate_encrypted_record(&replacement_payload)?;

    let update = record
        .commit_authenticated_status(evidence.observed_status, evidence.source_issued_at, now)
        .map_err(|_| InventoryError::new(InventoryErrorReason::InvalidRefreshEvidence))?;
    record.encrypted_payload = replacement_payload;

    Ok(update)
}

pub(crate) fn validate_refresh_evidence(
    record: &CredentialRecord,
    evidence: &CredentialStatusEvidence,
    now: UnixTimestamp,
) -> InventoryResult<()> {
    if evidence.method != CredentialStatusEvidenceMethod::IssuerRefresh {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidRefreshEvidence,
        ));
    }
    if matches!(
        evidence.observed_status,
        CredentialStatus::Revoked | CredentialStatus::Deleted
    ) {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidRefreshEvidence,
        ));
    }
    if record.status() == CredentialStatus::Revoked {
        return Err(InventoryError::new(InventoryErrorReason::CredentialRevoked));
    }

    validate_status_evidence(record, evidence, now)
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod tests;
