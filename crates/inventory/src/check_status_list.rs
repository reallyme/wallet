// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Apply identity-verified token status-list evidence to wallet inventory.

use reallyme_credential_status::{
    verify_status, CredentialStatusError, StatusList, StatusListVerifier,
};
use reallyme_wallet_types::{
    CredentialRecord, CredentialStatus, CredentialStatusEvidence, CredentialStatusEvidenceMethod,
    CredentialStatusUpdate, UnixTimestamp,
};

use crate::{
    update_status::apply_status_evidence, InventoryError, InventoryErrorReason, InventoryResult,
};

/// Verify a token status list through identity and apply the resulting lifecycle update.
///
/// Wallet-core does not fetch or parse status-list credentials. It receives the
/// already constructed identity status-list model plus an injected verifier, then
/// translates the checked outcome into wallet lifecycle evidence.
pub fn apply_token_status_list(
    record: &mut CredentialRecord,
    list: &StatusList,
    status_index: u64,
    now: UnixTimestamp,
    verifier: &dyn StatusListVerifier,
) -> InventoryResult<CredentialStatusUpdate> {
    let reference = record
        .status_reference()
        .ok_or_else(|| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?;
    let list_id = list
        .list_id
        .ok_or_else(|| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?;
    if list.issuer != reference.issuer.as_str()
        || list_id != reference.list_id
        || status_index != reference.status_index
    {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidStatusEvidence,
        ));
    }
    let now_unix = u64::try_from(now.as_seconds())
        .map_err(|_| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?;
    let observed_status = checked_status(list, status_index, now_unix, verifier)?;
    let evidence = status_evidence(
        record,
        observed_status,
        list.issued_at,
        now,
        list.next_update,
    )?;
    apply_status_evidence(record, &evidence, now)
}

fn checked_status(
    list: &StatusList,
    status_index: u64,
    now_unix: u64,
    verifier: &dyn StatusListVerifier,
) -> InventoryResult<CredentialStatus> {
    match verify_status(list, status_index, now_unix, verifier) {
        Ok(()) => Ok(CredentialStatus::Active),
        Err(CredentialStatusError::Revoked) => Ok(CredentialStatus::Revoked),
        Err(CredentialStatusError::Suspended) => Ok(CredentialStatus::Suspended),
        Err(CredentialStatusError::Expired) | Err(CredentialStatusError::NotYetValid) => Err(
            InventoryError::new(InventoryErrorReason::StaleStatusEvidence),
        ),
        Err(CredentialStatusError::InvalidInput(_))
        | Err(CredentialStatusError::InvalidSignature) => Err(InventoryError::new(
            InventoryErrorReason::InvalidStatusEvidence,
        )),
        // The external error enum is non-exhaustive. An unrecognized verification
        // outcome cannot establish an active credential status.
        #[allow(unreachable_patterns)]
        Err(_) => Err(InventoryError::new(
            InventoryErrorReason::InvalidStatusEvidence,
        )),
    }
}

fn status_evidence(
    record: &CredentialRecord,
    observed_status: CredentialStatus,
    source_issued_at_unix: u64,
    checked_at: UnixTimestamp,
    valid_until_unix: u64,
) -> InventoryResult<CredentialStatusEvidence> {
    let valid_until_seconds = i64::try_from(valid_until_unix)
        .map_err(|_| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?;
    let valid_until = UnixTimestamp::from_seconds(valid_until_seconds)
        .map_err(|_| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?;
    let source_issued_at_seconds = i64::try_from(source_issued_at_unix)
        .map_err(|_| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?;
    let source_issued_at = UnixTimestamp::from_seconds(source_issued_at_seconds)
        .map_err(|_| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?;

    Ok(CredentialStatusEvidence {
        credential_id: record.id.clone(),
        observed_status,
        method: CredentialStatusEvidenceMethod::TokenStatusList,
        source_issuer: record
            .status_reference()
            .ok_or_else(|| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?
            .issuer
            .clone(),
        source_list_id: record
            .status_reference()
            .ok_or_else(|| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?
            .list_id,
        status_index: record
            .status_reference()
            .ok_or_else(|| InventoryError::new(InventoryErrorReason::InvalidStatusEvidence))?
            .status_index,
        source_issued_at,
        checked_at,
        valid_until,
    })
}

#[cfg(test)]
#[path = "check_status_list_tests.rs"]
mod tests;
