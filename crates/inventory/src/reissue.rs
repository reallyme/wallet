// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Replace a credential record after issuer reissuance.

use reallyme_wallet_types::{
    CredentialRecord, CredentialStatus, CredentialStatusEvidence, UnixTimestamp,
};

use crate::{
    import::import_validated_credential, refresh::validate_refresh_evidence, InventoryError,
    InventoryErrorReason, InventoryResult,
};

/// Retire a credential and return the already validated replacement record.
///
/// Reissuance is stricter than refresh because it changes the local credential
/// id. Wallet requires an active credential, an active same-issuer replacement
/// that keeps status-list coverage, and issuer-refresh evidence reporting the
/// retired credential as active.
///
/// This function does not authenticate anything. The evidence is a caller
/// DTO checked for consistency with `current`, and the replacement must
/// already have passed the issuance flow's credential validation. Reissue
/// grants nothing a caller could not do by deleting `current` and importing
/// `replacement`; it exists so the two happen together under these checks.
pub fn reissue_credential_record(
    current: &mut CredentialRecord,
    replacement: CredentialRecord,
    evidence: &CredentialStatusEvidence,
    now: UnixTimestamp,
) -> InventoryResult<CredentialRecord> {
    // Reissuance replaces an active credential with an active successor. A
    // suspended, revoked, or deleted credential must not become active again
    // through this path; lifting a suspension needs authenticated status.
    match current.status() {
        CredentialStatus::Active => {}
        CredentialStatus::Revoked => {
            return Err(InventoryError::new(InventoryErrorReason::CredentialRevoked));
        }
        CredentialStatus::Deleted => {
            return Err(InventoryError::new(InventoryErrorReason::CredentialDeleted));
        }
        CredentialStatus::Suspended => {
            return Err(InventoryError::new(
                InventoryErrorReason::InvalidRefreshEvidence,
            ));
        }
    }
    if evidence.observed_status != CredentialStatus::Active {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidRefreshEvidence,
        ));
    }
    // A replacement must have a separate identity so retiring the old record
    // cannot also delete its replacement or revive its consumed copy history.
    if current.id == replacement.id {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidRefreshEvidence,
        ));
    }
    if current.signed_issuer.is_none()
        || current.signed_issuer != replacement.signed_issuer
        || current.issuer_id != replacement.issuer_id
    {
        return Err(InventoryError::new(InventoryErrorReason::IssuerMismatch));
    }
    // A replacement must stay covered by revocation checks if its predecessor was.
    // The replacement may name a different status list, for example after the
    // issuer moves its lists; each status check authenticates the list
    // against the reference it is given.
    if current.status_reference().is_some() && replacement.status_reference().is_none() {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidRefreshEvidence,
        ));
    }
    validate_refresh_evidence(current, evidence, now)?;

    let replacement = import_validated_credential(replacement)?;
    let _ = current.mark_deleted();

    Ok(replacement)
}

#[cfg(test)]
#[path = "reissue_tests.rs"]
mod tests;
