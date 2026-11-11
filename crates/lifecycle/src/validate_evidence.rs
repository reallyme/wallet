// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate Wallet Unit lifecycle evidence records.

use crate::{
    LifecycleError, LifecycleErrorReason, LifecycleResult, WalletLifecycleEvent,
    WalletLifecycleEvidenceKind, WalletLifecycleEvidenceRecord,
};

/// Maximum digest length accepted for lifecycle evidence references.
pub const MAX_LIFECYCLE_EVIDENCE_DIGEST_LEN: usize = 128;

/// Validate a durable lifecycle evidence record before persistence.
pub fn validate_wallet_lifecycle_evidence_record(
    record: &WalletLifecycleEvidenceRecord,
) -> LifecycleResult<()> {
    validate_evidence_kind_event(record.kind, record.event)?;
    validate_evidence_digest(&record.evidence_digest)
}

fn validate_evidence_kind_event(
    kind: WalletLifecycleEvidenceKind,
    event: WalletLifecycleEvent,
) -> LifecycleResult<()> {
    let valid = matches!(
        (kind, event),
        (
            WalletLifecycleEvidenceKind::Provisioning,
            WalletLifecycleEvent::BeginProvisioning
                | WalletLifecycleEvent::CompleteProvisioning
                | WalletLifecycleEvent::MarkFailed
                | WalletLifecycleEvent::RetryProvisioning
        ) | (
            WalletLifecycleEvidenceKind::Backup,
            WalletLifecycleEvent::CompleteProvisioning | WalletLifecycleEvent::CompleteMigration
        ) | (
            WalletLifecycleEvidenceKind::Restore,
            WalletLifecycleEvent::BeginRecovery | WalletLifecycleEvent::CompleteRecovery
        ) | (
            WalletLifecycleEvidenceKind::Recovery,
            WalletLifecycleEvent::BeginRecovery
                | WalletLifecycleEvent::CompleteRecovery
                | WalletLifecycleEvent::MarkFailed
        ) | (
            WalletLifecycleEvidenceKind::Migration,
            WalletLifecycleEvent::BeginMigration
                | WalletLifecycleEvent::CompleteMigration
                | WalletLifecycleEvent::MarkFailed
        ) | (
            WalletLifecycleEvidenceKind::PortabilityExport,
            WalletLifecycleEvent::BeginMigration | WalletLifecycleEvent::CompleteMigration
        ) | (
            WalletLifecycleEvidenceKind::PortabilityImport,
            WalletLifecycleEvent::BeginMigration | WalletLifecycleEvent::CompleteMigration
        ) | (
            WalletLifecycleEvidenceKind::Withdrawal,
            WalletLifecycleEvent::BeginWithdrawal
                | WalletLifecycleEvent::CompleteWithdrawal
                | WalletLifecycleEvent::MarkFailed
        ) | (
            WalletLifecycleEvidenceKind::Deletion,
            WalletLifecycleEvent::BeginDeletion
                | WalletLifecycleEvent::CompleteDeletion
                | WalletLifecycleEvent::MarkFailed
        ) | (
            WalletLifecycleEvidenceKind::Suspension,
            WalletLifecycleEvent::Suspend
        ) | (
            WalletLifecycleEvidenceKind::Reactivation,
            WalletLifecycleEvent::Reactivate
        )
    );

    if valid {
        Ok(())
    } else {
        Err(LifecycleError::new(LifecycleErrorReason::InvalidEvidence))
    }
}

fn validate_evidence_digest(digest: &[u8]) -> LifecycleResult<()> {
    if digest.is_empty() {
        return Err(LifecycleError::new(
            LifecycleErrorReason::EvidenceDigestRequired,
        ));
    }
    if digest.len() > MAX_LIFECYCLE_EVIDENCE_DIGEST_LEN {
        return Err(LifecycleError::new(
            LifecycleErrorReason::EvidenceDigestTooLarge,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "validate_evidence_tests.rs"]
mod tests;
