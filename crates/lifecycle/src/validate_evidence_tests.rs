// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    validate_wallet_lifecycle_evidence_record, LifecycleErrorReason, WalletLifecycleEvent,
    WalletLifecycleEvidenceKind, WalletLifecycleEvidenceRecord, MAX_LIFECYCLE_EVIDENCE_DIGEST_LEN,
};
use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp, WalletTypesError};

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn evidence_record(
    kind: WalletLifecycleEvidenceKind,
    event: WalletLifecycleEvent,
    digest: Vec<u8>,
) -> Result<WalletLifecycleEvidenceRecord, WalletTypesError> {
    Ok(WalletLifecycleEvidenceRecord {
        id: id("evidence-1")?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind,
        event,
        occurred_at: timestamp(10)?,
        authority_id: id("platform-secure-area")?,
        evidence_ref: id("provider-receipt-1")?,
        evidence_digest: digest,
    })
}

#[test]
fn accepts_backup_evidence_for_completed_provisioning() -> Result<(), WalletTypesError> {
    let record = evidence_record(
        WalletLifecycleEvidenceKind::Backup,
        WalletLifecycleEvent::CompleteProvisioning,
        vec![7; 32],
    )?;

    assert!(validate_wallet_lifecycle_evidence_record(&record).is_ok());
    Ok(())
}

#[test]
fn accepts_portability_export_for_migration() -> Result<(), WalletTypesError> {
    let record = evidence_record(
        WalletLifecycleEvidenceKind::PortabilityExport,
        WalletLifecycleEvent::BeginMigration,
        vec![7; 32],
    )?;

    assert!(validate_wallet_lifecycle_evidence_record(&record).is_ok());
    Ok(())
}

#[test]
fn rejects_kind_event_mismatch() -> Result<(), WalletTypesError> {
    let record = evidence_record(
        WalletLifecycleEvidenceKind::Deletion,
        WalletLifecycleEvent::CompleteRecovery,
        vec![7; 32],
    )?;

    let result = validate_wallet_lifecycle_evidence_record(&record);

    assert!(matches!(
        result,
        Err(error) if error.reason == LifecycleErrorReason::InvalidEvidence
    ));
    Ok(())
}

#[test]
fn rejects_empty_evidence_digest() -> Result<(), WalletTypesError> {
    let record = evidence_record(
        WalletLifecycleEvidenceKind::Deletion,
        WalletLifecycleEvent::BeginDeletion,
        Vec::new(),
    )?;

    let result = validate_wallet_lifecycle_evidence_record(&record);

    assert!(matches!(
        result,
        Err(error) if error.reason == LifecycleErrorReason::EvidenceDigestRequired
    ));
    Ok(())
}

#[test]
fn rejects_oversized_evidence_digest() -> Result<(), WalletTypesError> {
    let record = evidence_record(
        WalletLifecycleEvidenceKind::Deletion,
        WalletLifecycleEvent::BeginDeletion,
        vec![7; MAX_LIFECYCLE_EVIDENCE_DIGEST_LEN + 1],
    )?;

    let result = validate_wallet_lifecycle_evidence_record(&record);

    assert!(matches!(
        result,
        Err(error) if error.reason == LifecycleErrorReason::EvidenceDigestTooLarge
    ));
    Ok(())
}
