// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};
use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;

use super::{
    credential_format_from_proto, credential_format_to_proto, credential_status_from_proto,
    credential_status_to_proto, encrypted_record_from_proto, encrypted_record_to_proto, known_enum,
    unix_timestamp_from_proto, unix_timestamp_to_proto, wallet_lifecycle_event_from_proto,
    wallet_lifecycle_event_to_proto, wallet_lifecycle_state_from_proto,
    wallet_lifecycle_state_to_proto, ConvertError, ConvertErrorReason, ConvertResult,
};

/// Convert a wallet lifecycle record into protobuf.
#[must_use]
pub fn wallet_lifecycle_record_to_proto(
    record: &lifecycle::WalletLifecycleRecord,
) -> pb::WalletLifecycleRecord {
    let mut result = pb::WalletLifecycleRecord::default();
    result.wallet_instance_id = record.wallet_instance_id().as_str().to_owned();
    result.state = EnumValue::from(wallet_lifecycle_state_to_proto(record.state()));
    result.updated_at = MessageField::some(unix_timestamp_to_proto(record.updated_at()));
    result.last_event = record
        .last_event()
        .map(wallet_lifecycle_event_to_proto)
        .map_or_else(EnumValue::default, EnumValue::from);
    result.resume_state = record
        .resume_state()
        .map(wallet_lifecycle_state_to_proto)
        .map_or_else(EnumValue::default, EnumValue::from);
    result.failed_from = record
        .failed_from()
        .map(wallet_lifecycle_state_to_proto)
        .map_or_else(EnumValue::default, EnumValue::from);
    result.last_evidence = record
        .last_evidence()
        .map(wallet_lifecycle_evidence_record_to_proto)
        .map_or_else(MessageField::none, MessageField::some);
    result
}

/// Convert a generated protobuf lifecycle record into wallet-core record.
pub fn wallet_lifecycle_record_from_proto(
    record: &pb::WalletLifecycleRecord,
) -> ConvertResult<lifecycle::WalletLifecycleRecord> {
    let updated_at = record
        .updated_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let last_event = optional_wallet_lifecycle_event_from_proto(record.last_event)?;
    let resume_state = optional_wallet_lifecycle_state_from_proto(record.resume_state)?;
    let failed_from = optional_wallet_lifecycle_state_from_proto(record.failed_from)?;
    let last_evidence = record
        .last_evidence
        .as_option()
        .map(wallet_lifecycle_evidence_record_from_proto)
        .transpose()?;

    lifecycle::restore_wallet_lifecycle(
        wallet::NonEmptyIdentifier::new(record.wallet_instance_id.clone())?,
        wallet_lifecycle_state_from_proto(known_enum(record.state)?)?,
        updated_at,
        last_event,
        resume_state,
        failed_from,
        last_evidence,
    )
    .map_err(ConvertError::from)
}

fn optional_wallet_lifecycle_state_from_proto(
    state: EnumValue<pb::WalletLifecycleState>,
) -> ConvertResult<Option<lifecycle::WalletLifecycleState>> {
    match state.as_known() {
        Some(pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_UNSPECIFIED) => Ok(None),
        Some(known) => wallet_lifecycle_state_from_proto(known).map(Some),
        None => Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue)),
    }
}

/// Convert a wallet lifecycle evidence kind into protobuf.
#[must_use]
pub const fn wallet_lifecycle_evidence_kind_to_proto(
    kind: lifecycle::WalletLifecycleEvidenceKind,
) -> pb::WalletLifecycleEvidenceKind {
    match kind {
        lifecycle::WalletLifecycleEvidenceKind::Provisioning => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_PROVISIONING
        }
        lifecycle::WalletLifecycleEvidenceKind::Backup => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_BACKUP
        }
        lifecycle::WalletLifecycleEvidenceKind::Restore => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_RESTORE
        }
        lifecycle::WalletLifecycleEvidenceKind::Recovery => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_RECOVERY
        }
        lifecycle::WalletLifecycleEvidenceKind::Migration => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_MIGRATION
        }
        lifecycle::WalletLifecycleEvidenceKind::PortabilityExport => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_PORTABILITY_EXPORT
        }
        lifecycle::WalletLifecycleEvidenceKind::PortabilityImport => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_PORTABILITY_IMPORT
        }
        lifecycle::WalletLifecycleEvidenceKind::Withdrawal => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_WITHDRAWAL
        }
        lifecycle::WalletLifecycleEvidenceKind::Deletion => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_DELETION
        }
        lifecycle::WalletLifecycleEvidenceKind::Suspension => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_SUSPENSION
        }
        lifecycle::WalletLifecycleEvidenceKind::Reactivation => {
            pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_REACTIVATION
        }
    }
}

/// Convert a generated protobuf lifecycle evidence kind into wallet-core kind.
pub const fn wallet_lifecycle_evidence_kind_from_proto(
    kind: pb::WalletLifecycleEvidenceKind,
) -> ConvertResult<lifecycle::WalletLifecycleEvidenceKind> {
    match kind {
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_PROVISIONING => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Provisioning)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_BACKUP => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Backup)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_RESTORE => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Restore)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_RECOVERY => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Recovery)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_MIGRATION => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Migration)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_PORTABILITY_EXPORT => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::PortabilityExport)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_PORTABILITY_IMPORT => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::PortabilityImport)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_WITHDRAWAL => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Withdrawal)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_DELETION => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Deletion)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_SUSPENSION => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Suspension)
        }
        pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_REACTIVATION => {
            Ok(lifecycle::WalletLifecycleEvidenceKind::Reactivation)
        }
    }
}

/// Convert a wallet lifecycle evidence record into protobuf.
#[must_use]
pub fn wallet_lifecycle_evidence_record_to_proto(
    record: &lifecycle::WalletLifecycleEvidenceRecord,
) -> pb::WalletLifecycleEvidenceRecord {
    let mut result = pb::WalletLifecycleEvidenceRecord::default();
    result.id = record.id.as_str().to_owned();
    result.wallet_instance_id = record.wallet_instance_id.as_str().to_owned();
    result.kind = EnumValue::from(wallet_lifecycle_evidence_kind_to_proto(record.kind));
    result.event = EnumValue::from(wallet_lifecycle_event_to_proto(record.event));
    result.occurred_at = MessageField::some(unix_timestamp_to_proto(record.occurred_at));
    result.authority_id = record.authority_id.as_str().to_owned();
    result.evidence_ref = record.evidence_ref.as_str().to_owned();
    result.evidence_digest = record.evidence_digest.clone();
    result
}

/// Convert generated protobuf lifecycle evidence into wallet-core record.
pub fn wallet_lifecycle_evidence_record_from_proto(
    record: &pb::WalletLifecycleEvidenceRecord,
) -> ConvertResult<lifecycle::WalletLifecycleEvidenceRecord> {
    let occurred_at = record
        .occurred_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let evidence = lifecycle::WalletLifecycleEvidenceRecord {
        id: wallet::NonEmptyIdentifier::new(record.id.clone())?,
        wallet_instance_id: wallet::NonEmptyIdentifier::new(record.wallet_instance_id.clone())?,
        kind: wallet_lifecycle_evidence_kind_from_proto(known_enum(record.kind)?)?,
        event: wallet_lifecycle_event_from_proto(known_enum(record.event)?)?,
        occurred_at,
        authority_id: wallet::NonEmptyIdentifier::new(record.authority_id.clone())?,
        evidence_ref: wallet::NonEmptyIdentifier::new(record.evidence_ref.clone())?,
        evidence_digest: record.evidence_digest.clone(),
    };
    lifecycle::validate_wallet_lifecycle_evidence_record(&evidence)?;
    Ok(evidence)
}

fn optional_wallet_lifecycle_event_from_proto(
    event: EnumValue<pb::WalletLifecycleEvent>,
) -> ConvertResult<Option<lifecycle::WalletLifecycleEvent>> {
    match event.as_known() {
        Some(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_UNSPECIFIED) => Ok(None),
        Some(known) => wallet_lifecycle_event_from_proto(known).map(Some),
        None => Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue)),
    }
}

/// Convert a wallet credential record into protobuf.
#[must_use]
pub fn credential_record_to_proto(record: &wallet::CredentialRecord) -> pb::CredentialRecord {
    let mut result = pb::CredentialRecord::default();
    result.id = record.id.as_str().to_owned();
    result.issuer_id = record.issuer_id.as_str().to_owned();
    result.signed_issuer = record
        .signed_issuer
        .as_ref()
        .map_or_else(String::new, |value| value.as_str().to_owned());
    result.holder_key_handle_id = record
        .holder_key_handle_id
        .as_ref()
        .map_or_else(String::new, |value| value.as_str().to_owned());
    result.status_reference = record
        .status_reference()
        .map(|reference| {
            let mut value = pb::CredentialStatusReference::default();
            value.issuer = reference.issuer.as_str().to_owned();
            value.list_id = reference.list_id.to_vec();
            value.status_index = reference.status_index;
            value.last_source_issued_at = reference
                .last_source_issued_at()
                .map(unix_timestamp_to_proto)
                .map_or_else(MessageField::none, MessageField::some);
            value
        })
        .map_or_else(MessageField::none, MessageField::some);
    result.format = EnumValue::from(credential_format_to_proto(record.format));
    result.status = EnumValue::from(credential_status_to_proto(record.status()));
    result.received_at = MessageField::some(unix_timestamp_to_proto(record.received_at));
    result.encrypted_payload =
        MessageField::some(encrypted_record_to_proto(&record.encrypted_payload));
    result
}

/// Convert a generated protobuf credential record into a wallet credential record.
pub fn credential_record_from_proto(
    record: &pb::CredentialRecord,
) -> ConvertResult<wallet::CredentialRecord> {
    let received_at = record
        .received_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let encrypted_payload = record
        .encrypted_payload
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(encrypted_record_from_proto)?;

    Ok(wallet::CredentialRecord::new(
        wallet::CredentialRecordId::new(record.id.clone())?,
        wallet::IssuerId::new(record.issuer_id.clone())?,
        optional_signed_issuer_from_proto(&record.signed_issuer)?,
        optional_holder_key_handle_from_proto(&record.holder_key_handle_id)?,
        record
            .status_reference
            .as_option()
            .map(credential_status_reference_from_proto)
            .transpose()?,
        credential_format_from_proto(known_enum(record.format)?)?,
        credential_status_from_proto(known_enum(record.status)?)?,
        received_at,
        encrypted_payload,
    ))
}

fn credential_status_reference_from_proto(
    reference: &pb::CredentialStatusReference,
) -> ConvertResult<wallet::CredentialStatusReference> {
    let list_id = <[u8; 32]>::try_from(reference.list_id.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::IntegerOutOfRange))?;
    let last_source_issued_at = reference
        .last_source_issued_at
        .as_option()
        .map(unix_timestamp_from_proto)
        .transpose()?;
    Ok(wallet::CredentialStatusReference::new(
        wallet::SignedCredentialIssuer::new(reference.issuer.clone())?,
        list_id,
        reference.status_index,
        last_source_issued_at,
    ))
}

fn optional_signed_issuer_from_proto(
    value: &str,
) -> ConvertResult<Option<wallet::SignedCredentialIssuer>> {
    if value.is_empty() {
        return Ok(None);
    }
    wallet::SignedCredentialIssuer::new(value.to_owned())
        .map(Some)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIdentifier))
}

fn optional_holder_key_handle_from_proto(
    value: &str,
) -> ConvertResult<Option<wallet::KeyHandleId>> {
    if value.is_empty() {
        return Ok(None);
    }
    if !value.as_bytes().iter().all(u8::is_ascii_graphic) {
        return Err(ConvertError::new(ConvertErrorReason::InvalidIdentifier));
    }
    wallet::KeyHandleId::new(value.to_owned())
        .map(Some)
        .map_err(ConvertError::from)
}

/// Convert a wallet batch copy state into protobuf.
#[must_use]
pub fn batch_copy_state_to_proto(state: wallet::BatchCopyState) -> pb::BatchCopyState {
    match state {
        wallet::BatchCopyState::Available => pb::BatchCopyState::BATCH_COPY_STATE_AVAILABLE,
        wallet::BatchCopyState::Claimed => pb::BatchCopyState::BATCH_COPY_STATE_CLAIMED,
    }
}

/// Convert a generated protobuf batch copy state into wallet state.
pub fn batch_copy_state_from_proto(
    state: pb::BatchCopyState,
) -> ConvertResult<wallet::BatchCopyState> {
    match state {
        pb::BatchCopyState::BATCH_COPY_STATE_AVAILABLE => Ok(wallet::BatchCopyState::Available),
        pb::BatchCopyState::BATCH_COPY_STATE_CLAIMED => Ok(wallet::BatchCopyState::Claimed),
        pb::BatchCopyState::BATCH_COPY_STATE_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet once-only presentation copy into protobuf.
#[must_use]
pub fn presentation_copy_to_proto(
    copy: &wallet::OnceOnlyPresentationCopy,
) -> pb::OnceOnlyPresentationCopy {
    let mut result = pb::OnceOnlyPresentationCopy::default();
    result.id = copy.id.as_str().to_owned();
    result.credential_id = copy.credential_id.as_str().to_owned();
    result.prepared_claim_selector_digest = copy
        .prepared_claim_selector_digest
        .map_or_else(Vec::new, |digest| digest.to_vec());
    result.state = EnumValue::from(batch_copy_state_to_proto(copy.state));
    result.encrypted_payload =
        MessageField::some(encrypted_record_to_proto(&copy.encrypted_payload));
    result
}

/// Convert a generated protobuf once-only presentation copy into wallet state.
pub fn presentation_copy_from_proto(
    copy: &pb::OnceOnlyPresentationCopy,
) -> ConvertResult<wallet::OnceOnlyPresentationCopy> {
    let encrypted_payload = copy
        .encrypted_payload
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(encrypted_record_from_proto)?;

    let prepared_claim_selector_digest = match copy.prepared_claim_selector_digest.as_slice() {
        [] => None,
        bytes if bytes.len() == 32 && bytes.iter().any(|byte| *byte != 0) => {
            let mut digest = [0_u8; 32];
            digest.copy_from_slice(bytes);
            Some(digest)
        }
        _ => return Err(ConvertError::new(ConvertErrorReason::InvalidZkArtifact)),
    };
    Ok(wallet::OnceOnlyPresentationCopy {
        id: wallet::PresentationCopyId::new(copy.id.clone())?,
        credential_id: wallet::CredentialRecordId::new(copy.credential_id.clone())?,
        prepared_claim_selector_digest,
        state: batch_copy_state_from_proto(known_enum(copy.state)?)?,
        encrypted_payload,
    })
}
