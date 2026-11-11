// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated transaction log and decision record conversions.

use buffa::{EnumValue, MessageField};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;

use super::{
    known_enum, unix_timestamp_from_proto, unix_timestamp_to_proto, ConvertError,
    ConvertErrorReason, ConvertResult,
};

/// Convert a wallet transaction purpose into protobuf.
#[must_use]
pub fn transaction_purpose_to_proto(purpose: wallet::TransactionPurpose) -> pb::TransactionPurpose {
    match purpose {
        wallet::TransactionPurpose::Issuance => {
            pb::TransactionPurpose::TRANSACTION_PURPOSE_ISSUANCE
        }
        wallet::TransactionPurpose::Presentation => {
            pb::TransactionPurpose::TRANSACTION_PURPOSE_PRESENTATION
        }
        wallet::TransactionPurpose::Refresh => pb::TransactionPurpose::TRANSACTION_PURPOSE_REFRESH,
        wallet::TransactionPurpose::Deletion => {
            pb::TransactionPurpose::TRANSACTION_PURPOSE_DELETION
        }
    }
}

/// Convert a generated protobuf transaction purpose into wallet state.
pub fn transaction_purpose_from_proto(
    purpose: pb::TransactionPurpose,
) -> ConvertResult<wallet::TransactionPurpose> {
    match purpose {
        pb::TransactionPurpose::TRANSACTION_PURPOSE_ISSUANCE => {
            Ok(wallet::TransactionPurpose::Issuance)
        }
        pb::TransactionPurpose::TRANSACTION_PURPOSE_PRESENTATION => {
            Ok(wallet::TransactionPurpose::Presentation)
        }
        pb::TransactionPurpose::TRANSACTION_PURPOSE_REFRESH => {
            Ok(wallet::TransactionPurpose::Refresh)
        }
        pb::TransactionPurpose::TRANSACTION_PURPOSE_DELETION => {
            Ok(wallet::TransactionPurpose::Deletion)
        }
        pb::TransactionPurpose::TRANSACTION_PURPOSE_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet disclosed attribute into protobuf.
#[must_use]
pub fn disclosed_attribute_to_proto(
    attribute: &wallet::DisclosedAttribute,
) -> pb::DisclosedAttribute {
    let mut result = pb::DisclosedAttribute::default();
    result.name = attribute.name.as_str().to_owned();
    result
}

/// Convert a generated protobuf disclosed attribute into wallet state.
pub fn disclosed_attribute_from_proto(
    attribute: &pb::DisclosedAttribute,
) -> ConvertResult<wallet::DisclosedAttribute> {
    Ok(wallet::DisclosedAttribute {
        name: wallet::AttributeName::new(attribute.name.clone())?,
    })
}

/// Convert a wallet transaction log entry into protobuf.
#[must_use]
pub fn transaction_log_entry_to_proto(
    entry: &wallet::TransactionLogEntry,
) -> pb::TransactionLogEntry {
    let mut result = pb::TransactionLogEntry::default();
    result.id = entry.id.as_str().to_owned();
    result.purpose = EnumValue::from(transaction_purpose_to_proto(entry.purpose));
    result.relying_party_id = entry
        .relying_party_id
        .as_ref()
        .map_or_else(String::new, |id| id.as_str().to_owned());
    result.disclosed_attributes = entry
        .disclosed_attributes
        .iter()
        .map(disclosed_attribute_to_proto)
        .collect();
    result.occurred_at = MessageField::some(unix_timestamp_to_proto(entry.occurred_at));
    result.sequence = entry.sequence;
    result.previous_entry_hash = entry.previous_entry_hash.to_vec();
    result.entry_hash = entry.entry_hash.to_vec();
    result
}

/// Convert a generated protobuf transaction log entry into wallet state.
pub fn transaction_log_entry_from_proto(
    entry: &pb::TransactionLogEntry,
) -> ConvertResult<wallet::TransactionLogEntry> {
    let occurred_at = entry
        .occurred_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let relying_party_id = if entry.relying_party_id.is_empty() {
        None
    } else {
        Some(wallet::RelyingPartyId::new(entry.relying_party_id.clone())?)
    };
    let mut disclosed_attributes = Vec::with_capacity(entry.disclosed_attributes.len());
    for attribute in &entry.disclosed_attributes {
        disclosed_attributes.push(disclosed_attribute_from_proto(attribute)?);
    }

    let previous_entry_hash =
        <[u8; wallet::TRANSACTION_LOG_HASH_BYTES]>::try_from(entry.previous_entry_hash.as_slice())
            .map_err(|_| ConvertError::new(ConvertErrorReason::IntegerOutOfRange))?;
    let entry_hash =
        <[u8; wallet::TRANSACTION_LOG_HASH_BYTES]>::try_from(entry.entry_hash.as_slice())
            .map_err(|_| ConvertError::new(ConvertErrorReason::IntegerOutOfRange))?;

    Ok(wallet::TransactionLogEntry {
        id: wallet::TransactionLogEntryId::new(entry.id.clone())?,
        purpose: transaction_purpose_from_proto(known_enum(entry.purpose)?)?,
        relying_party_id,
        disclosed_attributes,
        occurred_at,
        sequence: entry.sequence,
        previous_entry_hash,
        entry_hash,
    })
}

/// Convert a wallet decision outcome into protobuf.
#[must_use]
pub fn decision_outcome_to_proto(outcome: wallet::DecisionOutcome) -> pb::DecisionOutcome {
    match outcome {
        wallet::DecisionOutcome::Accept => pb::DecisionOutcome::DECISION_OUTCOME_ACCEPT,
        wallet::DecisionOutcome::Reject => pb::DecisionOutcome::DECISION_OUTCOME_REJECT,
    }
}

/// Convert a generated protobuf decision outcome into wallet state.
pub fn decision_outcome_from_proto(
    outcome: pb::DecisionOutcome,
) -> ConvertResult<wallet::DecisionOutcome> {
    match outcome {
        pb::DecisionOutcome::DECISION_OUTCOME_ACCEPT => Ok(wallet::DecisionOutcome::Accept),
        pb::DecisionOutcome::DECISION_OUTCOME_REJECT => Ok(wallet::DecisionOutcome::Reject),
        pb::DecisionOutcome::DECISION_OUTCOME_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet QTSP decision kind into protobuf.
#[must_use]
pub fn qtsp_decision_kind_to_proto(kind: wallet::QtspDecisionKind) -> pb::QtspDecisionKind {
    match kind {
        wallet::QtspDecisionKind::RelyingPartyRegistrationCertificate => {
            pb::QtspDecisionKind::QTSP_DECISION_KIND_RELYING_PARTY_REGISTRATION_CERTIFICATE
        }
        wallet::QtspDecisionKind::IssuerTrustChain => {
            pb::QtspDecisionKind::QTSP_DECISION_KIND_ISSUER_TRUST_CHAIN
        }
        wallet::QtspDecisionKind::CredentialStatus => {
            pb::QtspDecisionKind::QTSP_DECISION_KIND_CREDENTIAL_STATUS
        }
        wallet::QtspDecisionKind::QualifiedElectronicSignature => {
            pb::QtspDecisionKind::QTSP_DECISION_KIND_QUALIFIED_ELECTRONIC_SIGNATURE
        }
        wallet::QtspDecisionKind::QualifiedElectronicSeal => {
            pb::QtspDecisionKind::QTSP_DECISION_KIND_QUALIFIED_ELECTRONIC_SEAL
        }
    }
}

/// Convert a generated protobuf QTSP decision kind into wallet state.
pub fn qtsp_decision_kind_from_proto(
    kind: pb::QtspDecisionKind,
) -> ConvertResult<wallet::QtspDecisionKind> {
    match kind {
        pb::QtspDecisionKind::QTSP_DECISION_KIND_RELYING_PARTY_REGISTRATION_CERTIFICATE => {
            Ok(wallet::QtspDecisionKind::RelyingPartyRegistrationCertificate)
        }
        pb::QtspDecisionKind::QTSP_DECISION_KIND_ISSUER_TRUST_CHAIN => {
            Ok(wallet::QtspDecisionKind::IssuerTrustChain)
        }
        pb::QtspDecisionKind::QTSP_DECISION_KIND_CREDENTIAL_STATUS => {
            Ok(wallet::QtspDecisionKind::CredentialStatus)
        }
        pb::QtspDecisionKind::QTSP_DECISION_KIND_QUALIFIED_ELECTRONIC_SIGNATURE => {
            Ok(wallet::QtspDecisionKind::QualifiedElectronicSignature)
        }
        pb::QtspDecisionKind::QTSP_DECISION_KIND_QUALIFIED_ELECTRONIC_SEAL => {
            Ok(wallet::QtspDecisionKind::QualifiedElectronicSeal)
        }
        pb::QtspDecisionKind::QTSP_DECISION_KIND_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet QTSP decision record into protobuf.
#[must_use]
pub fn qtsp_decision_record_to_proto(
    record: &wallet::QtspDecisionRecord,
) -> pb::QtspDecisionRecord {
    let mut result = pb::QtspDecisionRecord::default();
    result.kind = EnumValue::from(qtsp_decision_kind_to_proto(record.kind));
    result.outcome = EnumValue::from(decision_outcome_to_proto(record.outcome));
    result.input_sha256_b64url = record.input_sha256_b64url.clone();
    result.decided_at = MessageField::some(unix_timestamp_to_proto(record.decided_at));
    result
}

/// Convert a generated protobuf QTSP decision record into wallet state.
pub fn qtsp_decision_record_from_proto(
    record: &pb::QtspDecisionRecord,
) -> ConvertResult<wallet::QtspDecisionRecord> {
    let decided_at = record
        .decided_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;

    Ok(wallet::QtspDecisionRecord {
        kind: qtsp_decision_kind_from_proto(known_enum(record.kind)?)?,
        outcome: decision_outcome_from_proto(known_enum(record.outcome)?)?,
        input_sha256_b64url: record.input_sha256_b64url.clone(),
        decided_at,
    })
}
