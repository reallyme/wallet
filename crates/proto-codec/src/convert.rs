// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated conversions between generated Buffa DTOs and wallet-core types.

use buffa::EnumValue;
use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_types as wallet;
use thiserror::Error;

/// Result type for wallet protobuf conversions.
pub type ConvertResult<T> = Result<T, ConvertError>;

/// Typed conversion error with stable, audit-safe reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet protobuf conversion failed: {reason}")]
pub struct ConvertError {
    /// Stable reason code.
    pub reason: ConvertErrorReason,
}

impl ConvertError {
    /// Construct a conversion error from a stable reason.
    #[must_use]
    pub const fn new(reason: ConvertErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable wallet protobuf conversion failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConvertErrorReason {
    /// A required message field was absent.
    #[error("missing_required_field")]
    MissingRequiredField,
    /// A required identifier was empty or too long.
    #[error("invalid_identifier")]
    InvalidIdentifier,
    /// A timestamp failed wallet validation.
    #[error("invalid_timestamp")]
    InvalidTimestamp,
    /// A protobuf enum was unspecified or unsupported.
    #[error("invalid_enum_value")]
    InvalidEnumValue,
    /// A protobuf integer could not fit the target wallet type.
    #[error("integer_out_of_range")]
    IntegerOutOfRange,
    /// A persisted record schema version is absent or unsupported.
    #[error("unsupported_schema")]
    UnsupportedSchema,
    /// A persisted flow-state schema version is absent or unsupported.
    #[error("unsupported_flow_state_schema_version")]
    UnsupportedFlowStateSchemaVersion,
    /// A persisted flow-state payload is malformed or mismatched with its kind.
    #[error("invalid_flow_state_payload")]
    InvalidFlowStatePayload,
    /// A lifecycle evidence record failed lifecycle validation.
    #[error("invalid_lifecycle_evidence")]
    InvalidLifecycleEvidence,
    /// A distribution-card DTO failed wallet validation.
    #[error("invalid_distribution_card")]
    InvalidDistributionCard,
    /// An issuance notification endpoint was invalid.
    #[error("invalid_notification_endpoint")]
    InvalidNotificationEndpoint,
    /// A credential reuse policy selection was internally inconsistent.
    #[error("invalid_credential_reuse_policy")]
    InvalidCredentialReusePolicy,
    /// An issuance commit carried invalid idempotency material.
    #[error("invalid_idempotency_key")]
    InvalidIdempotencyKey,
    /// An atomic issuance commit omitted required state.
    #[error("invalid_issuance_commit")]
    InvalidIssuanceCommit,
    /// A decoded attestation omitted or exceeded its signed evidence boundary.
    #[error("invalid_attestation_evidence")]
    InvalidAttestationEvidence,
    /// Consent action omits or contradicts its derivation semantics.
    #[error("invalid_consent_action")]
    InvalidConsentAction,
    /// A ZK cache descriptor or its authenticated ciphertext was invalid.
    #[error("invalid_zk_artifact")]
    InvalidZkArtifact,
}

impl From<wallet::WalletTypesError> for ConvertError {
    fn from(error: wallet::WalletTypesError) -> Self {
        match error.reason {
            wallet::WalletTypesErrorReason::EmptyIdentifier
            | wallet::WalletTypesErrorReason::IdentifierTooLong
            | wallet::WalletTypesErrorReason::InvalidIdentifier
            | wallet::WalletTypesErrorReason::EmptyAttributeName => {
                Self::new(ConvertErrorReason::InvalidIdentifier)
            }
            wallet::WalletTypesErrorReason::TimestampOutOfRange => {
                Self::new(ConvertErrorReason::InvalidTimestamp)
            }
            wallet::WalletTypesErrorReason::InvalidDistributionCard
            | wallet::WalletTypesErrorReason::TooManyDistributionFields
            | wallet::WalletTypesErrorReason::DistributionTextTooLong
            | wallet::WalletTypesErrorReason::DistributionBarcodeTooLarge => {
                Self::new(ConvertErrorReason::InvalidDistributionCard)
            }
            wallet::WalletTypesErrorReason::InvalidNotificationEndpoint => {
                Self::new(ConvertErrorReason::InvalidNotificationEndpoint)
            }
            wallet::WalletTypesErrorReason::InvalidCredentialReusePolicy => {
                Self::new(ConvertErrorReason::InvalidCredentialReusePolicy)
            }
        }
    }
}

impl From<lifecycle::LifecycleError> for ConvertError {
    fn from(_error: lifecycle::LifecycleError) -> Self {
        Self::new(ConvertErrorReason::InvalidLifecycleEvidence)
    }
}

fn known_enum<E: buffa::Enumeration>(value: EnumValue<E>) -> ConvertResult<E> {
    value
        .as_known()
        .ok_or(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
}

#[path = "convert_consent_log.rs"]
mod convert_consent_log;
#[path = "convert_flows.rs"]
mod convert_flows;
#[path = "convert_issuance_commit.rs"]
mod convert_issuance_commit;
#[path = "convert_lifecycle.rs"]
mod convert_lifecycle;
#[path = "convert_lifecycle_events.rs"]
mod convert_lifecycle_events;
#[path = "convert_records.rs"]
mod convert_records;
#[path = "convert_transaction_log.rs"]
mod convert_transaction_log;

pub use convert_consent_log::{
    consent_action_from_proto, consent_action_kind_from_proto, consent_action_kind_to_proto,
    consent_action_to_proto, consent_request_from_proto, consent_request_to_proto,
    consent_scope_from_proto, consent_scope_to_proto, disclosure_policy_decision_from_proto,
    disclosure_policy_decision_to_proto, verifier_entitlement_from_proto,
    verifier_entitlement_to_proto,
};
pub use convert_flows::{
    credential_reuse_policy_from_proto, credential_reuse_policy_to_proto, flow_kind_from_proto,
    flow_kind_to_proto, flow_snapshot_from_proto, flow_snapshot_to_proto,
    issuer_metadata_profile_from_proto, issuer_metadata_profile_to_proto,
    issuer_nonce_binding_from_proto, issuer_nonce_binding_to_proto,
};
pub use convert_issuance_commit::{
    build_openid4vci_issuance_commit, issuance_commit_from_proto, issuance_commit_to_proto,
    notification_delivery_state_from_proto, notification_delivery_state_to_proto,
    notification_outbox_from_proto, notification_outbox_to_proto, OpenId4VciIssuanceCommit,
};
pub use convert_lifecycle::{
    batch_copy_state_from_proto, batch_copy_state_to_proto, credential_record_from_proto,
    credential_record_to_proto, presentation_copy_from_proto, presentation_copy_to_proto,
    wallet_lifecycle_evidence_kind_from_proto, wallet_lifecycle_evidence_kind_to_proto,
    wallet_lifecycle_evidence_record_from_proto, wallet_lifecycle_evidence_record_to_proto,
    wallet_lifecycle_record_from_proto, wallet_lifecycle_record_to_proto,
};
pub use convert_lifecycle_events::{
    wallet_lifecycle_event_from_proto, wallet_lifecycle_event_to_proto,
    wallet_lifecycle_state_from_proto, wallet_lifecycle_state_to_proto,
};
pub use convert_records::{
    credential_format_from_proto, credential_format_to_proto,
    credential_status_evidence_from_proto, credential_status_evidence_method_from_proto,
    credential_status_evidence_method_to_proto, credential_status_evidence_to_proto,
    credential_status_from_proto, credential_status_to_proto, encrypted_record_from_proto,
    encrypted_record_header_from_proto, encrypted_record_header_to_proto,
    encrypted_record_to_proto, key_attestation_evidence_from_proto,
    key_attestation_evidence_to_proto, storage_encryption_algorithm_from_proto,
    storage_encryption_algorithm_to_proto, unix_timestamp_from_proto, unix_timestamp_to_proto,
    wallet_unit_attestation_from_proto, wallet_unit_attestation_to_proto,
};
pub use convert_transaction_log::{
    decision_outcome_from_proto, decision_outcome_to_proto, disclosed_attribute_from_proto,
    disclosed_attribute_to_proto, qtsp_decision_kind_from_proto, qtsp_decision_kind_to_proto,
    qtsp_decision_record_from_proto, qtsp_decision_record_to_proto,
    transaction_log_entry_from_proto, transaction_log_entry_to_proto,
    transaction_purpose_from_proto, transaction_purpose_to_proto,
};
