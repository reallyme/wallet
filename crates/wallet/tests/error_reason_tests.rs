// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for public wallet error reason mapping.

#![cfg(feature = "native")]

use buffa::{EnumValue, Message};
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};
use reallyme_wallet::map_error_reason::{
    consent_error_to_proto, convert_error_to_proto, error_reason_code,
    error_reason_from_enum_value, error_reason_from_i32, error_reason_from_identity_stack_error,
    flow_error_to_proto, identity_stack_error_from_reason, inventory_error_to_proto,
    keystore_error_to_proto, map_consent_error_reason, map_convert_error_reason,
    map_flow_error_reason, map_inventory_error_reason, map_keystore_error_reason,
    map_proto_error_reason, map_runtime_error_reason, map_storage_error_reason,
    proto_error_to_proto, runtime_error_to_proto, storage_error_to_proto,
    wallet_error_envelope_from_error,
};
use reallyme_wallet::proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet::proto_codec::convert::ConvertErrorReason;
use serde_json::json;

#[test]
fn storage_reasons_map_to_proto_categories_and_detail() {
    assert_eq!(
        map_storage_error_reason(reallyme_wallet::storage::StorageErrorReason::RecordNotFound),
        pb::WalletErrorReason::WALLET_ERROR_REASON_RECORD_NOT_FOUND
    );
    assert_eq!(
        map_storage_error_reason(reallyme_wallet::storage::StorageErrorReason::ReadRejected),
        pb::WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE
    );
    assert_eq!(
        map_storage_error_reason(reallyme_wallet::storage::StorageErrorReason::RevisionConflict),
        pb::WalletErrorReason::WALLET_ERROR_REASON_REVISION_CONFLICT
    );

    let error =
        storage_error_to_proto(reallyme_wallet::storage::StorageErrorReason::RecordNotFound);

    assert_eq!(
        error.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_RECORD_NOT_FOUND)
    );
    assert!(matches!(
        error.detail,
        Some(pb::wallet_error::Detail::Storage(value))
            if value.as_known()
                == Some(pb::StorageErrorReason::STORAGE_ERROR_REASON_RECORD_NOT_FOUND)
    ));
}

#[test]
fn keystore_reasons_map_to_proto_categories_and_detail() {
    assert_eq!(
        map_keystore_error_reason(
            reallyme_wallet::keystore::KeystoreErrorReason::UnsupportedAlgorithm
        ),
        pb::WalletErrorReason::WALLET_ERROR_REASON_UNSUPPORTED_ALGORITHM
    );
    assert_eq!(
        map_keystore_error_reason(reallyme_wallet::keystore::KeystoreErrorReason::OperationRefused),
        pb::WalletErrorReason::WALLET_ERROR_REASON_KEYSTORE_UNAVAILABLE
    );

    let error = keystore_error_to_proto(
        reallyme_wallet::keystore::KeystoreErrorReason::UnsupportedAlgorithm,
    );

    assert!(matches!(
        error.detail,
        Some(pb::wallet_error::Detail::Keystore(value))
            if value.as_known()
                == Some(pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_UNSUPPORTED_ALGORITHM)
    ));
}

#[test]
fn inventory_reasons_map_to_proto_categories_and_detail() {
    assert_eq!(
        map_inventory_error_reason(
            reallyme_wallet::inventory::InventoryErrorReason::BatchPoolExhausted,
        ),
        pb::WalletErrorReason::WALLET_ERROR_REASON_BATCH_POOL_EXHAUSTED
    );
    assert_eq!(
        map_inventory_error_reason(
            reallyme_wallet::inventory::InventoryErrorReason::CredentialDeleted,
        ),
        pb::WalletErrorReason::WALLET_ERROR_REASON_CREDENTIAL_DELETED
    );

    let error = inventory_error_to_proto(
        reallyme_wallet::inventory::InventoryErrorReason::DuplicatePresentationCopy,
    );

    assert!(matches!(
        error.detail,
        Some(pb::wallet_error::Detail::Inventory(value))
            if value.as_known()
                == Some(pb::InventoryErrorReason::INVENTORY_ERROR_REASON_DUPLICATE_PRESENTATION_COPY)
    ));
}

#[test]
fn consent_reasons_map_to_proto_categories_and_detail() {
    let stale = consent_error_to_proto(
        reallyme_wallet::consent::ConsentErrorReason::RegistrationCertificateStale,
    );
    assert_eq!(
        stale.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_REGISTRATION_CERTIFICATE_INVALID)
    );
    assert!(matches!(
        stale.detail,
        Some(pb::wallet_error::Detail::Consent(value))
            if value.as_known()
                == Some(pb::ConsentErrorReason::CONSENT_ERROR_REASON_REGISTRATION_CERTIFICATE_STALE)
    ));
    let replay =
        consent_error_to_proto(reallyme_wallet::consent::ConsentErrorReason::CaptureAlreadyUsed);
    assert_eq!(
        replay.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE)
    );
    assert!(matches!(
        replay.detail,
        Some(pb::wallet_error::Detail::Consent(value))
            if value.as_known()
                == Some(pb::ConsentErrorReason::CONSENT_ERROR_REASON_CAPTURE_ALREADY_USED)
    ));
    let unavailable = consent_error_to_proto(
        reallyme_wallet::consent::ConsentErrorReason::CaptureStoreUnavailable,
    );
    assert_eq!(
        unavailable.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE)
    );
    assert!(matches!(
        unavailable.detail,
        Some(pb::wallet_error::Detail::Consent(value))
            if value.as_known()
                == Some(pb::ConsentErrorReason::CONSENT_ERROR_REASON_CAPTURE_STORE_UNAVAILABLE)
    ));
    let out_of_scope = consent_error_to_proto(
        reallyme_wallet::consent::ConsentErrorReason::FinalDisclosureOutOfScope,
    );
    assert_eq!(
        out_of_scope.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_ATTRIBUTE_NOT_AUTHORIZED)
    );
    assert!(matches!(
        out_of_scope.detail,
        Some(pb::wallet_error::Detail::Consent(value))
            if value.as_known()
                == Some(pb::ConsentErrorReason::CONSENT_ERROR_REASON_FINAL_DISCLOSURE_OUT_OF_SCOPE)
    ));
    let client_binding =
        consent_error_to_proto(reallyme_wallet::consent::ConsentErrorReason::ClientBindingMismatch);
    assert_eq!(
        client_binding.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_RELYING_PARTY_MISMATCH)
    );
    assert!(matches!(
        client_binding.detail,
        Some(pb::wallet_error::Detail::Consent(value))
            if value.as_known()
                == Some(pb::ConsentErrorReason::CONSENT_ERROR_REASON_CLIENT_BINDING_MISMATCH)
    ));
    assert_eq!(
        map_consent_error_reason(
            reallyme_wallet::consent::ConsentErrorReason::AttributeNotAuthorized,
        ),
        pb::WalletErrorReason::WALLET_ERROR_REASON_ATTRIBUTE_NOT_AUTHORIZED
    );
    assert_eq!(
        map_consent_error_reason(reallyme_wallet::consent::ConsentErrorReason::UserRejected),
        pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED
    );

    let error = consent_error_to_proto(
        reallyme_wallet::consent::ConsentErrorReason::DerivationIdentifierMissing,
    );

    assert_eq!(
        error.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_SATISFACTION_PLAN)
    );
    assert!(matches!(
        error.detail,
        Some(pb::wallet_error::Detail::Consent(value))
            if value.as_known()
                == Some(pb::ConsentErrorReason::CONSENT_ERROR_REASON_DERIVATION_IDENTIFIER_MISSING)
    ));
}

#[test]
fn flow_reasons_map_to_proto_categories_and_detail() {
    assert_eq!(
        map_flow_error_reason(
            reallyme_wallet::flows::FlowErrorReason::ContactSessionTranscriptMismatch,
        ),
        pb::WalletErrorReason::WALLET_ERROR_REASON_CONTACT_SESSION_BINDING_FAILED
    );

    let error =
        flow_error_to_proto(reallyme_wallet::flows::FlowErrorReason::TransactionCodeUnexpected);

    assert_eq!(
        error.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_TRANSACTION_CODE_INVALID)
    );
    assert!(matches!(
        error.detail,
        Some(pb::wallet_error::Detail::Flow(value))
            if value.as_known()
                == Some(pb::FlowErrorReason::FLOW_ERROR_REASON_TRANSACTION_CODE_UNEXPECTED)
    ));
}

#[test]
fn proto_and_runtime_reasons_map_to_proto_categories_and_detail() {
    assert_eq!(
        map_proto_error_reason(reallyme_wallet::proto_codec::ProtoErrorReason::MalformedWire),
        pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_MALFORMED_WIRE
    );
    assert_eq!(
        map_runtime_error_reason(reallyme_wallet::runtime::RuntimeErrorReason::InvalidRequest),
        pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID
    );
    assert_eq!(
        map_runtime_error_reason(
            reallyme_wallet::runtime::RuntimeErrorReason::CredentialRevisionConflict,
        ),
        pb::WalletErrorReason::WALLET_ERROR_REASON_REVISION_CONFLICT
    );
    assert_eq!(
        map_runtime_error_reason(reallyme_wallet::runtime::RuntimeErrorReason::IdempotencyConflict,),
        pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_CONFLICT
    );

    let proto_error =
        proto_error_to_proto(reallyme_wallet::proto_codec::ProtoErrorReason::InvalidUtf8);
    assert!(matches!(
        proto_error.detail,
        Some(pb::wallet_error::Detail::Proto(value))
            if value.as_known() == Some(pb::ProtoErrorReason::PROTO_ERROR_REASON_INVALID_UTF8)
    ));

    let runtime_error =
        runtime_error_to_proto(reallyme_wallet::runtime::RuntimeErrorReason::LogStoreRejected);
    assert!(matches!(
        runtime_error.detail,
        Some(pb::wallet_error::Detail::Runtime(value))
            if value.as_known()
                == Some(pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LOG_STORE_REJECTED)
    ));

    let conflict = runtime_error_to_proto(
        reallyme_wallet::runtime::RuntimeErrorReason::LifecycleRevisionConflict,
    );
    assert!(matches!(
        conflict.detail,
        Some(pb::wallet_error::Detail::Runtime(value))
            if value.as_known()
                == Some(
                    pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_REVISION_CONFLICT
                )
    ));
}

#[test]
fn unsupported_flow_state_schema_version_preserves_its_typed_reason() {
    let reason = ConvertErrorReason::UnsupportedFlowStateSchemaVersion;

    assert_eq!(
        map_convert_error_reason(reason),
        pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_UNSUPPORTED_SCHEMA
    );
    let error = convert_error_to_proto(reason);
    assert!(matches!(
        error.detail,
        Some(pb::wallet_error::Detail::Convert(value))
            if value.as_known()
                == Some(
                    pb::ConvertErrorReason::CONVERT_ERROR_REASON_UNSUPPORTED_FLOW_STATE_SCHEMA_VERSION
                )
    ));
}

#[test]
fn invalid_flow_state_payload_preserves_its_typed_reason() {
    let reason = ConvertErrorReason::InvalidFlowStatePayload;

    assert_eq!(
        map_convert_error_reason(reason),
        pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT
    );
    let error = convert_error_to_proto(reason);
    assert!(matches!(
        error.detail,
        Some(pb::wallet_error::Detail::Convert(value))
            if value.as_known()
                == Some(pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_FLOW_STATE_PAYLOAD)
    ));
}

#[test]
fn unsupported_record_schema_version_preserves_its_typed_reason() {
    let reason = ConvertErrorReason::UnsupportedSchema;

    assert_eq!(
        map_convert_error_reason(reason),
        pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_UNSUPPORTED_SCHEMA
    );
    let error = convert_error_to_proto(reason);
    assert!(matches!(
        error.detail,
        Some(pb::wallet_error::Detail::Convert(value))
            if value.as_known()
                == Some(pb::ConvertErrorReason::CONVERT_ERROR_REASON_UNSUPPORTED_SCHEMA)
    ));
}

#[test]
fn wallet_reason_decoding_fails_closed_for_unknown_values() {
    assert_eq!(
        error_reason_from_i32(999_999),
        Err(ConvertErrorReason::InvalidEnumValue)
    );
    assert_eq!(
        error_reason_from_enum_value(EnumValue::from(999_999)),
        Err(ConvertErrorReason::InvalidEnumValue)
    );
}

#[test]
fn identity_stack_error_preserves_wallet_domain_and_reason_code() {
    let stack = identity_stack_error_from_reason(
        pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED,
        Some("corr-01"),
    );

    assert_eq!(
        stack.domain.as_known(),
        Some(IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_WALLET)
    );
    assert_eq!(
        stack.reason_code,
        error_reason_code(pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED)
    );
    assert_eq!(stack.correlation_id, "corr-01");
    assert_eq!(
        error_reason_from_identity_stack_error(&stack),
        Ok(pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED)
    );

    let wrong_domain = IdentityStackError {
        domain: IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VP.into(),
        reason_code: error_reason_code(pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED),
        ..IdentityStackError::default()
    };
    assert_eq!(
        error_reason_from_identity_stack_error(&wrong_domain),
        Err(ConvertErrorReason::InvalidEnumValue)
    );
}

#[test]
fn wallet_error_envelope_preserves_stack_and_wallet_detail() {
    let error = consent_error_to_proto(reallyme_wallet::consent::ConsentErrorReason::UserRejected);
    let envelope = wallet_error_envelope_from_error(error, Some("corr-02"));

    assert_eq!(
        envelope
            .stack
            .as_option()
            .map(|stack| stack.domain.as_known()),
        Some(Some(
            IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_WALLET
        ))
    );
    assert_eq!(
        envelope.stack.as_option().map(|stack| stack.reason_code),
        Some(error_reason_code(
            pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED
        ))
    );
    assert_eq!(
        envelope
            .wallet
            .as_option()
            .map(|wallet| wallet.reason.as_known()),
        Some(Some(
            pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED
        ))
    );
}

#[test]
fn wallet_reason_json_encoding_is_stable() -> Result<(), serde_json::Error> {
    let serialized =
        serde_json::to_value(pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED)?;
    assert_eq!(serialized, json!("WALLET_ERROR_REASON_USER_REJECTED"));
    Ok(())
}

#[test]
fn wallet_error_protobuf_encoding_is_stable() -> Result<(), buffa::DecodeError> {
    let error = consent_error_to_proto(reallyme_wallet::consent::ConsentErrorReason::UserRejected);
    let encoded = error.encode_to_vec();
    let decoded = pb::WalletError::decode(&mut encoded.as_slice())?;

    assert_eq!(
        decoded.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED)
    );
    assert!(matches!(
        decoded.detail,
        Some(pb::wallet_error::Detail::Consent(value))
            if value.as_known()
                == Some(pb::ConsentErrorReason::CONSENT_ERROR_REASON_USER_REJECTED)
    ));
    Ok(())
}

#[test]
fn presentation_and_submission_reasons_keep_their_meaning() {
    use reallyme_wallet::flows::FlowErrorReason;

    for (reason, coarse, detail) in [
        (
            FlowErrorReason::PresentationConsentExpired,
            pb::WalletErrorReason::WALLET_ERROR_REASON_CONSENT_REQUIRED,
            pb::FlowErrorReason::FLOW_ERROR_REASON_PRESENTATION_CONSENT_EXPIRED,
        ),
        (
            FlowErrorReason::PresentationRequestMismatch,
            pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT,
            pb::FlowErrorReason::FLOW_ERROR_REASON_PRESENTATION_REQUEST_MISMATCH,
        ),
        (
            FlowErrorReason::CredentialSubmissionUncertain,
            pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
            pb::FlowErrorReason::FLOW_ERROR_REASON_CREDENTIAL_SUBMISSION_UNCERTAIN,
        ),
    ] {
        let error = flow_error_to_proto(reason);
        assert_eq!(error.reason.as_known(), Some(coarse));
        assert!(matches!(
            error.detail,
            Some(pb::wallet_error::Detail::Flow(value)) if value.as_known() == Some(detail)
        ));
    }
}

#[test]
fn copy_claim_reasons_say_whether_a_copy_was_consumed() {
    use reallyme_wallet::runtime::RuntimeErrorReason;

    for (reason, detail) in [
        (
            RuntimeErrorReason::CredentialNotActive,
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CREDENTIAL_NOT_ACTIVE,
        ),
        (
            RuntimeErrorReason::ClaimedCopyDiscarded,
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CLAIMED_COPY_DISCARDED,
        ),
    ] {
        let error = runtime_error_to_proto(reason);
        assert_eq!(
            error.reason.as_known(),
            Some(pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE)
        );
        assert!(matches!(
            error.detail,
            Some(pb::wallet_error::Detail::Runtime(value)) if value.as_known() == Some(detail)
        ));
    }
}

#[cfg(feature = "render")]
#[test]
fn a_missing_render_signer_is_reported_as_unavailable() {
    use reallyme_wallet::map_error_reason::{map_render_detail_reason, map_render_error_reason};
    use reallyme_wallet::render::RenderErrorReason;

    assert_eq!(
        map_render_error_reason(RenderErrorReason::SignerRequired),
        pb::WalletErrorReason::WALLET_ERROR_REASON_BACKEND_UNAVAILABLE
    );
    assert_eq!(
        map_render_detail_reason(RenderErrorReason::SignerRequired),
        pb::RenderErrorReason::RENDER_ERROR_REASON_SIGNER_REQUIRED
    );
    assert_eq!(
        map_render_error_reason(RenderErrorReason::ExpiredDelivery),
        pb::WalletErrorReason::WALLET_ERROR_REASON_DELIVERY_EXPIRED
    );
}

#[test]
fn provider_gaps_and_skewed_records_have_their_own_reasons() {
    use reallyme_wallet::runtime::RuntimeErrorReason;

    for (reason, coarse, detail) in [
        (
            RuntimeErrorReason::ProviderCapabilityUnsupported,
            pb::WalletErrorReason::WALLET_ERROR_REASON_BACKEND_UNAVAILABLE,
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_PROVIDER_CAPABILITY_UNSUPPORTED,
        ),
        (
            RuntimeErrorReason::RecordClockSkew,
            pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID,
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_RECORD_CLOCK_SKEW,
        ),
    ] {
        let error = runtime_error_to_proto(reason);
        assert_eq!(error.reason.as_known(), Some(coarse));
        assert!(matches!(
            error.detail,
            Some(pb::wallet_error::Detail::Runtime(value)) if value.as_known() == Some(detail)
        ));
    }
    let expired =
        consent_error_to_proto(reallyme_wallet::consent::ConsentErrorReason::RequestExpired);
    assert_eq!(
        expired.reason.as_known(),
        Some(pb::WalletErrorReason::WALLET_ERROR_REASON_CONSENT_REQUIRED)
    );
}
