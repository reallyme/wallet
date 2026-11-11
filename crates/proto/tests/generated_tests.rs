// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated wallet protobuf bindings.

#![cfg(feature = "generated")]
#![allow(clippy::unwrap_used)]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1 as crypto_pb;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1 as common_pb;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    wallet_error, ConsentErrorReason, CredentialRecord, EncryptedRecord, EncryptedRecordHeader,
    OpenId4VciIssuanceSnapshot, OpenId4VciIssuanceStage, OpenId4VciIssuerMetadataProfile,
    UnixTimestamp, WalletError, WalletErrorEnvelope, WalletErrorReason, WalletLifecycleEvent,
    WalletLifecycleState,
};

fn sample_credential_record() -> CredentialRecord {
    let timestamp = UnixTimestamp {
        seconds: 1,
        __buffa_unknown_fields: Default::default(),
    };

    CredentialRecord {
        id: "credential-1".to_owned(),
        issuer_id: "issuer-1".to_owned(),
        signed_issuer: "https://issuer.example".to_owned(),
        holder_key_handle_id: "holder-key-1".to_owned(),
        status_reference: Default::default(),
        format: EnumValue::from(openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT),
        status: Default::default(),
        received_at: Some(timestamp.clone()).into(),
        encrypted_payload: Some(EncryptedRecord {
            header: Some(EncryptedRecordHeader {
                schema_version: 1,
                key_handle_id: "key-1".to_owned(),
                encryption_algorithm: EnumValue::from(
                    crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM_SIV,
                ),
                created_at: Some(timestamp).into(),
                __buffa_unknown_fields: Default::default(),
            })
            .into(),
            nonce: vec![1; 12],
            aad: vec![4, 5, 6],
            ciphertext: vec![7; 16],
            __buffa_unknown_fields: Default::default(),
        })
        .into(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn wallet_error_envelope() -> WalletErrorEnvelope {
    let reason_code =
        u32::try_from(WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED.to_i32()).unwrap();
    let wallet = WalletError {
        reason: EnumValue::from(WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED),
        detail: Some(wallet_error::Detail::Consent(EnumValue::from(
            ConsentErrorReason::CONSENT_ERROR_REASON_USER_REJECTED,
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    WalletErrorEnvelope {
        stack: MessageField::some(common_pb::IdentityStackError {
            domain: EnumValue::from(
                common_pb::IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_WALLET,
            ),
            reason_code,
            correlation_id: "correlation-1".to_owned(),
            __buffa_unknown_fields: Default::default(),
        }),
        wallet: MessageField::some(wallet),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn credential_format_enum_value_is_stable() {
    assert_eq!(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT.to_i32(),
        2
    );
}

#[test]
fn wallet_error_reason_enum_values_are_stable() {
    assert_eq!(
        WalletErrorReason::WALLET_ERROR_REASON_UNSUPPORTED_FORMAT.to_i32(),
        1
    );
    assert_eq!(
        WalletErrorReason::WALLET_ERROR_REASON_KEYSTORE_UNAVAILABLE.to_i32(),
        4
    );
    assert_eq!(
        WalletErrorReason::WALLET_ERROR_REASON_BATCH_POOL_EXHAUSTED.to_i32(),
        100
    );
    assert_eq!(
        WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID.to_i32(),
        503
    );
    assert_eq!(
        WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_STORE_UNAVAILABLE.to_i32(),
        508
    );
}

#[test]
fn wallet_error_round_trips_with_detail_oneof() {
    let error = WalletError {
        reason: EnumValue::from(WalletErrorReason::WALLET_ERROR_REASON_INVALID_SATISFACTION_PLAN),
        detail: Some(wallet_error::Detail::Consent(EnumValue::from(
            ConsentErrorReason::CONSENT_ERROR_REASON_DERIVATION_IDENTIFIER_MISSING,
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = error.encode_to_vec();
    let decoded = WalletError::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(
        decoded.reason.as_known(),
        Some(WalletErrorReason::WALLET_ERROR_REASON_INVALID_SATISFACTION_PLAN)
    );
    assert!(matches!(
        decoded.detail,
        Some(wallet_error::Detail::Consent(value))
            if value.as_known()
                == Some(ConsentErrorReason::CONSENT_ERROR_REASON_DERIVATION_IDENTIFIER_MISSING)
    ));
}

#[test]
fn wallet_error_envelope_round_trips_with_identity_common_stack_error() {
    let envelope = wallet_error_envelope();

    let encoded = envelope.encode_to_vec();
    let decoded = WalletErrorEnvelope::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(
        decoded
            .stack
            .as_option()
            .map(|stack| stack.domain.as_known()),
        Some(Some(
            common_pb::IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_WALLET
        ))
    );
    assert_eq!(
        decoded
            .wallet
            .as_option()
            .map(|wallet| wallet.reason.as_known()),
        Some(Some(WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED))
    );
}

#[test]
fn openid4vci_issuance_stage_enum_value_is_stable() {
    assert_eq!(
        OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_DEFERRED.to_i32(),
        5
    );
}

#[test]
fn wallet_lifecycle_state_enum_value_is_stable() {
    assert_eq!(
        WalletLifecycleState::WALLET_LIFECYCLE_STATE_ACTIVE.to_i32(),
        3
    );
}

#[test]
fn wallet_lifecycle_event_enum_value_is_stable() {
    assert_eq!(
        WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_DELETION.to_i32(),
        12
    );
}

#[test]
fn credential_record_round_trips_with_buffa() {
    let record = sample_credential_record();

    let encoded = record.encode_to_vec();
    let decoded = CredentialRecord::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(decoded, record);
}

#[test]
fn openid4vci_issuance_snapshot_round_trips_with_buffa() {
    let mut offer = openid4vci_pb::CredentialOffer::default();
    offer.credential_issuer = "https://issuer.example".to_owned();
    offer.credential_configuration_ids = vec!["pid".to_owned()];

    let mut selector = openid4vci_pb::CredentialSelector::default();
    selector.selector = Some(
        openid4vci_pb::credential_selector::Selector::CredentialConfigurationId("pid".to_owned()),
    );
    let request = openid4vci_pb::CredentialRequest {
        selector: Some(selector).into(),
        proofs: Default::default(),
        credential_response_encryption: Default::default(),
        reallyme_zk_v1_issuance: Default::default(),
        __buffa_unknown_fields: Default::default(),
    };

    let mut deferred = openid4vci_pb::DeferredCredentialResponse::default();
    deferred.transaction_id = "txn-1".to_owned();
    deferred.interval = 30;
    let response = openid4vci_pb::CredentialResponse {
        response: Some(openid4vci_pb::credential_response::Response::Deferred(
            Box::new(deferred),
        )),
        __buffa_unknown_fields: Default::default(),
    };

    let snapshot = OpenId4VciIssuanceSnapshot {
        issuer_nonce_binding: Default::default(),
        stage: EnumValue::from(OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_DEFERRED),
        credential_offer: Some(offer).into(),
        credential_request: Some(request).into(),
        credential_response: Some(response).into(),
        deferred_transaction_id: "txn-1".to_owned(),
        deferred_interval_seconds: 30,
        notification_id: String::new(),
        credential_record_id: String::new(),
        credential_record_ids: Vec::new(),
        credential_binding_key_handle_ids: Vec::new(),
        access_token_binding_handle: String::new(),
        notification_endpoint: String::new(),
        wallet_unit_attestation: Default::default(),
        credential_reuse_policy: Default::default(),
        issuer_metadata_profile: EnumValue::from(
            OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_OPENID4VCI,
        ),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = snapshot.encode_to_vec();
    let decoded = OpenId4VciIssuanceSnapshot::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(decoded, snapshot);
}
