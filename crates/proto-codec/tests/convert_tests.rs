// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for wallet protobuf conversion boundaries.

use buffa::{EnumValue, Message, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1 as crypto_pb;
use reallyme_wallet_attestation as attestation;
use reallyme_wallet_keystore as keystore;
use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    consent_request_from_proto, consent_request_to_proto, credential_format_from_proto,
    credential_format_to_proto, credential_record_from_proto, credential_reuse_policy_from_proto,
    credential_reuse_policy_to_proto, credential_status_evidence_from_proto,
    credential_status_evidence_to_proto, encrypted_record_header_from_proto,
    encrypted_record_header_to_proto, flow_snapshot_from_proto, flow_snapshot_to_proto,
    issuer_metadata_profile_from_proto, issuer_metadata_profile_to_proto,
    key_attestation_evidence_from_proto, key_attestation_evidence_to_proto,
    presentation_copy_from_proto, presentation_copy_to_proto,
    wallet_lifecycle_evidence_record_from_proto, wallet_lifecycle_evidence_record_to_proto,
    wallet_lifecycle_record_from_proto, wallet_lifecycle_record_to_proto,
    wallet_unit_attestation_from_proto, wallet_unit_attestation_to_proto, ConvertError,
    ConvertErrorReason,
};
use reallyme_wallet_types as wallet;
use thiserror::Error;

#[derive(Debug, Error)]
enum ConvertFixtureError {
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("lifecycle")]
    Lifecycle(#[from] lifecycle::LifecycleError),
    #[error("attestation")]
    Attestation(#[from] attestation::AttestationError),
    #[error("conversion")]
    Conversion(#[from] ConvertError),
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp() -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    timestamp_at(1)
}

fn timestamp_at(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
}

fn issuance_flow_state() -> Vec<u8> {
    let mut state = pb::OpenId4VciIssuanceSnapshot::default();
    state.stage =
        EnumValue::from(pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_OFFER_RECEIVED);
    let offer = openid4vci_pb::CredentialOffer {
        credential_issuer: "https://issuer.example".to_owned(),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: MessageField::none(),
        __buffa_unknown_fields: Default::default(),
    };
    state.credential_offer = MessageField::some(offer);
    state.encode_to_vec()
}

fn encrypted_record() -> Result<wallet::EncryptedRecord, wallet::WalletTypesError> {
    Ok(wallet::EncryptedRecord {
        header: wallet::EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: wallet::KeyHandleId::new("key-1".to_owned())?,
            algorithm: wallet::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp()?,
        },
        nonce: vec![1; 12],
        aad: vec![4, 5, 6],
        ciphertext: vec![7; 16],
    })
}

#[test]
fn prepared_copy_selector_requires_exact_nonzero_digest() -> Result<(), ConvertFixtureError> {
    let copy = wallet::OnceOnlyPresentationCopy {
        id: id("copy-1")?,
        credential_id: id("credential-1")?,
        prepared_claim_selector_digest: Some([7; 32]),
        state: wallet::BatchCopyState::Available,
        encrypted_payload: encrypted_record()?,
    };
    let mut wire = presentation_copy_to_proto(&copy);
    let restored = presentation_copy_from_proto(&wire)?;
    assert_eq!(restored.prepared_claim_selector_digest, Some([7; 32]));

    wire.prepared_claim_selector_digest = vec![7; 31];
    assert_eq!(
        presentation_copy_from_proto(&wire)
            .err()
            .map(|error| error.reason),
        Some(ConvertErrorReason::InvalidZkArtifact)
    );
    wire.prepared_claim_selector_digest = vec![0; 32];
    assert_eq!(
        presentation_copy_from_proto(&wire)
            .err()
            .map(|error| error.reason),
        Some(ConvertErrorReason::InvalidZkArtifact)
    );
    Ok(())
}

fn proto_encrypted_record_header(algorithm: crypto_pb::AeadAlgorithm) -> pb::EncryptedRecordHeader {
    pb::EncryptedRecordHeader {
        schema_version: 1,
        key_handle_id: "key-1".to_owned(),
        created_at: MessageField::some(pb::UnixTimestamp {
            seconds: 1,
            ..pb::UnixTimestamp::default()
        }),
        encryption_algorithm: EnumValue::from(algorithm),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn encrypted_record_header_emits_only_typed_crypto_algorithm(
) -> Result<(), wallet::WalletTypesError> {
    let record = encrypted_record()?;

    let proto = encrypted_record_header_to_proto(&record.header);

    assert!(
        proto.encryption_algorithm
            == EnumValue::from(crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM_SIV)
    );
    Ok(())
}

#[test]
fn encrypted_record_header_rejects_unapproved_crypto_algorithm() {
    let proto = proto_encrypted_record_header(crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM);

    let decoded = encrypted_record_header_from_proto(&proto);

    assert!(matches!(
        decoded,
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));
}

#[test]
fn encrypted_record_header_rejects_missing_algorithm_and_schema_version() {
    let missing_algorithm =
        proto_encrypted_record_header(crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_UNSPECIFIED);
    let mut missing_schema =
        proto_encrypted_record_header(crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM_SIV);
    missing_schema.schema_version = 0;

    let algorithm_result = encrypted_record_header_from_proto(&missing_algorithm);
    let schema_result = encrypted_record_header_from_proto(&missing_schema);

    assert!(matches!(
        algorithm_result,
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));
    assert!(matches!(
        schema_result,
        Err(error) if error.reason == ConvertErrorReason::UnsupportedSchema
    ));
}

fn key_attestation_evidence() -> Result<keystore::KeyAttestationEvidence, wallet::WalletTypesError>
{
    Ok(keystore::KeyAttestationEvidence {
        key_handle_id: wallet::KeyHandleId::new("key-1".to_owned())?,
        evidence: vec![1, 2, 3],
        issued_at: timestamp_at(10)?,
        challenge: [7; 32],
    })
}

struct AcceptAttestationVerifier;

impl attestation::WalletUnitAttestationVerifier for AcceptAttestationVerifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &attestation::UnverifiedWalletUnitAttestation,
        _now: wallet::UnixTimestamp,
    ) -> attestation::AttestationResult<attestation::VerifiedWalletKeyThumbprint> {
        attestation::VerifiedWalletKeyThumbprint::new([1; 32])
    }
}

fn wallet_unit_attestation() -> Result<attestation::WalletUnitAttestation, ConvertFixtureError> {
    let unverified = attestation::UnverifiedWalletUnitAttestation::new(
        id("wua-1")?,
        key_attestation_evidence()?,
        timestamp_at(20)?,
        vec![9, 8, 7],
    )?;
    Ok(attestation::verify_wallet_unit_attestation(
        unverified,
        &AcceptAttestationVerifier,
        timestamp_at(10)?,
    )?)
}

fn consent_request() -> Result<wallet::ConsentRequest, wallet::WalletTypesError> {
    Ok(wallet::ConsentRequest {
        relying_party_id: id("rp-1")?,
        requested_scope: wallet::ConsentScope {
            attributes: vec![wallet::AttributeName::new("age_over_18".to_owned())?],
        },
        policy_decision: wallet::DisclosurePolicyDecision::Allowed,
        actions: vec![
            wallet::ConsentAction {
                kind: wallet::ConsentActionKind::Derive,
                scope: wallet::ConsentScope {
                    attributes: vec![wallet::AttributeName::new("age_over_18".to_owned())?],
                },
                derivation_id: Some(id("rm-zk-vc-base-v1")?),
                derivation_inputs: vec![wallet::ConsentDerivationInput {
                    attribute: wallet::AttributeName::new("age_over_18".to_owned())?,
                    mode: wallet::ConsentDerivationMode::Gte,
                    operand: wallet::ConsentPredicateOperand::Threshold(18),
                }],
            },
            wallet::ConsentAction {
                kind: wallet::ConsentActionKind::QualifiedSignature,
                scope: wallet::ConsentScope {
                    attributes: vec![wallet::AttributeName::new("age_over_18".to_owned())?],
                },
                derivation_id: None,
                derivation_inputs: Vec::new(),
            },
        ],
        request_nonce: id("request-nonce-1")?,
        request_digest: [8; wallet::CONSENT_REQUEST_DIGEST_BYTES],
        created_at: timestamp_at(10)?,
    })
}

fn wallet_lifecycle_record() -> Result<lifecycle::WalletLifecycleRecord, ConvertFixtureError> {
    Ok(lifecycle::restore_wallet_lifecycle(
        id("wallet-unit-1")?,
        lifecycle::WalletLifecycleState::Active,
        timestamp_at(30)?,
        Some(lifecycle::WalletLifecycleEvent::CompleteProvisioning),
        None,
        None,
        Some(wallet_lifecycle_evidence_record()?),
    )?)
}

fn wallet_lifecycle_evidence_record(
) -> Result<lifecycle::WalletLifecycleEvidenceRecord, wallet::WalletTypesError> {
    Ok(lifecycle::WalletLifecycleEvidenceRecord {
        id: id("lifecycle-evidence-1")?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind: lifecycle::WalletLifecycleEvidenceKind::Backup,
        event: lifecycle::WalletLifecycleEvent::CompleteProvisioning,
        occurred_at: timestamp_at(30)?,
        authority_id: id("wallet-provider-1")?,
        evidence_ref: id("backup-evidence-1")?,
        evidence_digest: vec![1, 3, 3, 7],
    })
}

#[test]
fn key_attestation_evidence_round_trips_through_proto_conversion(
) -> Result<(), wallet::WalletTypesError> {
    let evidence = key_attestation_evidence()?;

    let proto = key_attestation_evidence_to_proto(&evidence);
    let decoded = key_attestation_evidence_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded == evidence));
    Ok(())
}

#[test]
fn wallet_unit_attestation_round_trips_through_proto_conversion() -> Result<(), ConvertFixtureError>
{
    let attestation = wallet_unit_attestation()?;

    let proto = wallet_unit_attestation_to_proto(&attestation);
    let decoded = wallet_unit_attestation_from_proto(&proto);

    assert!(
        matches!(decoded, Ok(decoded) if decoded.id() == attestation.id()
        && decoded.evidence() == attestation.evidence()
        && decoded.valid_until() == attestation.valid_until()
        && decoded.signed_provider_artifact() == attestation.signed_provider_artifact())
    );
    Ok(())
}

#[test]
fn consent_request_round_trips_through_proto_conversion() -> Result<(), wallet::WalletTypesError> {
    let request = consent_request()?;

    let proto = consent_request_to_proto(&request);
    let decoded = consent_request_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded == request));
    Ok(())
}

#[test]
fn consent_conversion_rejects_hidden_predicate_and_oversized_operand(
) -> Result<(), wallet::WalletTypesError> {
    let request = consent_request()?;
    let mut proto = consent_request_to_proto(&request);
    let input = &mut proto.actions[0].derivation_inputs[0];
    input.mode = EnumValue::from(pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_HIDDEN);
    let result = consent_request_from_proto(&proto);
    assert!(
        matches!(result, Err(error) if error.reason == ConvertErrorReason::InvalidConsentAction)
    );

    let mut proto = consent_request_to_proto(&request);
    let input = &mut proto.actions[0].derivation_inputs[0];
    input.operand_kind =
        EnumValue::from(pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_VALUE);
    input.value = vec![0x41; 4_097];
    let result = consent_request_from_proto(&proto);
    assert!(
        matches!(result, Err(error) if error.reason == ConvertErrorReason::InvalidConsentAction)
    );
    Ok(())
}

#[test]
fn status_evidence_round_trips_through_proto_conversion() -> Result<(), wallet::WalletTypesError> {
    let evidence = wallet::CredentialStatusEvidence {
        credential_id: id("credential-1")?,
        observed_status: wallet::CredentialStatus::Suspended,
        method: wallet::CredentialStatusEvidenceMethod::TokenStatusList,
        source_issuer: wallet::SignedCredentialIssuer::new("issuer-1".to_owned())?,
        source_list_id: [9; 32],
        status_index: 0,
        source_issued_at: timestamp_at(9)?,
        checked_at: timestamp_at(10)?,
        valid_until: timestamp_at(20)?,
    };

    let proto = credential_status_evidence_to_proto(&evidence);
    let decoded = credential_status_evidence_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded == evidence));
    Ok(())
}

#[test]
fn flow_snapshot_round_trips_through_proto_conversion() -> Result<(), wallet::WalletTypesError> {
    let snapshot = wallet::FlowSnapshot {
        id: id("flow-1")?,
        kind: wallet::FlowKind::Issuance,
        state: issuance_flow_state(),
        state_schema_version: wallet::FlowStateSchemaVersion::V1,
        updated_at: timestamp()?,
    };

    let proto = flow_snapshot_to_proto(&snapshot);
    let decoded = flow_snapshot_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded == snapshot));
    Ok(())
}

#[test]
fn credential_reuse_policy_round_trips_with_thresholds() -> Result<(), ConvertFixtureError> {
    let policy = wallet::CredentialReusePolicySelection::new(
        id("pid")?,
        wallet::CredentialReuseMethod::OnceOnly,
        Some(5),
        Some(1),
        None,
    )?;

    let wire = credential_reuse_policy_to_proto(&policy);
    let decoded = credential_reuse_policy_from_proto(&wire)?;

    assert_eq!(decoded, policy);
    Ok(())
}

#[test]
fn credential_reuse_policy_rejects_missing_method_and_invalid_thresholds() {
    let mut wire = pb::OpenId4VciCredentialReusePolicySelection::default();
    wire.credential_configuration_id = "pid".to_owned();
    assert!(matches!(
        credential_reuse_policy_from_proto(&wire),
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));

    wire.method = EnumValue::from(
        pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_ONCE_ONLY,
    );
    wire.batch_size = Some(2);
    wire.reissue_trigger_unused = Some(2);
    assert!(matches!(
        credential_reuse_policy_from_proto(&wire),
        Err(error) if error.reason == ConvertErrorReason::InvalidCredentialReusePolicy
    ));
}

#[test]
fn issuer_metadata_profile_round_trips_without_stringly_typed_policy(
) -> Result<(), ConvertFixtureError> {
    for profile in [
        wallet::OpenId4VciIssuerMetadataProfile::OpenId4Vci,
        wallet::OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3,
        wallet::OpenId4VciIssuerMetadataProfile::EuEtsiTs119472Part3,
    ] {
        let encoded = issuer_metadata_profile_to_proto(profile);
        assert_eq!(issuer_metadata_profile_from_proto(encoded)?, profile);
    }
    assert!(matches!(
        issuer_metadata_profile_from_proto(
            pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_UNSPECIFIED
        ),
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));
    Ok(())
}

#[test]
fn wallet_lifecycle_record_round_trips_through_proto_conversion() -> Result<(), ConvertFixtureError>
{
    let record = wallet_lifecycle_record()?;

    let proto = wallet_lifecycle_record_to_proto(&record);
    let decoded = wallet_lifecycle_record_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}

#[test]
fn wallet_lifecycle_evidence_record_round_trips_through_proto_conversion(
) -> Result<(), wallet::WalletTypesError> {
    let record = wallet_lifecycle_evidence_record()?;

    let proto = wallet_lifecycle_evidence_record_to_proto(&record);
    let decoded = wallet_lifecycle_evidence_record_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}

#[test]
fn jwt_vc_json_ld_format_is_rejected_until_supported() {
    let format = credential_format_from_proto(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_JWT_VC_JSON_LD,
    );

    assert!(matches!(
        format,
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));
}

#[test]
fn reallyme_zk_v1_format_round_trips() {
    let format = credential_format_from_proto(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_REALLYME_ZK_V1,
    );

    assert!(matches!(format, Ok(wallet::CredentialFormat::ReallyMeZkV1)));
    assert_eq!(
        credential_format_to_proto(wallet::CredentialFormat::ReallyMeZkV1),
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_REALLYME_ZK_V1
    );
}

#[test]
fn rejects_unspecified_credential_format() {
    let proto = pb::CredentialRecord {
        id: "credential-1".to_owned(),
        issuer_id: "issuer-1".to_owned(),
        signed_issuer: String::new(),
        holder_key_handle_id: String::new(),
        status_reference: MessageField::none(),
        format: EnumValue::from(openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_UNSPECIFIED),
        status: EnumValue::from(pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_ACTIVE),
        received_at: MessageField::some(pb::UnixTimestamp {
            seconds: 1,
            ..pb::UnixTimestamp::default()
        }),
        encrypted_payload: MessageField::some(pb::EncryptedRecord {
            header: MessageField::some(pb::EncryptedRecordHeader {
                schema_version: 1,
                key_handle_id: "key-1".to_owned(),
                encryption_algorithm: EnumValue::default(),
                created_at: MessageField::some(pb::UnixTimestamp {
                    seconds: 1,
                    ..pb::UnixTimestamp::default()
                }),
                __buffa_unknown_fields: Default::default(),
            }),
            nonce: vec![1; 12],
            aad: vec![2],
            ciphertext: vec![3; 16],
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    };

    let result = credential_record_from_proto(&proto);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));
}

#[test]
fn rejects_unspecified_status_evidence_method() {
    let proto = pb::CredentialStatusEvidence {
        credential_id: "credential-1".to_owned(),
        observed_status: EnumValue::from(
            pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_ACTIVE,
        ),
        method: EnumValue::from(
            pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_UNSPECIFIED,
        ),
        source_issuer: "issuer-1".to_owned(),
        source_list_id: vec![9; 32],
        status_index: 0,
        source_issued_at: MessageField::some(pb::UnixTimestamp {
            seconds: 1,
            ..pb::UnixTimestamp::default()
        }),
        checked_at: MessageField::some(pb::UnixTimestamp {
            seconds: 1,
            ..pb::UnixTimestamp::default()
        }),
        valid_until: MessageField::some(pb::UnixTimestamp {
            seconds: 2,
            ..pb::UnixTimestamp::default()
        }),
        __buffa_unknown_fields: Default::default(),
    };

    let result = credential_status_evidence_from_proto(&proto);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));
}

#[test]
fn rejects_unspecified_flow_kind() {
    let proto = pb::FlowSnapshot {
        id: "flow-1".to_owned(),
        kind: EnumValue::from(pb::FlowKind::FLOW_KIND_UNSPECIFIED),
        state: vec![1],
        state_schema_version: 1,
        updated_at: MessageField::some(pb::UnixTimestamp {
            seconds: 1,
            ..pb::UnixTimestamp::default()
        }),
        __buffa_unknown_fields: Default::default(),
    };

    let result = flow_snapshot_from_proto(&proto);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));
}

#[test]
fn rejects_missing_and_unknown_flow_state_schema_versions() {
    for state_schema_version in [0, 2, u32::MAX] {
        let proto = pb::FlowSnapshot {
            id: "flow-1".to_owned(),
            kind: EnumValue::from(pb::FlowKind::FLOW_KIND_ISSUANCE),
            state: vec![1],
            updated_at: MessageField::some(pb::UnixTimestamp {
                seconds: 1,
                ..pb::UnixTimestamp::default()
            }),
            state_schema_version,
            __buffa_unknown_fields: Default::default(),
        };

        let result = flow_snapshot_from_proto(&proto);

        assert!(matches!(
            result,
            Err(error)
                if error.reason == ConvertErrorReason::UnsupportedFlowStateSchemaVersion
        ));
    }
}

#[test]
fn rejects_malformed_empty_and_kind_mismatched_flow_state_payloads() {
    for (kind, state) in [
        (pb::FlowKind::FLOW_KIND_ISSUANCE, vec![0x0f]),
        (pb::FlowKind::FLOW_KIND_ISSUANCE, Vec::new()),
        (pb::FlowKind::FLOW_KIND_PRESENTATION, issuance_flow_state()),
    ] {
        let proto = pb::FlowSnapshot {
            id: "flow-1".to_owned(),
            kind: EnumValue::from(kind),
            state,
            updated_at: MessageField::some(pb::UnixTimestamp {
                seconds: 1,
                ..pb::UnixTimestamp::default()
            }),
            state_schema_version: 1,
            __buffa_unknown_fields: Default::default(),
        };

        let result = flow_snapshot_from_proto(&proto);

        assert!(matches!(
            result,
            Err(error) if error.reason == ConvertErrorReason::InvalidFlowStatePayload
        ));
    }
}

#[test]
fn rejects_unspecified_wallet_lifecycle_state() {
    let proto = pb::WalletLifecycleRecord {
        wallet_instance_id: "wallet-unit-1".to_owned(),
        state: EnumValue::from(pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_UNSPECIFIED),
        updated_at: MessageField::some(pb::UnixTimestamp {
            seconds: 1,
            ..pb::UnixTimestamp::default()
        }),
        last_event: EnumValue::default(),
        resume_state: EnumValue::default(),
        failed_from: EnumValue::default(),
        last_evidence: MessageField::none(),
        __buffa_unknown_fields: Default::default(),
    };

    let result = wallet_lifecycle_record_from_proto(&proto);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue
    ));
}

#[test]
fn rejects_wallet_lifecycle_evidence_kind_event_mismatch() -> Result<(), wallet::WalletTypesError> {
    let mut proto = wallet_lifecycle_evidence_record_to_proto(&wallet_lifecycle_evidence_record()?);
    proto.kind =
        EnumValue::from(pb::WalletLifecycleEvidenceKind::WALLET_LIFECYCLE_EVIDENCE_KIND_DELETION);
    proto.event =
        EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_RECOVERY);

    let result = wallet_lifecycle_evidence_record_from_proto(&proto);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConvertErrorReason::InvalidLifecycleEvidence
    ));
    Ok(())
}
