// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for SDK-facing protobuf byte codecs.

use buffa::{EnumValue, Message, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_wallet_attestation as attestation;
use reallyme_wallet_keystore as keystore;
use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::decode::{
    decode_consent_request, decode_credential_record, decode_credential_status_evidence,
    decode_flow_snapshot, decode_key_attestation_evidence, decode_qtsp_decision_record,
    decode_transaction_log_entry, decode_wallet_lifecycle_evidence_record,
    decode_wallet_lifecycle_record, decode_wallet_unit_attestation,
};
use reallyme_wallet_proto_codec::encode::{
    encode_consent_request, encode_credential_record, encode_credential_status_evidence,
    encode_flow_snapshot, encode_key_attestation_evidence, encode_qtsp_decision_record,
    encode_transaction_log_entry, encode_wallet_lifecycle_evidence_record,
    encode_wallet_lifecycle_record, encode_wallet_unit_attestation,
};
use reallyme_wallet_proto_codec::{ProtoError, ProtoErrorReason};
use reallyme_wallet_types as wallet;
use thiserror::Error;

#[derive(Debug, Error)]
enum CodecTestError {
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("proto")]
    Proto(#[from] ProtoError),
    #[error("lifecycle")]
    Lifecycle(#[from] lifecycle::LifecycleError),
    #[error("attestation")]
    Attestation(#[from] attestation::AttestationError),
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
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

fn timestamp() -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    timestamp_at(1)
}

fn timestamp_at(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
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

fn credential_record() -> Result<wallet::CredentialRecord, wallet::WalletTypesError> {
    Ok(wallet::CredentialRecord::new(
        id("credential-1")?,
        id("issuer-1")?,
        None,
        None,
        None,
        wallet::CredentialFormat::SdJwtVc,
        wallet::CredentialStatus::Active,
        timestamp()?,
        encrypted_record()?,
    ))
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

fn wallet_unit_attestation() -> Result<attestation::WalletUnitAttestation, CodecTestError> {
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
                kind: wallet::ConsentActionKind::QualifiedSeal,
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

fn credential_status_evidence() -> Result<wallet::CredentialStatusEvidence, wallet::WalletTypesError>
{
    Ok(wallet::CredentialStatusEvidence {
        credential_id: id("credential-1")?,
        observed_status: wallet::CredentialStatus::Suspended,
        method: wallet::CredentialStatusEvidenceMethod::TokenStatusList,
        source_issuer: wallet::SignedCredentialIssuer::new("issuer-1".to_owned())?,
        source_list_id: [9; 32],
        status_index: 0,
        source_issued_at: timestamp_at(9)?,
        checked_at: timestamp_at(10)?,
        valid_until: timestamp_at(20)?,
    })
}

fn transaction_log_entry() -> Result<wallet::TransactionLogEntry, wallet::WalletTypesError> {
    Ok(wallet::TransactionLogEntry {
        id: id("log-1")?,
        purpose: wallet::TransactionPurpose::Presentation,
        relying_party_id: Some(id("rp-1")?),
        disclosed_attributes: vec![wallet::DisclosedAttribute {
            name: wallet::AttributeName::new("age_over_18".to_owned())?,
        }],
        occurred_at: timestamp()?,
        sequence: 1,
        previous_entry_hash: [0; 32],
        entry_hash: [1; 32],
    })
}

fn qtsp_decision_record() -> Result<wallet::QtspDecisionRecord, wallet::WalletTypesError> {
    Ok(wallet::QtspDecisionRecord {
        kind: wallet::QtspDecisionKind::QualifiedElectronicSeal,
        outcome: wallet::DecisionOutcome::Accept,
        input_sha256_b64url: "input-digest".to_owned(),
        decided_at: timestamp()?,
    })
}

fn wallet_lifecycle_record() -> Result<lifecycle::WalletLifecycleRecord, CodecTestError> {
    Ok(lifecycle::restore_wallet_lifecycle(
        id("wallet-unit-1")?,
        lifecycle::WalletLifecycleState::Active,
        timestamp_at(30)?,
        Some(lifecycle::WalletLifecycleEvent::CompleteMigration),
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
        kind: lifecycle::WalletLifecycleEvidenceKind::Migration,
        event: lifecycle::WalletLifecycleEvent::CompleteMigration,
        occurred_at: timestamp_at(30)?,
        authority_id: id("wallet-provider-1")?,
        evidence_ref: id("migration-evidence-1")?,
        evidence_digest: vec![1, 2, 3, 4],
    })
}

#[test]
fn credential_record_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let record = credential_record()?;

    let bytes = encode_credential_record(&record)?;
    let decoded = decode_credential_record(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}

#[test]
fn credential_status_evidence_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let evidence = credential_status_evidence()?;

    let bytes = encode_credential_status_evidence(&evidence)?;
    let decoded = decode_credential_status_evidence(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == evidence));
    Ok(())
}

#[test]
fn key_attestation_evidence_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let evidence = key_attestation_evidence()?;

    let bytes = encode_key_attestation_evidence(&evidence)?;
    let decoded = decode_key_attestation_evidence(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == evidence));
    Ok(())
}

#[test]
fn wallet_unit_attestation_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let attestation = wallet_unit_attestation()?;

    let bytes = encode_wallet_unit_attestation(&attestation)?;
    let decoded = decode_wallet_unit_attestation(&bytes);

    assert!(
        matches!(decoded, Ok(decoded) if decoded.id() == attestation.id()
        && decoded.evidence() == attestation.evidence()
        && decoded.valid_until() == attestation.valid_until()
        && decoded.signed_provider_artifact() == attestation.signed_provider_artifact())
    );
    Ok(())
}

#[test]
fn consent_request_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let request = consent_request()?;

    let bytes = encode_consent_request(&request)?;
    let decoded = decode_consent_request(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == request));
    Ok(())
}

#[test]
fn flow_snapshot_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let snapshot = wallet::FlowSnapshot {
        id: id("flow-1")?,
        kind: wallet::FlowKind::Issuance,
        state: issuance_flow_state(),
        state_schema_version: wallet::FlowStateSchemaVersion::V1,
        updated_at: timestamp()?,
    };

    let bytes = encode_flow_snapshot(&snapshot)?;
    let decoded = decode_flow_snapshot(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == snapshot));
    Ok(())
}

#[test]
fn wallet_lifecycle_record_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let record = wallet_lifecycle_record()?;

    let bytes = encode_wallet_lifecycle_record(&record)?;
    let decoded = decode_wallet_lifecycle_record(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}

#[test]
fn wallet_lifecycle_evidence_record_round_trips_through_proto_bytes() -> Result<(), CodecTestError>
{
    let record = wallet_lifecycle_evidence_record()?;

    let bytes = encode_wallet_lifecycle_evidence_record(&record)?;
    let decoded = decode_wallet_lifecycle_evidence_record(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}

#[test]
fn transaction_log_entry_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let entry = transaction_log_entry()?;

    let bytes = encode_transaction_log_entry(&entry)?;
    let decoded = decode_transaction_log_entry(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == entry));
    Ok(())
}

#[test]
fn qtsp_decision_record_round_trips_through_proto_bytes() -> Result<(), CodecTestError> {
    let record = qtsp_decision_record()?;

    let bytes = encode_qtsp_decision_record(&record)?;
    let decoded = decode_qtsp_decision_record(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}

#[test]
fn malformed_proto_bytes_return_stable_reason() {
    let result = decode_credential_record(&[0x0f]);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::MalformedWire
    ));
}

#[test]
fn credential_record_prefix_truncations_return_stable_typed_errors() -> Result<(), CodecTestError> {
    let bytes = encode_credential_record(&credential_record()?)?;

    for prefix_len in 0..bytes.len() {
        assert_stable_proto_failure(decode_credential_record(&bytes[..prefix_len]));
    }

    Ok(())
}

#[test]
fn malformed_proto_corpus_returns_stable_typed_errors() {
    const MALFORMED_CORPUS: &[&[u8]] = &[
        &[
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        ],
        &[0x0c],
        &[0x12, 0xff, 0xff, 0xff, 0xff, 0x0f],
        &[0xff],
        &[0x0a, 0x02, 0xff, 0xff],
    ];

    for bytes in MALFORMED_CORPUS {
        assert_stable_proto_failure(decode_credential_record(bytes));
    }
}

#[test]
fn structurally_valid_proto_with_missing_required_wallet_fields_is_invalid_dto() {
    let result = decode_credential_record(&[]);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::InvalidDto
    ));
}

fn assert_stable_proto_failure<T>(result: Result<T, ProtoError>) {
    assert!(matches!(result, Err(error) if is_stable_proto_reason(error.reason)));
}

fn is_stable_proto_reason(reason: ProtoErrorReason) -> bool {
    matches!(
        reason,
        ProtoErrorReason::UnsupportedSchema
            | ProtoErrorReason::TruncatedInput
            | ProtoErrorReason::MalformedWire
            | ProtoErrorReason::MessageTooLarge
            | ProtoErrorReason::RecursionLimitExceeded
            | ProtoErrorReason::UnknownFieldLimitExceeded
            | ProtoErrorReason::InvalidUtf8
            | ProtoErrorReason::InvalidDto
    )
}
