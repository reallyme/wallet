// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Atomic OpenID4VCI issuance commit invariants.

use buffa::{EnumValue, Message, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    build_openid4vci_issuance_commit, credential_record_from_proto, flow_snapshot_from_proto,
    issuance_commit_from_proto, issuance_commit_to_proto, ConvertError, ConvertErrorReason,
};
use reallyme_wallet_types as wallet;
use thiserror::Error;

#[derive(Debug, Error)]
enum TestError {
    #[error("wallet type test fixture failed")]
    Wallet(#[from] wallet::WalletTypesError),
    #[error("wallet conversion test fixture failed")]
    Convert(#[from] ConvertError),
}

fn timestamp() -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(1_700_000_000)
}

fn identifier(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn credential_record(id: &str) -> Result<wallet::CredentialRecord, wallet::WalletTypesError> {
    Ok(wallet::CredentialRecord::new(
        identifier(id)?,
        identifier("https://issuer.example")?,
        None,
        Some(wallet::KeyHandleId::new(binding_key_handle(id))?),
        None,
        wallet::CredentialFormat::SdJwtVc,
        wallet::CredentialStatus::Active,
        timestamp()?,
        wallet::EncryptedRecord {
            header: wallet::EncryptedRecordHeader {
                schema_version: 1,
                key_handle_id: wallet::KeyHandleId::new("storage-key".to_owned())?,
                algorithm: wallet::StorageEncryptionAlgorithm::Aes256GcmSiv,
                created_at: timestamp()?,
            },
            nonce: vec![1; wallet::AES_256_GCM_SIV_NONCE_LENGTH],
            aad: vec![2; 16],
            ciphertext: vec![3; 32],
        },
    ))
}

fn binding_key_handle(id: &str) -> String {
    format!("{id}-holder-key")
}

fn issuance_state(ids: &[&str], legacy: bool) -> Vec<u8> {
    let mut state = pb::OpenId4VciIssuanceSnapshot::default();
    state.stage =
        EnumValue::from(pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_CREDENTIAL_STORED);
    let offer = openid4vci_pb::CredentialOffer {
        credential_issuer: "https://issuer.example".to_owned(),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: MessageField::none(),
        __buffa_unknown_fields: Default::default(),
    };
    state.credential_offer = MessageField::some(offer);
    state.access_token_binding_handle = "token-handle-1".to_owned();
    if legacy {
        state.wallet_unit_attestation = MessageField::some(pb::WalletUnitAttestation::default());
        let envelope = openid4vci_pb::CredentialEnvelope {
            credential: Some(openid4vci_pb::credential_envelope::Credential::Compact(
                "credential-envelope".to_owned(),
            )),
            __buffa_unknown_fields: Default::default(),
        };
        let immediate = openid4vci_pb::ImmediateCredentialResponse {
            credentials: vec![envelope],
            notification_id: String::new(),
            __buffa_unknown_fields: Default::default(),
        };
        state.credential_response = MessageField::some(openid4vci_pb::CredentialResponse {
            response: Some(openid4vci_pb::credential_response::Response::Immediate(
                Box::new(immediate),
            )),
            __buffa_unknown_fields: Default::default(),
        });
        state.credential_record_id = ids.first().copied().unwrap_or_default().to_owned();
    } else {
        state.credential_record_ids = ids.iter().map(|id| (*id).to_owned()).collect();
        state.credential_binding_key_handle_ids =
            ids.iter().map(|id| binding_key_handle(id)).collect();
    }
    state.encode_to_vec()
}

fn flow_snapshot(ids: &[&str], legacy: bool) -> Result<wallet::FlowSnapshot, TestError> {
    Ok(wallet::FlowSnapshot {
        id: identifier("flow-1")?,
        kind: wallet::FlowKind::Issuance,
        state: issuance_state(ids, legacy),
        state_schema_version: wallet::FlowStateSchemaVersion::V1,
        updated_at: timestamp()?,
    })
}

fn proto_commit(ids: &[&str], legacy: bool) -> Result<pb::OpenId4VciIssuanceCommit, TestError> {
    let records = ids
        .iter()
        .map(|id| credential_record(id))
        .collect::<Result<Vec<_>, _>>()?;
    let commit = build_openid4vci_issuance_commit(
        [7; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
        records,
        flow_snapshot(ids, legacy)?,
        None,
    )?;
    Ok(issuance_commit_to_proto(&commit))
}

fn update_digest_after_valid_change(
    commit: &mut pb::OpenId4VciIssuanceCommit,
) -> Result<(), TestError> {
    let idempotency_key = <[u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES]>::try_from(
        commit.idempotency_key.as_slice(),
    )
    .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIdempotencyKey))?;
    let records = commit
        .credential_records
        .iter()
        .map(credential_record_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = commit
        .flow_snapshot
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(flow_snapshot_from_proto)?;
    let rebuilt = build_openid4vci_issuance_commit(idempotency_key, records, snapshot, None)?;
    commit.request_digest = rebuilt.request_digest().to_vec();
    Ok(())
}

#[test]
fn canonical_batch_ids_round_trip_and_legacy_single_decodes() -> Result<(), TestError> {
    let commit = issuance_commit_from_proto(&proto_commit(&["record-a", "record-b"], false)?)?;
    let encoded = issuance_commit_to_proto(&commit);
    let snapshot = encoded
        .flow_snapshot
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))?;
    let decoded = pb::OpenId4VciIssuanceSnapshot::decode(&mut snapshot.state.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    assert!(decoded.credential_record_id.is_empty());
    assert_eq!(decoded.credential_record_ids, ["record-a", "record-b"]);

    let legacy = issuance_commit_from_proto(&proto_commit(&["record-a"], true)?)?;
    assert_eq!(legacy.credential_records().len(), 1);

    let response_ordered =
        issuance_commit_from_proto(&proto_commit(&["record-z", "record-a"], false)?)?;
    assert_eq!(
        response_ordered
            .credential_records()
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        ["record-z", "record-a"]
    );
    Ok(())
}

#[test]
fn accepts_batch_credentials_in_an_order_independent_of_proofs() -> Result<(), TestError> {
    let mut commit = proto_commit(&["record-a", "record-b"], false)?;
    let snapshot = commit
        .flow_snapshot
        .as_option_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))?;
    let mut state = pb::OpenId4VciIssuanceSnapshot::decode(&mut snapshot.state.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    state.credential_binding_key_handle_ids.reverse();
    snapshot.state = state.encode_to_vec();
    update_digest_after_valid_change(&mut commit)?;

    let decoded = issuance_commit_from_proto(&commit)?;

    assert_eq!(decoded.credential_records().len(), 2);
    Ok(())
}

#[test]
fn rejects_duplicate_batch_binding_key_handles() -> Result<(), TestError> {
    let mut commit = proto_commit(&["record-a", "record-b"], false)?;
    commit.credential_records[1].holder_key_handle_id = binding_key_handle("record-a");

    assert!(matches!(
        issuance_commit_from_proto(&commit),
        Err(error) if error.reason == ConvertErrorReason::InvalidIssuanceCommit
    ));
    Ok(())
}

#[test]
fn rejects_mismatched_duplicate_and_conflicting_record_ids() -> Result<(), TestError> {
    let mut mismatched = proto_commit(&["record-a"], false)?;
    let snapshot = mismatched
        .flow_snapshot
        .as_option_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))?;
    snapshot.state = issuance_state(&["record-b"], false);
    assert!(matches!(
        issuance_commit_from_proto(&mismatched),
        Err(error) if error.reason == ConvertErrorReason::InvalidIssuanceCommit
    ));

    let mut duplicate = proto_commit(&["record-a", "record-b"], false)?;
    duplicate.credential_records[1].id = "record-a".to_owned();
    assert!(matches!(
        issuance_commit_from_proto(&duplicate),
        Err(error) if error.reason == ConvertErrorReason::InvalidIssuanceCommit
    ));

    let mut conflicting = proto_commit(&["record-a"], false)?;
    let snapshot = conflicting
        .flow_snapshot
        .as_option_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))?;
    let mut state = pb::OpenId4VciIssuanceSnapshot::decode(&mut snapshot.state.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    state.credential_record_id = "record-a".to_owned();
    snapshot.state = state.encode_to_vec();
    assert!(matches!(
        issuance_commit_from_proto(&conflicting),
        Err(error) if error.reason == ConvertErrorReason::InvalidFlowStatePayload
    ));
    Ok(())
}

#[test]
fn rejects_wrong_stage_and_invalid_idempotency() -> Result<(), TestError> {
    let mut wrong_stage = proto_commit(&["record-a"], false)?;
    let snapshot = wrong_stage
        .flow_snapshot
        .as_option_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))?;
    let mut state = pb::OpenId4VciIssuanceSnapshot::decode(&mut snapshot.state.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    state.stage =
        EnumValue::from(pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_TOKEN_EXCHANGED);
    snapshot.state = state.encode_to_vec();
    assert!(matches!(
        issuance_commit_from_proto(&wrong_stage),
        Err(error) if error.reason == ConvertErrorReason::InvalidFlowStatePayload
    ));

    let mut invalid_key = proto_commit(&["record-a"], false)?;
    invalid_key.idempotency_key.fill(0);
    assert!(matches!(
        issuance_commit_from_proto(&invalid_key),
        Err(error) if error.reason == ConvertErrorReason::InvalidIdempotencyKey
    ));
    Ok(())
}

#[test]
fn rejects_untrusted_or_precompleted_notification_outbox() -> Result<(), TestError> {
    let mut commit = proto_commit(&["record-a"], false)?;
    let snapshot = commit
        .flow_snapshot
        .as_option_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))?;
    let mut state = pb::OpenId4VciIssuanceSnapshot::decode(&mut snapshot.state.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    state.notification_id = "notification-1".to_owned();
    state.access_token_binding_handle = "token-binding-1".to_owned();
    state.notification_endpoint = "https://issuer.example/notify".to_owned();
    snapshot.state = state.encode_to_vec();

    let mut outbox = pb::OpenId4VciNotificationOutboxEntry::default();
    outbox.credential_issuer = "https://issuer.example".to_owned();
    outbox.notification_id = "notification-1".to_owned();
    outbox.notification_endpoint = "http://issuer.example/notify".to_owned();
    outbox.access_token_binding_handle = "token-binding-1".to_owned();
    outbox.delivery_state = EnumValue::from(
        pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_PENDING,
    );
    outbox.updated_at = MessageField::some(pb::UnixTimestamp {
        seconds: timestamp()?.as_seconds(),
        ..pb::UnixTimestamp::default()
    });
    commit.notification_outbox = MessageField::some(outbox.clone());
    assert!(matches!(
        issuance_commit_from_proto(&commit),
        Err(error) if error.reason == ConvertErrorReason::InvalidNotificationEndpoint
    ));

    outbox.notification_endpoint = "https://issuer.example/notify".to_owned();
    outbox.delivery_state = EnumValue::from(
        pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_DELIVERED,
    );
    commit.notification_outbox = MessageField::some(outbox.clone());
    assert!(matches!(
        issuance_commit_from_proto(&commit),
        Err(error) if error.reason == ConvertErrorReason::InvalidIssuanceCommit
    ));

    outbox.delivery_state = EnumValue::from(
        pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_PENDING,
    );
    outbox.delivery_attempts = 1;
    commit.notification_outbox = MessageField::some(outbox);
    assert!(matches!(
        issuance_commit_from_proto(&commit),
        Err(error) if error.reason == ConvertErrorReason::InvalidIssuanceCommit
    ));
    Ok(())
}

#[test]
fn builder_is_the_only_source_of_commit_idempotency_material() -> Result<(), TestError> {
    let records = vec![credential_record("record-a")?];
    let commit = build_openid4vci_issuance_commit(
        [1; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
        records,
        flow_snapshot(&["record-a"], false)?,
        None,
    )?;
    assert_eq!(commit.idempotency_key(), &[1; 32]);
    assert_ne!(commit.request_digest(), &[0; 32]);
    Ok(())
}

#[test]
fn rejects_changed_credential_under_the_same_idempotency_material() -> Result<(), TestError> {
    let mut commit = proto_commit(&["record-a"], false)?;
    let record = commit
        .credential_records
        .first_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
    let payload = record
        .encrypted_payload
        .as_option_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
    payload.ciphertext.push(0xA5);
    assert!(matches!(
        issuance_commit_from_proto(&commit),
        Err(error) if error.reason == ConvertErrorReason::InvalidIdempotencyKey
    ));
    Ok(())
}

#[test]
fn rejects_added_notification_under_the_same_idempotency_material() -> Result<(), TestError> {
    let mut commit = proto_commit(&["record-a"], false)?;
    let snapshot = commit
        .flow_snapshot
        .as_option_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))?;
    let mut state = pb::OpenId4VciIssuanceSnapshot::decode(&mut snapshot.state.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    state.notification_id = "notification-1".to_owned();
    state.notification_endpoint = "https://issuer.example/notify".to_owned();
    state.access_token_binding_handle = "token-binding-1".to_owned();
    snapshot.state = state.encode_to_vec();
    let mut outbox = pb::OpenId4VciNotificationOutboxEntry::default();
    outbox.credential_issuer = "https://issuer.example".to_owned();
    outbox.notification_id = "notification-1".to_owned();
    outbox.notification_endpoint = "https://issuer.example/notify".to_owned();
    outbox.access_token_binding_handle = "token-binding-1".to_owned();
    outbox.delivery_state = EnumValue::from(
        pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_PENDING,
    );
    outbox.updated_at = MessageField::some(pb::UnixTimestamp {
        seconds: timestamp()?.as_seconds(),
        ..pb::UnixTimestamp::default()
    });
    commit.notification_outbox = MessageField::some(outbox);
    assert!(matches!(
        issuance_commit_from_proto(&commit),
        Err(error) if error.reason == ConvertErrorReason::InvalidIdempotencyKey
    ));
    Ok(())
}

#[test]
fn accepts_cleanup_handle_without_notification_outbox() -> Result<(), TestError> {
    let mut commit = proto_commit(&["record-a"], false)?;
    let snapshot = commit
        .flow_snapshot
        .as_option_mut()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))?;
    let mut state = pb::OpenId4VciIssuanceSnapshot::decode(&mut snapshot.state.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    state.access_token_binding_handle = "token-cleanup-1".to_owned();
    snapshot.state = state.encode_to_vec();
    update_digest_after_valid_change(&mut commit)?;

    let decoded = issuance_commit_from_proto(&commit)?;

    assert!(decoded.notification_outbox().is_none());
    Ok(())
}
