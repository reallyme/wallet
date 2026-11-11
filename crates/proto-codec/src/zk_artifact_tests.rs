// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use buffa::Message;
use reallyme_wallet_types::{
    CredentialRecordId, EncryptedRecord, EncryptedRecordHeader, KeyHandleId,
    StorageEncryptionAlgorithm, UnixTimestamp,
};
use reallyme_wallet_zk::{ZkArtifactDescriptor, ZkArtifactKind, ZkStoredArtifactRecord};
use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCircuitStage},
    proofs::ZkSessionBinding,
};

use super::{decode_zk_artifact, encode_zk_artifact, zk_artifact_to_proto};
use crate::ProtoErrorReason;

fn fixture_for_stage(
    kind: ZkArtifactKind,
    prepared_stage: ZkCircuitStage,
) -> ZkStoredArtifactRecord {
    let circuit_ref = if kind == ZkArtifactKind::PreparedPublicProof {
        *ZkCircuitRef::ALL
            .iter()
            .find(|reference| reference.stage == prepared_stage)
            .expect("production prepared stage exists")
    } else {
        ZkCircuitRef::ALL[0]
    };
    let binding = ZkSessionBinding {
        nonce_hash: [0x32; 32],
        audience_hash: [0x43; 32],
        transaction_data_hash: None,
    };
    let descriptor = ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        circuit_ref,
        kind,
        [0x55; 32],
        match kind {
            ZkArtifactKind::PreparedInput | ZkArtifactKind::PreparedPublicProof => None,
            ZkArtifactKind::Witness | ZkArtifactKind::Proof => Some(binding),
        },
        UnixTimestamp::from_seconds(1_200).expect("valid time"),
    )
    .expect("valid descriptor");
    let header = EncryptedRecordHeader {
        schema_version: 1,
        key_handle_id: KeyHandleId::new("key-1".to_owned()).expect("valid id"),
        algorithm: StorageEncryptionAlgorithm::Aes256GcmSiv,
        created_at: UnixTimestamp::from_seconds(1_000).expect("valid time"),
    };
    let record = EncryptedRecord {
        aad: descriptor.aad_digest(&header).expect("valid aad").to_vec(),
        header,
        nonce: vec![0x22; 12],
        ciphertext: vec![0x77; 32],
    };
    ZkStoredArtifactRecord::new(descriptor, record).expect("valid encrypted record")
}

fn fixture(kind: ZkArtifactKind) -> ZkStoredArtifactRecord {
    fixture_for_stage(kind, ZkCircuitStage::EvidencePublicClaim)
}

#[test]
fn every_cache_class_round_trips_through_bounded_buffa() {
    for kind in [
        ZkArtifactKind::PreparedInput,
        ZkArtifactKind::Witness,
        ZkArtifactKind::Proof,
        ZkArtifactKind::PreparedPublicProof,
    ] {
        let record = fixture(kind);
        let encoded = encode_zk_artifact(&record).expect("valid encoding");
        let decoded = decode_zk_artifact(&encoded).expect("valid decoding");
        assert_eq!(decoded.descriptor().kind(), kind);
        assert_eq!(
            decoded.descriptor().circuit_ref(),
            record.descriptor().circuit_ref()
        );
        assert_eq!(decoded.encrypted().aad, record.encrypted().aad);
    }
}

#[test]
fn every_public_prepared_stage_round_trips_with_authenticated_circuit_identity() {
    for stage in [
        ZkCircuitStage::EvidenceIssuerEnvelope,
        ZkCircuitStage::EvidenceClaimRoot,
        ZkCircuitStage::EvidenceSignedValidity,
        ZkCircuitStage::EvidencePublicClaim,
        ZkCircuitStage::EvidenceCurrentState,
    ] {
        let record = fixture_for_stage(ZkArtifactKind::PreparedPublicProof, stage);
        let encoded = encode_zk_artifact(&record).expect("valid encoding");
        let decoded = decode_zk_artifact(&encoded).expect("valid decoding");
        assert_eq!(
            decoded.descriptor().circuit_ref(),
            record.descriptor().circuit_ref()
        );
        assert_eq!(decoded.encrypted().aad, record.encrypted().aad);
    }
}

#[test]
fn tampered_scope_and_request_binding_fail_decode() {
    let record = fixture(ZkArtifactKind::Witness);
    let mut message = zk_artifact_to_proto(&record);
    message.claim_scope_digest[0] ^= 1;
    let error = decode_zk_artifact(&message.encode_to_vec())
        .err()
        .expect("tampered scope rejected");
    assert_eq!(error.reason, ProtoErrorReason::InvalidDto);

    let mut message = zk_artifact_to_proto(&record);
    message.audience_hash[0] ^= 1;
    let error = decode_zk_artifact(&message.encode_to_vec())
        .err()
        .expect("tampered binding rejected");
    assert_eq!(error.reason, ProtoErrorReason::InvalidDto);
}

#[test]
fn malformed_and_oversized_artifacts_fail_before_domain_use() {
    let record = fixture(ZkArtifactKind::PreparedInput);
    let mut message = zk_artifact_to_proto(&record);
    message
        .credential_record_ids
        .push("credential-1".to_owned());
    let error = decode_zk_artifact(&message.encode_to_vec())
        .err()
        .expect("duplicate credential rejected");
    assert_eq!(error.reason, ProtoErrorReason::InvalidDto);

    let error = decode_zk_artifact(&vec![0; crate::MAX_WALLET_PROTO_MESSAGE_BYTES + 1])
        .err()
        .expect("oversized message rejected");
    assert_eq!(error.reason, ProtoErrorReason::MessageTooLarge);
}
