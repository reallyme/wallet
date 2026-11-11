// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_wallet_types::{
    CredentialRecordId, EncryptedRecord, EncryptedRecordHeader, KeyHandleId,
    StorageEncryptionAlgorithm, UnixTimestamp,
};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage},
    proofs::ZkSessionBinding,
};

use super::{ZkArtifactDescriptor, ZkArtifactKind, ZkStoredArtifactRecord};
use crate::ErrorReason;

// Keep the storage coverage pinned to the exact production registry. A new
// source circuit needs an explicit review of its artifact and binding policy.
const PRODUCTION_SOURCE_CIRCUIT_COUNT: usize = 42;

fn timestamp(seconds: i64) -> UnixTimestamp {
    UnixTimestamp::from_seconds(seconds).expect("bounded test timestamp")
}

fn binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [0x31; 32],
        audience_hash: [0x42; 32],
        transaction_data_hash: None,
    }
}

fn descriptor(circuit_ref: ZkCircuitRef, kind: ZkArtifactKind) -> ZkArtifactDescriptor {
    ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        circuit_ref,
        kind,
        [0x22; 32],
        match kind {
            ZkArtifactKind::PreparedInput | ZkArtifactKind::PreparedPublicProof => None,
            ZkArtifactKind::Witness | ZkArtifactKind::Proof => Some(binding()),
        },
        timestamp(1_200),
    )
    .expect("valid descriptor")
}

fn encrypted(descriptor: &ZkArtifactDescriptor) -> EncryptedRecord {
    let header = EncryptedRecordHeader {
        schema_version: 1,
        key_handle_id: KeyHandleId::new("key-1".to_owned()).expect("valid id"),
        algorithm: StorageEncryptionAlgorithm::XChaCha20Poly1305,
        created_at: timestamp(1_000),
    };
    EncryptedRecord {
        aad: descriptor.aad_digest(&header).expect("valid aad").to_vec(),
        header,
        nonce: vec![0x73; 24],
        ciphertext: vec![0x44; 32],
    }
}

#[test]
fn every_production_source_circuit_has_its_correct_storage_policy() {
    let mut count = 0_usize;
    for circuit_ref in ZkCircuitRef::ALL {
        if circuit_ref.stage == ZkCircuitStage::ClaimBundle4 {
            continue;
        }
        count = count.checked_add(1).expect("bounded circuit registry");
        let kinds: &[ZkArtifactKind] =
            if circuit_ref.family == ZkCircuitFamily::PersonaCredentialEvidenceV1 {
                if circuit_ref.stage == ZkCircuitStage::EvidencePrivateClaim {
                    &[ZkArtifactKind::PreparedInput]
                } else {
                    &[
                        ZkArtifactKind::PreparedInput,
                        ZkArtifactKind::PreparedPublicProof,
                    ]
                }
            } else {
                &[
                    ZkArtifactKind::PreparedInput,
                    ZkArtifactKind::Witness,
                    ZkArtifactKind::Proof,
                ]
            };
        for kind in kinds {
            let descriptor = descriptor(*circuit_ref, *kind);
            let ciphertext = encrypted(&descriptor);
            let record = ZkStoredArtifactRecord::new(descriptor, ciphertext);
            assert!(record.is_ok());
        }
    }
    assert_eq!(count, PRODUCTION_SOURCE_CIRCUIT_COUNT);
}

#[test]
fn public_prepared_proofs_are_reusable_without_admitting_private_tokens() {
    for stage in [
        ZkCircuitStage::EvidenceIssuerEnvelope,
        ZkCircuitStage::EvidenceClaimRoot,
        ZkCircuitStage::EvidenceSignedValidity,
        ZkCircuitStage::EvidencePublicClaim,
        ZkCircuitStage::EvidenceCurrentState,
    ] {
        for prepared in ZkCircuitRef::ALL
            .iter()
            .filter(|reference| reference.stage == stage)
        {
            let reusable = descriptor(*prepared, ZkArtifactKind::PreparedPublicProof);
            assert!(reusable.validate_use(timestamp(1_100), None).is_ok());
            assert!(reusable
                .validate_use(timestamp(1_100), Some(binding()))
                .is_ok());
        }
    }
    let prepared = ZkCircuitRef::ALL
        .iter()
        .find(|reference| reference.stage == ZkCircuitStage::EvidencePublicClaim)
        .expect("production prepared public claim exists");
    let descriptor = descriptor(*prepared, ZkArtifactKind::PreparedPublicProof);
    assert!(descriptor.validate_use(timestamp(1_100), None).is_ok());
    assert!(descriptor
        .validate_use(timestamp(1_100), Some(binding()))
        .is_ok());
    assert_eq!(
        descriptor
            .validate_use(timestamp(1_200), None)
            .err()
            .map(|error| error.reason),
        Some(ErrorReason::ArtifactExpired)
    );
    let wrong_circuit = ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        ZkCircuitRef::ALL[0],
        ZkArtifactKind::PreparedPublicProof,
        [0x22; 32],
        None,
        timestamp(1_200),
    );
    assert_eq!(
        wrong_circuit.err().map(|error| error.reason),
        Some(ErrorReason::UnsupportedCircuit)
    );
    let request_bound_prepared = ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        *prepared,
        ZkArtifactKind::PreparedPublicProof,
        [0x22; 32],
        Some(binding()),
        timestamp(1_200),
    );
    assert_eq!(
        request_bound_prepared.err().map(|error| error.reason),
        Some(ErrorReason::InvalidArtifactScope)
    );
    let private = ZkCircuitRef::ALL
        .iter()
        .find(|reference| reference.stage == ZkCircuitStage::EvidencePrivateClaim)
        .expect("production prepared private claim exists");
    let private_as_reusable = ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        *private,
        ZkArtifactKind::PreparedPublicProof,
        [0x22; 32],
        None,
        timestamp(1_200),
    );
    assert_eq!(
        private_as_reusable.err().map(|error| error.reason),
        Some(ErrorReason::UnsupportedCircuit)
    );
    let two_credentials = ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![
            CredentialRecordId::new("credential-1".to_owned()).expect("valid id"),
            CredentialRecordId::new("credential-2".to_owned()).expect("valid id"),
        ],
        *prepared,
        ZkArtifactKind::PreparedPublicProof,
        [0x22; 32],
        None,
        timestamp(1_200),
    );
    assert_eq!(
        two_credentials.err().map(|error| error.reason),
        Some(ErrorReason::InvalidArtifactIdentity)
    );
}

#[test]
fn prepared_inputs_are_reusable_only_before_expiry() {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let descriptor = descriptor(circuit_ref, ZkArtifactKind::PreparedInput);
    assert!(descriptor.validate_use(timestamp(1_100), None).is_ok());
    assert!(descriptor
        .validate_use(timestamp(1_100), Some(binding()))
        .is_ok());
    assert_eq!(
        descriptor
            .validate_use(timestamp(1_200), None)
            .err()
            .map(|error| error.reason),
        Some(ErrorReason::ArtifactExpired)
    );
}

#[test]
fn exact_request_artifacts_reject_another_verifier_or_tampered_header() {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let descriptor = descriptor(circuit_ref, ZkArtifactKind::Witness);
    let mut other_request = binding();
    other_request.audience_hash = [0x55; 32];
    assert_eq!(
        descriptor
            .validate_use(timestamp(1_100), Some(other_request))
            .err()
            .map(|error| error.reason),
        Some(ErrorReason::ArtifactBindingMismatch)
    );
    let mut ciphertext = encrypted(&descriptor);
    ciphertext.header.key_handle_id = KeyHandleId::new("key-2".to_owned()).expect("valid id");
    assert_eq!(
        ZkStoredArtifactRecord::new(descriptor, ciphertext)
            .err()
            .map(|error| error.reason),
        Some(ErrorReason::ArtifactBindingMismatch)
    );
}

#[test]
fn malformed_metadata_and_diagnostic_circuits_fail_closed() {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let invalid = ZkArtifactDescriptor::new(
        [0; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        circuit_ref,
        ZkArtifactKind::PreparedInput,
        [0x22; 32],
        None,
        timestamp(1_200),
    );
    assert_eq!(
        invalid.err().map(|error| error.reason),
        Some(ErrorReason::InvalidArtifactIdentity)
    );
    for diagnostic in ZkCircuitRef::ALL
        .iter()
        .filter(|reference| reference.stage == ZkCircuitStage::ClaimBundle4)
    {
        let rejected = ZkArtifactDescriptor::new(
            [0x11; 32],
            vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
            *diagnostic,
            ZkArtifactKind::PreparedInput,
            [0x22; 32],
            None,
            timestamp(1_200),
        );
        assert_eq!(
            rejected.err().map(|error| error.reason),
            Some(ErrorReason::UnsupportedCircuit)
        );
    }
}

#[test]
fn request_outputs_require_binding_and_short_retention() {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let missing_binding = ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        circuit_ref,
        ZkArtifactKind::Proof,
        [0x22; 32],
        None,
        timestamp(1_200),
    );
    assert_eq!(
        missing_binding.err().map(|error| error.reason),
        Some(ErrorReason::InvalidArtifactScope)
    );

    let long_lived = ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        circuit_ref,
        ZkArtifactKind::Proof,
        [0x22; 32],
        Some(binding()),
        timestamp(1_301),
    )
    .expect("valid descriptor before storage deadline check");
    let ciphertext = encrypted(&long_lived);
    assert_eq!(
        ZkStoredArtifactRecord::new(long_lived, ciphertext)
            .err()
            .map(|error| error.reason),
        Some(ErrorReason::InvalidArtifactScope)
    );
}

#[test]
fn malformed_nonce_and_short_ciphertext_are_rejected() {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let nonce_descriptor = descriptor(circuit_ref, ZkArtifactKind::PreparedInput);
    let mut wrong_nonce = encrypted(&nonce_descriptor);
    let _removed = wrong_nonce.nonce.pop();
    assert_eq!(
        ZkStoredArtifactRecord::new(nonce_descriptor, wrong_nonce)
            .err()
            .map(|error| error.reason),
        Some(ErrorReason::InvalidArtifactEncoding)
    );

    let descriptor = descriptor(circuit_ref, ZkArtifactKind::PreparedInput);
    let mut short_ciphertext = encrypted(&descriptor);
    short_ciphertext.ciphertext.truncate(15);
    assert_eq!(
        ZkStoredArtifactRecord::new(descriptor, short_ciphertext)
            .err()
            .map(|error| error.reason),
        Some(ErrorReason::InvalidArtifactEncoding)
    );
}

#[test]
fn aad_binds_the_circuit_revision() {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let kind = ZkArtifactKind::PreparedInput;
    let current = descriptor(circuit_ref, kind);
    let header = encrypted(&current).header.clone();
    let current_aad = current.aad_digest(&header).expect("valid aad");
    // Only one revision is admissible today, so change it on a built
    // descriptor to compare the transcripts directly.
    let mut next = descriptor(circuit_ref, kind);
    next.circuit_ref.revision = circuit_ref.revision + 1;
    let next_aad = next.aad_digest(&header).expect("valid aad");

    assert_ne!(next_aad, current_aad);
}

#[test]
fn stored_record_refuses_a_creation_time_after_trusted_now() {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let descriptor_for_aad = descriptor(circuit_ref, ZkArtifactKind::PreparedInput);
    let ciphertext = encrypted(&descriptor_for_aad);
    let record = ZkStoredArtifactRecord::new(
        descriptor(circuit_ref, ZkArtifactKind::PreparedInput),
        ciphertext,
    )
    .expect("valid record");
    assert!(record.validate_use(timestamp(1_100), None).is_ok());
    assert!(matches!(
        record.validate_use(timestamp(999), None),
        Err(error) if error.reason == ErrorReason::InvalidArtifactScope
    ));
}

#[test]
fn prepared_artifacts_cannot_be_stored_indefinitely() {
    let circuit_ref = ZkCircuitRef::ALL[0];
    let long_lived = ZkArtifactDescriptor::new(
        [0x11; 32],
        vec![CredentialRecordId::new("credential-1".to_owned()).expect("valid id")],
        circuit_ref,
        ZkArtifactKind::PreparedInput,
        [0x22; 32],
        None,
        timestamp(1_000 + 367 * 24 * 60 * 60),
    )
    .expect("valid descriptor");
    let ciphertext = encrypted(&long_lived);
    assert!(matches!(
        ZkStoredArtifactRecord::new(long_lived, ciphertext),
        Err(error) if error.reason == ErrorReason::InvalidArtifactScope
    ));
}
