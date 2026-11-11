// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::ZkCredentialHashAlgorithm,
    circuits::{ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage},
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProof, ZkProofSuite, ZkProveRequest, ZkProver, ZkPublicInputDescriptor,
        ZkPublicInputName, ZkPublicInputs, ZkSessionBinding, ZkWitness,
    },
};

use super::{prove_presentation_derivation, PresentationDerivationContext};
use crate::ErrorReason;

struct StaticProver;

struct TamperingProver {
    change_suite: bool,
    change_inputs: bool,
}

impl ZkProver for TamperingProver {
    fn prove(&self, request: ZkProveRequest<'_>) -> core::result::Result<ZkProof, ZkError> {
        let circuit_ref = request.circuit_ref();
        let suite = if self.change_suite {
            ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa
        } else {
            request.proof_suite()
        };
        let mut inputs = request.public_inputs().as_bytes().to_vec();
        if self.change_inputs {
            let first = inputs
                .first_mut()
                .ok_or_else(|| ZkError::new(ZkErrorReason::EmptyInput))?;
            *first ^= 1;
        }
        ZkProof::try_from_exact_parts(
            request.circuit_id(),
            circuit_ref,
            suite,
            ZkArtifactManifestDigest::from_bytes([7_u8; 32]),
            vec![1, 2, 3],
            ZkPublicInputs::try_from_bytes(inputs)?,
        )
    }
}

impl ZkProver for StaticProver {
    fn prove(&self, request: ZkProveRequest<'_>) -> core::result::Result<ZkProof, ZkError> {
        let circuit_ref = request.circuit_ref();

        ZkProof::try_from_exact_parts(
            request.circuit_id(),
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            ZkArtifactManifestDigest::from_bytes([7_u8; 32]),
            vec![1, 2, 3],
            ZkPublicInputs::try_copy_from_slice(request.public_inputs().as_bytes())?,
        )
    }
}

fn binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: Some([3_u8; 32]),
    }
}

const fn circuit_ref() -> ZkCircuitRef {
    ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Session,
    )
}

fn public_inputs(circuit_ref: ZkCircuitRef) -> core::result::Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    let session = binding();
    for (name, value) in [
        (ZkPublicInputName::Challenge, session.nonce_hash),
        (ZkPublicInputName::AudienceHash, session.audience_hash),
        (
            ZkPublicInputName::TransactionDataHash,
            session.transaction_data_public_input(),
        ),
    ] {
        let range = descriptor.field_range(name)?;
        let target = bytes
            .get_mut(range)
            .ok_or_else(|| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        if target.len() != value.len() {
            return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
        }
        target.copy_from_slice(&value);
    }
    let range = descriptor.field_range(ZkPublicInputName::ExpiryUnix)?;
    let target = bytes
        .get_mut(range)
        .ok_or_else(|| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if target.len() != core::mem::size_of::<u64>() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    target.copy_from_slice(&42_u64.to_be_bytes());
    ZkPublicInputs::try_from_bytes(bytes)
}

#[test]
fn zk_derivation_fails_closed_without_prover() -> core::result::Result<(), ZkError> {
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9])?;
    let public_inputs = public_inputs(circuit_ref)?;
    let request = ZkProveRequest::try_new(
        ZkCircuitId::CredentialSubjectClaimV1,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding(),
    )?;

    let result = prove_presentation_derivation(
        &PresentationDerivationContext::without_prover(),
        request,
        binding(),
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == ErrorReason::ProverUnavailable
    ));
    Ok(())
}

#[test]
fn zk_derivation_uses_injected_prover() -> core::result::Result<(), ZkError> {
    let context = PresentationDerivationContext::with_prover(Arc::new(StaticProver));
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9])?;
    let public_inputs = public_inputs(circuit_ref)?;
    let request = ZkProveRequest::try_new(
        ZkCircuitId::CredentialSubjectClaimV1,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding(),
    )?;

    let proof = prove_presentation_derivation(&context, request, binding());

    assert!(
        matches!(proof, Ok(proof) if proof.circuit_id() == ZkCircuitId::CredentialSubjectClaimV1)
    );
    Ok(())
}

#[test]
fn zk_request_rejects_session_binding_mismatch() -> core::result::Result<(), ZkError> {
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9])?;
    let public_inputs = public_inputs(circuit_ref)?;
    let mut wrong_binding = binding();
    wrong_binding.nonce_hash[15] ^= 1;
    let result = ZkProveRequest::try_new(
        ZkCircuitId::CredentialSubjectClaimV1,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        wrong_binding,
    );

    assert!(matches!(result, Err(error) if error.reason() == ZkErrorReason::BindingMismatch));
    Ok(())
}

#[test]
fn zk_derivation_rejects_prover_metadata_substitution() -> core::result::Result<(), ZkError> {
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9])?;
    let public_inputs = public_inputs(circuit_ref)?;
    for (change_suite, change_inputs) in [(true, false), (false, true)] {
        let context = PresentationDerivationContext::with_prover(Arc::new(TamperingProver {
            change_suite,
            change_inputs,
        }));
        let request = ZkProveRequest::try_new(
            ZkCircuitId::CredentialSubjectClaimV1,
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            &witness,
            &public_inputs,
            binding(),
        )?;
        assert!(matches!(
            prove_presentation_derivation(&context, request, binding()),
            Err(error) if error.reason == ErrorReason::ProofMetadataMismatch
        ));
    }
    Ok(())
}

#[test]
fn zk_derivation_rejects_a_request_prepared_for_another_session(
) -> core::result::Result<(), ZkError> {
    let context = PresentationDerivationContext::with_prover(Arc::new(StaticProver));
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9])?;
    let public_inputs = public_inputs(circuit_ref)?;
    let request = ZkProveRequest::try_new(
        ZkCircuitId::CredentialSubjectClaimV1,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding(),
    )?;
    let mut active_session = binding();
    active_session.audience_hash[0] ^= 1;

    assert!(matches!(
        prove_presentation_derivation(&context, request, active_session),
        Err(error) if error.reason == ErrorReason::SessionBindingInvalid
    ));
    Ok(())
}

#[test]
fn zk_derivation_refuses_non_production_suites() -> core::result::Result<(), ZkError> {
    let context = PresentationDerivationContext::with_prover(Arc::new(StaticProver));
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9])?;
    let public_inputs = public_inputs(circuit_ref)?;
    for suite in [
        ZkProofSuite::BarretenbergUltraHonkPoseidon2ZkNoIpa,
        ZkProofSuite::BarretenbergUltraHonkKeccakUnmaskedNoIpa,
    ] {
        let request = ZkProveRequest::try_new_compatibility(
            ZkCircuitId::CredentialSubjectClaimV1,
            circuit_ref,
            suite,
            &witness,
            &public_inputs,
            binding(),
            reallyme_zk_api::claim_bundle::ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
        )?;
        assert!(matches!(
            prove_presentation_derivation(&context, request, binding()),
            Err(error) if error.reason == ErrorReason::UnsupportedProofSuite
        ));
    }
    Ok(())
}
