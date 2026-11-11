// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VP ZK presentation conformance tests for wallet-owned injection.

use std::ops::Range;
use std::sync::Arc;

use reallyme_wallet_zk::{
    prove_presentation_derivation, Error as WalletZkError, ErrorReason,
    PresentationDerivationContext,
};
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

const FIXTURE_ARTIFACT_MANIFEST_SHA256: ZkArtifactManifestDigest =
    ZkArtifactManifestDigest::from_bytes([7_u8; 32]);

struct FixtureProver;

struct ContextSubstitutingProver(ZkPublicInputName);

impl ZkProver for ContextSubstitutingProver {
    fn prove(&self, request: ZkProveRequest<'_>) -> Result<ZkProof, ZkError> {
        let descriptor = ZkPublicInputDescriptor::for_circuit(request.circuit_ref())?;
        let range = descriptor.field_range(self.0)?;
        let mut bytes = request.public_inputs().as_bytes().to_vec();
        let field = bytes
            .get_mut(range)
            .and_then(|field| field.first_mut())
            .ok_or_else(|| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
        *field ^= 1;
        ZkProof::try_from_exact_parts(
            request.circuit_id(),
            request.circuit_ref(),
            request.proof_suite(),
            FIXTURE_ARTIFACT_MANIFEST_SHA256,
            vec![1, 2, 3],
            ZkPublicInputs::try_from_bytes(bytes)?,
        )
    }
}

impl ZkProver for FixtureProver {
    fn prove(&self, request: ZkProveRequest<'_>) -> Result<ZkProof, ZkError> {
        let circuit_ref = request.circuit_ref();

        ZkProof::try_from_exact_parts(
            request.circuit_id(),
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            FIXTURE_ARTIFACT_MANIFEST_SHA256,
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

fn public_inputs(circuit_ref: ZkCircuitRef) -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    let session = binding();
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::Challenge)?,
        &session.nonce_hash,
    )?;
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::AudienceHash)?,
        &session.audience_hash,
    )?;
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::TransactionDataHash)?,
        &session.transaction_data_public_input(),
    )?;
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::ExpiryUnix)?,
        &42_u64.to_be_bytes(),
    )?;
    ZkPublicInputs::try_from_bytes(bytes)
}

fn write_field(bytes: &mut [u8], range: Range<usize>, value: &[u8]) -> Result<(), ZkError> {
    let target = bytes
        .get_mut(range)
        .ok_or_else(|| ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if target.len() != value.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    target.copy_from_slice(value);
    Ok(())
}

#[test]
fn zk_presentation_fails_closed_without_backend() -> Result<(), ZkError> {
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
fn zk_presentation_uses_injected_backend_and_preserves_public_inputs() -> Result<(), TestError> {
    let context = PresentationDerivationContext::with_prover(Arc::new(FixtureProver));
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

    let proof = prove_presentation_derivation(&context, request, binding())?;

    assert_eq!(proof.circuit_id(), ZkCircuitId::CredentialSubjectClaimV1);
    assert_eq!(
        proof.artifact_identity().require_manifest()?,
        FIXTURE_ARTIFACT_MANIFEST_SHA256
    );
    assert_eq!(proof.proof_bytes(), &[1, 2, 3]);
    assert_eq!(proof.public_inputs(), &public_inputs);
    Ok(())
}

#[test]
fn zk_presentation_rejects_prover_substitution_of_each_session_context() -> Result<(), ZkError> {
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![9])?;
    let public_inputs = public_inputs(circuit_ref)?;
    for field in [
        ZkPublicInputName::Challenge,
        ZkPublicInputName::AudienceHash,
        ZkPublicInputName::TransactionDataHash,
    ] {
        let context =
            PresentationDerivationContext::with_prover(Arc::new(ContextSubstitutingProver(field)));
        let request = ZkProveRequest::try_new(
            ZkCircuitId::CredentialSubjectClaimV1,
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            &witness,
            &public_inputs,
            binding(),
        )?;
        // Wallet must reject a provider result tied to any different consent
        // context, even when its circuit, suite and artifact identity agree.
        assert!(matches!(
            prove_presentation_derivation(&context, request, binding()),
            Err(error) if error.reason == ErrorReason::ProofMetadataMismatch
        ));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("wallet_zk")]
    WalletZk(#[from] WalletZkError),
    #[error("zk")]
    Zk(#[from] ZkError),
}
