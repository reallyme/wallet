// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_keystore::{
    verify_key_attestation_evidence, KeyAttestationEvidence, KeyAttestationEvidenceVerifier,
    KeyHandle, KeystoreResult, SigningAlgorithm, VerifiedKeyAttestationBinding,
    VerifiedKeyAttestationEvidence,
};
use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp, WalletTypesError};

use super::{
    obtain_wallet_unit_attestation, WalletUnitAttestationProvider, WalletUnitAttestationVerifier,
};
use crate::{
    AttestationError, AttestationErrorReason, AttestationResult, UnverifiedWalletUnitAttestation,
};

struct Provider;
struct Verifier;
struct RejectingVerifier;
struct WrongKeyVerifier;
struct AcceptKeyVerifier;

impl KeyAttestationEvidenceVerifier for AcceptKeyVerifier {
    fn verify_key_attestation_evidence(
        &self,
        _evidence: &KeyAttestationEvidence,
        _now: UnixTimestamp,
    ) -> KeystoreResult<VerifiedKeyAttestationBinding> {
        VerifiedKeyAttestationBinding::new(SigningAlgorithm::Es256, [1; 32])
    }
}

fn validated_evidence(
    evidence: KeyAttestationEvidence,
) -> Result<VerifiedKeyAttestationEvidence, WalletTypesError> {
    let handle = KeyHandle {
        id: evidence.key_handle_id.clone(),
        algorithm: SigningAlgorithm::Es256,
        created_at: timestamp(1)?,
    };
    let challenge = evidence.challenge;
    verify_key_attestation_evidence(
        &handle,
        evidence,
        &challenge,
        timestamp(15)?,
        &AcceptKeyVerifier,
    )
    .map_err(|_| {
        WalletTypesError::new(reallyme_wallet_types::WalletTypesErrorReason::InvalidIdentifier)
    })
}

impl WalletUnitAttestationVerifier for Verifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &UnverifiedWalletUnitAttestation,
        _now: UnixTimestamp,
    ) -> AttestationResult<crate::VerifiedWalletKeyThumbprint> {
        crate::VerifiedWalletKeyThumbprint::new([1; 32])
    }
}

impl WalletUnitAttestationVerifier for RejectingVerifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &UnverifiedWalletUnitAttestation,
        _now: UnixTimestamp,
    ) -> AttestationResult<crate::VerifiedWalletKeyThumbprint> {
        Err(AttestationError::new(
            AttestationErrorReason::AttestationSignatureInvalid,
        ))
    }
}

impl WalletUnitAttestationVerifier for WrongKeyVerifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &UnverifiedWalletUnitAttestation,
        _now: UnixTimestamp,
    ) -> AttestationResult<crate::VerifiedWalletKeyThumbprint> {
        crate::VerifiedWalletKeyThumbprint::new([2; 32])
    }
}

impl WalletUnitAttestationProvider for Provider {
    fn obtain_wallet_unit_attestation(
        &self,
        evidence: KeyAttestationEvidence,
        valid_until: UnixTimestamp,
    ) -> AttestationResult<UnverifiedWalletUnitAttestation> {
        UnverifiedWalletUnitAttestation::new(
            NonEmptyIdentifier::new("wua-1".to_owned()).map_err(|_| {
                crate::AttestationError::new(
                    crate::AttestationErrorReason::InvalidAttestationEvidence,
                )
            })?,
            evidence,
            valid_until,
            vec![0xA5],
        )
    }
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

#[test]
fn obtains_and_validates_attestation() -> Result<(), WalletTypesError> {
    let evidence = KeyAttestationEvidence {
        key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
        evidence: vec![1],
        issued_at: timestamp(10)?,
        challenge: [7; 32],
    };

    let result = obtain_wallet_unit_attestation(
        &Provider,
        &Verifier,
        validated_evidence(evidence)?,
        timestamp(20)?,
        timestamp(15)?,
    );

    assert!(matches!(result, Ok(attestation) if attestation.id().as_str() == "wua-1"));
    Ok(())
}

#[test]
fn rejects_attestation_when_cryptographic_verifier_rejects() -> Result<(), WalletTypesError> {
    let evidence = KeyAttestationEvidence {
        key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
        evidence: vec![1],
        issued_at: timestamp(10)?,
        challenge: [7; 32],
    };

    let result = obtain_wallet_unit_attestation(
        &Provider,
        &RejectingVerifier,
        validated_evidence(evidence)?,
        timestamp(20)?,
        timestamp(15)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::AttestationSignatureInvalid
    ));
    Ok(())
}

#[test]
fn rejects_provider_attestation_for_a_different_verified_key() -> Result<(), WalletTypesError> {
    let evidence = KeyAttestationEvidence {
        key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
        evidence: vec![1],
        issued_at: timestamp(10)?,
        challenge: [7; 32],
    };
    let result = obtain_wallet_unit_attestation(
        &Provider,
        &WrongKeyVerifier,
        validated_evidence(evidence)?,
        timestamp(20)?,
        timestamp(15)?,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::ProviderBindingMismatch
    ));
    Ok(())
}

#[test]
fn rejects_oversized_key_evidence_before_provider_call() -> Result<(), WalletTypesError> {
    let evidence = KeyAttestationEvidence {
        key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
        evidence: vec![0xA5; reallyme_wallet_keystore::MAX_KEY_ATTESTATION_EVIDENCE_BYTES + 1],
        issued_at: timestamp(10)?,
        challenge: [7; 32],
    };

    // Unvalidated evidence cannot be passed to the WUA provider API.
    assert!(validated_evidence(evidence).is_err());
    Ok(())
}

#[test]
fn rejects_old_key_evidence_before_provider_call() -> Result<(), WalletTypesError> {
    let evidence = KeyAttestationEvidence {
        key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
        evidence: vec![1],
        issued_at: timestamp(10)?,
        challenge: [7; 32],
    };
    let result = obtain_wallet_unit_attestation(
        &Provider,
        &Verifier,
        validated_evidence(evidence)?,
        timestamp(1_000)?,
        timestamp(311)?,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::AttestationChallengeStale
    ));
    Ok(())
}

#[test]
fn rejects_zero_challenge_before_provider_call() -> Result<(), WalletTypesError> {
    let evidence = KeyAttestationEvidence {
        key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
        evidence: vec![1],
        issued_at: timestamp(10)?,
        challenge: [0; 32],
    };
    assert!(validated_evidence(evidence).is_err());
    Ok(())
}

fn evidence_issued_at(seconds: i64) -> Result<KeyAttestationEvidence, WalletTypesError> {
    Ok(KeyAttestationEvidence {
        key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
        evidence: vec![1],
        issued_at: timestamp(seconds)?,
        challenge: [7; 32],
    })
}

#[test]
fn key_evidence_age_bound_is_inclusive_at_three_hundred_seconds() -> Result<(), WalletTypesError> {
    let at_bound = obtain_wallet_unit_attestation(
        &Provider,
        &Verifier,
        validated_evidence(evidence_issued_at(10)?)?,
        timestamp(1_000)?,
        timestamp(310)?,
    );
    assert!(at_bound.is_ok());
    let past_bound = obtain_wallet_unit_attestation(
        &Provider,
        &Verifier,
        validated_evidence(evidence_issued_at(10)?)?,
        timestamp(1_000)?,
        timestamp(311)?,
    );
    assert!(matches!(
        past_bound,
        Err(error) if error.reason == AttestationErrorReason::AttestationChallengeStale
    ));
    Ok(())
}

#[test]
fn attestation_lifetime_bound_is_inclusive_at_one_day() -> Result<(), WalletTypesError> {
    let at_bound = obtain_wallet_unit_attestation(
        &Provider,
        &Verifier,
        validated_evidence(evidence_issued_at(10)?)?,
        timestamp(10 + 86_400)?,
        timestamp(15)?,
    );
    assert!(at_bound.is_ok());
    let past_bound = obtain_wallet_unit_attestation(
        &Provider,
        &Verifier,
        validated_evidence(evidence_issued_at(10)?)?,
        timestamp(10 + 86_401)?,
        timestamp(15)?,
    );
    assert!(matches!(
        past_bound,
        Err(error) if error.reason == AttestationErrorReason::InvalidValidityWindow
    ));
    Ok(())
}
