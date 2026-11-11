// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_keystore::{
    verify_key_attestation_evidence, KeyAttestationEvidence, KeyAttestationEvidenceVerifier,
    KeyHandle, KeystoreResult, SigningAlgorithm, VerifiedKeyAttestationBinding,
    VerifiedKeyAttestationEvidence,
};
use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp};

use super::rotate_wallet_unit_attestation;
use crate::{
    verify_wallet_unit_attestation, AttestationError, AttestationErrorReason, AttestationResult,
    UnverifiedWalletUnitAttestation, WalletUnitAttestationVerifier,
};

struct Verifier;
struct AcceptKeyVerifier;

impl KeyAttestationEvidenceVerifier for AcceptKeyVerifier {
    fn verify_key_attestation_evidence(
        &self,
        evidence: &KeyAttestationEvidence,
        _now: UnixTimestamp,
    ) -> KeystoreResult<VerifiedKeyAttestationBinding> {
        // The first evidence byte names the attested key, as in `Verifier`.
        let key_marker = evidence.evidence.first().copied().unwrap_or(0);
        VerifiedKeyAttestationBinding::new(SigningAlgorithm::Es256, [key_marker; 32])
    }
}

/// Promote evidence through the keystore boundary as the Wallet would.
fn fresh(evidence: &KeyAttestationEvidence) -> AttestationResult<VerifiedKeyAttestationEvidence> {
    let handle = KeyHandle {
        id: evidence.key_handle_id.clone(),
        algorithm: SigningAlgorithm::Es256,
        created_at: timestamp(1)?,
    };
    verify_key_attestation_evidence(
        &handle,
        evidence.clone(),
        &evidence.challenge,
        timestamp(15)?,
        &AcceptKeyVerifier,
    )
    .map_err(|_| AttestationError::new(AttestationErrorReason::InvalidAttestationEvidence))
}

/// Rotate using the replacement's own evidence as the Wallet-sent evidence.
fn rotate(
    current: &crate::WalletUnitAttestation,
    replacement: UnverifiedWalletUnitAttestation,
    now: UnixTimestamp,
) -> AttestationResult<crate::WalletUnitAttestation> {
    let evidence = fresh(replacement.evidence())?;
    rotate_wallet_unit_attestation(current, replacement, &evidence, now, &Verifier)
}

impl WalletUnitAttestationVerifier for Verifier {
    fn verify_wallet_unit_attestation(
        &self,
        attestation: &UnverifiedWalletUnitAttestation,
        _now: UnixTimestamp,
    ) -> AttestationResult<crate::VerifiedWalletKeyThumbprint> {
        let key_marker = attestation
            .evidence()
            .evidence
            .first()
            .copied()
            .ok_or_else(|| {
                AttestationError::new(AttestationErrorReason::InvalidAttestationEvidence)
            })?;
        crate::VerifiedWalletKeyThumbprint::new([key_marker; 32])
    }
}

fn id(value: &str) -> AttestationResult<NonEmptyIdentifier> {
    NonEmptyIdentifier::new(value.to_owned())
        .map_err(|_| AttestationError::new(AttestationErrorReason::InvalidAttestationEvidence))
}

fn timestamp(seconds: i64) -> AttestationResult<UnixTimestamp> {
    UnixTimestamp::from_seconds(seconds)
        .map_err(|_| AttestationError::new(AttestationErrorReason::InvalidValidityWindow))
}

fn attestation(value: &str) -> AttestationResult<UnverifiedWalletUnitAttestation> {
    attestation_with_key(value, 1)
}

fn attestation_with_key(
    value: &str,
    key_marker: u8,
) -> AttestationResult<UnverifiedWalletUnitAttestation> {
    attestation_at(value, key_marker, 10, 20)
}

fn replacement(value: &str) -> AttestationResult<UnverifiedWalletUnitAttestation> {
    attestation_at(value, 1, 12, 30)
}

fn attestation_at(
    value: &str,
    key_marker: u8,
    issued_at: i64,
    valid_until: i64,
) -> AttestationResult<UnverifiedWalletUnitAttestation> {
    UnverifiedWalletUnitAttestation::new(
        id(value)?,
        KeyAttestationEvidence {
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned()).map_err(
                |_| AttestationError::new(AttestationErrorReason::InvalidAttestationEvidence),
            )?,
            evidence: vec![key_marker],
            issued_at: timestamp(issued_at)?,
            challenge: [7; 32],
        },
        timestamp(valid_until)?,
        vec![0xA5],
    )
}

#[test]
fn rotates_to_distinct_valid_replacement() -> AttestationResult<()> {
    let current = verify_wallet_unit_attestation(attestation("wua-1")?, &Verifier, timestamp(15)?)?;
    let replacement = replacement("wua-2")?;

    let result = rotate(&current, replacement, timestamp(15)?);

    assert!(matches!(result, Ok(attestation) if attestation.id().as_str() == "wua-2"));
    Ok(())
}

#[test]
fn rejects_same_attestation_id() -> AttestationResult<()> {
    let current = verify_wallet_unit_attestation(attestation("wua-1")?, &Verifier, timestamp(15)?)?;
    let replacement = attestation("wua-1")?;

    let result = rotate(&current, replacement, timestamp(15)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::ReplacementNotAvailable
    ));
    Ok(())
}

#[test]
fn rejects_reused_handle_name_with_different_verified_key() -> AttestationResult<()> {
    let current = verify_wallet_unit_attestation(attestation("wua-1")?, &Verifier, timestamp(15)?)?;
    let replacement = attestation_at("wua-2", 2, 12, 30)?;
    let result = rotate(&current, replacement, timestamp(15)?);
    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::KeyContinuityMismatch
    ));
    Ok(())
}

#[test]
fn rejects_an_older_or_equally_old_replacement() -> AttestationResult<()> {
    let current = verify_wallet_unit_attestation(
        attestation_at("wua-1", 1, 12, 30)?,
        &Verifier,
        timestamp(15)?,
    )?;
    for (issued_at, valid_until) in [(10, 40), (12, 40), (13, 15), (13, 14)] {
        let replacement = attestation_at("wua-2", 1, issued_at, valid_until)?;
        let result = rotate(&current, replacement, timestamp(15)?);
        assert!(matches!(
            result,
            Err(error) if error.reason == AttestationErrorReason::ReplacementNotAvailable
        ));
    }
    Ok(())
}

#[test]
fn rejects_a_replacement_with_stale_key_evidence() -> AttestationResult<()> {
    let current = verify_wallet_unit_attestation(attestation("wua-1")?, &Verifier, timestamp(15)?)?;
    let replacement = attestation_at("wua-2", 1, 12, 1_000)?;
    let result = rotate(&current, replacement, timestamp(400)?);
    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::AttestationChallengeStale
    ));
    Ok(())
}

#[test]
fn restore_verification_requires_the_expected_key() -> AttestationResult<()> {
    let key_handle = reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())
        .map_err(|_| AttestationError::new(AttestationErrorReason::InvalidAttestationEvidence))?;
    let other_handle = reallyme_wallet_types::KeyHandleId::new("key-2".to_owned())
        .map_err(|_| AttestationError::new(AttestationErrorReason::InvalidAttestationEvidence))?;

    let restored = crate::verify_wallet_unit_attestation_for_key(
        attestation("wua-1")?,
        &Verifier,
        timestamp(15)?,
        &key_handle,
        &[1; 32],
    )?;
    assert_eq!(restored.id().as_str(), "wua-1");

    for (handle, thumbprint) in [(&key_handle, [2; 32]), (&other_handle, [1; 32])] {
        let result = crate::verify_wallet_unit_attestation_for_key(
            attestation("wua-1")?,
            &Verifier,
            timestamp(15)?,
            handle,
            &thumbprint,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason == AttestationErrorReason::ProviderBindingMismatch
        ));
    }
    Ok(())
}

#[test]
fn rejects_a_replacement_that_does_not_carry_the_wallet_sent_evidence() -> AttestationResult<()> {
    let current = verify_wallet_unit_attestation(attestation("wua-1")?, &Verifier, timestamp(15)?)?;
    let replacement = replacement("wua-2")?;
    let mut sent = replacement.evidence().clone();
    sent.challenge = [8; 32];
    let sent = fresh(&sent)?;

    let result =
        rotate_wallet_unit_attestation(&current, replacement, &sent, timestamp(15)?, &Verifier);

    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::ProviderBindingMismatch
    ));
    Ok(())
}

#[test]
fn accepts_a_replacement_that_expires_earlier_than_the_current_one() -> AttestationResult<()> {
    let current = verify_wallet_unit_attestation(
        attestation_at("wua-1", 1, 12, 30)?,
        &Verifier,
        timestamp(15)?,
    )?;
    let replacement = attestation_at("wua-2", 1, 13, 20)?;

    let rotated = rotate(&current, replacement, timestamp(15)?)?;

    assert_eq!(rotated.id().as_str(), "wua-2");
    Ok(())
}

/// WUA verifier that reports a key other than the one the evidence attests.
struct OtherKeyVerifier;

impl WalletUnitAttestationVerifier for OtherKeyVerifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &UnverifiedWalletUnitAttestation,
        _now: UnixTimestamp,
    ) -> AttestationResult<crate::VerifiedWalletKeyThumbprint> {
        crate::VerifiedWalletKeyThumbprint::new([9; 32])
    }
}

#[test]
fn rejects_a_replacement_whose_signed_key_differs_from_the_fresh_evidence() -> AttestationResult<()>
{
    let current = verify_wallet_unit_attestation(attestation("wua-1")?, &Verifier, timestamp(15)?)?;
    let replacement = replacement("wua-2")?;
    let sent = fresh(replacement.evidence())?;

    let result = rotate_wallet_unit_attestation(
        &current,
        replacement,
        &sent,
        timestamp(15)?,
        &OtherKeyVerifier,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::ProviderBindingMismatch
    ));
    Ok(())
}
