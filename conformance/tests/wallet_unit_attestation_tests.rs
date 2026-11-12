// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet unit attestation lifecycle conformance tests.

use reallyme_wallet::attestation::{
    obtain_wallet_unit_attestation, rotate_wallet_unit_attestation,
    verify_wallet_unit_attestation_for_key, AttestationError, AttestationErrorReason,
    AttestationResult, UnverifiedWalletUnitAttestation, WalletUnitAttestationProvider,
    WalletUnitAttestationVerifier,
};
use reallyme_wallet::keystore::{
    verify_key_attestation_evidence, KeyAttestationEvidence, KeyAttestationEvidenceVerifier,
    KeyHandle, KeystoreError, KeystoreResult, SigningAlgorithm, VerifiedKeyAttestationBinding,
    VerifiedKeyAttestationEvidence,
};
use reallyme_wallet::types as wallet;

struct Provider {
    attestation_id: &'static str,
}

struct Verifier;
struct KeyVerifier;

impl KeyAttestationEvidenceVerifier for KeyVerifier {
    fn verify_key_attestation_evidence(
        &self,
        _evidence: &KeyAttestationEvidence,
        _now: wallet::UnixTimestamp,
    ) -> KeystoreResult<VerifiedKeyAttestationBinding> {
        VerifiedKeyAttestationBinding::new(SigningAlgorithm::Es256, [1; 32])
    }
}

impl WalletUnitAttestationVerifier for Verifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &UnverifiedWalletUnitAttestation,
        _now: wallet::UnixTimestamp,
    ) -> AttestationResult<reallyme_wallet::attestation::VerifiedWalletKeyThumbprint> {
        reallyme_wallet::attestation::VerifiedWalletKeyThumbprint::new([1; 32])
    }
}

impl WalletUnitAttestationProvider for Provider {
    fn obtain_wallet_unit_attestation(
        &self,
        evidence: KeyAttestationEvidence,
        valid_until: wallet::UnixTimestamp,
    ) -> AttestationResult<UnverifiedWalletUnitAttestation> {
        UnverifiedWalletUnitAttestation::new(
            id(self.attestation_id).map_err(|_| {
                AttestationError::new(AttestationErrorReason::InvalidAttestationEvidence)
            })?,
            evidence,
            valid_until,
            vec![9, 8, 7],
        )
    }
}

#[test]
fn eudi_wua_obtains_validates_and_rotates_through_injected_provider() -> Result<(), TestError> {
    let current = obtain_wallet_unit_attestation(
        &Provider {
            attestation_id: "wua-1",
        },
        &Verifier,
        validated_key_attestation(10, &[1, 2, 3])?,
        timestamp(30)?,
        timestamp(20)?,
    )?;
    let sent = validated_key_attestation(20, &[4, 5, 6])?;
    let replacement = Provider {
        attestation_id: "wua-2",
    }
    .obtain_wallet_unit_attestation(sent.evidence().clone(), timestamp(40)?)?;

    let rotated =
        rotate_wallet_unit_attestation(&current, replacement, &sent, timestamp(25)?, &Verifier)?;

    assert_eq!(rotated.id().as_str(), "wua-2");
    assert_eq!(rotated.evidence().key_handle_id.as_str(), "key-1");
    Ok(())
}

#[test]
fn eudi_wua_rejects_empty_key_attestation_evidence() -> Result<(), TestError> {
    // The provider entry point requires an opaque verified-evidence owner.
    assert!(validated_key_attestation(10, &[]).is_err());
    Ok(())
}

#[test]
fn eudi_wua_rejects_reusing_the_same_attestation_id() -> Result<(), TestError> {
    let current = obtain_wallet_unit_attestation(
        &Provider {
            attestation_id: "wua-1",
        },
        &Verifier,
        validated_key_attestation(10, &[1, 2, 3])?,
        timestamp(30)?,
        timestamp(20)?,
    )?;
    let sent = validated_key_attestation(20, &[4, 5, 6])?;
    let replacement = Provider {
        attestation_id: "wua-1",
    }
    .obtain_wallet_unit_attestation(sent.evidence().clone(), timestamp(40)?)?;

    let result =
        rotate_wallet_unit_attestation(&current, replacement, &sent, timestamp(25)?, &Verifier);

    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::ReplacementNotAvailable
    ));
    Ok(())
}

#[test]
fn eudi_wua_technical_lifetime_has_an_exclusive_twenty_four_hour_bound() -> Result<(), TestError> {
    let current = obtain_wallet_unit_attestation(
        &Provider {
            attestation_id: "wua-1",
        },
        &Verifier,
        validated_key_attestation(10, &[1, 2, 3])?,
        timestamp(30)?,
        timestamp(20)?,
    )?;
    let provider = Provider {
        attestation_id: "wua-2",
    };
    let handle = wallet::KeyHandleId::new("key-1".to_owned())?;
    for (lifetime, accepted) in [(86_399_i64, true), (86_400, false), (86_401, false)] {
        let until = |issued_at: i64| -> Result<wallet::UnixTimestamp, TestError> {
            let seconds = issued_at.checked_add(lifetime).ok_or_else(|| {
                AttestationError::new(AttestationErrorReason::InvalidValidityWindow)
            })?;
            Ok(timestamp(seconds)?)
        };
        let obtained = obtain_wallet_unit_attestation(
            &provider,
            &Verifier,
            validated_key_attestation(10, &[1, 2, 3])?,
            until(10)?,
            timestamp(20)?,
        );
        let restored = verify_wallet_unit_attestation_for_key(
            provider
                .obtain_wallet_unit_attestation(key_attestation(10, &[1, 2, 3])?, until(10)?)?,
            &Verifier,
            timestamp(20)?,
            &handle,
            &[1; 32],
        );
        let fresh = validated_key_attestation(20, &[4, 5, 6])?;
        let rotated = rotate_wallet_unit_attestation(
            &current,
            provider.obtain_wallet_unit_attestation(fresh.evidence().clone(), until(20)?)?,
            &fresh,
            timestamp(25)?,
            &Verifier,
        );
        for result in [obtained, restored, rotated] {
            if accepted {
                assert!(result.is_ok(), "lifetime: {lifetime}");
            } else {
                assert!(matches!(
                    result,
                    Err(error) if error.reason == AttestationErrorReason::InvalidValidityWindow
                ));
            }
        }
    }
    Ok(())
}

fn key_attestation(
    issued_at: i64,
    evidence: &[u8],
) -> Result<KeyAttestationEvidence, wallet::WalletTypesError> {
    Ok(KeyAttestationEvidence {
        key_handle_id: wallet::KeyHandleId::new("key-1".to_owned())?,
        evidence: evidence.to_vec(),
        issued_at: timestamp(issued_at)?,
        challenge: [7; 32],
    })
}

fn validated_key_attestation(
    issued_at: i64,
    evidence_bytes: &[u8],
) -> Result<VerifiedKeyAttestationEvidence, TestError> {
    let evidence = key_attestation(issued_at, evidence_bytes)?;
    let handle = KeyHandle {
        id: evidence.key_handle_id.clone(),
        algorithm: SigningAlgorithm::Es256,
        created_at: timestamp(1)?,
    };
    Ok(verify_key_attestation_evidence(
        &handle,
        evidence,
        &[7; 32],
        timestamp(20)?,
        &KeyVerifier,
    )?)
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("attestation")]
    Attestation(#[from] AttestationError),
    #[error("keystore")]
    Keystore(#[from] KeystoreError),
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
}
