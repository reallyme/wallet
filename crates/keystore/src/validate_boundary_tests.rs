// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{KeyHandleId, UnixTimestamp, WalletTypesError};

use super::{
    attest_key_with_validated_boundary, require_key_custody, validate_key_attestation_boundary,
    verify_key_attestation_evidence, KeyAttestationEvidenceVerifier, VerifiedKeyAttestationBinding,
    WalletKeystoreBackend,
};
use crate::{
    KeyAttestationEvidence, KeyCustodyKind, KeyHandle, KeystoreError, KeystoreErrorReason,
    KeystoreResult, Signature, SigningAlgorithm, SigningRequest, WalletKeystore,
};

struct Backend {
    custody_kind: KeyCustodyKind,
    evidence: KeyAttestationEvidence,
}

struct AcceptVerifier;
struct WrongAlgorithmVerifier;
struct HardwareVerifier;

impl KeyAttestationEvidenceVerifier for HardwareVerifier {
    fn verify_key_attestation_evidence(
        &self,
        _evidence: &KeyAttestationEvidence,
        _now: UnixTimestamp,
    ) -> KeystoreResult<VerifiedKeyAttestationBinding> {
        Ok(
            VerifiedKeyAttestationBinding::new(SigningAlgorithm::Es256, [1; 32])?
                .with_authenticated_custody(KeyCustodyKind::PlatformSecureArea),
        )
    }
}

impl KeyAttestationEvidenceVerifier for AcceptVerifier {
    fn verify_key_attestation_evidence(
        &self,
        _evidence: &KeyAttestationEvidence,
        _now: UnixTimestamp,
    ) -> KeystoreResult<VerifiedKeyAttestationBinding> {
        VerifiedKeyAttestationBinding::new(SigningAlgorithm::Es256, [1; 32])
    }
}

impl KeyAttestationEvidenceVerifier for WrongAlgorithmVerifier {
    fn verify_key_attestation_evidence(
        &self,
        _evidence: &KeyAttestationEvidence,
        _now: UnixTimestamp,
    ) -> KeystoreResult<VerifiedKeyAttestationBinding> {
        VerifiedKeyAttestationBinding::new(SigningAlgorithm::Ed25519, [1; 32])
    }
}

impl WalletKeystore for Backend {
    fn sign(&self, _key_handle: &KeyHandle, _request: SigningRequest) -> KeystoreResult<Signature> {
        Err(KeystoreError::new(KeystoreErrorReason::OperationRefused))
    }

    fn attest_key(
        &self,
        _key_handle: &KeyHandle,
        challenge: [u8; 32],
        issued_at: UnixTimestamp,
    ) -> KeystoreResult<KeyAttestationEvidence> {
        let mut evidence = self.evidence.clone();
        evidence.challenge = challenge;
        evidence.issued_at = issued_at;
        Ok(evidence)
    }
}

impl WalletKeystoreBackend for Backend {
    fn custody_kind(&self) -> KeyCustodyKind {
        self.custody_kind
    }
}

fn id(value: &str) -> Result<KeyHandleId, WalletTypesError> {
    KeyHandleId::new(value.to_owned())
}

fn timestamp(value: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(value)
}

fn key_handle() -> Result<KeyHandle, WalletTypesError> {
    Ok(KeyHandle {
        id: id("key-1")?,
        algorithm: SigningAlgorithm::Es256,
        created_at: timestamp(1)?,
    })
}

fn evidence_for(key_handle_id: &str) -> Result<KeyAttestationEvidence, WalletTypesError> {
    Ok(KeyAttestationEvidence {
        key_handle_id: id(key_handle_id)?,
        evidence: vec![1, 2, 3],
        issued_at: timestamp(10)?,
        challenge: challenge(),
    })
}

fn challenge() -> [u8; 32] {
    [7; 32]
}

#[test]
fn validates_platform_secure_area_attestation_boundary() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let backend = Backend {
        custody_kind: KeyCustodyKind::PlatformSecureArea,
        evidence: evidence_for("key-1")?,
    };

    let result = attest_key_with_validated_boundary(
        &backend,
        &AcceptVerifier,
        &key_handle,
        challenge(),
        timestamp(11)?,
    );

    assert!(
        matches!(result, Ok(evidence) if evidence.evidence().key_handle_id == key_handle.id && evidence.evidence().issued_at == timestamp(11)?)
    );
    Ok(())
}

#[test]
fn validates_vault_service_attestation_boundary() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let backend = Backend {
        custody_kind: KeyCustodyKind::VaultService,
        evidence: evidence_for("key-1")?,
    };

    let result = attest_key_with_validated_boundary(
        &backend,
        &AcceptVerifier,
        &key_handle,
        challenge(),
        timestamp(11)?,
    );

    assert!(
        matches!(result, Ok(evidence) if evidence.evidence().key_handle_id == key_handle.id && evidence.evidence().issued_at == timestamp(11)?)
    );
    Ok(())
}

#[test]
fn rejects_attestation_for_different_key_handle() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let evidence = evidence_for("key-2")?;

    let result =
        validate_key_attestation_boundary(&key_handle, &evidence, &challenge(), timestamp(11)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == KeystoreErrorReason::AttestationKeyHandleMismatch
    ));
    Ok(())
}

#[test]
fn rejects_empty_attestation_evidence() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let mut evidence = evidence_for("key-1")?;
    evidence.evidence.clear();

    let result =
        validate_key_attestation_boundary(&key_handle, &evidence, &challenge(), timestamp(11)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == KeystoreErrorReason::AttestationUnavailable
    ));
    Ok(())
}

#[test]
fn rejects_future_issued_attestation_evidence() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let evidence = evidence_for("key-1")?;

    let result =
        validate_key_attestation_boundary(&key_handle, &evidence, &challenge(), timestamp(9)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == KeystoreErrorReason::AttestationIssuedInFuture
    ));
    Ok(())
}

#[test]
fn rejects_evidence_issued_before_handle_creation() -> Result<(), WalletTypesError> {
    let mut key_handle = key_handle()?;
    key_handle.created_at = timestamp(11)?;
    let evidence = evidence_for("key-1")?;
    let result =
        validate_key_attestation_boundary(&key_handle, &evidence, &challenge(), timestamp(12)?);
    assert!(matches!(
        result,
        Err(error) if error.reason == KeystoreErrorReason::AttestationStale
    ));
    Ok(())
}

#[test]
fn rejects_zero_challenge_at_validation_boundary() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let mut evidence = evidence_for("key-1")?;
    evidence.challenge = [0; 32];
    let result =
        validate_key_attestation_boundary(&key_handle, &evidence, &[0; 32], timestamp(11)?);
    assert!(matches!(
        result,
        Err(error) if error.reason == KeystoreErrorReason::AttestationChallengeMismatch
    ));
    Ok(())
}

#[test]
fn rejects_authenticated_algorithm_mismatch() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let result = verify_key_attestation_evidence(
        &key_handle,
        evidence_for("key-1")?,
        &challenge(),
        timestamp(11)?,
        &WrongAlgorithmVerifier,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == KeystoreErrorReason::AttestationAlgorithmMismatch
    ));
    Ok(())
}

#[test]
fn hardware_custody_requires_verifier_authentication() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let hardware = Backend {
        custody_kind: KeyCustodyKind::PlatformSecureArea,
        evidence: evidence_for("key-1")?,
    };

    let unauthenticated = attest_key_with_validated_boundary(
        &hardware,
        &AcceptVerifier,
        &key_handle,
        challenge(),
        timestamp(11)?,
    )
    .map_err(|_| {
        WalletTypesError::new(reallyme_wallet_types::WalletTypesErrorReason::InvalidIdentifier)
    })?;
    assert!(matches!(
        require_key_custody(&unauthenticated, KeyCustodyKind::PlatformSecureArea),
        Err(error) if error.reason == KeystoreErrorReason::OperationRefused
    ));

    let authenticated = attest_key_with_validated_boundary(
        &hardware,
        &HardwareVerifier,
        &key_handle,
        challenge(),
        timestamp(11)?,
    )
    .map_err(|_| {
        WalletTypesError::new(reallyme_wallet_types::WalletTypesErrorReason::InvalidIdentifier)
    })?;
    assert!(require_key_custody(&authenticated, KeyCustodyKind::PlatformSecureArea).is_ok());
    Ok(())
}

#[test]
fn backend_custody_claim_contradicting_the_evidence_is_refused() -> Result<(), WalletTypesError> {
    let key_handle = key_handle()?;
    let vault = Backend {
        custody_kind: KeyCustodyKind::VaultService,
        evidence: evidence_for("key-1")?,
    };
    let result = attest_key_with_validated_boundary(
        &vault,
        &HardwareVerifier,
        &key_handle,
        challenge(),
        timestamp(11)?,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == KeystoreErrorReason::OperationRefused
    ));
    Ok(())
}
