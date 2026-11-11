// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::RefCell;

use reallyme_wallet_lifecycle::{
    ensure_wallet_operation_allowed, restore_wallet_lifecycle, LifecycleError,
    WalletLifecycleEvent, WalletLifecycleEvidenceKind, WalletLifecycleEvidenceRecord,
    WalletLifecycleRecord, WalletLifecycleState, WalletOperation,
};
use reallyme_wallet_types::{KeyHandleId, NonEmptyIdentifier, UnixTimestamp, WalletTypesError};
use zeroize::Zeroizing;

use super::{
    sign_wallet_p256_presentation_digest, SigningInputKind, SigningPurpose, SigningRequest,
};
use crate::{
    KeyAttestationEvidence, KeyHandle, KeystoreError, KeystoreErrorReason, KeystoreResult,
    Signature, SigningAlgorithm, WalletKeystore,
};

const MAX_SIGNING_PAYLOAD_BYTES: usize = 262_144;

fn sign_wallet_payload(
    backend: &dyn WalletKeystore,
    lifecycle: &WalletLifecycleRecord,
    key_handle: &KeyHandle,
    purpose: SigningPurpose,
    payload: &[u8],
) -> KeystoreResult<Signature> {
    ensure_wallet_operation_allowed(lifecycle, WalletOperation::SignWithWalletKey)
        .map_err(|_| KeystoreError::new(KeystoreErrorReason::WalletNotActive))?;
    if payload.is_empty() || payload.len() > MAX_SIGNING_PAYLOAD_BYTES {
        return Err(KeystoreError::new(KeystoreErrorReason::InvalidSigningInput));
    }
    let mut message = Zeroizing::new(Vec::new());
    message
        .try_reserve_exact(payload.len())
        .map_err(|_| KeystoreError::new(KeystoreErrorReason::InvalidSigningInput))?;
    message.extend_from_slice(payload);
    backend.sign(
        key_handle,
        SigningRequest {
            purpose,
            input_kind: SigningInputKind::Message,
            message,
        },
    )
}

struct RecordingBackend {
    request: RefCell<Option<(SigningPurpose, Vec<u8>)>>,
}

struct DigestBackend {
    request: RefCell<Option<(SigningPurpose, SigningInputKind, Vec<u8>)>>,
    signature: Vec<u8>,
}

impl WalletKeystore for DigestBackend {
    fn sign(&self, _key_handle: &KeyHandle, request: SigningRequest) -> KeystoreResult<Signature> {
        self.request.replace(Some((
            request.purpose(),
            request.input_kind(),
            request.message().to_vec(),
        )));
        Ok(Signature {
            bytes: self.signature.clone(),
        })
    }

    fn attest_key(
        &self,
        _key_handle: &KeyHandle,
        _challenge: [u8; 32],
        _issued_at: UnixTimestamp,
    ) -> KeystoreResult<KeyAttestationEvidence> {
        Err(KeystoreError::new(KeystoreErrorReason::OperationRefused))
    }
}

#[derive(Debug)]
enum TestError {
    Lifecycle,
    Types,
}

impl From<LifecycleError> for TestError {
    fn from(_error: LifecycleError) -> Self {
        Self::Lifecycle
    }
}

impl From<WalletTypesError> for TestError {
    fn from(_error: WalletTypesError) -> Self {
        Self::Types
    }
}

impl WalletKeystore for RecordingBackend {
    fn sign(&self, _key_handle: &KeyHandle, request: SigningRequest) -> KeystoreResult<Signature> {
        self.request
            .replace(Some((request.purpose(), request.message().to_vec())));
        Ok(Signature {
            bytes: vec![0x30, 0x00],
        })
    }

    fn attest_key(
        &self,
        _key_handle: &KeyHandle,
        _challenge: [u8; 32],
        _issued_at: UnixTimestamp,
    ) -> KeystoreResult<KeyAttestationEvidence> {
        Err(KeystoreError::new(KeystoreErrorReason::OperationRefused))
    }
}

fn timestamp(value: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(value)
}

fn active_lifecycle() -> Result<reallyme_wallet_lifecycle::WalletLifecycleRecord, TestError> {
    let wallet_id = NonEmptyIdentifier::new("wallet-1".to_owned())?;
    let evidence = WalletLifecycleEvidenceRecord {
        id: NonEmptyIdentifier::new("evidence-1".to_owned())?,
        wallet_instance_id: wallet_id.clone(),
        kind: WalletLifecycleEvidenceKind::Provisioning,
        event: WalletLifecycleEvent::CompleteProvisioning,
        occurred_at: timestamp(1)?,
        authority_id: NonEmptyIdentifier::new("provider-1".to_owned())?,
        evidence_ref: NonEmptyIdentifier::new("reference-1".to_owned())?,
        evidence_digest: vec![1],
    };
    let lifecycle = restore_wallet_lifecycle(
        wallet_id,
        WalletLifecycleState::Active,
        timestamp(1)?,
        Some(WalletLifecycleEvent::CompleteProvisioning),
        None,
        None,
        Some(evidence),
    )?;
    Ok(lifecycle)
}

fn key_handle() -> Result<KeyHandle, WalletTypesError> {
    Ok(KeyHandle {
        id: KeyHandleId::new("key-1".to_owned())?,
        algorithm: SigningAlgorithm::Es256,
        created_at: timestamp(1)?,
    })
}

#[test]
fn passes_exact_protocol_signing_input_to_backend() -> Result<(), TestError> {
    let backend = RecordingBackend {
        request: RefCell::new(None),
    };
    let signing_input = b"eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJpc3N1ZXIifQ";

    let result = sign_wallet_payload(
        &backend,
        &active_lifecycle()?,
        &key_handle()?,
        SigningPurpose::OpenId4VciCredentialProof,
        signing_input,
    );

    assert!(result.is_ok());
    assert_eq!(
        backend.request.borrow().as_ref(),
        Some(&(
            SigningPurpose::OpenId4VciCredentialProof,
            signing_input.to_vec()
        ))
    );
    Ok(())
}

#[test]
fn rejects_empty_and_oversized_signing_inputs() -> Result<(), TestError> {
    let backend = RecordingBackend {
        request: RefCell::new(None),
    };
    let lifecycle = active_lifecycle()?;
    let key_handle = key_handle()?;
    let oversized = vec![0_u8; MAX_SIGNING_PAYLOAD_BYTES + 1];

    for payload in [&[][..], oversized.as_slice()] {
        assert!(matches!(
            sign_wallet_payload(
                &backend,
                &lifecycle,
                &key_handle,
                SigningPurpose::OpenId4VpPresentation,
                payload,
            ),
            Err(error) if error.reason == KeystoreErrorReason::InvalidSigningInput
        ));
    }
    assert!(backend.request.borrow().is_none());
    Ok(())
}

#[test]
fn presentation_digest_uses_active_handle_and_exact_prehash() -> Result<(), TestError> {
    let backend = DigestBackend {
        request: RefCell::new(None),
        signature: vec![0x41; 64],
    };
    let digest = [0x29; 32];
    let signed = sign_wallet_p256_presentation_digest(
        &backend,
        &active_lifecycle()?,
        &key_handle()?,
        digest,
    );
    assert_eq!(signed.ok(), Some([0x41; 64]));
    assert_eq!(
        backend.request.borrow().as_ref(),
        Some(&(
            SigningPurpose::OpenId4VpPresentation,
            SigningInputKind::P256PrehashedDigest,
            digest.to_vec(),
        ))
    );
    Ok(())
}

#[test]
fn presentation_digest_rejects_wrong_lifecycle_algorithm_and_signature() -> Result<(), TestError> {
    let backend = DigestBackend {
        request: RefCell::new(None),
        signature: vec![0x41; 63],
    };
    let inactive = restore_wallet_lifecycle(
        NonEmptyIdentifier::new("wallet-inactive".to_owned())?,
        WalletLifecycleState::Unprovisioned,
        timestamp(1)?,
        None,
        None,
        None,
        None,
    )?;
    let handle = key_handle()?;
    assert!(matches!(
        sign_wallet_p256_presentation_digest(&backend, &inactive, &handle, [0x29; 32]),
        Err(error) if error.reason == KeystoreErrorReason::WalletNotActive
    ));
    assert!(backend.request.borrow().is_none());

    let mut wrong_algorithm = key_handle()?;
    wrong_algorithm.algorithm = SigningAlgorithm::Ed25519;
    assert!(matches!(
        sign_wallet_p256_presentation_digest(
            &backend,
            &active_lifecycle()?,
            &wrong_algorithm,
            [0x29; 32],
        ),
        Err(error) if error.reason == KeystoreErrorReason::UnsupportedAlgorithm
    ));
    assert!(backend.request.borrow().is_none());

    assert!(matches!(
        sign_wallet_p256_presentation_digest(&backend, &active_lifecycle()?, &handle, [0x29; 32]),
        Err(error) if error.reason == KeystoreErrorReason::OperationRefused
    ));
    Ok(())
}
