// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authorize protocol signing inputs behind lifecycle policy.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use reallyme_wallet_lifecycle::{
    ensure_wallet_operation_allowed, WalletLifecycleRecord, WalletOperation,
};

use crate::{
    KeyAttestationEvidence, KeyHandle, KeystoreError, KeystoreErrorReason, KeystoreResult,
    SigningAlgorithm, KEY_ATTESTATION_CHALLENGE_BYTES,
};

const P256_DIGEST_BYTES: usize = 32;
const P256_RAW_SIGNATURE_BYTES: usize = 64;

/// Whether a backend must hash the input or sign an already hashed digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum SigningInputKind {
    /// Exact protocol bytes that the backend hashes under its algorithm.
    Message,
    /// A 32-byte circuit-defined P-256 prehash; the backend must not hash it again.
    P256PrehashedDigest,
}

/// Wallet protocol purpose authorized for a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum SigningPurpose {
    /// OpenID4VCI holder proof.
    OpenId4VciCredentialProof,
    /// OpenID4VP presentation response.
    OpenId4VpPresentation,
    /// Wallet unit attestation proof of possession.
    WalletUnitAttestation,
    /// Qualified electronic signature operation.
    QualifiedElectronicSignature,
    /// Qualified electronic seal operation.
    QualifiedElectronicSeal,
}

/// Protocol signing input passed to a platform signing backend.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct SigningRequest {
    purpose: SigningPurpose,
    input_kind: SigningInputKind,
    message: Zeroizing<Vec<u8>>,
}

impl SigningRequest {
    /// Return the typed purpose selected by wallet-core.
    #[must_use]
    pub const fn purpose(&self) -> SigningPurpose {
        self.purpose
    }

    /// Distinguish prehashed circuit authorization from ordinary message signing.
    #[must_use]
    pub const fn input_kind(&self) -> SigningInputKind {
        self.input_kind
    }

    /// Borrow the exact protocol-defined signing input.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// Signature returned by the platform keystore.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct Signature {
    /// Signature bytes in the algorithm-native encoding.
    pub bytes: Vec<u8>,
}

/// Platform-provided signing and attestation boundary.
pub trait WalletKeystore {
    /// Sign the exact protocol-defined message after checking its typed purpose.
    fn sign(&self, key_handle: &KeyHandle, request: SigningRequest) -> KeystoreResult<Signature>;

    /// Return fresh attestation evidence for an opaque key handle.
    fn attest_key(
        &self,
        key_handle: &KeyHandle,
        challenge: [u8; KEY_ATTESTATION_CHALLENGE_BYTES],
        issued_at: reallyme_wallet_types::UnixTimestamp,
    ) -> KeystoreResult<KeyAttestationEvidence>;
}

/// Sign one already computed common-root authorization digest through a handle.
///
/// The caller derives the circuit-defined digest and must verify the returned
/// signature against the authenticated public key before building a witness.
/// The backend returns the canonical 64-byte P-256 `r || s` encoding.
///
/// `lifecycle` must be the Wallet Unit's record as just read from durable
/// lifecycle storage. The gate here checks that record; it cannot tell a
/// stored record from one the caller built, so the keystore backend remains
/// responsible for refusing keys of a unit it knows is not active.
pub fn sign_wallet_p256_presentation_digest(
    backend: &dyn WalletKeystore,
    lifecycle: &WalletLifecycleRecord,
    key_handle: &KeyHandle,
    digest: [u8; P256_DIGEST_BYTES],
) -> KeystoreResult<[u8; P256_RAW_SIGNATURE_BYTES]> {
    ensure_wallet_operation_allowed(lifecycle, WalletOperation::SignWithWalletKey)
        .map_err(|_| KeystoreError::new(KeystoreErrorReason::WalletNotActive))?;
    if key_handle.algorithm != SigningAlgorithm::Es256 {
        return Err(KeystoreError::new(
            KeystoreErrorReason::UnsupportedAlgorithm,
        ));
    }
    let request = SigningRequest {
        purpose: SigningPurpose::OpenId4VpPresentation,
        input_kind: SigningInputKind::P256PrehashedDigest,
        message: Zeroizing::new(digest.to_vec()),
    };
    let mut result = backend.sign(key_handle, request)?;
    let signature = Zeroizing::new(core::mem::take(&mut result.bytes));
    if signature.len() != P256_RAW_SIGNATURE_BYTES || signature.iter().all(|byte| *byte == 0) {
        return Err(KeystoreError::new(KeystoreErrorReason::OperationRefused));
    }
    signature
        .as_slice()
        .try_into()
        .map_err(|_| KeystoreError::new(KeystoreErrorReason::OperationRefused))
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod tests;
