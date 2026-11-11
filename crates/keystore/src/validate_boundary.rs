// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate the injected WSCD/WSCA keystore boundary.

use reallyme_wallet_types::UnixTimestamp;
use zeroize::ZeroizeOnDrop;

use crate::{
    KeyAttestationEvidence, KeyCustodyKind, KeyHandle, KeystoreError, KeystoreErrorReason,
    KeystoreResult, WalletKeystore, KEY_ATTESTATION_CHALLENGE_BYTES,
    MAX_KEY_ATTESTATION_EVIDENCE_BYTES,
};

const MAX_KEY_ATTESTATION_AGE_SECONDS: i64 = 300;

/// Public-key identity and algorithm authenticated by the hardware verifier.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct VerifiedKeyAttestationBinding {
    algorithm: crate::SigningAlgorithm,
    key_thumbprint: [u8; 32],
    custody_kind: Option<KeyCustodyKind>,
}

impl VerifiedKeyAttestationBinding {
    /// Construct the verifier result from authenticated public-key material.
    pub fn new(
        algorithm: crate::SigningAlgorithm,
        key_thumbprint: [u8; 32],
    ) -> KeystoreResult<Self> {
        if key_thumbprint.iter().all(|byte| *byte == 0) {
            return Err(KeystoreError::new(
                KeystoreErrorReason::AttestationUnavailable,
            ));
        }
        Ok(Self {
            algorithm,
            key_thumbprint,
            custody_kind: None,
        })
    }

    /// Record the custody class the verifier authenticated from the evidence.
    ///
    /// Report this only when the attestation chain itself establishes it, for
    /// example a hardware security level asserted by the platform root. A
    /// backend's own claim is never sufficient.
    #[must_use]
    pub const fn with_authenticated_custody(mut self, custody_kind: KeyCustodyKind) -> Self {
        self.custody_kind = Some(custody_kind);
        self
    }
}

/// Evidence promoted only after handle, challenge, time, and signature checks.
#[derive(ZeroizeOnDrop)]
pub struct VerifiedKeyAttestationEvidence {
    evidence: KeyAttestationEvidence,
    binding: VerifiedKeyAttestationBinding,
}

impl VerifiedKeyAttestationEvidence {
    /// Borrow the checked evidence for a provider exchange.
    #[must_use]
    pub const fn evidence(&self) -> &KeyAttestationEvidence {
        &self.evidence
    }

    /// Borrow the authenticated public-key fingerprint for WUA binding.
    #[must_use]
    pub const fn key_thumbprint(&self) -> &[u8; 32] {
        &self.binding.key_thumbprint
    }

    /// Return the custody class authenticated by the verifier, if it reported one.
    #[must_use]
    pub const fn authenticated_custody(&self) -> Option<KeyCustodyKind> {
        self.binding.custody_kind
    }
}

/// Wallet keystore backend selected by identity or an application.
///
/// Wallet-core uses the custody kind only for policy and audit branching. The
/// concrete platform secure-area or vault-service implementation remains above
/// this crate and never exposes private key material.
pub trait WalletKeystoreBackend: WalletKeystore {
    /// Return the custody class implemented by this backend.
    fn custody_kind(&self) -> KeyCustodyKind;
}

/// Cryptographic verifier for opaque key-attestation evidence.
pub trait KeyAttestationEvidenceVerifier {
    /// Verify the evidence signature/chain and binding to every typed field.
    ///
    /// The freshness and challenge checks in this crate read `issued_at` and
    /// `challenge` from `evidence`. The verifier must therefore confirm that
    /// both values are covered by the signed attestation, so a backend cannot
    /// make stale evidence look fresh by restamping the struct.
    fn verify_key_attestation_evidence(
        &self,
        evidence: &KeyAttestationEvidence,
        now: UnixTimestamp,
    ) -> KeystoreResult<VerifiedKeyAttestationBinding>;
}

/// Request key attestation through an injected backend and validate the boundary result.
pub fn attest_key_with_validated_boundary<B, V>(
    backend: &B,
    verifier: &V,
    key_handle: &KeyHandle,
    challenge: [u8; KEY_ATTESTATION_CHALLENGE_BYTES],
    now: UnixTimestamp,
) -> KeystoreResult<VerifiedKeyAttestationEvidence>
where
    B: WalletKeystoreBackend,
    V: KeyAttestationEvidenceVerifier + ?Sized,
{
    if challenge.iter().all(|byte| *byte == 0) {
        return Err(KeystoreError::new(
            KeystoreErrorReason::AttestationChallengeMismatch,
        ));
    }
    let evidence = backend.attest_key(key_handle, challenge, now)?;
    let verified =
        verify_key_attestation_evidence(key_handle, evidence, &challenge, now, verifier)?;
    // A backend that claims a custody class the evidence contradicts is not
    // trusted for any key operation.
    if verified
        .authenticated_custody()
        .is_some_and(|custody| custody != backend.custody_kind())
    {
        return Err(KeystoreError::new(KeystoreErrorReason::OperationRefused));
    }
    Ok(verified)
}

/// Require verifier-authenticated custody of the given class.
///
/// Use this where policy demands hardware-backed keys. Evidence whose verifier
/// reported no custody, or a different custody, is refused.
pub fn require_key_custody(
    evidence: &VerifiedKeyAttestationEvidence,
    required: KeyCustodyKind,
) -> KeystoreResult<()> {
    if evidence.authenticated_custody() == Some(required) {
        Ok(())
    } else {
        Err(KeystoreError::new(KeystoreErrorReason::OperationRefused))
    }
}

/// Promote externally decoded key evidence through the same trust boundary.
pub fn verify_key_attestation_evidence<V>(
    key_handle: &KeyHandle,
    evidence: KeyAttestationEvidence,
    expected_challenge: &[u8; KEY_ATTESTATION_CHALLENGE_BYTES],
    now: UnixTimestamp,
    verifier: &V,
) -> KeystoreResult<VerifiedKeyAttestationEvidence>
where
    V: KeyAttestationEvidenceVerifier + ?Sized,
{
    validate_key_attestation_boundary(key_handle, &evidence, expected_challenge, now)?;
    let binding = verifier.verify_key_attestation_evidence(&evidence, now)?;
    if binding.algorithm != key_handle.algorithm {
        return Err(KeystoreError::new(
            KeystoreErrorReason::AttestationAlgorithmMismatch,
        ));
    }
    Ok(VerifiedKeyAttestationEvidence { evidence, binding })
}

/// Validate that attestation evidence is usable for a key handle at a point in time.
pub fn validate_key_attestation_boundary(
    key_handle: &KeyHandle,
    evidence: &KeyAttestationEvidence,
    expected_challenge: &[u8; KEY_ATTESTATION_CHALLENGE_BYTES],
    now: UnixTimestamp,
) -> KeystoreResult<()> {
    if evidence.key_handle_id != key_handle.id {
        return Err(KeystoreError::new(
            KeystoreErrorReason::AttestationKeyHandleMismatch,
        ));
    }
    // A key cannot have been attested before its handle existed. This check
    // also prevents a stale document from being rebound to a later handle ID.
    if evidence.issued_at < key_handle.created_at {
        return Err(KeystoreError::new(KeystoreErrorReason::AttestationStale));
    }
    if evidence.evidence.is_empty() || evidence.evidence.len() > MAX_KEY_ATTESTATION_EVIDENCE_BYTES
    {
        return Err(KeystoreError::new(
            KeystoreErrorReason::AttestationUnavailable,
        ));
    }
    if evidence.issued_at > now {
        return Err(KeystoreError::new(
            KeystoreErrorReason::AttestationIssuedInFuture,
        ));
    }
    let oldest = now
        .as_seconds()
        .checked_sub(MAX_KEY_ATTESTATION_AGE_SECONDS)
        .ok_or_else(|| KeystoreError::new(KeystoreErrorReason::AttestationStale))?;
    if expected_challenge.iter().all(|byte| *byte == 0) || evidence.challenge != *expected_challenge
    {
        return Err(KeystoreError::new(
            KeystoreErrorReason::AttestationChallengeMismatch,
        ));
    }
    if evidence.issued_at.as_seconds() < oldest {
        return Err(KeystoreError::new(KeystoreErrorReason::AttestationStale));
    }

    Ok(())
}

#[cfg(test)]
#[path = "validate_boundary_tests.rs"]
mod tests;
