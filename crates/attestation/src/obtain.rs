// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Obtain wallet unit attestations through an injected provider.

use reallyme_wallet_keystore::{
    KeyAttestationEvidence, VerifiedKeyAttestationEvidence, MAX_KEY_ATTESTATION_EVIDENCE_BYTES,
};
use reallyme_wallet_types::{KeyHandleId, UnixTimestamp};
use subtle::ConstantTimeEq;

use crate::validate::validate_unverified_wallet_unit_attestation;
use crate::{
    AttestationResult, UnverifiedWalletUnitAttestation, VerifiedWalletKeyThumbprint,
    WalletUnitAttestation,
};

const MAX_KEY_ATTESTATION_AGE_SECONDS: i64 = 300;

/// Wallet-provider boundary for obtaining wallet unit attestations.
pub trait WalletUnitAttestationProvider {
    /// Exchange key attestation evidence for a wallet unit attestation.
    fn obtain_wallet_unit_attestation(
        &self,
        evidence: KeyAttestationEvidence,
        valid_until: UnixTimestamp,
    ) -> AttestationResult<UnverifiedWalletUnitAttestation>;
}

/// Cryptographic trust boundary for provider-issued Wallet Unit Attestations.
///
/// The signature must cover the whole key evidence, including its challenge
/// and `issued_at`. Wallet relies on both for freshness, so a verifier that
/// checks only the artifact bytes would let restamped evidence pass.
pub trait WalletUnitAttestationVerifier {
    /// Verify the attestation issuer signature, chain, and signed payload binding.
    fn verify_wallet_unit_attestation(
        &self,
        attestation: &UnverifiedWalletUnitAttestation,
        now: UnixTimestamp,
    ) -> AttestationResult<VerifiedWalletKeyThumbprint>;
}

/// Obtain and validate a wallet unit attestation.
pub fn obtain_wallet_unit_attestation<P, V>(
    provider: &P,
    verifier: &V,
    evidence: VerifiedKeyAttestationEvidence,
    valid_until: UnixTimestamp,
    now: UnixTimestamp,
) -> AttestationResult<WalletUnitAttestation>
where
    P: WalletUnitAttestationProvider,
    V: WalletUnitAttestationVerifier,
{
    // Reject before cloning provider-controlled evidence into a second buffer.
    if evidence.evidence().evidence.is_empty()
        || evidence.evidence().evidence.len() > MAX_KEY_ATTESTATION_EVIDENCE_BYTES
    {
        return Err(crate::AttestationError::new(
            crate::AttestationErrorReason::InvalidAttestationEvidence,
        ));
    }
    // Freshness is required when first exchanging key evidence. A previously
    // issued WUA may be reverified throughout its own signed validity window.
    validate_key_evidence_freshness(evidence.evidence(), now)?;
    let expected_evidence = evidence.evidence().clone();
    let attestation =
        provider.obtain_wallet_unit_attestation(evidence.evidence().clone(), valid_until)?;
    if attestation.evidence() != &expected_evidence || attestation.valid_until() != valid_until {
        return Err(crate::AttestationError::new(
            crate::AttestationErrorReason::ProviderBindingMismatch,
        ));
    }
    let verified_attestation = verify_wallet_unit_attestation(attestation, verifier, now)?;
    if verified_attestation.verified_key_thumbprint().as_bytes() != evidence.key_thumbprint() {
        return Err(crate::AttestationError::new(
            crate::AttestationErrorReason::ProviderBindingMismatch,
        ));
    }
    Ok(verified_attestation)
}

/// Require newly exchanged key evidence to be recent and challenge-bound.
pub(crate) fn validate_key_evidence_freshness(
    evidence: &KeyAttestationEvidence,
    now: UnixTimestamp,
) -> AttestationResult<()> {
    let age = now
        .as_seconds()
        .checked_sub(evidence.issued_at.as_seconds())
        .ok_or_else(|| {
            crate::AttestationError::new(crate::AttestationErrorReason::AttestationChallengeStale)
        })?;
    if evidence.challenge.iter().all(|byte| *byte == 0)
        || !(0..=MAX_KEY_ATTESTATION_AGE_SECONDS).contains(&age)
    {
        return Err(crate::AttestationError::new(
            crate::AttestationErrorReason::AttestationChallengeStale,
        ));
    }
    Ok(())
}

/// Verify a stored attestation and require it to belong to the expected key.
///
/// Use this when restoring a WUA from storage. The verifier derives the key
/// thumbprint from the signed provider artifact; it must equal the thumbprint
/// of the Wallet Unit's own attested key, and the evidence must name the
/// expected key handle, or the attestation belongs to another Wallet Unit.
pub fn verify_wallet_unit_attestation_for_key<V>(
    attestation: UnverifiedWalletUnitAttestation,
    verifier: &V,
    now: UnixTimestamp,
    expected_key_handle_id: &KeyHandleId,
    expected_key_thumbprint: &[u8; 32],
) -> AttestationResult<WalletUnitAttestation>
where
    V: WalletUnitAttestationVerifier + ?Sized,
{
    if &attestation.evidence().key_handle_id != expected_key_handle_id {
        return Err(crate::AttestationError::new(
            crate::AttestationErrorReason::ProviderBindingMismatch,
        ));
    }
    let verified = verify_wallet_unit_attestation(attestation, verifier, now)?;
    if !bool::from(
        verified
            .verified_key_thumbprint()
            .as_bytes()
            .ct_eq(expected_key_thumbprint),
    ) {
        return Err(crate::AttestationError::new(
            crate::AttestationErrorReason::ProviderBindingMismatch,
        ));
    }
    Ok(verified)
}

/// Verify and promote a decoded or provider-returned attestation.
pub fn verify_wallet_unit_attestation<V>(
    attestation: UnverifiedWalletUnitAttestation,
    verifier: &V,
    now: UnixTimestamp,
) -> AttestationResult<WalletUnitAttestation>
where
    V: WalletUnitAttestationVerifier + ?Sized,
{
    validate_unverified_wallet_unit_attestation(&attestation, now)?;
    let verified_key_thumbprint = verifier.verify_wallet_unit_attestation(&attestation, now)?;
    Ok(WalletUnitAttestation::from_verified(
        attestation,
        verified_key_thumbprint,
    ))
}

#[cfg(test)]
#[path = "obtain_tests.rs"]
mod tests;
