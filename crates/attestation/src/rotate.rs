// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rotate wallet unit attestations.

use reallyme_wallet_keystore::VerifiedKeyAttestationEvidence;
use reallyme_wallet_types::UnixTimestamp;

use crate::obtain::validate_key_evidence_freshness;
use crate::{
    verify_wallet_unit_attestation, AttestationError, AttestationErrorReason, AttestationResult,
    UnverifiedWalletUnitAttestation, WalletUnitAttestation, WalletUnitAttestationVerifier,
};

/// Replace a wallet unit attestation with a validated replacement.
///
/// The replacement must keep the same key, carry fresh key evidence issued
/// after the current attestation's evidence, and be valid now. `fresh_evidence` is the key evidence the Wallet sent for this
/// rotation, already checked by the keystore boundary against a challenge the
/// Wallet issued. The replacement must carry exactly that evidence, so a
/// captured older provider response cannot be offered as a rotation. Callers
/// persist the returned attestation in place of `current` so the superseded
/// attestation is no longer presented.
pub fn rotate_wallet_unit_attestation(
    current: &WalletUnitAttestation,
    replacement: UnverifiedWalletUnitAttestation,
    fresh_evidence: &VerifiedKeyAttestationEvidence,
    now: UnixTimestamp,
    verifier: &impl WalletUnitAttestationVerifier,
) -> AttestationResult<WalletUnitAttestation> {
    if replacement.evidence() != fresh_evidence.evidence() {
        return Err(AttestationError::new(
            AttestationErrorReason::ProviderBindingMismatch,
        ));
    }
    if current.id() == replacement.id() {
        return Err(AttestationError::new(
            AttestationErrorReason::ReplacementNotAvailable,
        ));
    }
    if current.evidence().key_handle_id != replacement.evidence().key_handle_id {
        return Err(AttestationError::new(
            AttestationErrorReason::KeyContinuityMismatch,
        ));
    }

    // A rotation must move forward: fresh key evidence issued after the
    // current attestation's evidence. The replacement may expire earlier than
    // the current one, for example when the provider shortens WUA lifetime,
    // but it must still be valid now.
    validate_key_evidence_freshness(replacement.evidence(), now)?;
    if replacement.evidence().issued_at <= current.evidence().issued_at
        || replacement.valid_until() <= now
    {
        return Err(AttestationError::new(
            AttestationErrorReason::ReplacementNotAvailable,
        ));
    }

    let verified_replacement = verify_wallet_unit_attestation(replacement, verifier, now)?;
    if verified_replacement.verified_key_thumbprint().as_bytes() != fresh_evidence.key_thumbprint()
    {
        return Err(AttestationError::new(
            AttestationErrorReason::ProviderBindingMismatch,
        ));
    }
    if current.verified_key_thumbprint() != verified_replacement.verified_key_thumbprint() {
        return Err(AttestationError::new(
            AttestationErrorReason::KeyContinuityMismatch,
        ));
    }
    Ok(verified_replacement)
}

#[cfg(test)]
#[path = "rotate_tests.rs"]
mod tests;
