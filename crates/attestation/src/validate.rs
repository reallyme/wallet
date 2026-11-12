// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate wallet unit attestation lifecycle state.

use reallyme_wallet_keystore::MAX_KEY_ATTESTATION_EVIDENCE_BYTES;
use reallyme_wallet_types::UnixTimestamp;

use crate::{
    AttestationError, AttestationErrorReason, AttestationResult, UnverifiedWalletUnitAttestation,
    WalletUnitAttestation,
};

// ARF v3.0.0 §6.5.3.5 requires WIA technical validity to be less than
// 24 hours. This bound is exclusive; revocation maintenance is a separate period.
const WALLET_UNIT_ATTESTATION_LIFETIME_LIMIT_SECONDS: i64 = 86_400;

/// Validate that a wallet unit attestation is usable at a point in time.
pub fn validate_wallet_unit_attestation(
    attestation: &WalletUnitAttestation,
    now: UnixTimestamp,
) -> AttestationResult<()> {
    validate_fields(attestation.evidence(), attestation.valid_until(), now)
}

pub(crate) fn validate_unverified_wallet_unit_attestation(
    attestation: &UnverifiedWalletUnitAttestation,
    now: UnixTimestamp,
) -> AttestationResult<()> {
    validate_fields(attestation.evidence(), attestation.valid_until(), now)
}

fn validate_fields(
    evidence: &reallyme_wallet_keystore::KeyAttestationEvidence,
    valid_until: UnixTimestamp,
    now: UnixTimestamp,
) -> AttestationResult<()> {
    if evidence.evidence.is_empty()
        || evidence.evidence.len() > MAX_KEY_ATTESTATION_EVIDENCE_BYTES
        || evidence.challenge.iter().all(|byte| *byte == 0)
    {
        return Err(AttestationError::new(
            AttestationErrorReason::InvalidAttestationEvidence,
        ));
    }
    if valid_until < evidence.issued_at {
        return Err(AttestationError::new(
            AttestationErrorReason::InvalidValidityWindow,
        ));
    }
    let lifetime = valid_until
        .as_seconds()
        .checked_sub(evidence.issued_at.as_seconds())
        .ok_or_else(|| AttestationError::new(AttestationErrorReason::InvalidValidityWindow))?;
    if lifetime >= WALLET_UNIT_ATTESTATION_LIFETIME_LIMIT_SECONDS {
        return Err(AttestationError::new(
            AttestationErrorReason::InvalidValidityWindow,
        ));
    }
    if evidence.issued_at > now {
        return Err(AttestationError::new(
            AttestationErrorReason::WalletUnitAttestationNotYetValid,
        ));
    }
    if now > valid_until {
        return Err(AttestationError::new(
            AttestationErrorReason::WalletUnitAttestationExpired,
        ));
    }

    Ok(())
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod tests;
