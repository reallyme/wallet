// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_keystore::KeyAttestationEvidence;
use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp, WalletTypesError};

use super::validate_wallet_unit_attestation;
use crate::{AttestationErrorReason, UnverifiedWalletUnitAttestation, WalletUnitAttestation};

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn attestation_with_evidence(
    evidence_bytes: Vec<u8>,
    valid_until: UnixTimestamp,
) -> Result<WalletUnitAttestation, WalletTypesError> {
    let unverified = UnverifiedWalletUnitAttestation::new(
        id("wua-1")?,
        KeyAttestationEvidence {
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            evidence: evidence_bytes,
            issued_at: timestamp(10)?,
            challenge: [7; 32],
        },
        valid_until,
        vec![0xA5],
    )
    .map_err(|_| {
        WalletTypesError::new(reallyme_wallet_types::WalletTypesErrorReason::InvalidIdentifier)
    })?;
    let thumbprint = crate::VerifiedWalletKeyThumbprint::new([1; 32]).map_err(|_| {
        WalletTypesError::new(reallyme_wallet_types::WalletTypesErrorReason::InvalidIdentifier)
    })?;
    Ok(WalletUnitAttestation::from_verified(unverified, thumbprint))
}

fn attestation() -> Result<WalletUnitAttestation, WalletTypesError> {
    attestation_with_evidence(vec![1, 2, 3], timestamp(20)?)
}

#[test]
fn validation_rejects_one_day_even_for_a_previously_verified_record() -> Result<(), WalletTypesError>
{
    for (valid_until, accepted) in [(86_409, true), (86_410, false), (86_411, false)] {
        let attestation = attestation_with_evidence(vec![1, 2, 3], timestamp(valid_until)?)?;
        let result = validate_wallet_unit_attestation(&attestation, timestamp(15)?);
        if accepted {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(error) if error.reason == AttestationErrorReason::InvalidValidityWindow
            ));
        }
    }
    Ok(())
}

#[test]
fn accepts_valid_attestation() -> Result<(), WalletTypesError> {
    let result = validate_wallet_unit_attestation(&attestation()?, timestamp(15)?);

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn rejects_empty_evidence() -> Result<(), WalletTypesError> {
    let result = UnverifiedWalletUnitAttestation::new(
        id("wua-1")?,
        KeyAttestationEvidence {
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            evidence: Vec::new(),
            issued_at: timestamp(10)?,
            challenge: [7; 32],
        },
        timestamp(20)?,
        vec![0xA5],
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::InvalidAttestationEvidence
    ));
    Ok(())
}

#[test]
fn rejects_future_evidence() -> Result<(), WalletTypesError> {
    let result = validate_wallet_unit_attestation(&attestation()?, timestamp(9)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::WalletUnitAttestationNotYetValid
    ));
    Ok(())
}
