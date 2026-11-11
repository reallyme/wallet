// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::ZeroizeOnDrop;

use super::{UnverifiedWalletUnitAttestation, WalletUnitAttestation};
use crate::AttestationErrorReason;
use reallyme_wallet_keystore::{KeyAttestationEvidence, MAX_KEY_ATTESTATION_EVIDENCE_BYTES};
use reallyme_wallet_types::{KeyHandleId, NonEmptyIdentifier, UnixTimestamp, WalletTypesError};

#[test]
fn wallet_attestations_advertise_drop_time_zeroization() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<WalletUnitAttestation>();
}

#[test]
fn unverified_attestation_rejects_oversized_evidence() -> Result<(), WalletTypesError> {
    let result = UnverifiedWalletUnitAttestation::new(
        NonEmptyIdentifier::new("wua-1".to_owned())?,
        KeyAttestationEvidence {
            key_handle_id: KeyHandleId::new("key-1".to_owned())?,
            evidence: vec![0xA5; MAX_KEY_ATTESTATION_EVIDENCE_BYTES + 1],
            issued_at: UnixTimestamp::from_seconds(10)?,
            challenge: [7; 32],
        },
        UnixTimestamp::from_seconds(20)?,
        vec![0xA5],
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == AttestationErrorReason::InvalidAttestationEvidence
    ));
    Ok(())
}
