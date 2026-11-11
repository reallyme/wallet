// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_types::ClientIdentifier;
use reallyme_wallet_types::{
    AttributeName, ConsentScope, NonEmptyIdentifier, UnixTimestamp, VerifierEntitlement,
};
use zeroize::ZeroizeOnDrop;

use super::{RegistrationAuthorizationSource, VerifiedRegistrationAuthorization};
use crate::ConsentErrorReason;

fn timestamp(seconds: i64) -> UnixTimestamp {
    UnixTimestamp::from_seconds(seconds).expect("fixture time is valid")
}

fn entitlement() -> VerifierEntitlement {
    VerifierEntitlement {
        relying_party_id: NonEmptyIdentifier::new("https://verifier.example".to_owned())
            .expect("fixture RP is valid"),
        authorized_scope: ConsentScope {
            attributes: vec![
                AttributeName::new("age_over_18".to_owned()).expect("fixture attribute is valid")
            ],
        },
        valid_until: timestamp(100),
    }
}

fn client_id(value: &str) -> ClientIdentifier {
    ClientIdentifier::parse(value).expect("fixture client identifier is valid")
}

#[test]
fn registration_receipt_requires_short_fresh_x509_hash_binding() {
    let valid = VerifiedRegistrationAuthorization::new(
        entitlement(),
        client_id("x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        [7; 32],
        timestamp(10),
        timestamp(70),
        RegistrationAuthorizationSource::Wrprc,
    )
    .expect("bounded authenticated facts are admitted");
    assert_eq!(valid.source(), RegistrationAuthorizationSource::Wrprc);

    for (client, digest, validated_at, fresh_until) in [
        (
            "x509_san_dns:verifier.example",
            [7; 32],
            timestamp(10),
            timestamp(20),
        ),
        (
            "x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            [0; 32],
            timestamp(10),
            timestamp(20),
        ),
        (
            "x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            [7; 32],
            timestamp(20),
            timestamp(10),
        ),
    ] {
        let result = VerifiedRegistrationAuthorization::new(
            entitlement(),
            client_id(client),
            digest,
            validated_at,
            fresh_until,
            RegistrationAuthorizationSource::RegistrarRecord,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason == ConsentErrorReason::ClientBindingMismatch
        ));
    }

    let stale = VerifiedRegistrationAuthorization::new(
        entitlement(),
        client_id("x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        [7; 32],
        timestamp(10),
        timestamp(71),
        RegistrationAuthorizationSource::RegistrarRecord,
    );
    assert!(matches!(
        stale,
        Err(error) if error.reason == ConsentErrorReason::RegistrationCertificateStale
    ));
}

#[test]
fn verified_registration_claims_wipe_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<VerifiedRegistrationAuthorization>();
}
