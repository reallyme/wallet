// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::ZeroizeOnDrop;

use super::{
    AttributeName, KeyHandleId, NonEmptyIdentifier, SignedCredentialIssuer,
    MAX_SIGNED_CREDENTIAL_ISSUER_BYTES,
};
use crate::WalletTypesErrorReason;

#[test]
fn rejects_empty_identifier() {
    let result = NonEmptyIdentifier::new(String::new());

    assert!(matches!(
        result,
        Err(error) if error.reason == WalletTypesErrorReason::EmptyIdentifier
    ));
}

#[test]
fn identifier_and_attribute_names_reject_unsafe_display_and_path_syntax() {
    for malformed in [
        "../record",
        "part/../record",
        "part\\..\\record",
        "part/%2e%2e/record",
        "..%2f..%2frecord",
        "part%5C..%5Crecord",
        "%252e%252e/record",
        "nul\0key",
        "line\nkey",
        "\u{202e}evil",
    ] {
        assert!(matches!(
            NonEmptyIdentifier::new(malformed.to_owned()),
            Err(error) if error.reason == WalletTypesErrorReason::InvalidIdentifier
        ));
    }
    for malformed in [
        "../attribute",
        "one/two",
        "space name",
        "nul\0key",
        "\u{202e}evil",
    ] {
        assert!(matches!(
            AttributeName::new(malformed.to_owned()),
            Err(error) if error.reason == WalletTypesErrorReason::InvalidIdentifier
        ));
    }
    assert!(NonEmptyIdentifier::new("https://issuer.example/path".to_owned()).is_ok());
    for accepted in [
        "redirect_uri:https%3A%2F%2Fverifier.example%2Fcallback",
        "issuer.example%2Ftenant%2E1",
        "100%25-match",
    ] {
        assert!(NonEmptyIdentifier::new(accepted.to_owned()).is_ok());
    }
    for malformed in [
        "%25252e%25252e/record",
        "key%2F..%2Fother",
        "%2%65%2%65/record",
        "%%32%65%%32%65/x",
        "part%5c%2E%2e",
        "..",
        "key\\name",
    ] {
        assert!(matches!(
            KeyHandleId::new(malformed.to_owned()),
            Err(error) if error.reason == WalletTypesErrorReason::InvalidIdentifier
        ));
    }
    assert!(KeyHandleId::new("device-key%2F1".to_owned()).is_ok());
    assert!(AttributeName::new("org.iso.18013.5.1:age_over_18".to_owned()).is_ok());
}

#[test]
fn debug_output_redacts_identifier_values() -> Result<(), crate::WalletTypesError> {
    let identifier = NonEmptyIdentifier::new("subject-identifier".to_owned())?;
    let attribute = AttributeName::new("family_name".to_owned())?;

    assert_eq!(format!("{identifier:?}"), "NonEmptyIdentifier(<redacted>)");
    assert_eq!(format!("{attribute:?}"), "AttributeName(<redacted>)");
    Ok(())
}

#[test]
fn identifiers_advertise_drop_time_zeroization() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<NonEmptyIdentifier>();
    assert_zeroize_on_drop::<KeyHandleId>();
    assert_zeroize_on_drop::<AttributeName>();
    assert_zeroize_on_drop::<SignedCredentialIssuer>();
}

#[test]
fn signed_credential_issuer_enforces_the_receipt_policy_bound() {
    assert!(SignedCredentialIssuer::new("i".repeat(MAX_SIGNED_CREDENTIAL_ISSUER_BYTES)).is_ok());
    assert!(SignedCredentialIssuer::new(
        "i".repeat(MAX_SIGNED_CREDENTIAL_ISSUER_BYTES.saturating_add(1))
    )
    .is_err());
}

#[test]
fn key_handle_is_distinct_redacted_and_rejects_non_graphic_input(
) -> Result<(), crate::WalletTypesError> {
    let handle = KeyHandleId::new("holder-key-1".to_owned())?;

    assert_eq!(format!("{handle:?}"), "KeyHandleId(<redacted>)");
    for malformed in [" holder-key-1", "holder key", "holder\nkey", "clé"] {
        assert!(matches!(
            KeyHandleId::new(malformed.to_owned()),
            Err(error) if error.reason == WalletTypesErrorReason::InvalidIdentifier
        ));
    }
    Ok(())
}

#[test]
fn rejects_empty_attribute_name() {
    let result = AttributeName::new(String::new());

    assert!(matches!(
        result,
        Err(error) if error.reason == WalletTypesErrorReason::EmptyAttributeName
    ));
}

/// Report whether `T` implements `Zeroize`, without requiring it to.
///
/// The inherent constant applies only when the bound holds; otherwise the
/// blanket trait constant is used.
struct ZeroizeProbe<T>(core::marker::PhantomData<T>);

trait LacksZeroize {
    const IMPLEMENTS_ZEROIZE: bool = false;
}

impl<T> LacksZeroize for ZeroizeProbe<T> {}

impl<T: zeroize::Zeroize> ZeroizeProbe<T> {
    const IMPLEMENTS_ZEROIZE: bool = true;
}

// A public `zeroize()` would leave an empty identifier that the constructors
// refuse. These types wipe themselves only when dropped; the build fails if
// one of them gains `Zeroize` again.
const _: () = {
    assert!(!ZeroizeProbe::<NonEmptyIdentifier>::IMPLEMENTS_ZEROIZE);
    assert!(!ZeroizeProbe::<KeyHandleId>::IMPLEMENTS_ZEROIZE);
    assert!(!ZeroizeProbe::<AttributeName>::IMPLEMENTS_ZEROIZE);
    assert!(!ZeroizeProbe::<SignedCredentialIssuer>::IMPLEMENTS_ZEROIZE);
    assert!(ZeroizeProbe::<String>::IMPLEMENTS_ZEROIZE);
};
