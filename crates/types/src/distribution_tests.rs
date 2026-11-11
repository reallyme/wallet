// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{DistributionBarcode, DistributionBarcodeFormat, DistributionCard, DistributionField};
use crate::{UnixTimestamp, WalletTypesError, WalletTypesErrorReason};

fn valid_card() -> Result<DistributionCard, WalletTypesError> {
    Ok(DistributionCard {
        title: "PID".to_owned(),
        subtitle: Some("Person identification data".to_owned()),
        issuer: "ReallyMe QTSP".to_owned(),
        valid_until: Some(UnixTimestamp::from_seconds(1_900_000_000)?),
        fields: vec![DistributionField {
            label: "Age".to_owned(),
            value: "Over 18".to_owned(),
            emphasized: true,
        }],
        barcode: Some(DistributionBarcode {
            format: DistributionBarcodeFormat::Qr,
            payload: b"openid4vp://authorize".to_vec(),
        }),
        verification_uri: Some("https://verify.example/session".to_owned()),
    })
}

#[test]
fn validates_distribution_card() -> Result<(), WalletTypesError> {
    valid_card()?.validate()
}

#[test]
fn rejects_empty_title() -> Result<(), WalletTypesError> {
    let mut card = valid_card()?;
    card.title.clear();

    let result = card.validate();

    assert!(matches!(
        result,
        Err(error) if error.reason == WalletTypesErrorReason::InvalidDistributionCard
    ));
    Ok(())
}

#[test]
fn rejects_control_and_direction_changing_display_text() -> Result<(), WalletTypesError> {
    for value in ["Alice\nAdmin", "Alice\u{202e}nimdA", "Alice\u{2067}Admin"] {
        let mut card = valid_card()?;
        card.fields[0].value = value.to_owned();
        assert!(matches!(
            card.validate(),
            Err(error) if error.reason == WalletTypesErrorReason::InvalidDistributionCard
        ));
    }
    Ok(())
}

#[test]
fn rejects_too_many_fields() -> Result<(), WalletTypesError> {
    let mut card = valid_card()?;
    card.fields = (0..33)
        .map(|index| DistributionField {
            label: "Field".to_owned(),
            value: index.to_string(),
            emphasized: false,
        })
        .collect();

    let result = card.validate();

    assert!(matches!(
        result,
        Err(error) if error.reason == WalletTypesErrorReason::TooManyDistributionFields
    ));
    Ok(())
}

#[test]
fn rejects_empty_barcode_payload() -> Result<(), WalletTypesError> {
    let mut card = valid_card()?;
    card.barcode = Some(DistributionBarcode {
        format: DistributionBarcodeFormat::Qr,
        payload: Vec::new(),
    });

    let result = card.validate();

    assert!(matches!(
        result,
        Err(error) if error.reason == WalletTypesErrorReason::DistributionBarcodeTooLarge
    ));
    Ok(())
}

#[test]
fn verification_uri_must_be_https_without_credentials() -> Result<(), WalletTypesError> {
    for uri in [
        "javascript:alert(1)",
        "data:text/html,x",
        "http://verify.example/session",
        "https://user@verify.example/session",
        "verify.example/session",
    ] {
        let mut invalid = valid_card()?;
        invalid.verification_uri = Some(uri.to_owned());
        assert!(invalid.validate().is_err());
    }
    Ok(())
}

#[test]
fn barcode_declares_drop_time_wiping() {
    // This checks the declared contract only; the wipe itself is the manual
    // `Drop` implementation on `DistributionBarcode`.
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<DistributionBarcode>();
}

#[test]
fn code128_barcode_rejects_non_ascii_payload() -> Result<(), WalletTypesError> {
    let mut card = valid_card()?;
    card.barcode = Some(DistributionBarcode {
        format: DistributionBarcodeFormat::Code128,
        payload: "caf\u{e9}".as_bytes().to_vec(),
    });
    assert!(card.validate().is_err());
    card.barcode = Some(DistributionBarcode {
        format: DistributionBarcodeFormat::Code128,
        payload: b"CAFE-128".to_vec(),
    });
    card.validate()
}
