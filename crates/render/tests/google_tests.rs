// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for Google Wallet rendering.

use reallyme_wallet_render::{
    build_google_wallet_save_link, GoogleWalletClock, GoogleWalletConfig, GoogleWalletJwtConfig,
    GoogleWalletRenderer, GoogleWalletSaveConfig, GoogleWalletSigner, RenderError,
    RenderErrorReason, WalletRenderer,
};
use reallyme_wallet_types::{
    DistributionBarcode, DistributionBarcodeFormat, DistributionCard, DistributionField,
    UnixTimestamp, WalletTypesError,
};
use serde_json::Value;

struct PrefixSigner;

struct FixedClock(UnixTimestamp);

impl GoogleWalletClock for FixedClock {
    fn now(&self) -> Result<UnixTimestamp, RenderError> {
        Ok(self.0)
    }
}

fn clock() -> Result<FixedClock, WalletTypesError> {
    Ok(FixedClock(UnixTimestamp::from_seconds(1_800_000_000)?))
}

impl GoogleWalletSigner for PrefixSigner {
    fn sign_payload(&self, payload_json: &[u8]) -> Result<Vec<u8>, RenderError> {
        let mut signed = b"signed.".to_vec();
        signed.extend_from_slice(payload_json);
        Ok(signed)
    }
}

fn config() -> GoogleWalletConfig {
    GoogleWalletConfig {
        issuer_id: "123456789".to_owned(),
        class_id: "pid-class".to_owned(),
        object_id: "pid-object".to_owned(),
    }
}

fn card() -> Result<DistributionCard, WalletTypesError> {
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
fn renders_google_wallet_generic_object_json() -> Result<(), TestError> {
    let renderer = GoogleWalletRenderer::<PrefixSigner, FixedClock>::new(config(), clock()?);

    let bytes = renderer.render_object_json(&card()?)?;
    let value: Value = serde_json::from_slice(&bytes)?;

    assert_eq!(value["id"], "123456789.pid-object");
    assert_eq!(value["classId"], "123456789.pid-class");
    assert_eq!(value["state"], "ACTIVE");
    assert_eq!(value["barcode"]["type"], "QR_CODE");
    assert_eq!(value["textModulesData"][0]["header"], "Age");
    assert_eq!(value["textModulesData"][0]["body"], "Over 18");
    assert_eq!(value["header"]["defaultValue"]["value"], "PID");
    assert!(value["validTimeInterval"]["end"]["date"].is_string());
    assert_eq!(
        value["linksModuleData"]["uris"][0]["uri"],
        "https://verify.example/session"
    );
    Ok(())
}

#[test]
fn renders_expired_card_with_expired_google_state() -> Result<(), TestError> {
    let renderer = GoogleWalletRenderer::<PrefixSigner, FixedClock>::new(
        config(),
        FixedClock(UnixTimestamp::from_seconds(1_900_000_001)?),
    );

    let bytes = renderer.render_object_json(&card()?)?;
    let value: Value = serde_json::from_slice(&bytes)?;

    assert_eq!(value["state"], "EXPIRED");
    assert!(value["validTimeInterval"]["end"]["date"].is_string());
    Ok(())
}

fn jwt_config() -> GoogleWalletJwtConfig {
    GoogleWalletJwtConfig {
        issuer: "wallet-signer@issuer.example.iam.gserviceaccount.com".to_owned(),
        origins: vec!["https://wallet.example".to_owned()],
    }
}

struct Rs256HeaderSigner(&'static str);

impl GoogleWalletSigner for Rs256HeaderSigner {
    fn sign_payload(&self, payload_json: &[u8]) -> Result<Vec<u8>, RenderError> {
        let header = reallyme_codec::base64url::bytes_to_base64url(self.0.as_bytes());
        let payload = reallyme_codec::base64url::bytes_to_base64url(payload_json);
        Ok(format!("{header}.{payload}.c2lnbmF0dXJl").into_bytes())
    }
}

#[test]
fn signed_render_builds_the_complete_save_claims() -> Result<(), TestError> {
    let renderer = GoogleWalletRenderer::new(config(), clock()?).with_signer(
        Rs256HeaderSigner(r#"{"alg":"RS256","typ":"JWT"}"#),
        jwt_config(),
    );

    let token = String::from_utf8(renderer.render_card(&card()?)?).map_err(|_| TestError::Utf8)?;
    let payload = token.split('.').nth(1).ok_or(TestError::Utf8)?;
    let claims: Value = serde_json::from_slice(
        &reallyme_codec::base64url::base64url_to_bytes(payload).map_err(|_| TestError::Utf8)?,
    )?;

    assert_eq!(claims["aud"], "google");
    assert_eq!(claims["typ"], "savetowallet");
    assert_eq!(claims["iss"], jwt_config().issuer);
    assert_eq!(claims["iat"], 1_800_000_000);
    assert_eq!(claims["origins"][0], "https://wallet.example");
    assert!(claims["payload"]["genericObjects"][0]["id"].is_string());
    Ok(())
}

#[test]
fn signed_render_rejects_tampered_or_wrong_algorithm_tokens() -> Result<(), TestError> {
    for signer in [
        Rs256HeaderSigner(r#"{"alg":"none"}"#),
        Rs256HeaderSigner(r#"{"alg":"ES256"}"#),
    ] {
        let renderer =
            GoogleWalletRenderer::new(config(), clock()?).with_signer(signer, jwt_config());
        assert!(matches!(
            renderer.render_card(&card()?),
            Err(error) if error.reason == RenderErrorReason::SigningFailed
        ));
    }
    let renderer =
        GoogleWalletRenderer::new(config(), clock()?).with_signer(PrefixSigner, jwt_config());
    assert!(matches!(
        renderer.render_card(&card()?),
        Err(error) if error.reason == RenderErrorReason::SigningFailed
    ));
    Ok(())
}

#[test]
fn signed_render_rejects_invalid_claim_configuration() -> Result<(), TestError> {
    for jwt in [
        GoogleWalletJwtConfig {
            issuer: "not-an-email".to_owned(),
            origins: Vec::new(),
        },
        GoogleWalletJwtConfig {
            issuer: jwt_config().issuer,
            origins: vec!["http://wallet.example".to_owned()],
        },
        GoogleWalletJwtConfig {
            issuer: jwt_config().issuer,
            origins: vec!["https://wallet.example/path".to_owned()],
        },
    ] {
        let renderer = GoogleWalletRenderer::new(config(), clock()?)
            .with_signer(Rs256HeaderSigner(r#"{"alg":"RS256"}"#), jwt);
        assert!(matches!(
            renderer.render_card(&card()?),
            Err(error) if error.reason == RenderErrorReason::InvalidRenderConfig
        ));
    }
    Ok(())
}

#[test]
fn builds_google_wallet_save_link_with_injected_signer() -> Result<(), TestError> {
    let config = GoogleWalletSaveConfig::default();

    let payload = br#"{"payload":true}"#;
    let header = r#"{"alg":"RS256"}"#;
    let link = build_google_wallet_save_link(payload, &Rs256HeaderSigner(header), &config)?;
    let token = link
        .as_str()
        .strip_prefix("https://pay.google.com/gp/v/save/")
        .ok_or(TestError::Utf8)?;
    let segments = token.split('.').collect::<Vec<_>>();
    assert_eq!(
        segments,
        [
            reallyme_codec::base64url::bytes_to_base64url(header.as_bytes()),
            reallyme_codec::base64url::bytes_to_base64url(payload),
            reallyme_codec::base64url::bytes_to_base64url(b"signature"),
        ]
    );
    Ok(())
}

#[test]
fn rejects_signer_output_that_is_not_a_compact_jws() {
    let config = GoogleWalletSaveConfig::default();

    let result = build_google_wallet_save_link(br#"{"payload":true}"#, &PrefixSigner, &config);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::SigningFailed
    ));
}

#[test]
fn rejects_oversized_google_wallet_save_link() {
    let config = GoogleWalletSaveConfig {
        save_url_prefix: "https://pay.google.com/gp/v/save/".to_owned(),
        max_url_bytes: 10,
    };

    let result = build_google_wallet_save_link(br#"{"payload":true}"#, &PrefixSigner, &config);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::PayloadTooLarge
    ));
}

#[test]
fn rejects_non_https_google_wallet_save_prefix() {
    let config = GoogleWalletSaveConfig {
        save_url_prefix: "http://pay.google.com/gp/v/save/".to_owned(),
        max_url_bytes: 4096,
    };

    let result = build_google_wallet_save_link(br#"{"payload":true}"#, &PrefixSigner, &config);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::InvalidRenderConfig
    ));
}

#[test]
fn rejects_non_utf8_google_barcode_payload() -> Result<(), TestError> {
    let mut card = card()?;
    card.barcode = Some(DistributionBarcode {
        format: DistributionBarcodeFormat::Qr,
        payload: vec![0xff],
    });
    let renderer = GoogleWalletRenderer::<PrefixSigner, FixedClock>::new(config(), clock()?);

    let result = renderer.render_object_json(&card);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::UnsupportedBarcodePayload
    ));
    Ok(())
}

#[test]
fn rejects_invalid_google_ids_and_verification_links() -> Result<(), TestError> {
    for object_id in ["../object", "object/name", "object name"] {
        let mut invalid = config();
        invalid.object_id = object_id.to_owned();
        assert!(matches!(
            GoogleWalletRenderer::<PrefixSigner, FixedClock>::new(invalid, clock()?)
                .render_object_json(&card()?),
            Err(error) if error.reason == RenderErrorReason::InvalidRenderConfig
        ));
    }
    for uri in [
        "javascript:alert(1)",
        "http://verify.example/",
        "https://user@verify.example/",
    ] {
        let mut invalid = card()?;
        invalid.verification_uri = Some(uri.to_owned());
        assert!(matches!(
            GoogleWalletRenderer::<PrefixSigner, FixedClock>::new(config(), clock()?)
                .render_object_json(&invalid),
            Err(error) if error.reason == RenderErrorReason::InvalidDistributionCard
        ));
    }
    Ok(())
}

#[test]
fn rejects_more_text_modules_than_google_displays() -> Result<(), TestError> {
    let mut invalid = card()?;
    invalid.fields = (0..11)
        .map(|index| DistributionField {
            label: "Field".to_owned(),
            value: index.to_string(),
            emphasized: false,
        })
        .collect();
    assert!(matches!(
        GoogleWalletRenderer::<PrefixSigner, FixedClock>::new(config(), clock()?)
            .render_object_json(&invalid),
        Err(error) if error.reason == RenderErrorReason::InvalidDistributionCard
    ));
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("render")]
    Render(#[from] RenderError),
    #[error("types")]
    Types(#[from] WalletTypesError),
    #[error("json")]
    Json(#[from] serde_json::Error),
    #[error("utf8")]
    Utf8,
}
