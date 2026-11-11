// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for Apple pkpass rendering.

use reallyme_wallet_render::{
    PassSigner, PkPassConfig, PkPassRenderer, RenderError, RenderErrorReason, WalletRenderer,
};
use reallyme_wallet_types::{
    DistributionBarcode, DistributionBarcodeFormat, DistributionCard, DistributionField,
    UnixTimestamp, WalletTypesError,
};

struct StaticSigner;

impl PassSigner for StaticSigner {
    fn sign_manifest(&self, manifest_json_bytes: &[u8]) -> Result<Vec<u8>, RenderError> {
        let mut signature = b"signature.".to_vec();
        signature.extend_from_slice(manifest_json_bytes);
        Ok(signature)
    }
}

fn config() -> PkPassConfig {
    PkPassConfig {
        pass_type_identifier: "pass.me.really.pid".to_owned(),
        team_identifier: "TEAMID1234".to_owned(),
        organization_name: "ReallyMe".to_owned(),
        description: "ReallyMe PID".to_owned(),
        serial_number: "credential-1".to_owned(),
        web_service_url: None,
        authentication_token: None,
    }
}

fn card() -> Result<DistributionCard, WalletTypesError> {
    Ok(DistributionCard {
        title: "PID".to_owned(),
        subtitle: Some("Person identification data".to_owned()),
        issuer: "ReallyMe QTSP".to_owned(),
        valid_until: Some(UnixTimestamp::from_seconds(1_900_000_000)?),
        fields: vec![
            DistributionField {
                label: "Age".to_owned(),
                value: "Over 18".to_owned(),
                emphasized: true,
            },
            DistributionField {
                label: "Country".to_owned(),
                value: "MT".to_owned(),
                emphasized: false,
            },
        ],
        barcode: Some(DistributionBarcode {
            format: DistributionBarcodeFormat::Qr,
            payload: b"openid4vp://authorize".to_vec(),
        }),
        verification_uri: Some("https://verify.example/session".to_owned()),
    })
}

fn solid_png(width: u32, height: u32) -> Result<Vec<u8>, png::EncodingError> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        let pixels = vec![200_u8; (width as usize) * (height as usize) * 4];
        writer.write_image_data(&pixels)?;
    }
    Ok(bytes)
}

fn icon_png() -> Result<Vec<u8>, png::EncodingError> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&[0, 0, 0, 255])?;
    }
    Ok(bytes)
}

#[test]
fn renders_pkpass_with_manifest_and_signature_entries() -> Result<(), TestError> {
    let renderer = PkPassRenderer::new(config(), StaticSigner)
        .with_asset("icon.png".to_owned(), icon_png()?)?;

    let bytes = renderer.render_card(&card()?)?;

    assert!(bytes.starts_with(&[0x50, 0x4b, 0x03, 0x04]));
    assert!(contains_bytes(&bytes, b"pass.json"));
    assert!(contains_bytes(&bytes, b"manifest.json"));
    assert!(contains_bytes(&bytes, b"signature"));
    assert!(contains_bytes(&bytes, b"icon.png"));
    assert!(contains_bytes(&bytes, b"signature."));
    Ok(())
}

#[test]
fn rejects_missing_or_malformed_icon_before_signing() -> Result<(), TestError> {
    assert!(matches!(
        PkPassRenderer::new(config(), StaticSigner).render_card(&card()?),
        Err(error) if error.reason == RenderErrorReason::InvalidRenderAsset
    ));
    let malformed = PkPassRenderer::new(config(), StaticSigner)
        .with_asset("icon.png".to_owned(), vec![1, 2, 3])?;
    assert!(matches!(
        malformed.render_card(&card()?),
        Err(error) if error.reason == RenderErrorReason::InvalidRenderAsset
    ));
    Ok(())
}

#[test]
fn rejects_case_aliased_reserved_names_and_path_components() {
    for name in [
        "PASS.JSON",
        "Manifest.Json",
        "SIGNATURE",
        "..icon.png",
        "logo:2.png",
        "logo\u{0007}.png",
        "strip.txt",
        ".hidden.png",
    ] {
        assert!(matches!(
            PkPassRenderer::new(config(), StaticSigner)
                .with_asset(name.to_owned(), vec![1, 2, 3]),
            Err(error) if error.reason == RenderErrorReason::InvalidRenderAsset
        ));
    }
}

#[test]
fn rejects_insecure_pass_update_configuration() -> Result<(), TestError> {
    for url in [
        "http://updates.example/",
        "https://user@updates.example/",
        "https://updates.example/#fragment",
    ] {
        let mut candidate = config();
        candidate.web_service_url = Some(url.to_owned());
        candidate.authentication_token = Some("0123456789abcdef".to_owned());
        let renderer = PkPassRenderer::new(candidate, StaticSigner)
            .with_asset("icon.png".to_owned(), icon_png()?)?;
        assert!(matches!(
            renderer.render_card(&card()?),
            Err(error) if error.reason == RenderErrorReason::InvalidRenderConfig
        ));
    }
    let mut candidate = config();
    candidate.web_service_url = Some("https://updates.example/".to_owned());
    candidate.authentication_token = Some("a".to_owned());
    let renderer = PkPassRenderer::new(candidate, StaticSigner)
        .with_asset("icon.png".to_owned(), icon_png()?)?;
    assert!(matches!(
        renderer.render_card(&card()?),
        Err(error) if error.reason == RenderErrorReason::InvalidRenderConfig
    ));
    Ok(())
}

#[test]
fn rejects_reserved_pkpass_asset_name() {
    let result = PkPassRenderer::new(config(), StaticSigner)
        .with_asset("manifest.json".to_owned(), vec![1, 2, 3]);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::InvalidRenderAsset
    ));
}

#[test]
fn rejects_non_utf8_pkpass_barcode_payload() -> Result<(), TestError> {
    let mut card = card()?;
    card.barcode = Some(DistributionBarcode {
        format: DistributionBarcodeFormat::Qr,
        payload: vec![0xff],
    });
    let renderer = PkPassRenderer::new(config(), StaticSigner)
        .with_asset("icon.png".to_owned(), icon_png()?)?;

    let result = renderer.render_card(&card);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::UnsupportedBarcodePayload
    ));
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("render")]
    Render(#[from] RenderError),
    #[error("types")]
    Types(#[from] WalletTypesError),
    #[error("png")]
    Png(#[from] png::EncodingError),
}

#[test]
fn rejects_repeated_or_uppercase_asset_names() -> Result<(), TestError> {
    for name in ["icon.png", "Icon.png", "ICON.PNG"] {
        let result = PkPassRenderer::new(config(), StaticSigner)
            .with_asset("icon.png".to_owned(), icon_png()?)?
            .with_asset(name.to_owned(), icon_png()?);
        assert!(matches!(
            result,
            Err(error) if error.reason == RenderErrorReason::InvalidRenderAsset
        ));
    }
    Ok(())
}

#[test]
fn rejects_a_malformed_non_icon_asset_before_signing() -> Result<(), TestError> {
    let renderer = PkPassRenderer::new(config(), StaticSigner)
        .with_asset("icon.png".to_owned(), icon_png()?)?
        .with_asset("logo@2x.png".to_owned(), vec![1, 2, 3])?;
    assert!(matches!(
        renderer.render_pkpass(&card()?),
        Err(error) if error.reason == RenderErrorReason::InvalidRenderAsset
    ));
    Ok(())
}

#[test]
fn accepts_standard_at_3x_strip_and_background_images() -> Result<(), TestError> {
    let renderer = PkPassRenderer::new(config(), StaticSigner)
        .with_asset("icon.png".to_owned(), icon_png()?)?
        .with_asset("strip@3x.png".to_owned(), solid_png(1125, 432)?)?
        .with_asset("background@3x.png".to_owned(), solid_png(540, 660)?)?;

    let bytes = renderer.render_pkpass(&card()?)?;

    assert!(contains_bytes(&bytes, b"strip@3x.png"));
    Ok(())
}
