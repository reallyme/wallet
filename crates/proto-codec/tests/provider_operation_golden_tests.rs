// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-language golden tests for the version-1 provider operation boundary.

use std::collections::BTreeMap;

use buffa::EnumValue;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    GetCredentialProviderRequest, WalletProviderCapability, WalletProviderDescriptor,
    WalletProviderError, WalletProviderErrorReason, WalletProviderInvocationMode,
    WalletProviderRequest, WalletProviderResponse,
};
use reallyme_wallet_proto_codec::decode::{
    decode_wallet_provider_descriptor, decode_wallet_provider_request,
    decode_wallet_provider_response,
};
use reallyme_wallet_proto_codec::encode::{
    encode_wallet_provider_descriptor, encode_wallet_provider_request,
    encode_wallet_provider_response,
};

const FIXTURE_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/wallet-provider-v1-golden.txt"
));
const FIXTURE_FIELD_COUNT: usize = 5;
const PROVIDER_CONTRACT_VERSION: u32 = 1;
const FIXTURE_EXECUTOR_ID: u64 = 7;
const FIXTURE_REQUEST_ID: u64 = 9;
const PROVIDER_MAX_RESPONSE_BYTES: u32 = 2_162_688;

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error("fixture_shape")]
    Shape,
    #[error("fixture_hex")]
    Hex,
    #[error("fixture_codec")]
    Codec,
    #[error("fixture_contract")]
    Contract,
}

#[test]
fn provider_golden_fixtures_match_canonical_protobuf() -> Result<(), FixtureError> {
    let fixture = parse_fixture(FIXTURE_SOURCE)?;
    if fixture.len() != FIXTURE_FIELD_COUNT
        || fixture.get("schema_version") != Some(&"1")
        || fixture.get("protobuf_package") != Some(&"reallyme.wallet.v1")
    {
        return Err(FixtureError::Contract);
    }

    let descriptor = descriptor_fixture();
    assert_fixture(
        &descriptor,
        required(&fixture, "wallet_provider_descriptor")?,
        encode_wallet_provider_descriptor,
        decode_wallet_provider_descriptor,
    )?;

    let request = request_fixture();
    assert_fixture(
        &request,
        required(&fixture, "get_credential_provider_request")?,
        encode_wallet_provider_request,
        decode_wallet_provider_request,
    )?;

    let response = response_fixture();
    assert_fixture(
        &response,
        required(&fixture, "not_found_provider_response")?,
        encode_wallet_provider_response,
        decode_wallet_provider_response,
    )?;

    Ok(())
}

fn descriptor_fixture() -> WalletProviderDescriptor {
    WalletProviderDescriptor {
        contract_version: PROVIDER_CONTRACT_VERSION,
        invocation_mode: EnumValue::from(
            WalletProviderInvocationMode::WALLET_PROVIDER_INVOCATION_MODE_SYNCHRONOUS_NATIVE,
        ),
        capabilities: vec![EnumValue::from(
            WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_CREDENTIAL,
        )],
        max_response_bytes: PROVIDER_MAX_RESPONSE_BYTES,
        ..Default::default()
    }
}

// Hardened request owners implement Drop, so struct update would attempt to
// move their private zeroizing unknown-field owner out of a temporary value.
#[allow(clippy::field_reassign_with_default)]
fn request_fixture() -> WalletProviderRequest {
    let mut get = GetCredentialProviderRequest::default();
    get.credential_id = "credential-provider-golden-1".to_owned();

    let mut request = WalletProviderRequest::default();
    request.contract_version = PROVIDER_CONTRACT_VERSION;
    request.executor_id = FIXTURE_EXECUTOR_ID;
    request.request_id = FIXTURE_REQUEST_ID;
    request.request = get.into();
    request
}

// See request_fixture: the response envelope is also a hardened Drop owner.
#[allow(clippy::field_reassign_with_default)]
fn response_fixture() -> WalletProviderResponse {
    let error = WalletProviderError {
        reason: EnumValue::from(WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_NOT_FOUND),
        ..Default::default()
    };

    let mut response = WalletProviderResponse::default();
    response.contract_version = PROVIDER_CONTRACT_VERSION;
    response.executor_id = FIXTURE_EXECUTOR_ID;
    response.request_id = FIXTURE_REQUEST_ID;
    response.outcome = error.into();
    response
}

fn assert_fixture<M>(
    message: &M,
    expected_hex: &str,
    encode: fn(&M) -> reallyme_wallet_proto_codec::ProtoResult<zeroize::Zeroizing<Vec<u8>>>,
    decode: fn(&[u8]) -> reallyme_wallet_proto_codec::ProtoResult<M>,
) -> Result<(), FixtureError>
where
    M: PartialEq,
{
    let expected = decode_hex(expected_hex)?;
    let encoded = encode(message).map_err(|_| FixtureError::Codec)?;
    let decoded = decode(&expected).map_err(|_| FixtureError::Codec)?;
    if encoded.as_slice() != expected || decoded != *message {
        return Err(FixtureError::Contract);
    }
    Ok(())
}

fn parse_fixture(source: &str) -> Result<BTreeMap<&str, &str>, FixtureError> {
    let mut values = BTreeMap::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(FixtureError::Shape)?;
        if key.is_empty() || value.is_empty() || values.insert(key, value).is_some() {
            return Err(FixtureError::Shape);
        }
    }
    Ok(values)
}

fn required<'a>(fixture: &'a BTreeMap<&str, &str>, key: &str) -> Result<&'a str, FixtureError> {
    fixture.get(key).copied().ok_or(FixtureError::Shape)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, FixtureError> {
    if !value.len().is_multiple_of(2) {
        return Err(FixtureError::Hex);
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(value.len() / 2)
        .map_err(|_| FixtureError::Hex)?;
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let text = core::str::from_utf8(pair).map_err(|_| FixtureError::Hex)?;
        bytes.push(u8::from_str_radix(text, 16).map_err(|_| FixtureError::Hex)?);
    }
    Ok(bytes)
}
