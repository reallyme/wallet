// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::jcs::canonicalize_json_text;
use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientIdentifier};
use serde_json::{json, Value};

use super::{
    derive_consent_claim_scope, derive_verified_request_binding, CONSENT_REQUEST_TRANSCRIPT_DOMAIN,
};
use crate::ConsentErrorReason;

#[derive(Debug)]
enum TestError {
    Fixture,
    Binding,
    UnexpectedSuccess,
}

fn request_json() -> Value {
    json!({
        "client_id": "x509_san_dns:verifier.example",
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": "https://verifier.example/response",
        "nonce": "verifier-nonce-1",
        "state": "state-1",
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:1"] },
                "claims": [{ "path": ["given_name"] }]
            }]
        }
    })
}

fn request_from(value: Value) -> Result<AuthorizationRequestObject, TestError> {
    serde_json::from_value(value).map_err(|_| TestError::Fixture)
}

fn digest_of(value: Value) -> Result<[u8; 32], TestError> {
    let request = request_from(value)?;
    derive_verified_request_binding(&request)
        .map(|binding| binding.request_digest)
        .map_err(|_| TestError::Binding)
}

fn with_field(field: &str, replacement: Value) -> Result<Value, TestError> {
    let mut value = request_json();
    let object = value.as_object_mut().ok_or(TestError::Fixture)?;
    object.insert(field.to_owned(), replacement);
    Ok(value)
}

#[test]
fn binding_uses_the_verifier_nonce() -> Result<(), TestError> {
    let request = request_from(request_json())?;
    let binding = derive_verified_request_binding(&request).map_err(|_| TestError::Binding)?;
    assert_eq!(binding.request_nonce.as_str(), "verifier-nonce-1");
    assert_ne!(binding.request_digest, [0; 32]);
    Ok(())
}

#[test]
fn binding_digest_is_deterministic() -> Result<(), TestError> {
    assert_eq!(digest_of(request_json())?, digest_of(request_json())?);
    Ok(())
}

#[test]
fn binding_digest_covers_security_relevant_request_fields() -> Result<(), TestError> {
    let baseline = digest_of(request_json())?;
    let variants = [
        with_field("nonce", json!("verifier-nonce-2"))?,
        with_field("response_uri", json!("https://attacker.example/response"))?,
        with_field("state", json!("state-2"))?,
        with_field("client_id", json!("x509_san_dns:other.example"))?,
        with_field(
            "dcql_query",
            json!({
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["urn:eudi:pid:1"] },
                    "claims": [{ "path": ["birthdate"] }]
                }]
            }),
        )?,
    ];
    for variant in variants {
        assert_ne!(digest_of(variant)?, baseline);
    }
    Ok(())
}

#[test]
fn binding_digest_is_domain_separated() -> Result<(), TestError> {
    let request = request_from(request_json())?;
    let serialized = serde_json::to_string(&request).map_err(|_| TestError::Fixture)?;
    let canonical = canonicalize_json_text(&serialized).map_err(|_| TestError::Fixture)?;
    let undomained = crypto_sha2_256::digest(canonical.as_bytes()).into_bytes();
    let mut transcript = CONSENT_REQUEST_TRANSCRIPT_DOMAIN.to_vec();
    transcript.extend_from_slice(canonical.as_bytes());
    let expected = crypto_sha2_256::digest(&transcript).into_bytes();

    let actual = digest_of(request_json())?;
    assert_eq!(actual, expected);
    assert_ne!(actual, undomained);
    Ok(())
}

#[test]
fn binding_rejects_an_empty_verifier_nonce() -> Result<(), TestError> {
    let request = request_from(with_field("nonce", json!(""))?)?;
    match derive_verified_request_binding(&request) {
        Err(error) if error.reason == ConsentErrorReason::RequestBindingMismatch => Ok(()),
        Err(_) => Err(TestError::Binding),
        Ok(_) => Err(TestError::UnexpectedSuccess),
    }
}

#[test]
fn transaction_data_changes_the_live_request_binding() -> Result<(), TestError> {
    let first = with_field(
        "transaction_data",
        json!(["eyJ0eXBlIjoicGF5bWVudCIsImNyZWRlbnRpYWxfaWRzIjpbInBpZCJdLCJhbW91bnQiOiIxMC4wMCJ9"]),
    )?;
    let second = with_field(
        "transaction_data",
        json!(["eyJ0eXBlIjoicGF5bWVudCIsImNyZWRlbnRpYWxfaWRzIjpbInBpZCJdLCJhbW91bnQiOiIyMC4wMCJ9"]),
    )?;
    assert_ne!(digest_of(first)?, digest_of(second)?);
    Ok(())
}

#[test]
fn claim_scope_ignores_dns_case_and_separates_verifiers() -> Result<(), TestError> {
    let scope = |value: &str| -> Result<String, TestError> {
        let client_id = ClientIdentifier::parse(value).map_err(|_| TestError::Fixture)?;
        derive_consent_claim_scope(&client_id)
            .map(|scope| scope.as_str().to_owned())
            .map_err(|_| TestError::Binding)
    };
    let lower = scope("x509_san_dns:verifier.example")?;
    assert_eq!(lower, scope("x509_san_dns:Verifier.EXAMPLE")?);
    assert_ne!(lower, scope("x509_san_dns:other.example")?);
    assert_ne!(lower, scope("redirect_uri:https://verifier.example/cb")?);
    assert!(lower.starts_with("client-sha256:"));
    Ok(())
}
