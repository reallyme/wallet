// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use openid4vci_profiles::ReuseMethodSet;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as vci_pb;
use openid4vci_types::{CredentialOffer, IssuerMetadata, Proofs, ReallyMeZkV1IssuanceRequest};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_openid4vci_wallet::CredentialOfferGrantType;
use reallyme_wallet_types::OpenId4VciIssuerMetadataProfile;

use crate::{
    prepare_openid4vci_credential_request, prepare_openid4vci_zk_credential_request,
    start_openid4vci_issuance, FlowErrorReason, FlowResult, OpenId4VciIssuanceSession,
};

fn zk_session() -> FlowResult<OpenId4VciIssuanceSession> {
    let metadata = IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "credential_endpoint":"https://issuer.example/credential",
            "credential_configurations_supported":{
                "zk":{"format":"reallyme_zk_v1"}
            }
        }"#,
    )
    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["zk".to_owned()],
        None,
    )
    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    start_openid4vci_issuance(
        offer,
        &metadata,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )
}

fn intent(version: u32) -> FlowResult<ReallyMeZkV1IssuanceRequest> {
    let mut wire = vci_pb::ReallyMeZkV1IssuanceRequest::default();
    wire.version = version;
    wire.claims_root = vec![0x11; 32];
    let mut holder_secret = [0_u8; 32];
    holder_secret[31] = 7;
    let (compressed, _) = crypto_p256::generate_p256_keypair_from_secret_key(&holder_secret)
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    wire.verified_holder_public_key = crypto_p256::decompress_public_key(&compressed)
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    wire.lineage_tag_commitment = vec![0x22; 32];
    wire.wallet_opening_commitment = vec![0x33; 32];
    wire.opaque_lineage_leaf = vec![0x44; 32];
    ReallyMeZkV1IssuanceRequest::new(bytes_to_base64url(&wire.encode_to_vec()))
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))
}

fn etsi_session() -> FlowResult<OpenId4VciIssuanceSession> {
    let metadata = IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "credential_endpoint":"https://issuer.example/credential",
            "nonce_endpoint":"https://issuer.example/nonce",
            "issuer_info":[{
                "format":"registrar_dataset",
                "data":{
                    "identifier":{"type":"https://example.com/id","identifier":"issuer-1"},
                    "srvDescription":[{"lang":"en","content":"PID issuance"}],
                    "registryURI":"https://registrar.example/issuer-1",
                    "providesAttestations":[]
                }
            }],
            "credential_configurations_supported":{
                "pid":{
                    "format":"dc+sd-jwt",
                    "vct":"https://example.com/pid",
                    "cryptographic_binding_methods_supported":["jwk"],
                    "proof_types_supported":{
                        "jwt":{"proof_signing_alg_values_supported":["ES256"]}
                    }
                }
            }
        }"#,
    )
    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    crate::issue::start_openid4vci_issuance_with_profile(
        offer,
        &metadata,
        OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        ReuseMethodSet::new(ReuseMethodSet::ONCE_ONLY)
            .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
    )
}

#[test]
fn zk_request_requires_explicit_intent() -> FlowResult<()> {
    let session = zk_session()?;
    let request =
        prepare_openid4vci_credential_request(&session, "zk".to_owned(), None, None, None);
    assert!(
        matches!(request, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
    );
    Ok(())
}

#[test]
fn etsi_profile_requires_exactly_one_jwt_proof() -> FlowResult<()> {
    let session = etsi_session()?;
    let missing =
        prepare_openid4vci_credential_request(&session, "pid".to_owned(), None, None, None);
    assert!(
        matches!(missing, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
    );

    let multiple = prepare_openid4vci_credential_request(
        &session,
        "pid".to_owned(),
        Some(Proofs {
            jwt: vec!["a.b.c".to_owned(), "d.e.f".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        None,
    );
    assert!(
        matches!(multiple, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
    );

    let single = prepare_openid4vci_credential_request(
        &session,
        "pid".to_owned(),
        Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        None,
    )?;
    assert_eq!(
        single
            .canonical_request
            .proofs
            .as_ref()
            .map(|proofs| proofs.jwt.len()),
        Some(1)
    );
    Ok(())
}

#[test]
fn zk_request_carries_canonical_protobuf_intent() -> FlowResult<()> {
    let session = zk_session()?;
    let prepared = prepare_openid4vci_zk_credential_request(
        &session,
        "zk".to_owned(),
        None,
        None,
        None,
        intent(1)?,
    )?;
    assert!(prepared.canonical_request.reallyme_zk_v1_issuance.is_some());
    let body = prepared
        .transport_request()
        .plaintext_json()
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    assert!(body.contains("reallyme_zk_v1_issuance"));
    Ok(())
}

#[test]
fn zk_request_rejects_wrong_protobuf_version() -> FlowResult<()> {
    let session = zk_session()?;
    let request = prepare_openid4vci_zk_credential_request(
        &session,
        "zk".to_owned(),
        None,
        None,
        None,
        intent(2)?,
    );
    assert!(
        matches!(request, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
    );
    Ok(())
}

#[test]
fn zk_request_rejects_malformed_and_noncanonical_protobuf() -> FlowResult<()> {
    let session = zk_session()?;
    let malformed = ReallyMeZkV1IssuanceRequest::new("AQID".to_owned())
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let request = prepare_openid4vci_zk_credential_request(
        &session,
        "zk".to_owned(),
        None,
        None,
        None,
        malformed,
    );
    assert!(
        matches!(request, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
    );

    let mut wire = vci_pb::ReallyMeZkV1IssuanceRequest::default();
    wire.version = 1;
    wire.claims_root = vec![0x11; 32];
    wire.verified_holder_public_key = {
        let mut key = vec![0_u8; 65];
        key[0] = 0x04;
        key
    };
    wire.lineage_tag_commitment = vec![0x22; 32];
    wire.wallet_opening_commitment = vec![0x33; 32];
    wire.opaque_lineage_leaf = vec![0x44; 32];
    let mut bytes = wire.encode_to_vec();
    bytes.extend_from_slice(&[0x08, 0x01]);
    let duplicate_version = ReallyMeZkV1IssuanceRequest::new(bytes_to_base64url(&bytes))
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let request = prepare_openid4vci_zk_credential_request(
        &session,
        "zk".to_owned(),
        None,
        None,
        None,
        duplicate_version,
    );
    assert!(
        matches!(request, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
    );
    Ok(())
}

#[test]
fn zk_request_rejects_non_zk_configuration() -> FlowResult<()> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let session = crate::test_support::start_authorization_code_issuance(offer)?;
    let request = prepare_openid4vci_zk_credential_request(
        &session,
        "pid".to_owned(),
        None,
        None,
        None,
        intent(1)?,
    );
    assert!(
        matches!(request, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
    );
    Ok(())
}

#[test]
fn zk_request_rejects_zero_reconciliation_commitments() -> FlowResult<()> {
    let session = zk_session()?;
    let bytes = base64url_to_bytes(intent(1)?.compact())
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let mut wire = DecodeOptions::new()
        .with_unknown_field_limit(0)
        .decode_from_slice::<vci_pb::ReallyMeZkV1IssuanceRequest>(&bytes)
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    wire.wallet_opening_commitment.fill(0);
    let zero = ReallyMeZkV1IssuanceRequest::new(bytes_to_base64url(&wire.encode_to_vec()))
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let request =
        prepare_openid4vci_zk_credential_request(&session, "zk".to_owned(), None, None, None, zero);
    assert!(
        matches!(request, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
    );
    Ok(())
}

#[test]
fn zk_request_rejects_invalid_lineage_leaf() -> FlowResult<()> {
    let session = zk_session()?;
    let bytes = base64url_to_bytes(intent(1)?.compact())
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let mut wire = DecodeOptions::new()
        .with_unknown_field_limit(0)
        .decode_from_slice::<vci_pb::ReallyMeZkV1IssuanceRequest>(&bytes)
        .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    for invalid_leaf in [Vec::new(), vec![0x44; 31], vec![0_u8; 32]] {
        wire.opaque_lineage_leaf = invalid_leaf;
        let invalid =
            ReallyMeZkV1IssuanceRequest::new(bytes_to_base64url(&wire.encode_to_vec()))
                .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        let request = prepare_openid4vci_zk_credential_request(
            &session,
            "zk".to_owned(),
            None,
            None,
            None,
            invalid,
        );
        assert!(
            matches!(request, Err(error) if error.reason == FlowErrorReason::InvalidOpenId4VciState)
        );
    }
    Ok(())
}
