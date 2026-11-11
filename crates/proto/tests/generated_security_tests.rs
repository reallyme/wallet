// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security regression tests for the deterministic generated-code hardener.

#![cfg(feature = "generated")]

use buffa::Message;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as openid4vp_pb;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1 as common_pb;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    hardware_key_binding_record, wallet_operation_request, BeginOperationProviderRequest,
    ConsentDerivationInput, CredentialRecord, EncryptedRecord, EncryptedRecordHeader,
    OpenId4VciIssuanceCommit, OpenId4VciIssuanceSnapshot, OpenId4VciNotificationOutboxEntry,
    OpenId4VpPresentationSnapshot, PutCredentialRecordRequest, WalletErrorEnvelope,
    WalletOperationRequest, WalletProviderRequest,
};
use zeroize::ZeroizeOnDrop;

const SECRET_IDENTIFIER: &str = "wallet-secret-identifier-7e5f";
const SECRET_BYTES: &[u8] = b"wallet-secret-payload-4d2a";
const NESTED_PROTOCOL_SECRET: &str = "nested-protocol-secret-b8a3";
const ERROR_CORRELATION_VALUE: &str = "error-correlation-private-b5d1";

fn sensitive_encrypted_record() -> EncryptedRecord {
    let mut header = EncryptedRecordHeader::default();
    header.key_handle_id = "key-handle-private-reference".to_owned();

    let mut encrypted = EncryptedRecord::default();
    encrypted.header = header.into();
    encrypted.nonce = SECRET_BYTES.to_vec();
    encrypted.aad = SECRET_BYTES.to_vec();
    encrypted.ciphertext = SECRET_BYTES.to_vec();
    encrypted
}

fn sensitive_record() -> CredentialRecord {
    let mut record = CredentialRecord::default();
    record.id = SECRET_IDENTIFIER.to_owned();
    record.issuer_id = "issuer-private-reference".to_owned();
    record.encrypted_payload = sensitive_encrypted_record().into();
    record
}

#[test]
// Hardened generated owners implement Drop, so Rust forbids struct-update
// syntax that would move their hidden unknown-field owner.
#[allow(clippy::field_reassign_with_default)]
fn owned_debug_redacts_direct_and_transitive_sensitive_material() {
    let record = sensitive_record();
    let put = PutCredentialRecordRequest {
        record: record.clone().into(),
        ..Default::default()
    };
    let mut request = WalletOperationRequest::default();
    request.operation = Some(wallet_operation_request::Operation::PutCredentialRecord(
        Box::new(put),
    ));

    let mut begin = BeginOperationProviderRequest::default();
    begin.idempotency_key = SECRET_BYTES.to_vec();
    begin.request_digest = SECRET_BYTES.to_vec();
    let mut provider_request = WalletProviderRequest::default();
    provider_request.request = begin.into();

    for rendered in [
        format!("{record:?}"),
        format!("{request:?}"),
        format!("{provider_request:?}"),
    ] {
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(SECRET_IDENTIFIER));
        assert!(!rendered.contains("wallet-secret-payload"));
    }
}

#[test]
fn sensitive_clear_zeroizes_declared_buffers_before_reuse() {
    let mut encrypted = sensitive_encrypted_record();

    Message::clear(&mut encrypted);

    assert!(encrypted.nonce.is_empty());
    assert!(encrypted.aad.is_empty());
    assert!(encrypted.ciphertext.is_empty());
    assert!(!encrypted.header.is_set());
}

#[test]
fn sensitive_messages_advertise_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<EncryptedRecord>();
    assert_zeroize_on_drop::<CredentialRecord>();
    assert_zeroize_on_drop::<ConsentDerivationInput>();
    assert_zeroize_on_drop::<WalletOperationRequest>();
    assert_zeroize_on_drop::<WalletProviderRequest>();
    assert_zeroize_on_drop::<OpenId4VciIssuanceSnapshot>();
    assert_zeroize_on_drop::<OpenId4VciNotificationOutboxEntry>();
    assert_zeroize_on_drop::<OpenId4VciIssuanceCommit>();
    assert_zeroize_on_drop::<OpenId4VpPresentationSnapshot>();
    assert_zeroize_on_drop::<WalletErrorEnvelope>();
    assert_zeroize_on_drop::<hardware_key_binding_record::Binding>();
}

#[test]
// The hardened envelope implements Drop, so Rust forbids struct-update syntax
// that would move its zeroizing unknown-field owner.
#[allow(clippy::field_reassign_with_default)]
fn wallet_error_envelope_debug_redacts_nested_correlation_value() {
    let stack = common_pb::IdentityStackError {
        correlation_id: ERROR_CORRELATION_VALUE.to_owned(),
        ..Default::default()
    };

    let mut envelope = WalletErrorEnvelope::default();
    envelope.stack = stack.into();

    let rendered = format!("{envelope:?}");
    assert!(rendered.contains("WalletErrorEnvelope(<redacted>)"));
    assert!(!rendered.contains(ERROR_CORRELATION_VALUE));
}

#[test]
fn imported_protocol_owners_remain_redacted_by_wallet_snapshot_wrappers() {
    let mut offer = openid4vci_pb::CredentialOffer::default();
    offer.credential_issuer = NESTED_PROTOCOL_SECRET.to_owned();
    let mut issuance = OpenId4VciIssuanceSnapshot::default();
    issuance.credential_offer = offer.into();

    let mut authorization_request = openid4vp_pb::AuthorizationRequest::default();
    authorization_request.nonce = NESTED_PROTOCOL_SECRET.to_owned();
    let mut presentation = OpenId4VpPresentationSnapshot::default();
    presentation.authorization_request = authorization_request.into();

    for rendered in [format!("{issuance:?}"), format!("{presentation:?}")] {
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(NESTED_PROTOCOL_SECRET));
    }
}

#[test]
fn hardened_deserializer_preserves_owned_protojson_round_trip() -> Result<(), serde_json::Error> {
    let encrypted = sensitive_encrypted_record();
    let json = serde_json::to_string(&encrypted)?;
    let decoded: EncryptedRecord = serde_json::from_str(&json)?;

    assert_eq!(decoded, encrypted);
    Ok(())
}

#[test]
fn generated_contract_has_no_borrowed_or_owned_view_surface() {
    const GENERATED_MODULE: &str = include_str!("../src/generated/buffa/reallyme.wallet.v1.mod.rs");

    assert!(!GENERATED_MODULE.contains("__view"));
    assert!(!GENERATED_MODULE.contains("OwnedView"));
}
