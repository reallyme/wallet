// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validation and bounded-codec tests for Wallet-owned DID/key records.

use std::collections::BTreeMap;

use buffa::{EnumValue, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1 as crypto_pb;
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;
use reallyme_ssi_proto::generated::proto::identity::did::v1 as did_pb;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::decode::{
    decode_did_storage_record, decode_hardware_key_binding_record,
    decode_portable_key_storage_record,
};
use reallyme_wallet_proto_codec::encode::{
    encode_did_storage_record, encode_hardware_key_binding_record,
    encode_portable_key_storage_record,
};
use reallyme_wallet_proto_codec::{
    validate_hardware_key_binding_record, validate_portable_key_storage_record, ProtoResult,
};

const FIXTURE_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/wallet-key-storage-v1-golden.txt"
));
const FIXTURE_FIELD_COUNT: usize = 5;

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error("fixture_shape")]
    Shape,
    #[error("fixture_hex")]
    Hex,
    #[error("fixture_contract")]
    Contract,
}

#[test]
fn did_and_portable_key_records_round_trip_through_bounded_generated_contracts() -> ProtoResult<()>
{
    let did = did_record();
    let did_bytes = encode_did_storage_record(&did)?;
    assert_eq!(decode_did_storage_record(did_bytes.as_slice())?, did);

    let portable = portable_record();
    let portable_bytes = encode_portable_key_storage_record(&portable)?;
    assert_eq!(
        decode_portable_key_storage_record(portable_bytes.as_slice())?,
        portable
    );
    assert!(!format!("{portable:?}").contains("wrapped-key-set-sentinel"));
    Ok(())
}

#[test]
fn portable_policy_tuple_and_wrapped_material_fail_closed() {
    let mut wrong_custody = portable_record();
    wrong_custody.custody =
        EnumValue::from(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_PLATFORM_HARDWARE);
    assert!(validate_portable_key_storage_record(&wrong_custody).is_err());

    let mut wrong_exportability = portable_record();
    wrong_exportability.exportability =
        EnumValue::from(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_NON_EXPORTABLE);
    assert!(validate_portable_key_storage_record(&wrong_exportability).is_err());

    let mut wrong_protection = portable_record();
    wrong_protection.protection =
        EnumValue::from(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_PLATFORM_HARDWARE_BOUND);
    assert!(validate_portable_key_storage_record(&wrong_protection).is_err());

    let mut missing_wrapped_material = portable_record();
    missing_wrapped_material.wrapped_identity_key_set.clear();
    assert!(validate_portable_key_storage_record(&missing_wrapped_material).is_err());

    let mut wrong_wrapping_algorithm = portable_record();
    wrong_wrapping_algorithm.wrapping_algorithm = MessageField::some(signing_algorithm());
    assert!(validate_portable_key_storage_record(&wrong_wrapping_algorithm).is_err());

    let mut duplicated_format = portable_record();
    duplicated_format.credential_formats.push(EnumValue::from(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT,
    ));
    assert!(validate_portable_key_storage_record(&duplicated_format).is_err());

    let mut mismatched_algorithm = portable_record();
    if let Some(key) = mismatched_algorithm
        .credential_subject_key
        .as_option_mut()
        .and_then(|key| key.public_key.as_option_mut())
    {
        key.alg = EnumValue::from(credential_pb::Algorithm::ALGORITHM_ED25519);
    }
    assert!(validate_portable_key_storage_record(&mismatched_algorithm).is_err());

    let mut mismatched_raw_serialization = portable_record();
    if let Some(credential_pb::__buffa::oneof::public_key_material::Representation::Raw(raw)) =
        mismatched_raw_serialization
            .credential_subject_key
            .as_option_mut()
            .and_then(|key| key.public_key.as_option_mut())
            .and_then(|key| key.representation.as_mut())
    {
        raw.serialization = EnumValue::from(
            credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_FIXED_WIDTH,
        );
    }
    assert!(validate_portable_key_storage_record(&mismatched_raw_serialization).is_err());

    let mut mismatched_public_key = portable_record();
    if let Some(did_pb::verification_method::PublicKey::PublicKeyJwk(jwk)) = mismatched_public_key
        .verification_method
        .as_option_mut()
        .and_then(|method| method.public_key.as_mut())
    {
        jwk.public_key[0] = 0x02;
    }
    assert!(validate_portable_key_storage_record(&mismatched_public_key).is_err());

    let mut oversized_timestamp = portable_record();
    oversized_timestamp.created_at = MessageField::some(pb::UnixTimestamp {
        seconds: i64::MAX,
        ..Default::default()
    });
    assert!(validate_portable_key_storage_record(&oversized_timestamp).is_err());
}

#[test]
fn platform_and_wscd_bindings_are_non_exportable_and_hardware_bound() -> ProtoResult<()> {
    let platform = platform_record();
    let platform_bytes = encode_hardware_key_binding_record(&platform)?;
    assert_eq!(
        decode_hardware_key_binding_record(platform_bytes.as_slice())?,
        platform
    );

    let wscd = wscd_record();
    let wscd_bytes = encode_hardware_key_binding_record(&wscd)?;
    assert_eq!(
        decode_hardware_key_binding_record(wscd_bytes.as_slice())?,
        wscd
    );
    assert!(!format!("{wscd:?}").contains("wscd-handle-sentinel"));

    let mut software_claim = platform_record();
    if let Some(pb::hardware_key_binding_record::Binding::PlatformPrivateKey(handle)) =
        software_claim.binding.as_mut()
    {
        handle.actual_security_level = EnumValue::from(
            crypto_pb::PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_SOFTWARE,
        );
    }
    assert!(validate_hardware_key_binding_record(&software_claim).is_err());

    let mut exportable_hardware = platform_record();
    exportable_hardware.exportability =
        EnumValue::from(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_PORTABLE);
    assert!(validate_hardware_key_binding_record(&exportable_hardware).is_err());

    let mut mismatched_public_key = platform_record();
    if let Some(pb::hardware_key_binding_record::Binding::PlatformPrivateKey(handle)) =
        mismatched_public_key.binding.as_mut()
    {
        handle.public_key = vec![0x03; 33];
    }
    assert!(validate_hardware_key_binding_record(&mismatched_public_key).is_err());

    let mut mismatched_wscd_public_key = wscd_record();
    if let Some(did_pb::verification_method::PublicKey::PublicKeyJwk(jwk)) =
        mismatched_wscd_public_key
            .verification_method
            .as_option_mut()
            .and_then(|method| method.public_key.as_mut())
    {
        jwk.public_key[0] = 0x02;
    }
    assert!(validate_hardware_key_binding_record(&mismatched_wscd_public_key).is_err());

    let mut mismatched_handle_algorithm = platform_record();
    if let Some(pb::hardware_key_binding_record::Binding::PlatformPrivateKey(handle)) =
        mismatched_handle_algorithm.binding.as_mut()
    {
        handle.algorithm = MessageField::some(crypto_pb::CryptoAlgorithmIdentifier {
            algorithm: Some(
                crypto_pb::crypto_algorithm_identifier::Algorithm::Signature(EnumValue::from(
                    crypto_pb::SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519,
                )),
            ),
            ..Default::default()
        });
    }
    assert!(validate_hardware_key_binding_record(&mismatched_handle_algorithm).is_err());
    Ok(())
}

#[test]
fn key_storage_golden_vectors_match_canonical_protobuf() -> Result<(), FixtureError> {
    let fixture = parse_fixture(FIXTURE_SOURCE)?;
    if fixture.len() != FIXTURE_FIELD_COUNT
        || fixture.get("schema_version") != Some(&"1")
        || fixture.get("protobuf_package") != Some(&"reallyme.wallet.v1")
    {
        return Err(FixtureError::Contract);
    }

    assert_golden(
        &did_record(),
        required(&fixture, "did_storage_record")?,
        encode_did_storage_record,
        decode_did_storage_record,
    )?;
    assert_golden(
        &portable_record(),
        required(&fixture, "portable_key_storage_record")?,
        encode_portable_key_storage_record,
        decode_portable_key_storage_record,
    )?;
    assert_golden(
        &platform_record(),
        required(&fixture, "hardware_key_binding_record")?,
        encode_hardware_key_binding_record,
        decode_hardware_key_binding_record,
    )?;
    Ok(())
}

#[allow(clippy::field_reassign_with_default)]
fn did_record() -> pb::DidStorageRecord {
    let mut record = pb::DidStorageRecord::default();
    record.record_id = "did-record-1".to_owned();
    record.document = MessageField::some(did_pb::DidDocument {
        id: "did:example:holder".to_owned(),
        ..Default::default()
    });
    record.updated_at = timestamp();
    record
}

#[allow(clippy::field_reassign_with_default)]
fn portable_record() -> pb::PortableKeyStorageRecord {
    let mut record = pb::PortableKeyStorageRecord::default();
    record.record_id = "portable-key-1".to_owned();
    record.did_record_id = "did-record-1".to_owned();
    record.verification_method = MessageField::some(verification_method());
    record.credential_subject_key = MessageField::some(subject_key());
    record.purpose = EnumValue::from(crypto_pb::PlatformKeyPurpose::PLATFORM_KEY_PURPOSE_SIGNING);
    record.custody = EnumValue::from(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_WALLET_SOFTWARE);
    record.exportability =
        EnumValue::from(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_PORTABLE);
    record.protection =
        EnumValue::from(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_WRAPPED_IDENTITY_KEY_SET);
    record.credential_formats = vec![EnumValue::from(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT,
    )];
    record.wrapped_identity_key_set = b"wrapped-key-set-sentinel".to_vec();
    record.created_at = timestamp();
    record.wrapping_algorithm = MessageField::some(key_wrap_algorithm());
    record
}

#[allow(clippy::field_reassign_with_default)]
fn platform_record() -> pb::HardwareKeyBindingRecord {
    let mut handle = crypto_pb::CryptoPlatformPrivateKeyHandle::default();
    handle.provider =
        EnumValue::from(crypto_pb::PlatformKeyProvider::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN);
    handle.purpose = EnumValue::from(crypto_pb::PlatformKeyPurpose::PLATFORM_KEY_PURPOSE_SIGNING);
    handle.algorithm = MessageField::some(signing_algorithm());
    handle.opaque_handle = b"platform-handle-sentinel".to_vec();
    handle.public_key = p256_compressed_key();
    handle.actual_security_level = EnumValue::from(
        crypto_pb::PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE,
    );
    handle.requested_security_level = EnumValue::from(
        crypto_pb::PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE,
    );

    let mut record = pb::HardwareKeyBindingRecord::default();
    record.record_id = "hardware-key-1".to_owned();
    record.did_record_id = "did-record-1".to_owned();
    record.verification_method = MessageField::some(verification_method());
    record.credential_subject_key = MessageField::some(subject_key());
    record.purpose = EnumValue::from(crypto_pb::PlatformKeyPurpose::PLATFORM_KEY_PURPOSE_SIGNING);
    record.custody = EnumValue::from(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_PLATFORM_HARDWARE);
    record.exportability =
        EnumValue::from(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_NON_EXPORTABLE);
    record.protection =
        EnumValue::from(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_PLATFORM_HARDWARE_BOUND);
    record.credential_formats = vec![EnumValue::from(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT,
    )];
    record.binding =
        Some(pb::hardware_key_binding_record::Binding::PlatformPrivateKey(Box::new(handle)));
    record.created_at = timestamp();
    record
}

fn wscd_record() -> pb::HardwareKeyBindingRecord {
    let mut record = platform_record();
    record.record_id = "wscd-key-1".to_owned();
    record.custody = EnumValue::from(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_WSCD);
    record.protection = EnumValue::from(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_WSCD_BOUND);
    record.binding = Some(pb::hardware_key_binding_record::Binding::WscdOpaqueHandle(
        b"wscd-handle-sentinel".to_vec(),
    ));
    record
}

fn verification_method() -> did_pb::VerificationMethod {
    let mut jwk = crypto_pb::JsonWebKey::default();
    jwk.algorithm = MessageField::some(signing_algorithm());
    jwk.public_key = p256_compressed_key();
    jwk.canonical_jcs = br#"{"crv":"P-256","kty":"EC"}"#.to_vec();
    did_pb::VerificationMethod {
        id: "did:example:holder#key-1".to_owned(),
        r#type: EnumValue::from(
            did_pb::VerificationMethodType::VERIFICATION_METHOD_TYPE_JSON_WEB_KEY,
        ),
        controller: "did:example:holder".to_owned(),
        algorithm: MessageField::some(signing_algorithm()),
        public_key: Some(did_pb::verification_method::PublicKey::PublicKeyJwk(
            Box::new(jwk),
        )),
        ..Default::default()
    }
}

fn subject_key() -> credential_pb::PublicKeyRef {
    credential_pb::PublicKeyRef {
        reference: MessageField::some(credential_pb::KeyReference {
            kind: Some(
                credential_pb::__buffa::oneof::key_reference::Kind::DidVerificationMethod(
                    "did:example:holder#key-1".to_owned(),
                ),
            ),
            ..Default::default()
        }),
        public_key: MessageField::some(credential_pb::PublicKeyMaterial {
            alg: EnumValue::from(credential_pb::Algorithm::ALGORITHM_P_256),
            representation: Some(
                credential_pb::__buffa::oneof::public_key_material::Representation::Raw(
                    Box::new(credential_pb::RawPublicKey {
                        serialization: EnumValue::from(
                            credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_SEC1_COMPRESSED,
                        ),
                        bytes: p256_compressed_key(),
                        ..Default::default()
                    }),
                ),
            ),
            ..Default::default()
        }),
        assurance: MessageField::some(credential_pb::KeyAssurance {
            kind: Some(credential_pb::__buffa::oneof::key_assurance::Kind::None(
                Box::default(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn p256_compressed_key() -> Vec<u8> {
    vec![
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ]
}

fn p256_uncompressed_key() -> Vec<u8> {
    vec![
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ]
}

#[test]
fn hardware_binding_accepts_equivalent_p256_sec1_encodings() {
    let mut record = platform_record();
    if let Some(pb::hardware_key_binding_record::Binding::PlatformPrivateKey(handle)) =
        record.binding.as_mut()
    {
        handle.public_key = p256_uncompressed_key();
    }

    assert!(validate_hardware_key_binding_record(&record).is_ok());
}

fn signing_algorithm() -> crypto_pb::CryptoAlgorithmIdentifier {
    crypto_pb::CryptoAlgorithmIdentifier {
        algorithm: Some(
            crypto_pb::crypto_algorithm_identifier::Algorithm::Signature(EnumValue::from(
                crypto_pb::SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
            )),
        ),
        ..Default::default()
    }
}

fn key_wrap_algorithm() -> crypto_pb::CryptoAlgorithmIdentifier {
    crypto_pb::CryptoAlgorithmIdentifier {
        algorithm: Some(crypto_pb::crypto_algorithm_identifier::Algorithm::KeyWrap(
            EnumValue::from(crypto_pb::KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_256_KW),
        )),
        ..Default::default()
    }
}

fn timestamp() -> MessageField<pb::UnixTimestamp, buffa::Inline<pb::UnixTimestamp>> {
    MessageField::some(pb::UnixTimestamp {
        seconds: 1_700_000_000,
        ..Default::default()
    })
}

fn assert_golden<M>(
    message: &M,
    expected_hex: &str,
    encode: fn(&M) -> reallyme_wallet_proto_codec::ProtoResult<zeroize::Zeroizing<Vec<u8>>>,
    decode: fn(&[u8]) -> reallyme_wallet_proto_codec::ProtoResult<M>,
) -> Result<(), FixtureError>
where
    M: PartialEq,
{
    let expected = decode_hex(expected_hex)?;
    let encoded = encode(message).map_err(|_| FixtureError::Contract)?;
    let decoded = decode(&expected).map_err(|_| FixtureError::Contract)?;
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
