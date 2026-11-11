// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validation for Wallet-owned DID and key storage protobuf records.

use buffa::{EnumValue, Enumeration};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1::CredentialFormat;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    KeyWrapAlgorithm, PlatformKeyProvider, PlatformKeyPurpose, PlatformKeySecurityLevel,
};
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;
use reallyme_ssi_proto::generated::proto::identity::did::v1 as did_pb;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

use crate::key_storage_hardware::{
    hardware_key_material_matches, subject_key_matches_method_material,
};
use crate::{ProtoError, ProtoErrorReason, ProtoResult};

const MAX_RECORD_IDENTIFIER_BYTES: usize = 4_096;
const MAX_WRAPPED_IDENTITY_KEY_SET_BYTES: usize = 1_048_576;
const MAX_LOCAL_HARDWARE_HANDLE_BYTES: usize = 4_096;
const MAX_PUBLIC_KEY_BYTES: usize = 16_384;
const MAX_X509_CHAIN_CERTIFICATES: usize = 16;

/// Validate the Wallet-owned DID projection without interpreting DID semantics.
pub fn validate_did_storage_record(record: &pb::DidStorageRecord) -> ProtoResult<()> {
    validate_identifier(&record.record_id)?;
    let document = record
        .document
        .as_option()
        .ok_or_else(invalid_storage_record)?;
    validate_identifier(&document.id)?;
    validate_timestamp(record.updated_at.as_option())
}

/// Validate the exact replicated, portable key-record policy tuple.
pub fn validate_portable_key_storage_record(
    record: &pb::PortableKeyStorageRecord,
) -> ProtoResult<()> {
    validate_common_key_fields(
        &record.record_id,
        &record.did_record_id,
        record.verification_method.as_option(),
        record.credential_subject_key.as_option(),
        &record.purpose,
        &record.credential_formats,
        record.created_at.as_option(),
    )?;
    if record.custody.as_known() != Some(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_WALLET_SOFTWARE)
        || record.exportability.as_known()
            != Some(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_PORTABLE)
        || record.protection.as_known()
            != Some(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_WRAPPED_IDENTITY_KEY_SET)
        || record.wrapped_identity_key_set.is_empty()
        || record.wrapped_identity_key_set.len() < 24
        || !record.wrapped_identity_key_set.len().is_multiple_of(8)
        || record.wrapped_identity_key_set.len() > MAX_WRAPPED_IDENTITY_KEY_SET_BYTES
        || !is_canonical_wrapping_algorithm(record.wrapping_algorithm.as_option())
    {
        return Err(invalid_storage_record());
    }
    Ok(())
}

fn is_canonical_wrapping_algorithm(
    algorithm: Option<
        &reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::CryptoAlgorithmIdentifier,
    >,
) -> bool {
    use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::crypto_algorithm_identifier::Algorithm;
    matches!(
        algorithm.and_then(|identifier| identifier.algorithm.as_ref()),
        Some(Algorithm::KeyWrap(value))
            if value.as_known() == Some(KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_256_KW)
    )
}

/// Validate an installation-bound platform or WSCD private-key reference.
pub fn validate_hardware_key_binding_record(
    record: &pb::HardwareKeyBindingRecord,
) -> ProtoResult<()> {
    validate_common_key_fields(
        &record.record_id,
        &record.did_record_id,
        record.verification_method.as_option(),
        record.credential_subject_key.as_option(),
        &record.purpose,
        &record.credential_formats,
        record.created_at.as_option(),
    )?;
    if record.exportability.as_known()
        != Some(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_NON_EXPORTABLE)
    {
        return Err(invalid_storage_record());
    }

    use pb::hardware_key_binding_record::Binding;
    match record.binding.as_ref() {
        Some(Binding::PlatformPrivateKey(handle)) => {
            if record.custody.as_known()
                != Some(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_PLATFORM_HARDWARE)
                || record.protection.as_known()
                    != Some(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_PLATFORM_HARDWARE_BOUND)
                || handle.purpose.as_known() != record.purpose.as_known()
                || !platform_security_matches_provider(
                    handle.provider.as_known(),
                    handle.actual_security_level.as_known(),
                    handle.requested_security_level.as_known(),
                )
                || !algorithm_matches_purpose(
                    handle.algorithm.as_option(),
                    handle.purpose.as_known(),
                )
                || handle.algorithm.as_option()
                    != record
                        .verification_method
                        .as_option()
                        .and_then(|method| method.algorithm.as_option())
                || handle.opaque_handle.is_empty()
                || handle.opaque_handle.len() > MAX_LOCAL_HARDWARE_HANDLE_BYTES
                || handle.public_key.is_empty()
                || handle.public_key.len() > MAX_PUBLIC_KEY_BYTES
                || record
                    .credential_subject_key
                    .as_option()
                    .is_none_or(|subject_key| {
                        !hardware_key_material_matches(
                            subject_key,
                            record.verification_method.as_option(),
                            handle.public_key.as_slice(),
                        )
                    })
            {
                return Err(invalid_storage_record());
            }
        }
        Some(Binding::WscdOpaqueHandle(handle)) => {
            if record.custody.as_known() != Some(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_WSCD)
                || record.protection.as_known()
                    != Some(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_WSCD_BOUND)
                || handle.is_empty()
                || handle.len() > MAX_LOCAL_HARDWARE_HANDLE_BYTES
            {
                return Err(invalid_storage_record());
            }
        }
        None => return Err(invalid_storage_record()),
    }
    Ok(())
}

fn validate_common_key_fields(
    record_id: &str,
    did_record_id: &str,
    verification_method: Option<
        &reallyme_ssi_proto::generated::proto::identity::did::v1::VerificationMethod,
    >,
    credential_subject_key: Option<&credential_pb::PublicKeyRef>,
    purpose: &EnumValue<PlatformKeyPurpose>,
    credential_formats: &[EnumValue<CredentialFormat>],
    created_at: Option<&pb::UnixTimestamp>,
) -> ProtoResult<()> {
    validate_identifier(record_id)?;
    validate_identifier(did_record_id)?;
    let method = verification_method.ok_or_else(invalid_storage_record)?;
    let subject_key = credential_subject_key.ok_or_else(invalid_storage_record)?;
    validate_identifier(&method.id)?;
    validate_identifier(&method.controller)?;
    if !valid_verification_method_public_key(method)
        || !algorithm_matches_purpose(method.algorithm.as_option(), purpose.as_known())
        || !subject_key_matches_method(subject_key, &method.id, method.algorithm.as_option())
        || !subject_key_matches_method_material(subject_key, Some(method))
        || method.public_key.as_ref().is_some_and(|key| match key {
            did_pb::verification_method::PublicKey::PublicKeyJwk(jwk) => {
                jwk.algorithm.as_option() != method.algorithm.as_option()
            }
            did_pb::verification_method::PublicKey::PublicKeyMultibase(_) => false,
        })
        || purpose.as_known().is_none_or(|value| value.to_i32() == 0)
        || credential_formats.is_empty()
        || credential_formats
            .iter()
            .any(|format| format.as_known().is_none_or(|value| value.to_i32() == 0))
        || has_duplicate_formats(credential_formats)
    {
        return Err(invalid_storage_record());
    }
    validate_timestamp(created_at)
}

fn valid_verification_method_public_key(method: &did_pb::VerificationMethod) -> bool {
    match (method.r#type.as_known(), method.public_key.as_ref()) {
        (
            Some(did_pb::VerificationMethodType::VERIFICATION_METHOD_TYPE_MULTIKEY),
            Some(did_pb::verification_method::PublicKey::PublicKeyMultibase(value)),
        ) => value.starts_with('z') && value.len() <= MAX_PUBLIC_KEY_BYTES,
        (
            Some(did_pb::VerificationMethodType::VERIFICATION_METHOD_TYPE_JSON_WEB_KEY),
            Some(did_pb::verification_method::PublicKey::PublicKeyJwk(value)),
        ) => {
            value.algorithm.as_option().is_some()
                && !value.public_key.is_empty()
                && value.public_key.len() <= MAX_PUBLIC_KEY_BYTES
                && !value.canonical_jcs.is_empty()
                && value.canonical_jcs.len() <= MAX_PUBLIC_KEY_BYTES
        }
        _ => false,
    }
}

fn subject_key_matches_method(
    subject_key: &credential_pb::PublicKeyRef,
    method_id: &str,
    method_algorithm: Option<
        &reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::CryptoAlgorithmIdentifier,
    >,
) -> bool {
    use credential_pb::__buffa::oneof::key_assurance::Kind as AssuranceKind;
    use credential_pb::__buffa::oneof::key_reference::Kind as ReferenceKind;

    let reference_matches = matches!(
        subject_key.reference.as_option().and_then(|value| value.kind.as_ref()),
        Some(ReferenceKind::DidVerificationMethod(value)) if value == method_id
    );
    let public_key_is_valid = subject_key
        .public_key
        .as_option()
        .is_some_and(|public_key| {
            public_key.alg.as_known().is_some_and(|algorithm| {
                credential_algorithm_matches_method(algorithm, method_algorithm)
                    && representation_matches_algorithm(
                        algorithm,
                        public_key.representation.as_ref(),
                    )
            })
        });
    let assurance_is_valid = subject_key
        .assurance
        .as_option()
        .and_then(|value| value.kind.as_ref())
        .is_some_and(|kind| matches!(kind, AssuranceKind::None(_)) || assurance_has_evidence(kind));

    reference_matches && public_key_is_valid && assurance_is_valid
}

fn credential_algorithm_matches_method(
    credential_algorithm: credential_pb::Algorithm,
    method_algorithm: Option<
        &reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::CryptoAlgorithmIdentifier,
    >,
) -> bool {
    use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
        crypto_algorithm_identifier::Algorithm as MethodAlgorithm, KemAlgorithm,
        KeyAgreementAlgorithm, SignatureAlgorithm,
    };

    match method_algorithm.and_then(|identifier| identifier.algorithm.as_ref()) {
        Some(MethodAlgorithm::Signature(value)) => match value.as_known() {
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_ED25519
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_P_256
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_SECP256K1
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_44) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_ML_DSA_44
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_65) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_ML_DSA_65
            }
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_87) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_ML_DSA_87
            }
            _ => false,
        },
        Some(MethodAlgorithm::KeyAgreement(value)) => match value.as_known() {
            Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_X25519
            }
            Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P256_ECDH) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_P_256
            }
            _ => false,
        },
        Some(MethodAlgorithm::Kem(value)) => match value.as_known() {
            Some(KemAlgorithm::KEM_ALGORITHM_ML_KEM_768) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_ML_KEM_768
            }
            Some(KemAlgorithm::KEM_ALGORITHM_ML_KEM_1024) => {
                credential_algorithm == credential_pb::Algorithm::ALGORITHM_ML_KEM_1024
            }
            _ => false,
        },
        _ => false,
    }
}

fn representation_matches_algorithm(
    algorithm: credential_pb::Algorithm,
    representation: Option<&credential_pb::__buffa::oneof::public_key_material::Representation>,
) -> bool {
    use credential_pb::__buffa::oneof::public_key_material::Representation;

    match representation {
        Some(Representation::JwkJson(value) | Representation::CoseKey(value)) => {
            !value.is_empty() && value.len() <= MAX_PUBLIC_KEY_BYTES
        }
        Some(Representation::SubjectPublicKeyInfoDer(value)) => {
            value.first() == Some(&0x30) && value.len() <= MAX_PUBLIC_KEY_BYTES
        }
        Some(Representation::Multikey(value)) => {
            value.starts_with('z') && value.len() <= MAX_PUBLIC_KEY_BYTES
        }
        Some(Representation::Raw(value)) => match (algorithm, value.serialization.as_known()) {
            (
                credential_pb::Algorithm::ALGORITHM_ED25519
                | credential_pb::Algorithm::ALGORITHM_X25519,
                Some(credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_FIXED_WIDTH),
            ) => value.bytes.len() == 32,
            (
                credential_pb::Algorithm::ALGORITHM_P_256
                | credential_pb::Algorithm::ALGORITHM_SECP256K1
                | credential_pb::Algorithm::ALGORITHM_ES256K_RECOVERY,
                Some(credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_SEC1_COMPRESSED),
            ) => value.bytes.len() == 33,
            (
                credential_pb::Algorithm::ALGORITHM_P_256
                | credential_pb::Algorithm::ALGORITHM_SECP256K1
                | credential_pb::Algorithm::ALGORITHM_ES256K_RECOVERY,
                Some(credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_SEC1_UNCOMPRESSED),
            ) => value.bytes.len() == 65,
            (
                credential_pb::Algorithm::ALGORITHM_ML_DSA_44,
                Some(credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_FIXED_WIDTH),
            ) => value.bytes.len() == 1_312,
            (
                credential_pb::Algorithm::ALGORITHM_ML_DSA_65,
                Some(credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_FIXED_WIDTH),
            ) => value.bytes.len() == 1_952,
            (
                credential_pb::Algorithm::ALGORITHM_ML_DSA_87,
                Some(credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_FIXED_WIDTH),
            ) => value.bytes.len() == 2_592,
            (
                credential_pb::Algorithm::ALGORITHM_ML_KEM_768,
                Some(credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_FIXED_WIDTH),
            ) => value.bytes.len() == 1_184,
            (
                credential_pb::Algorithm::ALGORITHM_ML_KEM_1024,
                Some(credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_FIXED_WIDTH),
            ) => value.bytes.len() == 1_568,
            _ => false,
        },
        None => false,
    }
}

fn assurance_has_evidence(assurance: &credential_pb::__buffa::oneof::key_assurance::Kind) -> bool {
    use credential_pb::__buffa::oneof::key_assurance::Kind;

    match assurance {
        Kind::KeyAttestation(value) | Kind::HardwareAttestation(value) => {
            !value.is_empty() && value.len() <= MAX_PUBLIC_KEY_BYTES
        }
        Kind::X509Chain(value) => {
            !value.certificates_der.is_empty()
                && value.certificates_der.len() <= MAX_X509_CHAIN_CERTIFICATES
                && value.certificates_der.iter().all(|certificate| {
                    certificate.first() == Some(&0x30) && certificate.len() <= MAX_PUBLIC_KEY_BYTES
                })
        }
        Kind::None(_) => true,
    }
}

fn validate_identifier(value: &str) -> ProtoResult<()> {
    if value.is_empty() || value.len() > MAX_RECORD_IDENTIFIER_BYTES {
        return Err(invalid_storage_record());
    }
    Ok(())
}

fn validate_timestamp(timestamp: Option<&pb::UnixTimestamp>) -> ProtoResult<()> {
    if timestamp.is_none_or(|value| {
        reallyme_wallet_types::UnixTimestamp::from_seconds(value.seconds).is_err()
    }) {
        return Err(invalid_storage_record());
    }
    Ok(())
}

fn algorithm_matches_purpose(
    algorithm: Option<
        &reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::CryptoAlgorithmIdentifier,
    >,
    purpose: Option<PlatformKeyPurpose>,
) -> bool {
    use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::crypto_algorithm_identifier::Algorithm;
    match (
        purpose,
        algorithm.and_then(|identifier| identifier.algorithm.as_ref()),
    ) {
        (
            Some(PlatformKeyPurpose::PLATFORM_KEY_PURPOSE_SIGNING),
            Some(Algorithm::Signature(value)),
        ) => value.as_known().is_some_and(|known| known.to_i32() != 0),
        (
            Some(PlatformKeyPurpose::PLATFORM_KEY_PURPOSE_KEY_AGREEMENT),
            Some(Algorithm::KeyAgreement(value)),
        ) => value.as_known().is_some_and(|known| known.to_i32() != 0),
        _ => false,
    }
}

fn platform_security_matches_provider(
    provider: Option<PlatformKeyProvider>,
    actual: Option<PlatformKeySecurityLevel>,
    requested: Option<PlatformKeySecurityLevel>,
) -> bool {
    match provider {
        Some(PlatformKeyProvider::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN) => {
            actual == Some(PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE)
                && requested
                    == Some(PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE)
        }
        Some(PlatformKeyProvider::PLATFORM_KEY_PROVIDER_ANDROID_KEYSTORE) => {
            is_android_hardware_level(actual) && is_android_hardware_level(requested)
        }
        _ => false,
    }
}

fn is_android_hardware_level(level: Option<PlatformKeySecurityLevel>) -> bool {
    matches!(
        level,
        Some(
            PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_TRUSTED_EXECUTION_ENVIRONMENT
                | PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_STRONGBOX
        )
    )
}

fn has_duplicate_formats(formats: &[EnumValue<CredentialFormat>]) -> bool {
    formats.iter().enumerate().any(|(index, candidate)| {
        index
            .checked_add(1)
            .and_then(|start| formats.get(start..))
            .is_some_and(|remaining| remaining.contains(candidate))
    })
}

const fn invalid_storage_record() -> ProtoError {
    ProtoError::new(ProtoErrorReason::InvalidDto)
}
