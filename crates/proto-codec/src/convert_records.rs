// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1 as crypto_pb;
use reallyme_wallet_attestation as attestation;
use reallyme_wallet_keystore as keystore;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;

use super::{known_enum, ConvertError, ConvertErrorReason, ConvertResult};

/// Convert a wallet timestamp into protobuf.
#[must_use]
pub fn unix_timestamp_to_proto(timestamp: wallet::UnixTimestamp) -> pb::UnixTimestamp {
    pb::UnixTimestamp {
        seconds: timestamp.as_seconds(),
        ..pb::UnixTimestamp::default()
    }
}

/// Convert a generated protobuf timestamp into a wallet timestamp.
pub fn unix_timestamp_from_proto(
    timestamp: &pb::UnixTimestamp,
) -> ConvertResult<wallet::UnixTimestamp> {
    wallet::UnixTimestamp::from_seconds(timestamp.seconds).map_err(ConvertError::from)
}

/// Convert the Wallet storage algorithm into the shared Crypto enum.
#[must_use]
pub fn storage_encryption_algorithm_to_proto(
    algorithm: wallet::StorageEncryptionAlgorithm,
) -> crypto_pb::AeadAlgorithm {
    match algorithm {
        wallet::StorageEncryptionAlgorithm::Aes256GcmSiv => {
            crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM_SIV
        }
        wallet::StorageEncryptionAlgorithm::XChaCha20Poly1305 => {
            crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_XCHACHA20_POLY1305
        }
    }
}

/// Convert a shared Crypto AEAD enum into the approved Wallet storage subset.
pub fn storage_encryption_algorithm_from_proto(
    algorithm: crypto_pb::AeadAlgorithm,
) -> ConvertResult<wallet::StorageEncryptionAlgorithm> {
    match algorithm {
        crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM_SIV => {
            Ok(wallet::StorageEncryptionAlgorithm::Aes256GcmSiv)
        }
        crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_XCHACHA20_POLY1305 => {
            Ok(wallet::StorageEncryptionAlgorithm::XChaCha20Poly1305)
        }
        crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_UNSPECIFIED
        | crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_128_GCM
        | crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_192_GCM
        | crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM
        | crypto_pb::AeadAlgorithm::AEAD_ALGORITHM_CHACHA20_POLY1305 => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet encrypted-record header into protobuf.
#[must_use]
pub fn encrypted_record_header_to_proto(
    header: &wallet::EncryptedRecordHeader,
) -> pb::EncryptedRecordHeader {
    let mut result = pb::EncryptedRecordHeader::default();
    result.schema_version = u32::from(header.schema_version);
    result.key_handle_id = header.key_handle_id.as_str().to_owned();
    result.created_at = MessageField::some(unix_timestamp_to_proto(header.created_at));
    result.encryption_algorithm =
        EnumValue::from(storage_encryption_algorithm_to_proto(header.algorithm));
    result
}

/// Convert a generated protobuf encrypted-record header into a wallet header.
pub fn encrypted_record_header_from_proto(
    header: &pb::EncryptedRecordHeader,
) -> ConvertResult<wallet::EncryptedRecordHeader> {
    let schema_version = u16::try_from(header.schema_version)
        .map_err(|_| ConvertError::new(ConvertErrorReason::IntegerOutOfRange))?;
    if schema_version == 0 {
        return Err(ConvertError::new(ConvertErrorReason::UnsupportedSchema));
    }
    let created_at = header
        .created_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let algorithm = known_enum(header.encryption_algorithm)
        .and_then(storage_encryption_algorithm_from_proto)?;

    Ok(wallet::EncryptedRecordHeader {
        schema_version,
        key_handle_id: wallet::KeyHandleId::new(header.key_handle_id.clone())?,
        algorithm,
        created_at,
    })
}

/// Convert a wallet encrypted record into protobuf.
#[must_use]
pub fn encrypted_record_to_proto(record: &wallet::EncryptedRecord) -> pb::EncryptedRecord {
    let mut result = pb::EncryptedRecord::default();
    result.header = MessageField::some(encrypted_record_header_to_proto(&record.header));
    result.nonce = record.nonce.clone();
    result.aad = record.aad.clone();
    result.ciphertext = record.ciphertext.clone();
    result
}

/// Convert a generated protobuf encrypted record into a wallet encrypted record.
pub fn encrypted_record_from_proto(
    record: &pb::EncryptedRecord,
) -> ConvertResult<wallet::EncryptedRecord> {
    let header = record
        .header
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(encrypted_record_header_from_proto)?;

    Ok(wallet::EncryptedRecord {
        header,
        nonce: record.nonce.clone(),
        aad: record.aad.clone(),
        ciphertext: record.ciphertext.clone(),
    })
}

/// Convert key attestation evidence into protobuf.
#[must_use]
pub fn key_attestation_evidence_to_proto(
    evidence: &keystore::KeyAttestationEvidence,
) -> pb::KeyAttestationEvidence {
    let mut result = pb::KeyAttestationEvidence::default();
    result.key_handle_id = evidence.key_handle_id.as_str().to_owned();
    result.evidence = evidence.evidence.clone();
    result.issued_at = MessageField::some(unix_timestamp_to_proto(evidence.issued_at));
    result.challenge = evidence.challenge.to_vec();
    result
}

/// Convert generated protobuf key attestation evidence into wallet type.
pub fn key_attestation_evidence_from_proto(
    evidence: &pb::KeyAttestationEvidence,
) -> ConvertResult<keystore::KeyAttestationEvidence> {
    let issued_at = evidence
        .issued_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let challenge =
        <[u8; keystore::KEY_ATTESTATION_CHALLENGE_BYTES]>::try_from(evidence.challenge.as_slice())
            .map_err(|_| ConvertError::new(ConvertErrorReason::IntegerOutOfRange))?;

    Ok(keystore::KeyAttestationEvidence {
        key_handle_id: wallet::KeyHandleId::new(evidence.key_handle_id.clone())?,
        evidence: evidence.evidence.clone(),
        issued_at,
        challenge,
    })
}

/// Convert wallet unit attestation into protobuf.
#[must_use]
pub fn wallet_unit_attestation_to_proto(
    attestation: &attestation::WalletUnitAttestation,
) -> pb::WalletUnitAttestation {
    let mut result = pb::WalletUnitAttestation::default();
    result.id = attestation.id().as_str().to_owned();
    result.evidence = MessageField::some(key_attestation_evidence_to_proto(attestation.evidence()));
    result.valid_until = MessageField::some(unix_timestamp_to_proto(attestation.valid_until()));
    result.signed_provider_artifact = attestation.signed_provider_artifact().to_vec();
    result
}

/// Convert generated protobuf wallet unit attestation into wallet type.
pub fn wallet_unit_attestation_from_proto(
    attestation: &pb::WalletUnitAttestation,
) -> ConvertResult<attestation::UnverifiedWalletUnitAttestation> {
    let evidence = attestation
        .evidence
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(key_attestation_evidence_from_proto)?;
    let valid_until = attestation
        .valid_until
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;

    attestation::UnverifiedWalletUnitAttestation::new(
        wallet::WalletUnitAttestationId::new(attestation.id.clone())?,
        evidence,
        valid_until,
        attestation.signed_provider_artifact.clone(),
    )
    .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidAttestationEvidence))
}

/// Convert a wallet credential format into protobuf.
#[must_use]
pub fn credential_format_to_proto(
    format: wallet::CredentialFormat,
) -> openid4vci_pb::CredentialFormat {
    match format {
        wallet::CredentialFormat::SdJwtVc => {
            openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT
        }
        wallet::CredentialFormat::Mdoc => {
            openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_MSO_MDOC
        }
        wallet::CredentialFormat::JwtVc => {
            openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_JWT_VC_JSON
        }
        wallet::CredentialFormat::DataIntegrity => {
            openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_LDP_VC
        }
        wallet::CredentialFormat::ReallyMeZkV1 => {
            openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_REALLYME_ZK_V1
        }
    }
}

/// Convert a generated protobuf credential format into wallet format.
pub fn credential_format_from_proto(
    format: openid4vci_pb::CredentialFormat,
) -> ConvertResult<wallet::CredentialFormat> {
    match format {
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT => {
            Ok(wallet::CredentialFormat::SdJwtVc)
        }
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_MSO_MDOC => {
            Ok(wallet::CredentialFormat::Mdoc)
        }
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_JWT_VC_JSON => {
            Ok(wallet::CredentialFormat::JwtVc)
        }
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_JWT_VC_JSON_LD => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_REALLYME_ZK_V1 => {
            Ok(wallet::CredentialFormat::ReallyMeZkV1)
        }
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_LDP_VC => {
            Ok(wallet::CredentialFormat::DataIntegrity)
        }
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet credential status into protobuf.
#[must_use]
pub fn credential_status_to_proto(
    status: wallet::CredentialStatus,
) -> pb::CredentialLifecycleStatus {
    match status {
        wallet::CredentialStatus::Active => {
            pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_ACTIVE
        }
        wallet::CredentialStatus::Suspended => {
            pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_SUSPENDED
        }
        wallet::CredentialStatus::Revoked => {
            pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_REVOKED
        }
        wallet::CredentialStatus::Deleted => {
            pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_DELETED
        }
    }
}

/// Convert a generated protobuf credential status into wallet status.
pub fn credential_status_from_proto(
    status: pb::CredentialLifecycleStatus,
) -> ConvertResult<wallet::CredentialStatus> {
    match status {
        pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_ACTIVE => {
            Ok(wallet::CredentialStatus::Active)
        }
        pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_SUSPENDED => {
            Ok(wallet::CredentialStatus::Suspended)
        }
        pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_REVOKED => {
            Ok(wallet::CredentialStatus::Revoked)
        }
        pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_DELETED => {
            Ok(wallet::CredentialStatus::Deleted)
        }
        pb::CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet credential status evidence method into protobuf.
#[must_use]
pub fn credential_status_evidence_method_to_proto(
    method: wallet::CredentialStatusEvidenceMethod,
) -> pb::CredentialStatusEvidenceMethod {
    match method {
        wallet::CredentialStatusEvidenceMethod::TokenStatusList => {
            pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_TOKEN_STATUS_LIST
        }
        wallet::CredentialStatusEvidenceMethod::RevocationList => {
            pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_REVOCATION_LIST
        }
        wallet::CredentialStatusEvidenceMethod::SuspensionList => {
            pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_SUSPENSION_LIST
        }
        wallet::CredentialStatusEvidenceMethod::IssuerRefresh => {
            pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_ISSUER_REFRESH
        }
        wallet::CredentialStatusEvidenceMethod::QtspDecision => {
            pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_QTSP_DECISION
        }
    }
}

/// Convert a generated protobuf status evidence method into wallet type.
pub fn credential_status_evidence_method_from_proto(
    method: pb::CredentialStatusEvidenceMethod,
) -> ConvertResult<wallet::CredentialStatusEvidenceMethod> {
    match method {
        pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_TOKEN_STATUS_LIST => {
            Ok(wallet::CredentialStatusEvidenceMethod::TokenStatusList)
        }
        pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_REVOCATION_LIST => {
            Ok(wallet::CredentialStatusEvidenceMethod::RevocationList)
        }
        pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_SUSPENSION_LIST => {
            Ok(wallet::CredentialStatusEvidenceMethod::SuspensionList)
        }
        pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_ISSUER_REFRESH => {
            Ok(wallet::CredentialStatusEvidenceMethod::IssuerRefresh)
        }
        pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_QTSP_DECISION => {
            Ok(wallet::CredentialStatusEvidenceMethod::QtspDecision)
        }
        pb::CredentialStatusEvidenceMethod::CREDENTIAL_STATUS_EVIDENCE_METHOD_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert checked wallet credential status evidence into protobuf.
#[must_use]
pub fn credential_status_evidence_to_proto(
    evidence: &wallet::CredentialStatusEvidence,
) -> pb::CredentialStatusEvidence {
    let mut result = pb::CredentialStatusEvidence::default();
    result.credential_id = evidence.credential_id.as_str().to_owned();
    result.observed_status = EnumValue::from(credential_status_to_proto(evidence.observed_status));
    result.method = EnumValue::from(credential_status_evidence_method_to_proto(evidence.method));
    result.checked_at = MessageField::some(unix_timestamp_to_proto(evidence.checked_at));
    result.valid_until = MessageField::some(unix_timestamp_to_proto(evidence.valid_until));
    result.source_issuer = evidence.source_issuer.as_str().to_owned();
    result.source_list_id = evidence.source_list_id.to_vec();
    result.status_index = evidence.status_index;
    result.source_issued_at =
        MessageField::some(unix_timestamp_to_proto(evidence.source_issued_at));
    result
}

/// Convert generated protobuf status evidence into a wallet type.
pub fn credential_status_evidence_from_proto(
    evidence: &pb::CredentialStatusEvidence,
) -> ConvertResult<wallet::CredentialStatusEvidence> {
    let checked_at = evidence
        .checked_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let valid_until = evidence
        .valid_until
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let source_issued_at = evidence
        .source_issued_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let source_list_id = <[u8; 32]>::try_from(evidence.source_list_id.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::IntegerOutOfRange))?;

    Ok(wallet::CredentialStatusEvidence {
        credential_id: wallet::CredentialRecordId::new(evidence.credential_id.clone())?,
        observed_status: credential_status_from_proto(known_enum(evidence.observed_status)?)?,
        method: credential_status_evidence_method_from_proto(known_enum(evidence.method)?)?,
        source_issuer: wallet::SignedCredentialIssuer::new(evidence.source_issuer.clone())?,
        source_list_id,
        status_index: evidence.status_index,
        source_issued_at,
        checked_at,
        valid_until,
    })
}
