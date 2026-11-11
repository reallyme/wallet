// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical Wallet plaintext for one encrypted, once-only prepared token.
//!
//! This codec owns Wallet identity and size checks. The presentation adapter
//! separately decodes and joins the embedded ZK evidence before disclosure.

use buffa::{DecodeOptions, Message};
use crypto_sha2_256::digest;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types::{
    CredentialRecordId, EncryptedRecord, EncryptedRecordHeader, KeyHandleId, NonEmptyIdentifier,
    PresentationCopyId, StorageEncryptionAlgorithm,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    ProtoError, ProtoErrorReason, ProtoResult, MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES,
    MAX_WALLET_PROTO_MESSAGE_BYTES, MAX_WALLET_PROTO_RECURSION_DEPTH,
    WALLET_PROTO_UNKNOWN_FIELD_LIMIT,
};

const PRIVATE_TOKEN_AAD_DOMAIN: &[u8] = b"reallyme-wallet-private-prepared-token-v1\0";
const PRIVATE_TOKEN_SCHEMA_VERSION: u16 = 1;
const AEAD_TAG_BYTES: usize = 16;
const AAD_DIGEST_BYTES: usize = 32;

/// Checked Wallet envelope for four prepared private proofs and one key handle.
///
/// Proof bytes are sensitive even though they are zero-knowledge: retaining a
/// token after use would permit verifier correlation. The caller encrypts the
/// encoded form before persistence and burns its outer copy before decrypting.
#[derive(ZeroizeOnDrop)]
pub struct PreparedPrivateTokenPayload {
    copy_id: PresentationCopyId,
    credential_id: CredentialRecordId,
    prepared_credential_evidence: Zeroizing<Vec<u8>>,
    one_time_key_handle_id: KeyHandleId,
    wallet_instance_id: NonEmptyIdentifier,
}

impl PreparedPrivateTokenPayload {
    /// Validate Wallet identity and resource limits before encryption.
    pub fn try_new(
        copy_id: PresentationCopyId,
        credential_id: CredentialRecordId,
        prepared_credential_evidence: Zeroizing<Vec<u8>>,
        one_time_key_handle_id: KeyHandleId,
        wallet_instance_id: NonEmptyIdentifier,
    ) -> ProtoResult<Self> {
        if prepared_credential_evidence.is_empty()
            || prepared_credential_evidence.len() > MAX_WALLET_PROTO_MESSAGE_BYTES
        {
            return Err(ProtoError::new(ProtoErrorReason::InvalidDto));
        }
        Ok(Self {
            copy_id,
            credential_id,
            prepared_credential_evidence,
            one_time_key_handle_id,
            wallet_instance_id,
        })
    }

    /// Identity of the durable copy that must be claimed before opening.
    #[must_use]
    pub fn copy_id(&self) -> &PresentationCopyId {
        &self.copy_id
    }

    /// Inventory credential selected by consent.
    #[must_use]
    pub fn credential_id(&self) -> &CredentialRecordId {
        &self.credential_id
    }

    /// Canonical ZK evidence bytes, subject to ZK semantic validation.
    #[must_use]
    pub fn prepared_credential_evidence(&self) -> &[u8] {
        &self.prepared_credential_evidence
    }

    /// Opaque protected one-time signing-key reference.
    #[must_use]
    pub fn one_time_key_handle_id(&self) -> &KeyHandleId {
        &self.one_time_key_handle_id
    }

    /// Wallet lifecycle identity for the protected signer.
    #[must_use]
    pub fn wallet_instance_id(&self) -> &NonEmptyIdentifier {
        &self.wallet_instance_id
    }
}

/// Encode a validated token as bounded canonical Buffa protobuf plaintext.
pub fn encode_prepared_private_token(
    payload: &PreparedPrivateTokenPayload,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    // Buffa generates ZeroizeOnDrop for this sensitive protobuf message.
    let mut message = pb::PreparedPrivateTokenPayloadV1::default();
    message.copy_id = payload.copy_id.as_str().to_owned();
    message.credential_id = payload.credential_id.as_str().to_owned();
    message.prepared_credential_evidence = payload.prepared_credential_evidence.to_vec();
    message.one_time_key_handle_id = payload.one_time_key_handle_id.as_str().to_owned();
    message.wallet_instance_id = payload.wallet_instance_id.as_str().to_owned();
    let limit = u32::try_from(MAX_WALLET_PROTO_MESSAGE_BYTES)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    let length = message
        .try_encoded_len()
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    if length > limit {
        return Err(ProtoError::new(ProtoErrorReason::MessageTooLarge));
    }
    let capacity =
        usize::try_from(length).map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    message
        .try_encode_bounded(limit, &mut *encoded)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    Ok(encoded)
}

/// Decode and bind plaintext to the already claimed outer copy.
///
/// The caller must supply the expected copy and credential identifiers from
/// the durable claim. Unknown fields and alternate protobuf encodings fail.
pub fn decode_prepared_private_token(
    plaintext: &[u8],
    expected_copy_id: &PresentationCopyId,
    expected_credential_id: &CredentialRecordId,
) -> ProtoResult<PreparedPrivateTokenPayload> {
    if plaintext.len() > MAX_WALLET_PROTO_MESSAGE_BYTES {
        return Err(ProtoError::new(ProtoErrorReason::MessageTooLarge));
    }
    let mut message = DecodeOptions::new()
        .with_recursion_limit(MAX_WALLET_PROTO_RECURSION_DEPTH)
        .with_max_message_size(MAX_WALLET_PROTO_MESSAGE_BYTES)
        .with_element_memory_limit(MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES)
        .with_unknown_field_limit(WALLET_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice::<pb::PreparedPrivateTokenPayloadV1>(plaintext)
        .map_err(ProtoError::from)?;
    if message.copy_id != expected_copy_id.as_str()
        || message.credential_id != expected_credential_id.as_str()
    {
        return Err(ProtoError::new(ProtoErrorReason::InvalidDto));
    }
    let payload = PreparedPrivateTokenPayload::try_new(
        PresentationCopyId::new(core::mem::take(&mut message.copy_id))
            .map_err(|_| ProtoError::new(ProtoErrorReason::InvalidDto))?,
        CredentialRecordId::new(core::mem::take(&mut message.credential_id))
            .map_err(|_| ProtoError::new(ProtoErrorReason::InvalidDto))?,
        Zeroizing::new(core::mem::take(&mut message.prepared_credential_evidence)),
        KeyHandleId::new(core::mem::take(&mut message.one_time_key_handle_id))
            .map_err(|_| ProtoError::new(ProtoErrorReason::InvalidDto))?,
        NonEmptyIdentifier::new(core::mem::take(&mut message.wallet_instance_id))
            .map_err(|_| ProtoError::new(ProtoErrorReason::InvalidDto))?,
    )?;
    let encoded = encode_prepared_private_token(&payload)?;
    if encoded.as_slice() != plaintext {
        return Err(ProtoError::new(ProtoErrorReason::InvalidDto));
    }
    Ok(payload)
}

/// Bind the encrypted record header and both outer inventory identities.
///
/// The platform AEAD must authenticate this digest as its associated data.
/// The same digest is checked before a claimed copy reaches the opener.
pub fn prepared_private_token_aad_digest(
    copy_id: &PresentationCopyId,
    credential_id: &CredentialRecordId,
    header: &EncryptedRecordHeader,
) -> ProtoResult<[u8; AAD_DIGEST_BYTES]> {
    let key_handle = header.key_handle_id.as_str();
    let capacity = PRIVATE_TOKEN_AAD_DOMAIN
        .len()
        .checked_add(2)
        .and_then(|length| length.checked_add(copy_id.as_str().len()))
        .and_then(|length| length.checked_add(2))
        .and_then(|length| length.checked_add(credential_id.as_str().len()))
        .and_then(|length| length.checked_add(2))
        .and_then(|length| length.checked_add(key_handle.len()))
        .and_then(|length| length.checked_add(2))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(8))
        .ok_or(ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    bytes.extend_from_slice(PRIVATE_TOKEN_AAD_DOMAIN);
    append_bounded_identifier(&mut bytes, copy_id.as_str())?;
    append_bounded_identifier(&mut bytes, credential_id.as_str())?;
    bytes.extend_from_slice(&header.schema_version.to_be_bytes());
    append_bounded_identifier(&mut bytes, key_handle)?;
    bytes.push(match header.algorithm {
        StorageEncryptionAlgorithm::Aes256GcmSiv => 1,
        StorageEncryptionAlgorithm::XChaCha20Poly1305 => 2,
    });
    bytes.extend_from_slice(&header.created_at.as_seconds().to_be_bytes());
    Ok(digest(&bytes).into_bytes())
}

/// Reject a substituted or malformed encrypted copy before decrypting it.
pub fn validate_prepared_private_token_record(
    copy_id: &PresentationCopyId,
    credential_id: &CredentialRecordId,
    encrypted: &EncryptedRecord,
) -> ProtoResult<()> {
    let max_ciphertext = MAX_WALLET_PROTO_MESSAGE_BYTES
        .checked_add(AEAD_TAG_BYTES)
        .ok_or(ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    if encrypted.header.schema_version != PRIVATE_TOKEN_SCHEMA_VERSION
        || encrypted.nonce.len() != encrypted.header.algorithm.nonce_length()
        || encrypted.ciphertext.len() < AEAD_TAG_BYTES
        || encrypted.ciphertext.len() > max_ciphertext
    {
        return Err(ProtoError::new(ProtoErrorReason::InvalidDto));
    }
    let expected = prepared_private_token_aad_digest(copy_id, credential_id, &encrypted.header)?;
    if encrypted.aad.as_slice() != expected {
        return Err(ProtoError::new(ProtoErrorReason::InvalidDto));
    }
    Ok(())
}

fn append_bounded_identifier(bytes: &mut Vec<u8>, value: &str) -> ProtoResult<()> {
    let length =
        u16::try_from(value.len()).map_err(|_| ProtoError::new(ProtoErrorReason::InvalidDto))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
#[path = "prepared_private_token_tests.rs"]
mod tests;
