// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Buffa storage codec for encrypted ZK preparation and outputs.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types::CredentialRecordId;
use reallyme_wallet_zk::{ZkArtifactDescriptor, ZkArtifactKind, ZkStoredArtifactRecord};
use reallyme_zk_api::{circuits::ZkCircuitRef, proofs::ZkSessionBinding};
use zeroize::Zeroizing;

use crate::convert::{
    encrypted_record_from_proto, encrypted_record_to_proto, unix_timestamp_from_proto,
    unix_timestamp_to_proto, ConvertError, ConvertErrorReason, ConvertResult,
};
use crate::{
    ProtoError, ProtoErrorReason, ProtoResult, MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES,
    MAX_WALLET_PROTO_MESSAGE_BYTES, MAX_WALLET_PROTO_RECURSION_DEPTH,
    WALLET_PROTO_UNKNOWN_FIELD_LIMIT,
};

const DIGEST_BYTES: usize = 32;
const MAX_LINKED_CREDENTIALS: usize = 2;

/// Convert validated encrypted ZK storage into its canonical Wallet DTO.
#[must_use]
pub fn zk_artifact_to_proto(record: &ZkStoredArtifactRecord) -> pb::ZkStoredArtifact {
    let descriptor = record.descriptor();
    let mut message = pb::ZkStoredArtifact::default();
    message.artifact_id = descriptor.artifact_id().to_vec();
    message.credential_record_ids = descriptor
        .credential_ids()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    let circuit_ref = descriptor.circuit_ref();
    message.circuit_ref = format!(
        "{}:{}:{}:v1",
        circuit_ref.credential_hash_algorithm.as_str(),
        circuit_ref.family.as_str(),
        circuit_ref.stage.as_str()
    );
    message.kind = EnumValue::from(match descriptor.kind() {
        ZkArtifactKind::PreparedInput => {
            pb::ZkStoredArtifactKind::ZK_STORED_ARTIFACT_KIND_PREPARED_INPUT
        }
        ZkArtifactKind::Witness => pb::ZkStoredArtifactKind::ZK_STORED_ARTIFACT_KIND_WITNESS,
        ZkArtifactKind::Proof => pb::ZkStoredArtifactKind::ZK_STORED_ARTIFACT_KIND_PROOF,
        ZkArtifactKind::PreparedPublicProof => {
            pb::ZkStoredArtifactKind::ZK_STORED_ARTIFACT_KIND_PREPARED_PUBLIC_PROOF
        }
    });
    message.claim_scope_digest = descriptor.claim_scope_digest().to_vec();
    if let Some(binding) = descriptor.request_binding() {
        message.nonce_hash = binding.nonce_hash.to_vec();
        message.audience_hash = binding.audience_hash.to_vec();
        if let Some(hash) = binding.transaction_data_hash {
            message.transaction_data_hash = hash.to_vec();
        }
    }
    message.expires_at = MessageField::some(unix_timestamp_to_proto(descriptor.expires_at()));
    message.encrypted_payload = MessageField::some(encrypted_record_to_proto(record.encrypted()));
    message
}

/// Admit a decoded storage DTO only after checking all metadata and AEAD AAD.
pub fn zk_artifact_from_proto(
    message: &pb::ZkStoredArtifact,
) -> ConvertResult<ZkStoredArtifactRecord> {
    if message.credential_record_ids.is_empty()
        || message.credential_record_ids.len() > MAX_LINKED_CREDENTIALS
        || message.encrypted_payload.as_option().is_none()
    {
        return Err(ConvertError::new(ConvertErrorReason::InvalidZkArtifact));
    }
    let artifact_id = fixed_digest(&message.artifact_id)?;
    let claim_scope_digest = fixed_digest(&message.claim_scope_digest)?;
    let mut credential_ids = Vec::with_capacity(message.credential_record_ids.len());
    for value in &message.credential_record_ids {
        credential_ids.push(CredentialRecordId::new(value.clone())?);
    }
    let circuit_ref = ZkCircuitRef::try_from_stable_name(&message.circuit_ref)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidZkArtifact))?;
    let kind = match message.kind.as_known() {
        Some(pb::ZkStoredArtifactKind::ZK_STORED_ARTIFACT_KIND_PREPARED_INPUT) => {
            ZkArtifactKind::PreparedInput
        }
        Some(pb::ZkStoredArtifactKind::ZK_STORED_ARTIFACT_KIND_WITNESS) => ZkArtifactKind::Witness,
        Some(pb::ZkStoredArtifactKind::ZK_STORED_ARTIFACT_KIND_PROOF) => ZkArtifactKind::Proof,
        Some(pb::ZkStoredArtifactKind::ZK_STORED_ARTIFACT_KIND_PREPARED_PUBLIC_PROOF) => {
            ZkArtifactKind::PreparedPublicProof
        }
        _ => return Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue)),
    };
    let request_binding = match kind {
        ZkArtifactKind::PreparedInput | ZkArtifactKind::PreparedPublicProof => {
            if !message.nonce_hash.is_empty()
                || !message.audience_hash.is_empty()
                || !message.transaction_data_hash.is_empty()
            {
                return Err(ConvertError::new(ConvertErrorReason::InvalidZkArtifact));
            }
            None
        }
        ZkArtifactKind::Witness | ZkArtifactKind::Proof => Some(ZkSessionBinding {
            nonce_hash: fixed_digest(&message.nonce_hash)?,
            audience_hash: fixed_digest(&message.audience_hash)?,
            transaction_data_hash: if message.transaction_data_hash.is_empty() {
                None
            } else {
                Some(fixed_digest(&message.transaction_data_hash)?)
            },
        }),
    };
    let expires_at = message
        .expires_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let descriptor = ZkArtifactDescriptor::new(
        artifact_id,
        credential_ids,
        circuit_ref,
        kind,
        claim_scope_digest,
        request_binding,
        expires_at,
    )
    .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidZkArtifact))?;
    let encrypted = message
        .encrypted_payload
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(encrypted_record_from_proto)?;
    if encrypted.ciphertext.len() > MAX_WALLET_PROTO_MESSAGE_BYTES {
        return Err(ConvertError::new(ConvertErrorReason::InvalidZkArtifact));
    }
    ZkStoredArtifactRecord::new(descriptor, encrypted)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidZkArtifact))
}

/// Encode only validated storage records under the Wallet message limit.
pub fn encode_zk_artifact(record: &ZkStoredArtifactRecord) -> ProtoResult<Zeroizing<Vec<u8>>> {
    let message = zk_artifact_to_proto(record);
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
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(capacity)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    message
        .try_encode_bounded(limit, &mut *output)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    Ok(output)
}

/// Decode a persisted artifact with size, recursion, unknown-field and domain checks.
pub fn decode_zk_artifact(bytes: &[u8]) -> ProtoResult<ZkStoredArtifactRecord> {
    if bytes.len() > MAX_WALLET_PROTO_MESSAGE_BYTES {
        return Err(ProtoError::new(ProtoErrorReason::MessageTooLarge));
    }
    let message = DecodeOptions::new()
        .with_recursion_limit(MAX_WALLET_PROTO_RECURSION_DEPTH)
        .with_max_message_size(MAX_WALLET_PROTO_MESSAGE_BYTES)
        .with_element_memory_limit(MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES)
        .with_unknown_field_limit(WALLET_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice::<pb::ZkStoredArtifact>(bytes)
        .map_err(ProtoError::from)?;
    zk_artifact_from_proto(&message).map_err(ProtoError::from)
}

fn fixed_digest(bytes: &[u8]) -> ConvertResult<[u8; DIGEST_BYTES]> {
    <[u8; DIGEST_BYTES]>::try_from(bytes)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidZkArtifact))
}

#[cfg(test)]
#[path = "zk_artifact_tests.rs"]
mod tests;
