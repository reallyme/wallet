// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decode protobuf bytes into validated wallet-core domain values.

use buffa::{DecodeOptions, Message};
use reallyme_wallet_attestation as attestation;
use reallyme_wallet_keystore as keystore;
use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_types as wallet;

use crate::convert::{
    consent_request_from_proto, consent_scope_from_proto, credential_record_from_proto,
    credential_status_evidence_from_proto, encrypted_record_from_proto, flow_snapshot_from_proto,
    issuance_commit_from_proto, key_attestation_evidence_from_proto, presentation_copy_from_proto,
    qtsp_decision_record_from_proto, transaction_log_entry_from_proto,
    verifier_entitlement_from_proto, wallet_lifecycle_evidence_record_from_proto,
    wallet_lifecycle_record_from_proto, wallet_unit_attestation_from_proto,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

use crate::limits::{
    MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES, MAX_WALLET_PROTO_MESSAGE_BYTES,
    MAX_WALLET_PROTO_RECURSION_DEPTH, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES,
    WALLET_PROTO_UNKNOWN_FIELD_LIMIT,
};
use crate::{
    validate_did_storage_record, validate_hardware_key_binding_record,
    validate_portable_key_storage_record,
};
use crate::{ProtoError, ProtoErrorReason, ProtoResult};

fn decode_message<M: Message>(bytes: &[u8]) -> ProtoResult<M> {
    decode_message_with_limit(bytes, MAX_WALLET_PROTO_MESSAGE_BYTES)
}

fn decode_message_with_limit<M: Message>(bytes: &[u8], max_bytes: usize) -> ProtoResult<M> {
    if bytes.len() > max_bytes {
        return Err(ProtoError::new(ProtoErrorReason::MessageTooLarge));
    }

    DecodeOptions::new()
        .with_recursion_limit(MAX_WALLET_PROTO_RECURSION_DEPTH)
        .with_max_message_size(max_bytes)
        .with_element_memory_limit(MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES)
        .with_unknown_field_limit(WALLET_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(bytes)
        .map_err(ProtoError::from)
}

/// Decode a versioned Wallet provider descriptor under provider limits.
pub fn decode_wallet_provider_descriptor(
    bytes: &[u8],
) -> ProtoResult<pb::WalletProviderDescriptor> {
    decode_message_with_limit(bytes, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES)
}

/// Decode a versioned Wallet provider request under provider limits.
pub fn decode_wallet_provider_request(bytes: &[u8]) -> ProtoResult<pb::WalletProviderRequest> {
    decode_message_with_limit(bytes, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES)
}

/// Decode a versioned Wallet provider response under provider limits.
pub fn decode_wallet_provider_response(bytes: &[u8]) -> ProtoResult<pb::WalletProviderResponse> {
    decode_message_with_limit(bytes, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES)
}

/// Decode the canonical Wallet operation request under public boundary limits.
pub fn decode_wallet_operation_request(bytes: &[u8]) -> ProtoResult<pb::WalletOperationRequest> {
    decode_message(bytes)
}

/// Decode a canonical Wallet operation response under public boundary limits.
pub fn decode_wallet_operation_response(bytes: &[u8]) -> ProtoResult<pb::WalletOperationResponse> {
    decode_message(bytes)
}

/// Decode and validate a Wallet-owned DID storage record.
pub fn decode_did_storage_record(bytes: &[u8]) -> ProtoResult<pb::DidStorageRecord> {
    let record = decode_message::<pb::DidStorageRecord>(bytes)?;
    validate_did_storage_record(&record)?;
    Ok(record)
}

/// Decode and validate a portable wrapped-key storage record.
pub fn decode_portable_key_storage_record(
    bytes: &[u8],
) -> ProtoResult<pb::PortableKeyStorageRecord> {
    let record = decode_message::<pb::PortableKeyStorageRecord>(bytes)?;
    validate_portable_key_storage_record(&record)?;
    Ok(record)
}

/// Decode and validate an installation-bound hardware-key reference.
pub fn decode_hardware_key_binding_record(
    bytes: &[u8],
) -> ProtoResult<pb::HardwareKeyBindingRecord> {
    let record = decode_message::<pb::HardwareKeyBindingRecord>(bytes)?;
    validate_hardware_key_binding_record(&record)?;
    Ok(record)
}

/// Decode protobuf bytes into a validated wallet credential record.
pub fn decode_credential_record(bytes: &[u8]) -> ProtoResult<wallet::CredentialRecord> {
    let message = decode_message::<pb::CredentialRecord>(bytes)?;
    credential_record_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into checked credential status evidence.
pub fn decode_credential_status_evidence(
    bytes: &[u8],
) -> ProtoResult<wallet::CredentialStatusEvidence> {
    let message = decode_message::<pb::CredentialStatusEvidence>(bytes)?;
    credential_status_evidence_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a wallet encrypted record.
pub fn decode_encrypted_record(bytes: &[u8]) -> ProtoResult<wallet::EncryptedRecord> {
    let message = decode_message::<pb::EncryptedRecord>(bytes)?;
    encrypted_record_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into key attestation evidence.
pub fn decode_key_attestation_evidence(
    bytes: &[u8],
) -> ProtoResult<keystore::KeyAttestationEvidence> {
    let message = decode_message::<pb::KeyAttestationEvidence>(bytes)?;
    key_attestation_evidence_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a wallet unit attestation.
pub fn decode_wallet_unit_attestation(
    bytes: &[u8],
) -> ProtoResult<attestation::UnverifiedWalletUnitAttestation> {
    let message = decode_message::<pb::WalletUnitAttestation>(bytes)?;
    wallet_unit_attestation_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a once-only presentation copy.
pub fn decode_presentation_copy(bytes: &[u8]) -> ProtoResult<wallet::OnceOnlyPresentationCopy> {
    let message = decode_message::<pb::OnceOnlyPresentationCopy>(bytes)?;
    presentation_copy_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a consent scope.
pub fn decode_consent_scope(bytes: &[u8]) -> ProtoResult<wallet::ConsentScope> {
    let message = decode_message::<pb::ConsentScope>(bytes)?;
    consent_scope_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a prepared consent request.
pub fn decode_consent_request(bytes: &[u8]) -> ProtoResult<wallet::ConsentRequest> {
    let message = decode_message::<pb::ConsentRequest>(bytes)?;
    consent_request_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into verifier entitlement.
pub fn decode_verifier_entitlement(bytes: &[u8]) -> ProtoResult<wallet::VerifierEntitlement> {
    let message = decode_message::<pb::VerifierEntitlement>(bytes)?;
    verifier_entitlement_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a resumable wallet flow snapshot.
pub fn decode_flow_snapshot(bytes: &[u8]) -> ProtoResult<wallet::FlowSnapshot> {
    let message = decode_message::<pb::FlowSnapshot>(bytes)?;
    flow_snapshot_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a validated atomic OpenID4VCI issuance commit.
pub fn decode_openid4vci_issuance_commit(
    bytes: &[u8],
) -> ProtoResult<crate::convert::OpenId4VciIssuanceCommit> {
    let message = decode_message::<pb::OpenId4VciIssuanceCommit>(bytes)?;
    issuance_commit_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a Wallet Unit lifecycle record.
pub fn decode_wallet_lifecycle_record(
    bytes: &[u8],
) -> ProtoResult<lifecycle::WalletLifecycleRecord> {
    let message = decode_message::<pb::WalletLifecycleRecord>(bytes)?;
    wallet_lifecycle_record_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a Wallet Unit lifecycle evidence record.
pub fn decode_wallet_lifecycle_evidence_record(
    bytes: &[u8],
) -> ProtoResult<lifecycle::WalletLifecycleEvidenceRecord> {
    let message = decode_message::<pb::WalletLifecycleEvidenceRecord>(bytes)?;
    wallet_lifecycle_evidence_record_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a user-visible transaction log entry.
pub fn decode_transaction_log_entry(bytes: &[u8]) -> ProtoResult<wallet::TransactionLogEntry> {
    let message = decode_message::<pb::TransactionLogEntry>(bytes)?;
    transaction_log_entry_from_proto(&message).map_err(ProtoError::from)
}

/// Decode protobuf bytes into a QTSP decision record.
pub fn decode_qtsp_decision_record(bytes: &[u8]) -> ProtoResult<wallet::QtspDecisionRecord> {
    let message = decode_message::<pb::QtspDecisionRecord>(bytes)?;
    qtsp_decision_record_from_proto(&message).map_err(ProtoError::from)
}
