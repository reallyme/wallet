// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encode wallet-core domain values into protobuf bytes.

use buffa::Message;
use reallyme_wallet_attestation as attestation;
use reallyme_wallet_keystore as keystore;
use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

use crate::convert::{
    consent_request_to_proto, consent_scope_to_proto, credential_record_to_proto,
    credential_status_evidence_to_proto, encrypted_record_to_proto, flow_snapshot_to_proto,
    issuance_commit_to_proto, key_attestation_evidence_to_proto, presentation_copy_to_proto,
    qtsp_decision_record_to_proto, transaction_log_entry_to_proto, verifier_entitlement_to_proto,
    wallet_lifecycle_evidence_record_to_proto, wallet_lifecycle_record_to_proto,
    wallet_unit_attestation_to_proto,
};
use crate::{
    validate_did_storage_record, validate_hardware_key_binding_record,
    validate_portable_key_storage_record, ProtoError, ProtoErrorReason, ProtoResult,
    MAX_WALLET_PROTO_MESSAGE_BYTES, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES,
};

fn encode_message<M: Message>(message: &M) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message_with_limit(message, MAX_WALLET_PROTO_MESSAGE_BYTES)
}

fn encode_message_with_limit<M: Message>(
    message: &M,
    max_bytes: usize,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    let max_bytes =
        u32::try_from(max_bytes).map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    let encoded_len = message
        .try_encoded_len()
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    if encoded_len > max_bytes {
        return Err(ProtoError::new(ProtoErrorReason::MessageTooLarge));
    }
    let capacity = usize::try_from(encoded_len)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    let mut encoded = Zeroizing::new(Vec::new());
    // Reserve the exact encoded bound before secret bytes are written so Vec
    // growth cannot leave plaintext copies in retired allocations.
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    message
        .try_encode_bounded(max_bytes, &mut *encoded)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    Ok(encoded)
}

/// Encode a versioned Wallet provider descriptor under provider limits.
pub fn encode_wallet_provider_descriptor(
    descriptor: &pb::WalletProviderDescriptor,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message_with_limit(descriptor, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES)
}

/// Encode a versioned Wallet provider request under provider limits.
pub fn encode_wallet_provider_request(
    request: &pb::WalletProviderRequest,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message_with_limit(request, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES)
}

/// Encode a versioned Wallet provider response under provider limits.
pub fn encode_wallet_provider_response(
    response: &pb::WalletProviderResponse,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message_with_limit(response, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES)
}

/// Encode the canonical Wallet operation request as bounded protobuf bytes.
pub fn encode_wallet_operation_request(
    request: &pb::WalletOperationRequest,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(request)
}

/// Encode a canonical Wallet operation response as bounded protobuf bytes.
pub fn encode_wallet_operation_response(
    response: &pb::WalletOperationResponse,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(response)
}

/// Encode a validated Wallet-owned DID storage record.
pub fn encode_did_storage_record(record: &pb::DidStorageRecord) -> ProtoResult<Zeroizing<Vec<u8>>> {
    validate_did_storage_record(record)?;
    encode_message(record)
}

/// Encode a validated portable wrapped-key storage record.
pub fn encode_portable_key_storage_record(
    record: &pb::PortableKeyStorageRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    validate_portable_key_storage_record(record)?;
    encode_message(record)
}

/// Encode a validated installation-bound hardware-key reference.
pub fn encode_hardware_key_binding_record(
    record: &pb::HardwareKeyBindingRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    validate_hardware_key_binding_record(record)?;
    encode_message(record)
}

/// Encode a validated wallet credential record as protobuf bytes.
pub fn encode_credential_record(
    record: &wallet::CredentialRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&credential_record_to_proto(record))
}

/// Encode checked credential status evidence as protobuf bytes.
pub fn encode_credential_status_evidence(
    evidence: &wallet::CredentialStatusEvidence,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&credential_status_evidence_to_proto(evidence))
}

/// Encode a wallet encrypted record as protobuf bytes.
pub fn encode_encrypted_record(
    record: &wallet::EncryptedRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&encrypted_record_to_proto(record))
}

/// Encode key attestation evidence as protobuf bytes.
pub fn encode_key_attestation_evidence(
    evidence: &keystore::KeyAttestationEvidence,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&key_attestation_evidence_to_proto(evidence))
}

/// Encode a wallet unit attestation as protobuf bytes.
pub fn encode_wallet_unit_attestation(
    attestation: &attestation::WalletUnitAttestation,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&wallet_unit_attestation_to_proto(attestation))
}

/// Encode a once-only presentation copy as protobuf bytes.
pub fn encode_presentation_copy(
    copy: &wallet::OnceOnlyPresentationCopy,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&presentation_copy_to_proto(copy))
}

/// Encode a consent scope as protobuf bytes.
pub fn encode_consent_scope(scope: &wallet::ConsentScope) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&consent_scope_to_proto(scope))
}

/// Encode a prepared consent request as protobuf bytes.
pub fn encode_consent_request(request: &wallet::ConsentRequest) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&consent_request_to_proto(request))
}

/// Encode verifier entitlement as protobuf bytes.
pub fn encode_verifier_entitlement(
    entitlement: &wallet::VerifierEntitlement,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&verifier_entitlement_to_proto(entitlement))
}

/// Encode a resumable wallet flow snapshot as protobuf bytes.
pub fn encode_flow_snapshot(snapshot: &wallet::FlowSnapshot) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&flow_snapshot_to_proto(snapshot))
}

/// Encode an atomic OpenID4VCI issuance commit as protobuf bytes.
pub fn encode_openid4vci_issuance_commit(
    commit: &crate::convert::OpenId4VciIssuanceCommit,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&issuance_commit_to_proto(commit))
}

/// Encode a Wallet Unit lifecycle record as protobuf bytes.
pub fn encode_wallet_lifecycle_record(
    record: &lifecycle::WalletLifecycleRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&wallet_lifecycle_record_to_proto(record))
}

/// Encode a Wallet Unit lifecycle evidence record as protobuf bytes.
pub fn encode_wallet_lifecycle_evidence_record(
    record: &lifecycle::WalletLifecycleEvidenceRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&wallet_lifecycle_evidence_record_to_proto(record))
}

/// Encode a user-visible transaction log entry as protobuf bytes.
pub fn encode_transaction_log_entry(
    entry: &wallet::TransactionLogEntry,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&transaction_log_entry_to_proto(entry))
}

/// Encode a QTSP decision record as protobuf bytes.
pub fn encode_qtsp_decision_record(
    record: &wallet::QtspDecisionRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    encode_message(&qtsp_decision_record_to_proto(record))
}
