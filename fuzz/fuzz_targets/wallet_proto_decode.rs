// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz SDK-facing protobuf decoders on arbitrary bytes.
//! Property: every wallet DTO decoder must reject malformed input with a typed
//! error and must never panic on attacker-controlled bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_wallet_proto_codec::decode::{
    decode_consent_request, decode_consent_scope, decode_credential_record,
    decode_credential_status_evidence, decode_encrypted_record, decode_flow_snapshot,
    decode_hardware_key_binding_record, decode_key_attestation_evidence,
    decode_openid4vci_issuance_commit, decode_portable_key_storage_record,
    decode_presentation_copy, decode_qtsp_decision_record, decode_transaction_log_entry,
    decode_verifier_entitlement, decode_wallet_lifecycle_evidence_record,
    decode_wallet_lifecycle_record, decode_wallet_operation_request,
    decode_wallet_operation_response, decode_wallet_provider_response,
    decode_wallet_unit_attestation,
};

use reallyme_wallet_proto_codec::policy_records::{
    decode_consent_receipt, decode_credential_reuse_state, decode_flow_execution_record,
    decode_transaction_history_record,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode_credential_reuse_state(data);
    let _ = decode_consent_receipt(data);
    let _ = decode_transaction_history_record(data);
    let _ = decode_flow_execution_record(data);
    let _ = decode_credential_record(data);
    let _ = decode_credential_status_evidence(data);
    let _ = decode_encrypted_record(data);
    let _ = decode_key_attestation_evidence(data);
    let _ = decode_wallet_unit_attestation(data);
    let _ = decode_presentation_copy(data);
    let _ = decode_consent_scope(data);
    let _ = decode_consent_request(data);
    let _ = decode_verifier_entitlement(data);
    let _ = decode_flow_snapshot(data);
    let _ = decode_wallet_lifecycle_record(data);
    let _ = decode_wallet_lifecycle_evidence_record(data);
    let _ = decode_transaction_log_entry(data);
    let _ = decode_qtsp_decision_record(data);
    let _ = decode_wallet_operation_request(data);
    let _ = decode_wallet_operation_response(data);
    let _ = decode_wallet_provider_response(data);
    let _ = decode_portable_key_storage_record(data);
    let _ = decode_hardware_key_binding_record(data);
    let _ = decode_openid4vci_issuance_commit(data);
});
