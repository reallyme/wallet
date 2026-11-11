// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exhaustiveness checks for the versioned Wallet operation capability manifest.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

const CAPABILITY_MANIFEST: &str = "conformance/features/wallet-operation-capabilities-v1.json";
const OPERATION_PROTO: &str = "crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto";
const OPERATION_EXECUTOR: &str = "crates/runtime/src/execute_operation.rs";
const RUNTIME_BACKEND: &str = "crates/runtime/src/backend.rs";

struct ExpectedOperation {
    name: &'static str,
    rust_variant: &'static str,
    field_number: u64,
    mutability: &'static str,
    atomicity: &'static str,
    provider_calls: &'static [&'static str],
}

const EXPECTED_OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation {
        name: "put_wallet_lifecycle_record",
        rust_variant: "PutWalletLifecycleRecord",
        field_number: 1001,
        mutability: "mutating",
        atomicity: "atomic_create",
        provider_calls: &["trusted_now", "create_wallet_lifecycle_record"],
    },
    ExpectedOperation {
        name: "get_wallet_lifecycle_record",
        rust_variant: "GetWalletLifecycleRecord",
        field_number: 1002,
        mutability: "read_only",
        atomicity: "read",
        provider_calls: &["get_wallet_lifecycle_record"],
    },
    ExpectedOperation {
        name: "apply_wallet_lifecycle_event",
        rust_variant: "ApplyWalletLifecycleEvent",
        field_number: 1003,
        mutability: "mutating",
        atomicity: "atomic_state_and_evidence_compare_and_swap",
        provider_calls: &[
            "trusted_now",
            "get_wallet_lifecycle_record",
            "verify_wallet_lifecycle_authority",
            "reconcile_wallet_lifecycle_retry",
            "compare_and_swap_wallet_lifecycle_record",
        ],
    },
    ExpectedOperation {
        name: "append_wallet_lifecycle_evidence",
        rust_variant: "AppendWalletLifecycleEvidence",
        field_number: 1004,
        mutability: "mutating",
        atomicity: "none",
        provider_calls: &[],
    },
    ExpectedOperation {
        name: "put_credential_record",
        rust_variant: "PutCredentialRecord",
        field_number: 2001,
        mutability: "mutating",
        atomicity: "none",
        provider_calls: &[],
    },
    ExpectedOperation {
        name: "get_credential_record",
        rust_variant: "GetCredentialRecord",
        field_number: 2002,
        mutability: "read_only",
        atomicity: "read",
        provider_calls: &["get_credential_record"],
    },
    ExpectedOperation {
        name: "apply_credential_status_evidence",
        rust_variant: "ApplyCredentialStatusEvidence",
        field_number: 2003,
        mutability: "mutating",
        atomicity: "none",
        provider_calls: &[],
    },
    ExpectedOperation {
        name: "delete_credential_record",
        rust_variant: "DeleteCredentialRecord",
        field_number: 2004,
        mutability: "mutating",
        atomicity: "atomic_delete_or_tombstone",
        provider_calls: &["get_credential_record", "delete_credential_record"],
    },
    ExpectedOperation {
        name: "claim_presentation_copy",
        rust_variant: "ClaimPresentationCopy",
        field_number: 2005,
        mutability: "mutating",
        atomicity: "atomic_once_only_claim",
        provider_calls: &["get_credential_record", "claim_presentation_copy"],
    },
    ExpectedOperation {
        name: "evaluate_verifier_entitlement",
        rust_variant: "EvaluateVerifierEntitlement",
        field_number: 3001,
        mutability: "pure",
        atomicity: "none",
        provider_calls: &[],
    },
    ExpectedOperation {
        name: "save_flow_snapshot",
        rust_variant: "SaveFlowSnapshot",
        field_number: 5001,
        mutability: "mutating",
        atomicity: "compare_and_swap_create",
        provider_calls: &["save_flow_snapshot"],
    },
    ExpectedOperation {
        name: "get_flow_snapshot",
        rust_variant: "GetFlowSnapshot",
        field_number: 5002,
        mutability: "read_only",
        atomicity: "read",
        provider_calls: &["get_flow_snapshot"],
    },
    ExpectedOperation {
        name: "append_transaction_log",
        rust_variant: "AppendTransactionLog",
        field_number: 6001,
        mutability: "mutating",
        atomicity: "atomic_append",
        provider_calls: &["trusted_now", "append_transaction_log"],
    },
    ExpectedOperation {
        name: "append_qtsp_decision",
        rust_variant: "AppendQtspDecision",
        field_number: 6002,
        mutability: "mutating",
        atomicity: "atomic_append",
        provider_calls: &["trusted_now", "append_qtsp_decision"],
    },
];

#[test]
fn capability_manifest_is_exhaustive_and_matches_dispatch() -> Result<(), CapabilityTestError> {
    let root = repository_root()?;
    let manifest = read_json(&root, CAPABILITY_MANIFEST)?;
    validate_top_level_policy(&manifest)?;

    let operations = manifest
        .get("operations")
        .and_then(Value::as_array)
        .ok_or(CapabilityTestError::InvalidOperations)?;
    if operations.len() != EXPECTED_OPERATIONS.len() {
        return Err(CapabilityTestError::UnexpectedOperationCount);
    }

    let proto = read_text(&root, OPERATION_PROTO)?;
    let executor = read_text(&root, OPERATION_EXECUTOR)?;
    let dispatch = executor
        .split_once("fn dispatch_operation(")
        .and_then(|(_, body)| body.split_once("fn operation_is_mutating"))
        .map(|(body, _)| body)
        .ok_or(CapabilityTestError::DispatchMismatch)?;
    let backend = read_text(&root, RUNTIME_BACKEND)?;
    let mut names = HashSet::with_capacity(EXPECTED_OPERATIONS.len());
    let mut field_numbers = HashSet::with_capacity(EXPECTED_OPERATIONS.len());

    for expected in EXPECTED_OPERATIONS {
        let capability = operations
            .iter()
            .find(|operation| field(operation, "name") == Some(expected.name))
            .ok_or(CapabilityTestError::MissingOperation)?;

        if capability.get("field_number").and_then(Value::as_u64) != Some(expected.field_number)
            || field(capability, "mutability") != Some(expected.mutability)
            || field(capability, "atomicity") != Some(expected.atomicity)
        {
            return Err(CapabilityTestError::OperationPolicyMismatch);
        }
        let expected_idempotency = if expected.mutability == "mutating" {
            "required"
        } else {
            "forbidden"
        };
        if field(capability, "idempotency") != Some(expected_idempotency) {
            return Err(CapabilityTestError::OperationPolicyMismatch);
        }
        if expected.name == "evaluate_verifier_entitlement"
            && field(capability, "authority") != Some("disabled_pending_certificate_verifier")
        {
            return Err(CapabilityTestError::OperationPolicyMismatch);
        }
        if expected.name == "put_credential_record"
            && field(capability, "authority")
                != Some("disabled_pending_verified_credential_receipt")
        {
            return Err(CapabilityTestError::OperationPolicyMismatch);
        }
        if expected.name == "append_wallet_lifecycle_evidence"
            && field(capability, "authority") != Some("disabled_pending_atomic_transition")
        {
            return Err(CapabilityTestError::OperationPolicyMismatch);
        }
        if !matches!(
            field(capability, "security_class"),
            Some("privacy_sensitive" | "secret_bearing")
        ) {
            return Err(CapabilityTestError::InvalidSecurityClass);
        }
        validate_provider_calls(capability, expected.provider_calls)?;
        for provider_call in expected.provider_calls {
            let declaration = format!("fn {provider_call}(");
            if !backend.contains(&declaration) {
                return Err(CapabilityTestError::ProviderMismatch);
            }
        }

        if !names.insert(expected.name) || !field_numbers.insert(expected.field_number) {
            return Err(CapabilityTestError::DuplicateOperation);
        }

        let request_field = format!("{} = {};", expected.name, expected.field_number);
        if proto.matches(&request_field).count() != 2 {
            return Err(CapabilityTestError::RequestResultPairMismatch);
        }
        let dispatch_arm = format!("Operation::{}(request)", expected.rust_variant);
        if dispatch.matches(&dispatch_arm).count() != 1 {
            return Err(CapabilityTestError::DispatchMismatch);
        }
    }

    Ok(())
}

fn validate_top_level_policy(manifest: &Value) -> Result<(), CapabilityTestError> {
    if manifest.get("schema_version").and_then(Value::as_u64) != Some(1)
        || field(manifest, "contract") != Some("reallyme.wallet.v1.WalletOperationRequest")
        || field(manifest, "entrypoint") != Some("execute_wallet_operation_v1")
    {
        return Err(CapabilityTestError::InvalidManifestVersion);
    }

    let provider_policy = manifest
        .get("provider_policy")
        .ok_or(CapabilityTestError::InvalidProviderPolicy)?;
    for key in [
        "runtime_handle_required",
        "injected_backend_required",
        "caller_owns_request_bytes",
        "response_bytes_zeroize_on_drop",
    ] {
        if provider_policy.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(CapabilityTestError::InvalidProviderPolicy);
        }
    }
    if provider_policy
        .get("ambient_provider_fallback")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(CapabilityTestError::InvalidProviderPolicy);
    }

    let provider_contract = manifest
        .get("provider_contract")
        .ok_or(CapabilityTestError::InvalidProviderPolicy)?;
    if provider_contract
        .get("schema_version")
        .and_then(Value::as_u64)
        != Some(1)
        || field(provider_contract, "request") != Some("reallyme.wallet.v1.WalletProviderRequest")
        || field(provider_contract, "response") != Some("reallyme.wallet.v1.WalletProviderResponse")
        || field(provider_contract, "descriptor")
            != Some("reallyme.wallet.v1.WalletProviderDescriptor")
        || provider_contract
            .get("required_capabilities")
            .and_then(Value::as_u64)
            != Some(25)
        || field(provider_contract, "correlation") != Some("executor_id_and_request_id")
        || field(provider_contract, "result_pairing") != Some("exact_field_number")
    {
        return Err(CapabilityTestError::InvalidProviderPolicy);
    }
    validate_string_array(
        provider_contract,
        "invocation_modes",
        &["synchronous_native", "asynchronous_host"],
    )?;

    let lane_policy = manifest
        .get("lane_policy")
        .ok_or(CapabilityTestError::InvalidLanePolicy)?;
    if field(lane_policy, "missing_adapter_behavior") != Some("fail_closed")
        || field(lane_policy, "platform_binding_owner") != Some("reallyme/identity")
        || field(lane_policy, "generic_client_substrate_owner") != Some("reallyme/vaultkit")
        || field(lane_policy, "opaque_storage_surface_owner") != Some("reallyme/vaultwallet")
        || field(lane_policy, "final_artifact_composition_owner")
            != Some("top-level-sdk-or-application")
    {
        return Err(CapabilityTestError::InvalidLanePolicy);
    }
    validate_string_array(lane_policy, "supported_runtime_lanes", &["native", "wasm"])?;
    validate_string_array(lane_policy, "wallet_repository_platform_adapters", &[])?;

    let idempotency_policy = manifest
        .get("idempotency_policy")
        .ok_or(CapabilityTestError::InvalidIdempotencyPolicy)?;
    if idempotency_policy.get("key_bytes").and_then(Value::as_u64) != Some(32)
        || field(idempotency_policy, "mutating_operations") != Some("required")
        || field(idempotency_policy, "read_only_operations") != Some("forbidden")
        || field(idempotency_policy, "response_replay") != Some("exact_canonical_bytes")
        || field(idempotency_policy, "in_progress_expiry") != Some("never_implicit")
    {
        return Err(CapabilityTestError::InvalidIdempotencyPolicy);
    }
    Ok(())
}

fn validate_provider_calls(
    capability: &Value,
    expected: &[&str],
) -> Result<(), CapabilityTestError> {
    validate_string_array(capability, "provider_calls", expected)
}

fn validate_string_array(
    value: &Value,
    key: &str,
    expected: &[&str],
) -> Result<(), CapabilityTestError> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(CapabilityTestError::InvalidStringArray)?;
    if values.len() != expected.len()
        || values
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.as_str() != Some(*expected))
    {
        return Err(CapabilityTestError::InvalidStringArray);
    }
    Ok(())
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn read_json(root: &Path, path: &str) -> Result<Value, CapabilityTestError> {
    let document = read_text(root, path)?;
    serde_json::from_str(&document).map_err(|_| CapabilityTestError::InvalidJson)
}

fn read_text(root: &Path, path: &str) -> Result<String, CapabilityTestError> {
    std::fs::read_to_string(root.join(path)).map_err(|_| CapabilityTestError::Io)
}

fn repository_root() -> Result<PathBuf, CapabilityTestError> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or(CapabilityTestError::InvalidRepositoryRoot)
}

#[derive(Debug, thiserror::Error)]
enum CapabilityTestError {
    #[error("invalid_repository_root")]
    InvalidRepositoryRoot,
    #[error("io")]
    Io,
    #[error("invalid_json")]
    InvalidJson,
    #[error("invalid_manifest_version")]
    InvalidManifestVersion,
    #[error("invalid_provider_policy")]
    InvalidProviderPolicy,
    #[error("invalid_lane_policy")]
    InvalidLanePolicy,
    #[error("invalid_idempotency_policy")]
    InvalidIdempotencyPolicy,
    #[error("invalid_operations")]
    InvalidOperations,
    #[error("unexpected_operation_count")]
    UnexpectedOperationCount,
    #[error("missing_operation")]
    MissingOperation,
    #[error("operation_policy_mismatch")]
    OperationPolicyMismatch,
    #[error("invalid_security_class")]
    InvalidSecurityClass,
    #[error("invalid_string_array")]
    InvalidStringArray,
    #[error("duplicate_operation")]
    DuplicateOperation,
    #[error("request_result_pair_mismatch")]
    RequestResultPairMismatch,
    #[error("dispatch_mismatch")]
    DispatchMismatch,
    #[error("provider_mismatch")]
    ProviderMismatch,
}
