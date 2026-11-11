// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Executable ownership and compatibility checks for Identity consumers.

#![cfg(feature = "native")]

use std::path::{Path, PathBuf};

use reallyme_wallet::proto_codec::{
    MAX_WALLET_PROTO_MESSAGE_BYTES, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES,
};
use serde_json::Value;

const HANDOFF_MANIFEST: &str = "conformance/features/identity-wallet-handoff-v1.json";
const SHA2_256_HEX_LENGTH: usize = 64;
const CONSUMER_EVIDENCE: &[&str] = &[
    "canonical_operation_golden_parity",
    "typed_storage_algorithm_parity",
    "canonical_provider_golden_parity",
    "native_composed_symbol_verification",
    "wasm_single_module_verification",
    "swift_package_tests",
    "kotlin_and_android_package_tests",
    "typescript_package_tests",
    "legacy_method_catalog_absence",
];

#[test]
fn identity_handoff_matches_the_rust_only_wallet_boundary() -> Result<(), HandoffTestError> {
    let root = repository_root()?;
    let manifest = read_json(&root, HANDOFF_MANIFEST)?;

    validate_identity(&manifest)?;
    validate_ownership(&manifest)?;
    validate_schema_contract(&root, &manifest)?;
    validate_operation_and_provider_contracts(&manifest)?;
    validate_storage_record_contract(&manifest)?;
    validate_repository_policy(&root, &manifest)?;
    validate_golden_fixture(&root, &manifest, "golden_fixture")?;
    validate_golden_fixture(&root, &manifest, "provider_golden_fixture")?;
    validate_consumer_requirements(&manifest)?;
    Ok(())
}

fn validate_identity(manifest: &Value) -> Result<(), HandoffTestError> {
    if manifest.get("schema_version").and_then(Value::as_u64) != Some(1)
        || field(manifest, "contract_id") != Some("reallyme.wallet.identity-handoff.v1")
        || field(manifest, "producer") != Some("reallyme/wallet")
        || field(manifest, "consumer") != Some("reallyme/identity")
    {
        return Err(HandoffTestError::InvalidIdentity);
    }
    Ok(())
}

fn validate_ownership(manifest: &Value) -> Result<(), HandoffTestError> {
    let ownership = object(manifest, "ownership")?;
    for key in [
        "rust_engine",
        "canonical_proto_contracts",
        "generated_rust_bindings",
    ] {
        if field(ownership, key) != Some("reallyme/wallet") {
            return Err(HandoffTestError::InvalidOwnership);
        }
    }
    for key in [
        "native_ffi_and_jni_bindings",
        "wasm_bindings",
        "product_facing_swift_api",
        "product_facing_kotlin_api",
        "product_facing_typescript_api",
        "final_composed_artifacts",
    ] {
        if field(ownership, key) != Some("reallyme/identity") {
            return Err(HandoffTestError::InvalidOwnership);
        }
    }
    Ok(())
}

fn validate_schema_contract(root: &Path, manifest: &Value) -> Result<(), HandoffTestError> {
    let schema = object(manifest, "schema_contract")?;
    if field(schema, "package") != Some("reallyme.wallet.v1")
        || field(schema, "message_crate") != Some("crates/proto")
        || field(schema, "codec_crate") != Some("crates/proto-codec")
        || schema
            .get("connect_generated_in_wallet")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(HandoffTestError::InvalidSchemaContract);
    }

    for key in [
        "message_schema",
        "provider_schema",
        "error_schema",
        "service_schema",
    ] {
        let path = field(schema, key).ok_or(HandoffTestError::MissingField)?;
        if !root.join(path).is_file() {
            return Err(HandoffTestError::MissingSchema);
        }
    }

    let message = read_text(
        root,
        field(schema, "message_schema").ok_or(HandoffTestError::MissingField)?,
    )?;
    let service = read_text(
        root,
        field(schema, "service_schema").ok_or(HandoffTestError::MissingField)?,
    )?;
    if message.contains("service WalletCoreService")
        || !service.contains("service WalletCoreService")
        || !service.contains("rpc WalletOperation")
    {
        return Err(HandoffTestError::ServiceSchemaContamination);
    }
    Ok(())
}

fn validate_operation_and_provider_contracts(manifest: &Value) -> Result<(), HandoffTestError> {
    let maximum_operation_bytes = u64::try_from(MAX_WALLET_PROTO_MESSAGE_BYTES)
        .map_err(|_| HandoffTestError::InvalidOperationContract)?;
    let maximum_provider_bytes = u64::try_from(MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES)
        .map_err(|_| HandoffTestError::InvalidProviderContract)?;
    let operation = object(manifest, "operation_contract")?;
    if field(operation, "request") != Some("reallyme.wallet.v1.WalletOperationRequest")
        || field(operation, "response") != Some("reallyme.wallet.v1.WalletOperationResponse")
        || field(operation, "rust_entrypoint") != Some("execute_wallet_operation_v1")
        || operation
            .get("maximum_message_bytes")
            .and_then(Value::as_u64)
            != Some(maximum_operation_bytes)
    {
        return Err(HandoffTestError::InvalidOperationContract);
    }

    let provider = object(manifest, "provider_contract")?;
    if field(provider, "descriptor") != Some("reallyme.wallet.v1.WalletProviderDescriptor")
        || field(provider, "request") != Some("reallyme.wallet.v1.WalletProviderRequest")
        || field(provider, "response") != Some("reallyme.wallet.v1.WalletProviderResponse")
        || provider
            .get("maximum_message_bytes")
            .and_then(Value::as_u64)
            != Some(maximum_provider_bytes)
        || provider
            .get("ambient_fallback_allowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(HandoffTestError::InvalidProviderContract);
    }
    Ok(())
}

fn validate_storage_record_contract(manifest: &Value) -> Result<(), HandoffTestError> {
    let storage = object(manifest, "storage_record_contract")?;
    if field(storage, "header") != Some("reallyme.wallet.v1.EncryptedRecordHeader")
        || field(storage, "algorithm_enum") != Some("reallyme.crypto.v1.AeadAlgorithm")
        || storage.get("reserved_field_number").and_then(Value::as_u64) != Some(3)
        || field(storage, "reserved_field_name") != Some("algorithm")
        || field(storage, "canonical_field") != Some("encryption_algorithm")
    {
        return Err(HandoffTestError::InvalidStorageRecordContract);
    }
    validate_string_array(
        storage,
        "approved_algorithms",
        &[
            "AEAD_ALGORITHM_AES_256_GCM_SIV",
            "AEAD_ALGORITHM_XCHACHA20_POLY1305",
        ],
    )
    .map_err(|_| HandoffTestError::InvalidStorageRecordContract)
}

fn validate_repository_policy(root: &Path, manifest: &Value) -> Result<(), HandoffTestError> {
    let policy = object(manifest, "repository_policy")?;
    for key in [
        "wallet_platform_binding_crates_allowed",
        "wallet_platform_packages_allowed",
        "connect_dependency_in_message_crate_allowed",
        "method_name_dispatch_catalog_allowed",
        "platform_ordinal_catalog_allowed",
        "hand_rolled_json_protocol_allowed",
    ] {
        if policy.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(HandoffTestError::InvalidRepositoryPolicy);
        }
    }

    // Platform packages belong to Identity. Reject independent Wallet leaves
    // so consumers cannot accidentally load a second runtime or handle space.
    for forbidden in [
        "crates/ffi",
        "crates/wasm",
        "gen",
        "Package.swift",
        "Package.resolved",
    ] {
        if root.join(forbidden).exists() {
            return Err(HandoffTestError::PlatformBoundaryViolation);
        }
    }

    for manifest_path in [
        "Cargo.toml",
        "crates/wallet/Cargo.toml",
        "crates/proto/Cargo.toml",
    ] {
        let cargo = read_text(root, manifest_path)?;
        if cargo.contains("connectrpc") || cargo.contains("connect-rpc") {
            return Err(HandoffTestError::ConnectContamination);
        }
    }
    Ok(())
}

fn validate_golden_fixture(
    root: &Path,
    manifest: &Value,
    fixture_key: &str,
) -> Result<(), HandoffTestError> {
    let fixture = object(manifest, fixture_key)?;
    let path = field(fixture, "path").ok_or(HandoffTestError::MissingField)?;
    let expected = field(fixture, "sha2_256").ok_or(HandoffTestError::MissingField)?;
    if expected.len() != SHA2_256_HEX_LENGTH {
        return Err(HandoffTestError::InvalidFixtureHash);
    }

    let bytes = std::fs::read(root.join(path)).map_err(|_| HandoffTestError::Io)?;
    let digest = crypto_sha2_256::digest(&bytes);
    if encode_hex(digest.as_bytes()) != expected {
        return Err(HandoffTestError::FixtureHashMismatch);
    }
    Ok(())
}

fn validate_consumer_requirements(manifest: &Value) -> Result<(), HandoffTestError> {
    // Identity's v1 release checker requires these exact admission fields.
    // Retain the contract while validating its interoperability requirements.
    let requirements = object(manifest, "consumer_migration")?;
    if field(requirements, "status") != Some("complete") {
        return Err(HandoffTestError::InvalidConsumerCompatibility);
    }
    validate_string_array(requirements, "required_evidence", CONSUMER_EVIDENCE)
}

fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Value, HandoffTestError> {
    value
        .get(key)
        .filter(|candidate| candidate.is_object())
        .ok_or(HandoffTestError::MissingField)
}

fn validate_string_array(
    value: &Value,
    key: &str,
    expected: &[&str],
) -> Result<(), HandoffTestError> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(HandoffTestError::MissingField)?;
    if values.len() != expected.len()
        || values
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.as_str() != Some(*expected))
    {
        return Err(HandoffTestError::InvalidStringArray);
    }
    Ok(())
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn read_json(root: &Path, path: &str) -> Result<Value, HandoffTestError> {
    let text = read_text(root, path)?;
    serde_json::from_str(&text).map_err(|_| HandoffTestError::InvalidJson)
}

fn read_text(root: &Path, path: &str) -> Result<String, HandoffTestError> {
    std::fs::read_to_string(root.join(path)).map_err(|_| HandoffTestError::Io)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(SHA2_256_HEX_LENGTH);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn repository_root() -> Result<PathBuf, HandoffTestError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(HandoffTestError::InvalidRepositoryRoot)
}

#[derive(Debug, thiserror::Error)]
enum HandoffTestError {
    #[error("connect_contamination")]
    ConnectContamination,
    #[error("fixture_hash_mismatch")]
    FixtureHashMismatch,
    #[error("invalid_fixture_hash")]
    InvalidFixtureHash,
    #[error("invalid_identity")]
    InvalidIdentity,
    #[error("invalid_json")]
    InvalidJson,
    #[error("invalid_consumer_compatibility")]
    InvalidConsumerCompatibility,
    #[error("invalid_operation_contract")]
    InvalidOperationContract,
    #[error("invalid_ownership")]
    InvalidOwnership,
    #[error("invalid_provider_contract")]
    InvalidProviderContract,
    #[error("invalid_repository_policy")]
    InvalidRepositoryPolicy,
    #[error("invalid_repository_root")]
    InvalidRepositoryRoot,
    #[error("invalid_schema_contract")]
    InvalidSchemaContract,
    #[error("invalid_storage_record_contract")]
    InvalidStorageRecordContract,
    #[error("invalid_string_array")]
    InvalidStringArray,
    #[error("io")]
    Io,
    #[error("missing_field")]
    MissingField,
    #[error("missing_schema")]
    MissingSchema,
    #[error("platform_boundary_violation")]
    PlatformBoundaryViolation,
    #[error("service_schema_contamination")]
    ServiceSchemaContamination,
}
