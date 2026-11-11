// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Executable ownership boundary for Wallet, VaultWallet, and VaultKit clients.

#![cfg(feature = "native")]

use serde_json::{Map, Value};
use thiserror::Error;

const CONTRACT: &str = include_str!("../features/wallet-client-surface-ownership-v1.json");

#[test]
fn client_surface_ownership_is_closed_and_hardware_scope_is_exact() -> Result<(), ContractTestError>
{
    let contract: Value =
        serde_json::from_str(CONTRACT).map_err(|_| ContractTestError::Contract)?;
    if field(&contract, "SPDX-FileCopyrightText")
        != Some("Copyright © 2026 ReallyMe Technologies Limited. All rights reserved")
        || field(&contract, "SPDX-License-Identifier") != Some("MIT OR Apache-2.0")
        || contract.get("schema_version").and_then(Value::as_u64) != Some(1)
        || field(&contract, "contract_id") != Some("reallyme.wallet.client-surface-ownership.v1")
        || field(&contract, "status") != Some("ownership-contract-only")
        || field(&contract, "wallet_v1_protected_read_mode") != Some("vault-proxy-only")
    {
        return Err(ContractTestError::Contract);
    }
    validate_integration_revisions(object(&contract, "integration_revisions")?)?;
    validate_ownership(object(&contract, "ownership")?)?;
    require_exact(
        &contract,
        "vaultkit_generic_facilities",
        &[
            "unlock-security-authority",
            "protected-reads-and-streaming",
            "checkpoint-outbox-cache",
            "provider-transport",
            "materialization-sessions",
            "lifecycle-cancellation-progress",
            "generic-ffi-safe-handles",
        ],
    )?;
    require_exact(
        &contract,
        "wallet_domain_facilities",
        &[
            "credential-records",
            "did-and-key-records",
            "provider-operations",
            "hardware-key-binding-contracts",
        ],
    )?;
    require_exact(
        &contract,
        "vaultwallet_opaque_facilities",
        &[
            "record-and-revision-storage",
            "causal-and-precondition-state",
            "tombstones-and-concurrent-heads",
            "checkpoint-and-storage-operations",
            "opaque-engine-ffi",
        ],
    )?;
    require_exact(
        &contract,
        "target_wallet_v1_hardware",
        &["ios-secure-enclave", "android-strongbox", "android-tee"],
    )?;
    require_exact(
        &contract,
        "out_of_scope_wallet_v1_hardware",
        &["desktop-hardware", "wscd", "tpm", "smartcard", "other"],
    )
}

fn validate_integration_revisions(revisions: &Map<String, Value>) -> Result<(), ContractTestError> {
    for (name, expected) in [
        ("vaultkit", "121ecf457cb970a1c3022fe702484093efb2d9c0"),
        ("vault", "d0eb65e30e4a7399b29f9deca4fdb0f2cef29ddc"),
        ("vaultsync", "5664eaaf5be8723bc822f98e451be1d8d1bff9db"),
    ] {
        if revisions.get(name).and_then(Value::as_str) != Some(expected) {
            return Err(ContractTestError::IntegrationRevision);
        }
    }
    if revisions.len() != 3 {
        return Err(ContractTestError::IntegrationRevision);
    }
    Ok(())
}

fn validate_ownership(ownership: &Map<String, Value>) -> Result<(), ContractTestError> {
    for (name, expected) in [
        ("wallet_domain_contracts", "reallyme/wallet"),
        ("general_wallet_client_bindings", "reallyme/identity"),
        ("expert_hardware_binding_provider", "injected-platform-host"),
        ("opaque_storage_engine", "reallyme/vaultwallet"),
        ("opaque_storage_ffi", "reallyme/vaultwallet"),
        ("generic_client_substrate", "reallyme/vaultkit"),
        ("generic_ffi_handles", "reallyme/vaultkit"),
        ("final_artifact_composition", "top-level-sdk-or-application"),
    ] {
        if ownership.get(name).and_then(Value::as_str) != Some(expected) {
            return Err(ContractTestError::Ownership);
        }
    }
    if ownership.len() != 8 {
        return Err(ContractTestError::Ownership);
    }
    Ok(())
}

fn require_exact(contract: &Value, name: &str, expected: &[&str]) -> Result<(), ContractTestError> {
    let actual = contract
        .get(name)
        .and_then(Value::as_array)
        .ok_or(ContractTestError::Contract)?;
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(ContractTestError::FacilitySet);
    }
    Ok(())
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>, ContractTestError> {
    value
        .get(name)
        .and_then(Value::as_object)
        .ok_or(ContractTestError::Contract)
}

fn field<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::as_str)
}

#[derive(Debug, Error)]
enum ContractTestError {
    #[error("invalid_contract")]
    Contract,
    #[error("invalid_facility_set")]
    FacilitySet,
    #[error("invalid_ownership")]
    Ownership,
    #[error("invalid_integration_revision")]
    IntegrationRevision,
}
