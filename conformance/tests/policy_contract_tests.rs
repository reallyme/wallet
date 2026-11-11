// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy manifests describe core contracts without advertising uncomposed capabilities.
#![cfg(feature = "native")]
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};
use thiserror::Error;
fn contract() -> Result<Value, ContractError> {
    serde_json::from_str(include_str!("../features/wallet-policy-contracts-v1.json"))
        .map_err(|_| ContractError::Shape)
}
fn validate(value: &Value) -> Result<(), ContractError> {
    if value["schema_version"] != 1
        || value["certification_evidence"] != false
        || value["runtime_operation_union_changed"] != false
    {
        return Err(ContractError::Claim);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or(ContractError::Path)?;
    let mut ids = BTreeSet::new();
    for area in value["areas"].as_array().ok_or(ContractError::Shape)? {
        if area["owner"] != "reallyme/wallet"
            || area["status"] != "implemented_core_provider_contract"
            || area["composed_evidence_owner"] != "reallyme/identity-conformance"
        {
            return Err(ContractError::Owner);
        }
        if !ids.insert(area["id"].as_str().ok_or(ContractError::Shape)?) {
            return Err(ContractError::Shape);
        }
        for field in ["source", "tests"] {
            let path = area[field].as_str().ok_or(ContractError::Shape)?;
            if path.starts_with('/') || path.contains("..") || !root.join(path).is_file() {
                return Err(ContractError::Path);
            }
        }
        let source = std::fs::read_to_string(
            root.join(area["source"].as_str().ok_or(ContractError::Shape)?),
        )
        .map_err(|_| ContractError::Path)?;
        for symbol in area["symbols"].as_array().ok_or(ContractError::Shape)? {
            if !source.contains(symbol.as_str().ok_or(ContractError::Shape)?) {
                return Err(ContractError::Symbol);
            }
        }
    }
    if ids.len() != 9 {
        return Err(ContractError::Shape);
    }
    Ok(())
}
#[test]
fn policy_contracts_have_owned_executable_boundaries() -> Result<(), ContractError> {
    validate(&contract()?)
}
#[test]
fn policy_contracts_cannot_claim_certification_or_move_wallet_ownership(
) -> Result<(), ContractError> {
    let mut value = contract()?;
    value["certification_evidence"] = true.into();
    assert!(matches!(validate(&value), Err(ContractError::Claim)));
    let mut value = contract()?;
    value["areas"][0]["owner"] = "reallyme/identity".into();
    assert!(matches!(validate(&value), Err(ContractError::Owner)));
    Ok(())
}
#[derive(Debug, Error)]
enum ContractError {
    #[error("shape")]
    Shape,
    #[error("claim")]
    Claim,
    #[error("owner")]
    Owner,
    #[error("path")]
    Path,
    #[error("symbol")]
    Symbol,
}
