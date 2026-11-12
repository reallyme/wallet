// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package-ownership and current publication-frontier checks.

#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

const POLICY_PATH: &str = "conformance/features/wallet-package-policy-v1.json";

#[test]
fn package_policy_matches_the_workspace_and_authorizes_only_the_release_graph(
) -> Result<(), PackagePolicyTestError> {
    let root = workspace_root()?;
    let policy = read_json(&root, POLICY_PATH)?;
    validate_identity(&policy)?;
    validate_authorization_gate(&policy)?;

    let packages = policy
        .get("workspace_packages")
        .and_then(Value::as_array)
        .ok_or(PackagePolicyTestError::InvalidPolicy)?;
    let mut declared_manifests = BTreeSet::new();
    let mut intended_packages = BTreeSet::new();

    for package in packages {
        let name = string_field(package, "name")?;
        let manifest = string_field(package, "manifest")?;
        let classification = string_field(package, "classification")?;
        let publish = package
            .get("publish")
            .and_then(Value::as_bool)
            .ok_or(PackagePolicyTestError::InvalidPolicy)?;
        if !declared_manifests.insert(manifest.to_owned()) {
            return Err(PackagePolicyTestError::InvalidPolicy);
        }

        validate_manifest(&root.join(manifest), name, publish)?;
        match classification {
            "intended_rust_release" => {
                if !publish {
                    return Err(PackagePolicyTestError::InvalidPolicy);
                }
                intended_packages.insert(name.to_owned());
            }
            "private_composition" | "repository_tooling" => {
                if publish {
                    return Err(PackagePolicyTestError::InvalidPolicy);
                }
            }
            _ => return Err(PackagePolicyTestError::InvalidPolicy),
        }
    }

    if declared_manifests != workspace_manifests(&root)? {
        return Err(PackagePolicyTestError::WorkspaceMismatch);
    }
    validate_authorized_packages(&policy, &intended_packages)?;
    validate_release_order(&policy, &intended_packages)?;
    validate_product_ownership(&policy)?;
    Ok(())
}

fn validate_identity(policy: &Value) -> Result<(), PackagePolicyTestError> {
    if policy.get("schema_version").and_then(Value::as_u64) != Some(1)
        || string_field(policy, "policy_id")? != "reallyme.wallet.package-policy.v1"
        || string_field(policy, "owner")? != "reallyme/wallet"
        || string_field(policy, "versioning")? != "lockstep"
        || string_field(policy, "release_version")? != "0.1.2"
        || string_field(policy, "maintainer_rust_toolchain")? != "1.99.0"
        || string_field(policy, "public_crate_msrv")? != "1.99"
    {
        return Err(PackagePolicyTestError::InvalidPolicy);
    }
    Ok(())
}

fn validate_authorization_gate(policy: &Value) -> Result<(), PackagePolicyTestError> {
    let authorized = policy
        .get("authorized_public_packages")
        .and_then(Value::as_array)
        .ok_or(PackagePolicyTestError::InvalidPolicy)?;
    let gate = policy
        .get("authorization_gate")
        .and_then(Value::as_object)
        .ok_or(PackagePolicyTestError::InvalidPolicy)?;
    let evidence = gate
        .get("required_evidence")
        .and_then(Value::as_array)
        .ok_or(PackagePolicyTestError::InvalidPolicy)?;
    if authorized.is_empty()
        || gate.get("state").and_then(Value::as_str) != Some("authorized_for_crates_io_release")
        || evidence.len() != 6
    {
        return Err(PackagePolicyTestError::InvalidPolicy);
    }
    Ok(())
}

fn validate_manifest(
    path: &Path,
    expected_name: &str,
    expected_publish: bool,
) -> Result<(), PackagePolicyTestError> {
    let manifest = std::fs::read_to_string(path).map_err(|_| PackagePolicyTestError::Io)?;
    let package = manifest
        .split("[package]")
        .nth(1)
        .and_then(|value| value.split("\n[").next())
        .ok_or(PackagePolicyTestError::InvalidManifest)?;
    let name = package
        .lines()
        .find_map(|line| quoted_value(line, "name = "))
        .ok_or(PackagePolicyTestError::InvalidManifest)?;
    let publish = package
        .lines()
        .find_map(|line| line.trim().strip_prefix("publish = "))
        .ok_or(PackagePolicyTestError::InvalidManifest)?;
    let expected_publish_value = if expected_publish { "true" } else { "false" };
    if name != expected_name
        || publish != expected_publish_value
        || !manifest.contains("[lints]\nworkspace = true")
        || (expected_publish
            && (!package.contains("version.workspace = true")
                || !package.contains("rust-version.workspace = true")))
    {
        return Err(PackagePolicyTestError::InvalidManifest);
    }
    Ok(())
}

fn validate_authorized_packages(
    policy: &Value,
    intended_packages: &BTreeSet<String>,
) -> Result<(), PackagePolicyTestError> {
    let authorized = policy
        .get("authorized_public_packages")
        .and_then(Value::as_array)
        .ok_or(PackagePolicyTestError::InvalidPolicy)?;
    let mut authorized_packages = BTreeSet::new();
    for name in authorized {
        let name = name.as_str().ok_or(PackagePolicyTestError::InvalidPolicy)?;
        if !authorized_packages.insert(name.to_owned()) {
            return Err(PackagePolicyTestError::InvalidPolicy);
        }
    }
    if &authorized_packages != intended_packages {
        return Err(PackagePolicyTestError::InvalidPolicy);
    }
    Ok(())
}

fn quoted_value<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.trim()
        .strip_prefix(prefix)?
        .strip_prefix('"')?
        .strip_suffix('"')
}

fn workspace_manifests(root: &Path) -> Result<BTreeSet<String>, PackagePolicyTestError> {
    let cargo =
        std::fs::read_to_string(root.join("Cargo.toml")).map_err(|_| PackagePolicyTestError::Io)?;
    let members = cargo
        .split("members = [")
        .nth(1)
        .and_then(|value| value.split(']').next())
        .ok_or(PackagePolicyTestError::InvalidManifest)?;
    let mut manifests = BTreeSet::new();
    for member in members
        .lines()
        .filter_map(|line| quoted_value(line.trim_end_matches(','), ""))
    {
        if member == "." {
            manifests.insert("Cargo.toml".to_owned());
        } else {
            let mut path = member.to_owned();
            path.push_str("/Cargo.toml");
            manifests.insert(path);
        }
    }
    Ok(manifests)
}

fn validate_release_order(
    policy: &Value,
    intended_packages: &BTreeSet<String>,
) -> Result<(), PackagePolicyTestError> {
    let waves = policy
        .get("intended_rust_release_order")
        .and_then(Value::as_array)
        .ok_or(PackagePolicyTestError::InvalidPolicy)?;
    let mut ordered = BTreeSet::new();
    for wave in waves {
        let wave = wave
            .as_array()
            .ok_or(PackagePolicyTestError::InvalidPolicy)?;
        if wave.is_empty() {
            return Err(PackagePolicyTestError::InvalidPolicy);
        }
        for name in wave {
            let name = name.as_str().ok_or(PackagePolicyTestError::InvalidPolicy)?;
            if !ordered.insert(name.to_owned()) {
                return Err(PackagePolicyTestError::InvalidPolicy);
            }
        }
    }
    if &ordered != intended_packages {
        return Err(PackagePolicyTestError::InvalidPolicy);
    }

    let expected_waves = [
        ["reallyme-wallet-proto", "reallyme-wallet-types"].as_slice(),
        [
            "reallyme-wallet-lifecycle",
            "reallyme-wallet-render",
            "reallyme-wallet-zk",
        ]
        .as_slice(),
        ["reallyme-wallet-keystore"].as_slice(),
        ["reallyme-wallet-attestation"].as_slice(),
        ["reallyme-wallet-proto-codec"].as_slice(),
        ["reallyme-wallet-storage"].as_slice(),
        ["reallyme-wallet-inventory", "reallyme-wallet-log"].as_slice(),
        ["reallyme-wallet-consent"].as_slice(),
        ["reallyme-wallet-flows", "reallyme-wallet-runtime"].as_slice(),
        ["reallyme-wallet-http", "reallyme-wallet-provider"].as_slice(),
        ["reallyme-wallet"].as_slice(),
    ];
    if waves.len() != expected_waves.len()
        || waves.iter().zip(expected_waves).any(|(wave, expected)| {
            wave.as_array().is_none_or(|values| {
                values.len() != expected.len()
                    || values
                        .iter()
                        .zip(expected)
                        .any(|(value, expected_name)| value.as_str() != Some(expected_name))
            })
        })
    {
        return Err(PackagePolicyTestError::InvalidPolicy);
    }
    Ok(())
}

fn validate_product_ownership(policy: &Value) -> Result<(), PackagePolicyTestError> {
    let ownership = policy
        .get("product_package_ownership")
        .and_then(Value::as_object)
        .ok_or(PackagePolicyTestError::InvalidPolicy)?;
    if policy.get("expert_package_exception").is_some()
        || ownership.get("owner").and_then(Value::as_str) != Some("reallyme/identity")
        || ownership
            .iter()
            .filter(|(key, _)| key.as_str() != "owner")
            .any(|(_, value)| value.as_bool() != Some(false))
    {
        return Err(PackagePolicyTestError::InvalidPolicy);
    }
    Ok(())
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, PackagePolicyTestError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or(PackagePolicyTestError::InvalidPolicy)
}

fn read_json(root: &Path, path: &str) -> Result<Value, PackagePolicyTestError> {
    let contents =
        std::fs::read_to_string(root.join(path)).map_err(|_| PackagePolicyTestError::Io)?;
    serde_json::from_str(&contents).map_err(|_| PackagePolicyTestError::InvalidJson)
}

fn workspace_root() -> Result<PathBuf, PackagePolicyTestError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(PackagePolicyTestError::InvalidWorkspace)
}

#[derive(Debug, thiserror::Error)]
enum PackagePolicyTestError {
    #[error("invalid_json")]
    InvalidJson,
    #[error("invalid_manifest")]
    InvalidManifest,
    #[error("invalid_policy")]
    InvalidPolicy,
    #[error("invalid_workspace")]
    InvalidWorkspace,
    #[error("io")]
    Io,
    #[error("workspace_mismatch")]
    WorkspaceMismatch,
}
