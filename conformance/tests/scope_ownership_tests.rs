// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keeps Wallet scope ownership decisions explicit and backed by local evidence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

const WALLET_OWNER: &str = "reallyme/wallet";
const PENDING_OWNER: &str = "product decision pending";

const REQUIRED_AREAS: &[(&str, &str)] = &[
    ("wallet-unit-lifecycle-state", WALLET_OWNER),
    ("credential-revocation-state", WALLET_OWNER),
    ("wallet-unit-revocation-state", WALLET_OWNER),
    ("transaction-log-retention-policy", WALLET_OWNER),
    ("portability-policy", WALLET_OWNER),
    ("credential-classification", WALLET_OWNER),
    (
        "attestation-acquisition",
        "reallyme/identity and the wallet provider",
    ),
    (
        "proximity-and-digital-credentials-api",
        "reallyme/identity and the wallet provider",
    ),
    (
        "user-rights-workflows",
        "reallyme/identity and the wallet provider",
    ),
    ("backup-and-migration-storage", "reallyme/vaultwallet"),
    ("wallet-to-wallet-transfer", PENDING_OWNER),
    ("legal-person-wallets", PENDING_OWNER),
    ("payment-authentication", PENDING_OWNER),
];

const REQUIRED_EVIDENCE_BOUNDARIES: &[(&str, &str)] = &[
    ("wallet-executable-contracts", WALLET_OWNER),
    (
        "ownership-and-coverage-ledger",
        "reallyme/identity-taxonomy",
    ),
    ("composed-runs", "reallyme/identity-conformance"),
];

#[derive(Debug, thiserror::Error)]
enum ScopeOwnershipTestError {
    #[error("invalid_repository_root")]
    InvalidRepositoryRoot,
    #[error("io")]
    Io,
    #[error("invalid_json")]
    InvalidJson,
    #[error("missing_field")]
    MissingField,
    #[error("duplicate_area")]
    DuplicateArea,
    #[error("unexpected_area_set")]
    UnexpectedAreaSet,
    #[error("owner_mismatch")]
    OwnerMismatch,
    #[error("status_inconsistent_with_owner")]
    StatusInconsistentWithOwner,
    #[error("missing_evidence")]
    MissingEvidence,
    #[error("evidence_outside_wallet")]
    EvidenceOutsideWallet,
    #[error("unexpected_evidence_boundaries")]
    UnexpectedEvidenceBoundaries,
}

fn repository_root() -> Result<PathBuf, ScopeOwnershipTestError> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or(ScopeOwnershipTestError::InvalidRepositoryRoot)
}

fn contract(root: &Path) -> Result<Value, ScopeOwnershipTestError> {
    let text =
        std::fs::read_to_string(root.join("conformance/features/wallet-scope-ownership-v1.json"))
            .map_err(|_| ScopeOwnershipTestError::Io)?;
    serde_json::from_str(&text).map_err(|_| ScopeOwnershipTestError::InvalidJson)
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, ScopeOwnershipTestError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(ScopeOwnershipTestError::MissingField)
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value], ScopeOwnershipTestError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(ScopeOwnershipTestError::MissingField)
}

#[test]
fn every_scope_area_has_an_explicit_owner_and_status() -> Result<(), ScopeOwnershipTestError> {
    let root = repository_root()?;
    let contract = contract(&root)?;
    let mut seen = BTreeSet::new();

    for area in array(&contract, "areas")? {
        let id = text(area, "id")?;
        if !seen.insert(id.to_owned()) {
            return Err(ScopeOwnershipTestError::DuplicateArea);
        }
        let owner = text(area, "owner")?;
        let expected_owner = REQUIRED_AREAS
            .iter()
            .find(|(required, _)| *required == id)
            .map(|(_, owner)| *owner)
            .ok_or(ScopeOwnershipTestError::UnexpectedAreaSet)?;
        if owner != expected_owner {
            return Err(ScopeOwnershipTestError::OwnerMismatch);
        }
        text(area, "wallet_responsibility")?;
        let evidence = array(area, "evidence")?;
        let consistent = match text(area, "status")? {
            "implemented" | "partial" => owner == WALLET_OWNER && !evidence.is_empty(),
            "not_implemented" => owner == WALLET_OWNER && evidence.is_empty(),
            "delegated" => owner != WALLET_OWNER && owner != PENDING_OWNER,
            "product_decision_required" => owner == PENDING_OWNER && evidence.is_empty(),
            _ => false,
        };
        if !consistent {
            return Err(ScopeOwnershipTestError::StatusInconsistentWithOwner);
        }
        for path in evidence {
            let path = path.as_str().ok_or(ScopeOwnershipTestError::MissingField)?;
            if path.starts_with('/') || path.contains("..") {
                return Err(ScopeOwnershipTestError::EvidenceOutsideWallet);
            }
            if !root.join(path).is_file() {
                return Err(ScopeOwnershipTestError::MissingEvidence);
            }
        }
    }

    if seen.len() != REQUIRED_AREAS.len() {
        return Err(ScopeOwnershipTestError::UnexpectedAreaSet);
    }
    Ok(())
}

#[test]
fn evidence_boundaries_keep_wallet_contracts_local() -> Result<(), ScopeOwnershipTestError> {
    let root = repository_root()?;
    let contract = contract(&root)?;
    let boundaries = array(&contract, "evidence_boundaries")?;
    if boundaries.len() != REQUIRED_EVIDENCE_BOUNDARIES.len() {
        return Err(ScopeOwnershipTestError::UnexpectedEvidenceBoundaries);
    }
    for (id, owner) in REQUIRED_EVIDENCE_BOUNDARIES {
        let matches = boundaries.iter().any(|boundary| {
            text(boundary, "id").is_ok_and(|value| value == *id)
                && text(boundary, "owner").is_ok_and(|value| value == *owner)
                && text(boundary, "responsibility").is_ok()
        });
        if !matches {
            return Err(ScopeOwnershipTestError::UnexpectedEvidenceBoundaries);
        }
    }
    Ok(())
}
