// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Evidence bookkeeping checks; these do not establish implementation coverage.

#![cfg(feature = "native")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

const REVIEW_PATH: &str = "conformance/reports/reference-code-review.json";
const WALLET_OWNER: &str = "reallyme/wallet";
const GIT_COMMIT_HEX_BYTES: usize = 40;
const SHA256_HEX_BYTES: usize = 64;

#[test]
fn reference_review_has_owned_findings_and_identifiable_sources() -> Result<(), ReviewError> {
    validate_review(&read_review()?, &repository_root()?)
}

#[test]
fn open_findings_cannot_be_reported_as_complete() -> Result<(), ReviewError> {
    let mut review = read_review()?;
    review["status"] = Value::from("complete");
    assert_eq!(
        validate_review(&review, &repository_root()?),
        Err(ReviewError::Status)
    );
    Ok(())
}

#[test]
fn proposed_wallet_work_cannot_silently_move_to_a_sibling() -> Result<(), ReviewError> {
    let mut review = read_review()?;
    let finding = review["findings"]
        .as_array_mut()
        .and_then(|findings| {
            findings
                .iter_mut()
                .find(|finding| finding["disposition"] == "wallet_gap")
        })
        .ok_or(ReviewError::Shape)?;
    finding["change_owner"] = Value::from("reallyme/ssi");
    assert_eq!(
        validate_review(&review, &repository_root()?),
        Err(ReviewError::Ownership)
    );
    Ok(())
}

#[test]
fn review_rejects_unknown_sources_and_unpinned_files() -> Result<(), ReviewError> {
    for field in ["source", "path"] {
        let mut review = read_review()?;
        review["findings"][0]["reference_evidence"][0][field] = Value::from("unknown");
        assert_eq!(
            validate_review(&review, &repository_root()?),
            Err(ReviewError::Source)
        );
    }
    Ok(())
}

#[test]
fn review_rejects_invalid_digests_and_duplicate_identities() -> Result<(), ReviewError> {
    let mut review = read_review()?;
    review["sources"][0]["files"][0]["sha256"] = Value::from("unverified");
    assert_eq!(
        validate_review(&review, &repository_root()?),
        Err(ReviewError::Source)
    );

    let mut review = read_review()?;
    review["findings"][1]["id"] = review["findings"][0]["id"].clone();
    assert_eq!(
        validate_review(&review, &repository_root()?),
        Err(ReviewError::Identity)
    );
    Ok(())
}

#[test]
fn review_rejects_missing_or_escaping_local_evidence() -> Result<(), ReviewError> {
    for path in ["../ssi/README.md", "/tmp/evidence", "missing-evidence.rs"] {
        let mut review = read_review()?;
        review["findings"][0]["wallet_evidence"][0] = Value::from(path);
        assert_eq!(
            validate_review(&review, &repository_root()?),
            Err(ReviewError::Evidence)
        );
    }
    Ok(())
}

fn validate_review(review: &Value, root: &Path) -> Result<(), ReviewError> {
    if review["schema_version"].as_u64() != Some(1) {
        return Err(ReviewError::Shape);
    }
    text(review, "scope")?;
    text(review, "reviewed_on")?;
    for limitation in array(review, "limitations")? {
        nonempty(limitation)?;
    }
    let baseline = &review["wallet_baseline"];
    if !is_hex(text(baseline, "head")?, GIT_COMMIT_HEX_BYTES)
        || baseline["working_tree_modified"].as_bool().is_none()
    {
        return Err(ReviewError::Source);
    }
    let mut sources = BTreeMap::new();
    for source in array(review, "sources")? {
        let id = text(source, "id")?;
        if !is_hex(text(source, "head")?, GIT_COMMIT_HEX_BYTES)
            || !text(source, "repository")?.starts_with("https://")
            || source["working_tree_modified"].as_bool().is_none()
        {
            return Err(ReviewError::Source);
        }
        let mut paths = BTreeSet::new();
        for file in array(source, "files")? {
            let path = text(file, "path")?;
            if !relative_path(path)
                || !is_hex(text(file, "sha256")?, SHA256_HEX_BYTES)
                || !paths.insert(path)
            {
                return Err(ReviewError::Source);
            }
        }
        if sources.insert(id, paths).is_some() {
            return Err(ReviewError::Identity);
        }
    }

    let mut ids = BTreeSet::new();
    let mut open_findings = false;
    for finding in array(review, "findings")? {
        if !ids.insert(text(finding, "id")?) {
            return Err(ReviewError::Identity);
        }
        let owner = text(finding, "change_owner")?;
        match text(finding, "disposition")? {
            "wallet_gap" | "fixed" | "covered" if owner != WALLET_OWNER => {
                return Err(ReviewError::Ownership);
            }
            "wallet_gap" | "composition_gap" => open_findings = true,
            "fixed" | "covered" | "outside_wallet" => {}
            _ => return Err(ReviewError::Shape),
        }
        if !matches!(
            text(finding, "priority")?,
            "before_enablement" | "before_eudi_release" | "product_decision" | "maintain"
        ) {
            return Err(ReviewError::Shape);
        }
        for key in ["observation", "wallet_action", "boundary"] {
            text(finding, key)?;
        }
        for criterion in array(finding, "acceptance_criteria")? {
            nonempty(criterion)?;
        }
        for path in array(finding, "wallet_evidence")? {
            let path = nonempty(path)?;
            if !relative_path(path) || !root.join(path).is_file() {
                return Err(ReviewError::Evidence);
            }
        }
        for reference in array(finding, "reference_evidence")? {
            let source = text(reference, "source")?;
            let path = text(reference, "path")?;
            if !sources
                .get(source)
                .is_some_and(|paths| paths.contains(path))
            {
                return Err(ReviewError::Source);
            }
        }
    }
    let expected_status = if open_findings {
        "gaps_identified"
    } else {
        "complete"
    };
    if text(review, "status")? != expected_status {
        return Err(ReviewError::Status);
    }
    Ok(())
}

fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn nonempty(value: &Value) -> Result<&str, ReviewError> {
    value
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .ok_or(ReviewError::Shape)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ReviewError> {
    nonempty(&value[key])
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], ReviewError> {
    value[key]
        .as_array()
        .filter(|items| !items.is_empty())
        .map(Vec::as_slice)
        .ok_or(ReviewError::Shape)
}

fn repository_root() -> Result<PathBuf, ReviewError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or(ReviewError::Io)
}

fn read_review() -> Result<Value, ReviewError> {
    let bytes = std::fs::read(repository_root()?.join(REVIEW_PATH)).map_err(|_| ReviewError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| ReviewError::Shape)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum ReviewError {
    #[error("review_io")]
    Io,
    #[error("review_shape")]
    Shape,
    #[error("review_source")]
    Source,
    #[error("review_identity")]
    Identity,
    #[error("review_ownership")]
    Ownership,
    #[error("review_evidence")]
    Evidence,
    #[error("review_status")]
    Status,
}
