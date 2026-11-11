// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compliance-ledger conformance checks.

use std::path::{Path, PathBuf};

const LEDGER_PATH: &str = "contracts/compliance/requirements/wallet_core.toml";
const STATUS_NOT_IMPLEMENTED: &str = "not_implemented";
const STATUS_PARTIAL: &str = "partial";
const STATUS_COMPLETE: &str = "complete";

#[derive(Default)]
struct RequirementEntry {
    id: Option<String>,
    source_present: bool,
    status: Option<String>,
    reference_sections: Vec<String>,
    evidence: Vec<String>,
    test_evidence: Vec<String>,
}

impl RequirementEntry {
    fn has_active_status(&self) -> bool {
        matches!(
            self.status.as_deref(),
            Some(STATUS_PARTIAL | STATUS_COMPLETE)
        )
    }

    fn is_arf_wallet_requirement(&self) -> bool {
        matches!(self.id.as_deref(), Some(id) if id.starts_with("ARF-WALLET-"))
    }
}

#[test]
fn compliance_requirements_have_source_and_test_evidence() -> Result<(), LedgerTestError> {
    let root = repository_root()?;
    let ledger =
        std::fs::read_to_string(root.join(LEDGER_PATH)).map_err(|_| LedgerTestError::Io)?;
    let requirements = parse_requirements(&ledger)?;

    if requirements.is_empty() {
        return Err(LedgerTestError::MissingRequirement);
    }

    for requirement in requirements {
        validate_requirement(&root, &requirement)?;
    }

    Ok(())
}

fn repository_root() -> Result<PathBuf, LedgerTestError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(LedgerTestError::InvalidRepositoryRoot)
}

fn parse_requirements(ledger: &str) -> Result<Vec<RequirementEntry>, LedgerTestError> {
    let mut requirements = Vec::new();
    let mut current: Option<RequirementEntry> = None;

    for line in ledger.lines() {
        let trimmed = line.trim();
        if trimmed == "[[requirement]]" {
            if let Some(requirement) = current.take() {
                requirements.push(requirement);
            }
            current = Some(RequirementEntry::default());
            continue;
        }

        let Some(requirement) = current.as_mut() else {
            continue;
        };

        if let Some(id) = parse_string_field(trimmed, "id") {
            requirement.id = Some(id);
        } else if string_field_present(trimmed, "source") {
            requirement.source_present = true;
        } else if let Some(status) = parse_string_field(trimmed, "status") {
            requirement.status = Some(status);
        } else if let Some(reference_sections) = parse_array_field(trimmed, "reference_sections")? {
            requirement.reference_sections = reference_sections;
        } else if let Some(evidence) = parse_array_field(trimmed, "evidence")? {
            requirement.evidence = evidence;
        } else if let Some(test_evidence) = parse_array_field(trimmed, "test_evidence")? {
            requirement.test_evidence = test_evidence;
        }
    }

    if let Some(requirement) = current {
        requirements.push(requirement);
    }

    Ok(requirements)
}

fn validate_requirement(
    root: &Path,
    requirement: &RequirementEntry,
) -> Result<(), LedgerTestError> {
    if requirement.id.is_none() {
        return Err(LedgerTestError::MissingId);
    }
    if !requirement.source_present {
        return Err(LedgerTestError::MissingSource);
    }
    validate_status(requirement.status.as_deref())?;
    validate_paths(root, &requirement.evidence)?;

    if requirement.has_active_status() {
        if requirement.test_evidence.is_empty() {
            return Err(LedgerTestError::MissingTestEvidence);
        }
        validate_paths(root, &requirement.test_evidence)?;
    }
    if requirement.has_active_status() && requirement.is_arf_wallet_requirement() {
        validate_reference_sections(&requirement.reference_sections)?;
    }

    Ok(())
}

fn validate_status(status: Option<&str>) -> Result<(), LedgerTestError> {
    match status {
        Some(STATUS_NOT_IMPLEMENTED | STATUS_PARTIAL | STATUS_COMPLETE) => Ok(()),
        Some(_) => Err(LedgerTestError::InvalidStatus),
        None => Err(LedgerTestError::MissingStatus),
    }
}

fn validate_paths(root: &Path, paths: &[String]) -> Result<(), LedgerTestError> {
    if paths.is_empty() {
        return Err(LedgerTestError::MissingEvidence);
    }

    for path in paths {
        if path.is_empty() || !root.join(path).exists() {
            return Err(LedgerTestError::MissingEvidencePath);
        }
    }

    Ok(())
}

fn validate_reference_sections(reference_sections: &[String]) -> Result<(), LedgerTestError> {
    if reference_sections.is_empty() {
        return Err(LedgerTestError::MissingReferenceSections);
    }

    for section in reference_sections {
        if section.trim().is_empty() || !section.contains(':') {
            return Err(LedgerTestError::InvalidReferenceSection);
        }
    }

    Ok(())
}

fn string_field_present(line: &str, key: &str) -> bool {
    parse_string_field(line, key).is_some()
}

fn parse_string_field(line: &str, key: &str) -> Option<String> {
    let prefix = field_prefix(key);
    line.strip_prefix(prefix.as_str())
        .and_then(|value| value.strip_prefix('"'))
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
}

fn parse_array_field(line: &str, key: &str) -> Result<Option<Vec<String>>, LedgerTestError> {
    let prefix = field_prefix(key);
    let Some(value) = line.strip_prefix(prefix.as_str()) else {
        return Ok(None);
    };
    let Some(inner) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(LedgerTestError::MalformedArray);
    };
    if inner.trim().is_empty() {
        return Ok(Some(Vec::new()));
    }

    let mut values = Vec::new();
    for item in inner.split(',') {
        let trimmed = item.trim();
        let Some(path) = trimmed
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        else {
            return Err(LedgerTestError::MalformedArray);
        };
        values.push(path.to_owned());
    }

    Ok(Some(values))
}

fn field_prefix(key: &str) -> String {
    let mut prefix = String::with_capacity(key.len().saturating_add(3));
    prefix.push_str(key);
    prefix.push_str(" = ");
    prefix
}

#[derive(Debug, thiserror::Error)]
enum LedgerTestError {
    #[error("invalid_repository_root")]
    InvalidRepositoryRoot,
    #[error("io")]
    Io,
    #[error("missing_requirement")]
    MissingRequirement,
    #[error("missing_id")]
    MissingId,
    #[error("missing_source")]
    MissingSource,
    #[error("missing_status")]
    MissingStatus,
    #[error("invalid_status")]
    InvalidStatus,
    #[error("missing_evidence")]
    MissingEvidence,
    #[error("missing_test_evidence")]
    MissingTestEvidence,
    #[error("missing_evidence_path")]
    MissingEvidencePath,
    #[error("missing_reference_sections")]
    MissingReferenceSections,
    #[error("invalid_reference_section")]
    InvalidReferenceSection,
    #[error("malformed_array")]
    MalformedArray,
}
