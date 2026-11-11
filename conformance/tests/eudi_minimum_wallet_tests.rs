// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Executable checks for the minimum EUDI wallet evidence baseline.

use std::path::{Path, PathBuf};

use serde_json::Value;

const MINIMUMS_PATH: &str = "conformance/requirements/eudi-wallet-minimums.json";
const SOURCE_LOCK_PATH: &str = "conformance/sources.lock";
const TEST_CASES_PATH: &str = "conformance/eudi/test-cases.json";
const FIXTURE_HASHES_PATH: &str = "conformance/eudi/reference-fixture-hashes.json";
const REFERENCE_IMPLEMENTATION_LOCK_PATH: &str = "conformance/eudi/reference-implementation.lock";
const SHA2_256_HEX_LENGTH: usize = 64;

const REQUIRED_MINIMUM_IDS: &[&str] = &[
    "minimum.source-baseline",
    "minimum.pid-eaa-issuance-storage",
    "minimum.presentation-selective-disclosure-consent",
    "minimum.relying-party-entitlement-registration",
    "minimum.transaction-log-and-qtsp-decisions",
    "minimum.wallet-unit-attestation",
    "minimum.key-custody-no-key-bytes",
    "minimum.status-revocation-lifecycle",
    "minimum.presentation-delivery-online-cross-device",
    "minimum.proximity-offline-mdoc-boundary",
    "minimum.lifecycle-portability-withdrawal",
    "minimum.proto-connect-boundary",
    "minimum.reference-wallet-interop",
    "minimum.qes-qseal-support-boundary",
];

const ALLOWED_MINIMUM_STATUSES: &[&str] = &[
    "implemented",
    "partial",
    "delegated",
    "fixture_seeded",
    "operational_required",
];
const ALLOWED_TEST_CASE_STATUSES: &[&str] = &[
    "implemented",
    "unit_covered",
    "fixture_seeded",
    "fixture_available",
];

const REQUIRED_REFERENCE_IMPLEMENTATION_IDS: &[&str] = &[
    "eudi-lib-ios-wallet-kit",
    "av-app-android-wallet-ui",
    "av-app-ios-wallet-ui",
    "eudi-doc-testing-application",
];

const REQUIRED_REFERENCE_FIXTURE_PATHS: &[&str] = &[
    "conformance/fixtures/eudi-reference/issuance-offer-to-storage.json",
    "conformance/fixtures/eudi-reference/cross-device-presentation.json",
    "conformance/fixtures/eudi-reference/same-device-presentation.json",
    "conformance/fixtures/eudi-reference/presentation-nonce-mismatch.json",
    "conformance/fixtures/eudi-reference/proximity-presentation.json",
    "conformance/fixtures/eudi-reference/offline-presentation.json",
    "conformance/fixtures/eudi-reference/qr-deep-link-handoff.json",
];

#[test]
fn eudi_wallet_minimum_manifest_covers_required_baseline() -> Result<(), MinimumTestError> {
    let root = repository_root()?;
    let manifest = read_json(&root, MINIMUMS_PATH)?;
    let source_lock =
        std::fs::read_to_string(root.join(SOURCE_LOCK_PATH)).map_err(|_| MinimumTestError::Io)?;
    let test_case_ids = collect_test_case_ids(&root)?;

    require_schema_version(&manifest)?;
    require_exact_string(&manifest, "source_lock", SOURCE_LOCK_PATH)?;
    require_exact_string(
        &manifest,
        "reference_implementation_lock",
        REFERENCE_IMPLEMENTATION_LOCK_PATH,
    )?;

    let minimums = require_array(&manifest, "minimums")?;
    if minimums.is_empty() {
        return Err(MinimumTestError::MissingMinimum);
    }

    for required_id in REQUIRED_MINIMUM_IDS {
        if !minimums.iter().any(|minimum| id_is(minimum, required_id)) {
            return Err(MinimumTestError::MissingMinimum);
        }
    }

    for minimum in minimums {
        validate_minimum(&root, &source_lock, &test_case_ids, minimum)?;
    }

    Ok(())
}

#[test]
fn eudi_reference_implementation_lock_pins_required_targets() -> Result<(), MinimumTestError> {
    let root = repository_root()?;
    let lock = read_json(&root, REFERENCE_IMPLEMENTATION_LOCK_PATH)?;
    let references = require_array(&lock, "references")?;

    for required_id in REQUIRED_REFERENCE_IMPLEMENTATION_IDS {
        if !references
            .iter()
            .any(|reference| id_is(reference, required_id))
        {
            return Err(MinimumTestError::MissingReferenceImplementation);
        }
    }

    for reference in references {
        require_non_empty_string(reference, "id")?;
        require_non_empty_string(reference, "repository")?;
        require_non_empty_string(reference, "release")?;
        require_non_empty_string(reference, "commit")?;
        require_non_empty_string(reference, "purpose")?;
    }

    Ok(())
}

#[test]
fn eudi_reference_fixture_hashes_match_committed_files() -> Result<(), MinimumTestError> {
    let root = repository_root()?;
    let lock = read_json(&root, FIXTURE_HASHES_PATH)?;

    require_schema_version(&lock)?;
    require_exact_string(&lock, "algorithm", "sha2-256")?;
    require_exact_string(&lock, "source_lock", SOURCE_LOCK_PATH)?;
    require_exact_string(
        &lock,
        "reference_implementation_lock",
        REFERENCE_IMPLEMENTATION_LOCK_PATH,
    )?;

    let fixtures = require_array(&lock, "fixtures")?;
    if fixtures.is_empty() {
        return Err(MinimumTestError::MissingFixtureHash);
    }

    for required_path in REQUIRED_REFERENCE_FIXTURE_PATHS {
        if !fixtures
            .iter()
            .any(|fixture| path_is(fixture, required_path))
        {
            return Err(MinimumTestError::MissingFixtureHash);
        }
    }

    for fixture in fixtures {
        validate_fixture_hash(&root, fixture)?;
    }

    Ok(())
}

fn validate_minimum(
    root: &Path,
    source_lock: &str,
    test_case_ids: &[String],
    minimum: &Value,
) -> Result<(), MinimumTestError> {
    require_non_empty_string(minimum, "id")?;
    require_non_empty_string(minimum, "summary")?;
    let status = require_non_empty_string(minimum, "status")?;
    if !ALLOWED_MINIMUM_STATUSES.contains(&status) {
        return Err(MinimumTestError::InvalidMinimumStatus);
    }

    validate_source_ids(source_lock, minimum)?;
    validate_path_list(root, minimum, "evidence")?;
    validate_path_list(root, minimum, "test_evidence")?;
    validate_case_ids(test_case_ids, minimum)?;
    validate_limitations_for_status(minimum, status)?;

    Ok(())
}

fn validate_limitations_for_status(minimum: &Value, status: &str) -> Result<(), MinimumTestError> {
    let limitations = require_array(minimum, "limitations")?;
    if status == "implemented" {
        if !limitations.is_empty() {
            return Err(MinimumTestError::UnexpectedLimitation);
        }
        return Ok(());
    }

    validate_string_list(minimum, "limitations")
}

#[test]
fn implemented_minimum_rejects_an_unmet_limitation() {
    let minimum = serde_json::json!({ "limitations": ["External verification is unavailable."] });
    assert!(matches!(
        validate_limitations_for_status(&minimum, "implemented"),
        Err(MinimumTestError::UnexpectedLimitation)
    ));
}

#[test]
fn incomplete_minimum_requires_a_specific_limitation() {
    assert!(matches!(
        validate_limitations_for_status(
            &serde_json::json!({ "limitations": [] }),
            "operational_required",
        ),
        Err(MinimumTestError::MissingLimitation)
    ));
    for minimum in [
        serde_json::json!({ "limitations": [""] }),
        serde_json::json!({ "limitations": [false] }),
    ] {
        assert!(matches!(
            validate_limitations_for_status(&minimum, "operational_required"),
            Err(MinimumTestError::InvalidLimitation)
        ));
    }
    assert!(validate_limitations_for_status(
        &serde_json::json!({ "limitations": ["External verification is unavailable."] }),
        "operational_required",
    )
    .is_ok());
}

fn validate_fixture_hash(root: &Path, fixture: &Value) -> Result<(), MinimumTestError> {
    let path = require_non_empty_string(fixture, "path")?;
    let expected = require_non_empty_string(fixture, "sha2_256")?;
    if expected.len() != SHA2_256_HEX_LENGTH {
        return Err(MinimumTestError::InvalidFixtureHash);
    }

    let bytes = std::fs::read(root.join(path)).map_err(|_| MinimumTestError::Io)?;
    let digest = crypto_sha2_256::digest(&bytes);
    let actual = encode_hex(digest.as_bytes());
    if actual != expected {
        return Err(MinimumTestError::FixtureHashMismatch);
    }

    Ok(())
}

fn validate_source_ids(source_lock: &str, minimum: &Value) -> Result<(), MinimumTestError> {
    let source_ids = require_array(minimum, "source_ids")?;
    if source_ids.is_empty() {
        return Err(MinimumTestError::MissingSourceId);
    }

    for source_id in source_ids {
        let value = source_id
            .as_str()
            .ok_or(MinimumTestError::InvalidSourceId)?;
        if value.is_empty() {
            return Err(MinimumTestError::InvalidSourceId);
        }
        if !source_lock.contains(value) {
            return Err(MinimumTestError::MissingSourceId);
        }
    }

    Ok(())
}

fn validate_path_list(root: &Path, value: &Value, key: &str) -> Result<(), MinimumTestError> {
    let paths = require_array(value, key)?;
    if paths.is_empty() {
        return Err(MinimumTestError::MissingEvidencePath);
    }

    for path in paths {
        let relative_path = path.as_str().ok_or(MinimumTestError::InvalidEvidencePath)?;
        if relative_path.is_empty() {
            return Err(MinimumTestError::InvalidEvidencePath);
        }
        if !root.join(relative_path).exists() {
            return Err(MinimumTestError::MissingEvidencePath);
        }
    }

    Ok(())
}

fn validate_case_ids(known_case_ids: &[String], minimum: &Value) -> Result<(), MinimumTestError> {
    let case_ids = require_array(minimum, "conformance_case_ids")?;
    if case_ids.is_empty() {
        return Err(MinimumTestError::MissingCaseId);
    }

    for case_id in case_ids {
        let value = case_id.as_str().ok_or(MinimumTestError::InvalidCaseId)?;
        if value.is_empty() {
            return Err(MinimumTestError::InvalidCaseId);
        }
        if !known_case_ids.iter().any(|known| known == value) {
            return Err(MinimumTestError::MissingCaseId);
        }
    }

    Ok(())
}

fn collect_test_case_ids(root: &Path) -> Result<Vec<String>, MinimumTestError> {
    let test_cases = read_json(root, TEST_CASES_PATH)?;
    let cases = require_array(&test_cases, "test_cases")?;
    let mut ids = Vec::with_capacity(cases.len());

    for test_case in cases {
        validate_test_case(root, test_case)?;
        let id = require_non_empty_string(test_case, "id")?;
        ids.push(id.to_owned());
    }

    Ok(ids)
}

fn validate_test_case(root: &Path, test_case: &Value) -> Result<(), MinimumTestError> {
    require_non_empty_string(test_case, "id")?;
    let status = require_non_empty_string(test_case, "status")?;
    if !ALLOWED_TEST_CASE_STATUSES.contains(&status) {
        return Err(MinimumTestError::InvalidTestCaseStatus);
    }

    let source = require_non_empty_string(test_case, "source")?;
    if !root.join(source).exists() {
        return Err(MinimumTestError::MissingTestCaseSource);
    }

    validate_path_list(root, test_case, "fixtures")
}

fn validate_string_list(value: &Value, key: &str) -> Result<(), MinimumTestError> {
    let items = require_array(value, key)?;
    if items.is_empty() {
        return Err(MinimumTestError::MissingLimitation);
    }

    for item in items {
        let text = item.as_str().ok_or(MinimumTestError::InvalidLimitation)?;
        if text.is_empty() {
            return Err(MinimumTestError::InvalidLimitation);
        }
    }

    Ok(())
}

fn require_schema_version(value: &Value) -> Result<(), MinimumTestError> {
    let version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or(MinimumTestError::MissingSchemaVersion)?;
    if version == 0 {
        return Err(MinimumTestError::InvalidSchemaVersion);
    }

    Ok(())
}

fn require_exact_string(value: &Value, key: &str, expected: &str) -> Result<(), MinimumTestError> {
    let actual = require_non_empty_string(value, key)?;
    if actual != expected {
        return Err(MinimumTestError::UnexpectedFieldValue);
    }

    Ok(())
}

fn require_non_empty_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, MinimumTestError> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(MinimumTestError::MissingField)?;
    if text.is_empty() {
        return Err(MinimumTestError::MissingField);
    }

    Ok(text)
}

fn require_array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], MinimumTestError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(MinimumTestError::MissingField)
}

fn id_is(value: &Value, expected: &str) -> bool {
    value.get("id").and_then(Value::as_str) == Some(expected)
}

fn path_is(value: &Value, expected: &str) -> bool {
    value.get("path").and_then(Value::as_str) == Some(expected)
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

fn repository_root() -> Result<PathBuf, MinimumTestError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(MinimumTestError::InvalidRepositoryRoot)
}

fn read_json(root: &Path, relative_path: &str) -> Result<Value, MinimumTestError> {
    let document =
        std::fs::read_to_string(root.join(relative_path)).map_err(|_| MinimumTestError::Io)?;
    serde_json::from_str(&document).map_err(|_| MinimumTestError::InvalidJson)
}

#[derive(Debug, thiserror::Error)]
enum MinimumTestError {
    #[error("invalid_repository_root")]
    InvalidRepositoryRoot,
    #[error("io")]
    Io,
    #[error("invalid_json")]
    InvalidJson,
    #[error("missing_schema_version")]
    MissingSchemaVersion,
    #[error("invalid_schema_version")]
    InvalidSchemaVersion,
    #[error("missing_field")]
    MissingField,
    #[error("unexpected_field_value")]
    UnexpectedFieldValue,
    #[error("missing_minimum")]
    MissingMinimum,
    #[error("invalid_minimum_status")]
    InvalidMinimumStatus,
    #[error("missing_source_id")]
    MissingSourceId,
    #[error("invalid_source_id")]
    InvalidSourceId,
    #[error("missing_evidence_path")]
    MissingEvidencePath,
    #[error("invalid_evidence_path")]
    InvalidEvidencePath,
    #[error("missing_case_id")]
    MissingCaseId,
    #[error("invalid_case_id")]
    InvalidCaseId,
    #[error("missing_limitation")]
    MissingLimitation,
    #[error("invalid_limitation")]
    InvalidLimitation,
    #[error("unexpected_limitation")]
    UnexpectedLimitation,
    #[error("invalid_test_case_status")]
    InvalidTestCaseStatus,
    #[error("missing_test_case_source")]
    MissingTestCaseSource,
    #[error("missing_reference_implementation")]
    MissingReferenceImplementation,
    #[error("missing_fixture_hash")]
    MissingFixtureHash,
    #[error("invalid_fixture_hash")]
    InvalidFixtureHash,
    #[error("fixture_hash_mismatch")]
    FixtureHashMismatch,
}
