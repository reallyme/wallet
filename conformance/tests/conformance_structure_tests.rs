// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance source and scope structure checks.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

const REQUIRED_JSON_FILES: &[&str] = &[
    "conformance/scope.json",
    "conformance/requirements/regulation.json",
    "conformance/requirements/implementing-acts.json",
    "conformance/requirements/arf-wallet.json",
    "conformance/requirements/eudi-wallet-minimums.json",
    "conformance/requirements/technical-specifications.json",
    "conformance/requirements/fcaf.json",
    "conformance/features/wallet-capabilities.json",
    "conformance/features/supported-use-cases.json",
    "conformance/features/exclusions.json",
    "conformance/features/wallet-scope-ownership-v1.json",
    "conformance/eudi/upstream-tests.json",
    "conformance/eudi/reference-implementation.lock",
    "conformance/eudi/reference-fixture-hashes.json",
    "conformance/eudi/reference-run-manifest.json",
    "conformance/eudi/test-cases.json",
    "conformance/reports/wallet-security-controls.json",
    "conformance/reports/external-readiness.json",
    "conformance/reports/vaultwallet-r02-device-qualification.json",
];

const REQUIRED_DIRECTORIES: &[&str] = &[
    "conformance/fixtures/wallets",
    "conformance/fixtures/credentials",
    "conformance/fixtures/issuers",
    "conformance/fixtures/relying-parties",
    "conformance/fixtures/trust",
    "conformance/fixtures/lifecycle",
    "conformance/fixtures/eudi-reference",
];

const REQUIRED_SOURCE_IDS: &[&str] = &[
    "eidas-2024-1183",
    "eudi-arf",
    "eudi-fcaf",
    "eudi-standards-tracking",
];

const BANNED_OPENID4VP_LEGACY_FIELDS: &[&str] =
    &["presentation_definition", "presentation_submission"];

const VERIFIED_EXTERNAL_DEPENDENCY_STATUS: &str = "verified";

const REQUIRED_REFERENCE_RUN_ARTIFACTS: &[&str] = &[
    "suite_export",
    "run_summary",
    "fixture_hash_manifest",
    "environment_manifest",
    "difference_summary",
];

const REQUIRED_WALLET_HARDWARE_LANES: &[&str] = &[
    "ios-secure-enclave",
    "android-strongbox",
    "android-hardware-backed-tee",
];

#[test]
fn conformance_json_files_are_parseable_and_versioned() -> Result<(), StructureTestError> {
    let root = repository_root()?;

    for relative_path in REQUIRED_JSON_FILES {
        let value = read_json(&root, relative_path)?;
        let schema_version = value
            .get("schema_version")
            .and_then(Value::as_u64)
            .ok_or(StructureTestError::MissingSchemaVersion)?;
        if schema_version == 0 {
            return Err(StructureTestError::InvalidSchemaVersion);
        }
    }

    Ok(())
}

#[test]
fn conformance_source_lock_pins_required_sources() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let source_lock = std::fs::read_to_string(root.join("conformance/sources.lock"))
        .map_err(|_| StructureTestError::Io)?;

    for source_id in REQUIRED_SOURCE_IDS {
        if !source_lock.contains(source_id) {
            return Err(StructureTestError::MissingSourceId);
        }
    }

    if !source_lock.contains("v3.0.0") || !source_lock.contains("v0.0.10") {
        return Err(StructureTestError::MissingPinnedVersion);
    }

    Ok(())
}

#[test]
fn fixture_directories_are_committed() -> Result<(), StructureTestError> {
    let root = repository_root()?;

    for relative_path in REQUIRED_DIRECTORIES {
        if !root.join(relative_path).is_dir() {
            return Err(StructureTestError::MissingFixtureDirectory);
        }
        if !root.join(relative_path).join("README.md").is_file() {
            return Err(StructureTestError::MissingFixtureReadme);
        }
    }

    Ok(())
}

#[test]
fn functional_claims_have_evidence_paths() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let capabilities = read_json(&root, "conformance/features/wallet-capabilities.json")?;
    let capability_claims = capabilities
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingFunctionalClaims)?;
    validate_functional_claims(&root, capability_claims)?;

    let use_cases = read_json(&root, "conformance/features/supported-use-cases.json")?;
    let use_case_claims = use_cases
        .get("use_cases")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingFunctionalClaims)?;
    validate_functional_claims(&root, use_case_claims)?;

    Ok(())
}

#[test]
fn security_controls_report_has_evidence_paths() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let controls = read_json(&root, "conformance/reports/wallet-security-controls.json")?;

    require_non_empty_string(&controls, "status")?;
    validate_json_path_list(&root, &controls, "evidence_paths")?;

    Ok(())
}

#[test]
fn vaultwallet_r02_cannot_close_with_an_unqualified_hardware_lane() -> Result<(), StructureTestError>
{
    let root = repository_root()?;
    let report = read_json(
        &root,
        "conformance/reports/vaultwallet-r02-device-qualification.json",
    )?;
    let status = report
        .get("status")
        .and_then(Value::as_str)
        .ok_or(StructureTestError::InvalidDeviceQualification)?;
    let lanes = report
        .get("lanes")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::InvalidDeviceQualification)?;

    for required_lane in REQUIRED_WALLET_HARDWARE_LANES {
        if !lanes
            .iter()
            .any(|lane| category_id(lane) == Some(*required_lane))
        {
            return Err(StructureTestError::InvalidDeviceQualification);
        }
    }

    if status == "complete" {
        let published_api_supported = report
            .pointer("/crypto_dependency/published_api_supports_selected_profile")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let every_lane_passed = lanes
            .iter()
            .all(|lane| lane.get("status").and_then(Value::as_str) == Some("passed"));
        if !published_api_supported || !every_lane_passed {
            return Err(StructureTestError::InvalidDeviceQualification);
        }
    }

    Ok(())
}

#[test]
fn implemented_eudi_test_cases_have_fixture_evidence() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let value = read_json(&root, "conformance/eudi/test-cases.json")?;
    let test_cases = value
        .get("test_cases")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingTestCases)?;

    for test_case in test_cases {
        validate_test_case_fixtures(&root, test_case)?;
    }

    Ok(())
}

#[test]
fn conformance_claim_rejects_a_fixture_its_test_never_reads() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let case = serde_json::json!({
        "status": "implemented",
        "source": "conformance/tests/sdk_contract_tests.rs",
        "test_function": "sdk_boundary_fixture_names_only_the_canonical_operation_protocol",
        "fixtures": ["conformance/fixtures/wallets/wua-valid.json"]
    });
    assert!(matches!(
        validate_test_case_fixtures(&root, &case),
        Err(StructureTestError::MissingFixtureEvidence)
    ));
    Ok(())
}

#[test]
fn conformance_claim_rejects_an_unmapped_test_function() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let case = serde_json::json!({
        "status": "unit_covered",
        "source": "conformance/tests/sdk_contract_tests.rs",
        "test_function": "missing_conformance_test",
        "fixtures": []
    });
    assert!(matches!(
        validate_test_case_fixtures(&root, &case),
        Err(StructureTestError::MissingTestFunction)
    ));
    Ok(())
}

#[test]
fn external_readiness_dependencies_have_evidence() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let value = read_json(&root, "conformance/reports/external-readiness.json")?;
    let dependencies = value
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingExternalDependencies)?;

    if dependencies.is_empty() {
        return Err(StructureTestError::MissingExternalDependencies);
    }

    for dependency in dependencies {
        require_non_empty_string(dependency, "id")?;
        require_non_empty_string(dependency, "owner")?;
        require_non_empty_string(dependency, "status")?;
        require_non_empty_string(dependency, "wallet_boundary")?;
        validate_string_list(dependency, "observed_paths")?;
        validate_json_path_list(&root, dependency, "wallet_evidence")?;
        let status = dependency
            .get("status")
            .and_then(Value::as_str)
            .ok_or(StructureTestError::MissingExternalField)?;
        if status == VERIFIED_EXTERNAL_DEPENDENCY_STATUS {
            validate_empty_string_list(dependency, "limitations")?;
        } else {
            validate_string_list(dependency, "limitations")?;
        }
    }

    Ok(())
}

#[test]
fn wallet_evidence_cannot_require_external_checkouts() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    for path in [
        "../identity-conformance/evidence.json",
        "../identity-taxonomy/conformance/inventory/requirements.json",
        "/tmp/external-evidence.json",
        "..\\identity-conformance\\evidence.json",
        "",
    ] {
        assert!(matches!(
            validate_json_path_list(
                &root,
                &serde_json::json!({ "wallet_evidence": [path] }),
                "wallet_evidence",
            ),
            Err(StructureTestError::InvalidEvidencePath)
        ));
    }
    validate_json_path_list(
        &root,
        &serde_json::json!({
            "wallet_evidence": ["conformance/tests/presentation_zk_tests.rs"]
        }),
        "wallet_evidence",
    )
}

#[test]
fn openid4vp_fixtures_use_dcql_not_presentation_exchange() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let fixture_root = root.join("conformance/fixtures");
    let mut json_paths = Vec::new();
    collect_json_paths(&fixture_root, &mut json_paths)?;

    for path in json_paths {
        let document = std::fs::read_to_string(path).map_err(|_| StructureTestError::Io)?;
        for field in BANNED_OPENID4VP_LEGACY_FIELDS {
            if document.contains(field) {
                return Err(StructureTestError::LegacyOpenId4VpField);
            }
        }
    }

    Ok(())
}

#[test]
fn reference_wallet_run_manifest_covers_fixture_seeded_cases() -> Result<(), StructureTestError> {
    let root = repository_root()?;
    let test_cases = read_json(&root, "conformance/eudi/test-cases.json")?;
    let run_manifest = read_json(&root, "conformance/eudi/reference-run-manifest.json")?;
    let cases = test_cases
        .get("test_cases")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingTestCases)?;
    let runs = run_manifest
        .get("runs")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingReferenceRun)?;

    for test_case in cases {
        if test_case.get("status").and_then(Value::as_str) == Some("fixture_seeded") {
            let case_id = test_case
                .get("id")
                .and_then(Value::as_str)
                .ok_or(StructureTestError::MissingExternalField)?;
            let run = runs
                .iter()
                .find(|run| run.get("id").and_then(Value::as_str) == Some(case_id))
                .ok_or(StructureTestError::MissingReferenceRun)?;
            validate_reference_run(&root, run)?;
        }
    }

    Ok(())
}

fn repository_root() -> Result<PathBuf, StructureTestError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(StructureTestError::InvalidRepositoryRoot)
}

fn collect_json_paths(
    directory: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), StructureTestError> {
    let entries = std::fs::read_dir(directory).map_err(|_| StructureTestError::Io)?;

    for entry in entries {
        let entry = entry.map_err(|_| StructureTestError::Io)?;
        let path = entry.path();
        if path.is_dir() {
            collect_json_paths(&path, paths)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path);
        }
    }

    Ok(())
}

fn read_json(root: &Path, relative_path: &str) -> Result<Value, StructureTestError> {
    let document =
        std::fs::read_to_string(root.join(relative_path)).map_err(|_| StructureTestError::Io)?;
    serde_json::from_str(&document).map_err(|_| StructureTestError::InvalidJson)
}

fn category_id(category: &Value) -> Option<&str> {
    category.get("id").and_then(Value::as_str)
}

fn validate_functional_claims(root: &Path, claims: &[Value]) -> Result<(), StructureTestError> {
    for claim in claims {
        let status = claim
            .get("status")
            .and_then(Value::as_str)
            .ok_or(StructureTestError::MissingFunctionalClaimStatus)?;
        if matches!(status, "implemented" | "partial") {
            validate_json_path_list(root, claim, "evidence")?;
        }
    }

    Ok(())
}

fn validate_json_path_list(
    root: &Path,
    value: &Value,
    key: &str,
) -> Result<(), StructureTestError> {
    let paths = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingEvidenceList)?;
    if paths.is_empty() {
        return Err(StructureTestError::MissingEvidenceList);
    }

    for path in paths {
        let path = path
            .as_str()
            .ok_or(StructureTestError::InvalidEvidencePath)?;
        if path.is_empty()
            || path.contains('\\')
            || Path::new(path)
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(StructureTestError::InvalidEvidencePath);
        }
        let candidate = root.join(path);
        if !candidate.exists() {
            return Err(StructureTestError::MissingEvidenceFile);
        }
        // Source-local evidence cannot acquire a hidden sibling dependency
        // through a symlink while still looking local in the manifest.
        let canonical_root = root.canonicalize().map_err(|_| StructureTestError::Io)?;
        let canonical_path = candidate
            .canonicalize()
            .map_err(|_| StructureTestError::Io)?;
        if !canonical_path.starts_with(canonical_root) {
            return Err(StructureTestError::InvalidEvidencePath);
        }
    }

    Ok(())
}

fn require_non_empty_string(value: &Value, key: &str) -> Result<(), StructureTestError> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(StructureTestError::MissingExternalField)?;
    if text.is_empty() {
        return Err(StructureTestError::MissingExternalField);
    }
    Ok(())
}

fn validate_string_list(value: &Value, key: &str) -> Result<(), StructureTestError> {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingEvidenceList)?;
    if items.is_empty() {
        return Err(StructureTestError::MissingEvidenceList);
    }
    for item in items {
        let text = item
            .as_str()
            .ok_or(StructureTestError::InvalidEvidencePath)?;
        if text.is_empty() {
            return Err(StructureTestError::InvalidEvidencePath);
        }
    }
    Ok(())
}

fn validate_empty_string_list(value: &Value, key: &str) -> Result<(), StructureTestError> {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingEvidenceList)?;
    if !items.is_empty() {
        return Err(StructureTestError::VerifiedDependencyHasLimitations);
    }
    Ok(())
}

#[test]
fn verified_dependency_rejects_an_unmet_limitation() {
    assert!(matches!(
        validate_empty_string_list(
            &serde_json::json!({ "limitations": ["No executed evidence is attached."] }),
            "limitations",
        ),
        Err(StructureTestError::VerifiedDependencyHasLimitations)
    ));
    assert!(
        validate_empty_string_list(&serde_json::json!({ "limitations": [] }), "limitations",)
            .is_ok()
    );
}

fn validate_test_case_fixtures(root: &Path, test_case: &Value) -> Result<(), StructureTestError> {
    let status = test_case
        .get("status")
        .and_then(Value::as_str)
        .ok_or(StructureTestError::MissingTestCaseStatus)?;
    let fixtures = test_case
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingFixtureList)?;

    if status == "implemented" && fixtures.is_empty() {
        return Err(StructureTestError::MissingFixtureEvidence);
    }

    if matches!(status, "implemented" | "unit_covered") {
        let source = test_case
            .get("source")
            .and_then(Value::as_str)
            .ok_or(StructureTestError::InvalidEvidencePath)?;
        let test_function = test_case
            .get("test_function")
            .and_then(Value::as_str)
            .ok_or(StructureTestError::MissingTestFunction)?;
        let source_text = std::fs::read_to_string(root.join(source))
            .map_err(|_| StructureTestError::MissingEvidenceFile)?;
        if !source_text.contains(&format!("#[test]\nfn {test_function}(")) {
            return Err(StructureTestError::MissingTestFunction);
        }
        if status == "implemented"
            && fixtures.iter().any(|fixture| {
                fixture
                    .as_str()
                    .and_then(|path| Path::new(path).file_name())
                    .and_then(|name| name.to_str())
                    .is_none_or(|name| !source_text.contains(name))
            })
        {
            return Err(StructureTestError::MissingFixtureEvidence);
        }
    } else if !matches!(status, "fixture_available" | "fixture_seeded") {
        return Err(StructureTestError::MissingTestCaseStatus);
    }

    for fixture in fixtures {
        let path = fixture
            .as_str()
            .ok_or(StructureTestError::InvalidFixturePath)?;
        if !root.join(path).is_file() {
            return Err(StructureTestError::MissingFixtureFile);
        }
    }

    Ok(())
}

fn validate_reference_run(root: &Path, run: &Value) -> Result<(), StructureTestError> {
    require_non_empty_string(run, "id")?;
    require_non_empty_string(run, "status")?;
    require_non_empty_string(run, "wallet_flow")?;
    require_non_empty_string(run, "expected_archive_path")?;
    validate_string_list(run, "reference_targets")?;
    validate_json_path_list(root, run, "fixture_paths")?;

    let artifacts = run
        .get("required_artifacts")
        .and_then(Value::as_array)
        .ok_or(StructureTestError::MissingReferenceRunArtifact)?;
    for required in REQUIRED_REFERENCE_RUN_ARTIFACTS {
        if !artifacts
            .iter()
            .any(|artifact| artifact.as_str() == Some(required))
        {
            return Err(StructureTestError::MissingReferenceRunArtifact);
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum StructureTestError {
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
    #[error("missing_source_id")]
    MissingSourceId,
    #[error("missing_pinned_version")]
    MissingPinnedVersion,
    #[error("missing_fixture_directory")]
    MissingFixtureDirectory,
    #[error("missing_fixture_readme")]
    MissingFixtureReadme,
    #[error("missing_test_cases")]
    MissingTestCases,
    #[error("missing_test_case_status")]
    MissingTestCaseStatus,
    #[error("missing_fixture_list")]
    MissingFixtureList,
    #[error("missing_fixture_evidence")]
    MissingFixtureEvidence,
    #[error("missing_test_function")]
    MissingTestFunction,
    #[error("missing_functional_claims")]
    MissingFunctionalClaims,
    #[error("missing_functional_claim_status")]
    MissingFunctionalClaimStatus,
    #[error("missing_evidence_list")]
    MissingEvidenceList,
    #[error("invalid_evidence_path")]
    InvalidEvidencePath,
    #[error("missing_evidence_file")]
    MissingEvidenceFile,
    #[error("invalid_fixture_path")]
    InvalidFixturePath,
    #[error("missing_fixture_file")]
    MissingFixtureFile,
    #[error("missing_external_dependencies")]
    MissingExternalDependencies,
    #[error("missing_external_field")]
    MissingExternalField,
    #[error("verified_dependency_has_limitations")]
    VerifiedDependencyHasLimitations,
    #[error("legacy_openid4vp_field")]
    LegacyOpenId4VpField,
    #[error("missing_reference_run")]
    MissingReferenceRun,
    #[error("missing_reference_run_artifact")]
    MissingReferenceRunArtifact,
    #[error("invalid_device_qualification")]
    InvalidDeviceQualification,
}
