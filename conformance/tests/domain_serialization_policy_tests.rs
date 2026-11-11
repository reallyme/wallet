// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Enforces the absence of hand-written serialization in domain crates.

#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOMAIN_SOURCE_ROOTS: &[&str] = &[
    "crates/types/src",
    "crates/keystore/src",
    "crates/attestation/src",
    "crates/lifecycle/src",
    "crates/flows/src",
    "crates/consent/src",
    "crates/inventory/src",
    "crates/storage/src",
    "crates/log/src",
];

const ALLOWED_SERDE_FILES: &[&str] = &[];

const SERDE_MARKERS: &[&str] = &[
    "use serde::",
    "serde::Serialize",
    "serde::Deserialize",
    "#[serde",
    "Serialize,",
    "Deserialize,",
];

const MANIFESTS_WITHOUT_DOMAIN_SERDE: &[&str] = &[
    "crates/types/Cargo.toml",
    "crates/keystore/Cargo.toml",
    "crates/attestation/Cargo.toml",
    "crates/lifecycle/Cargo.toml",
    "crates/flows/Cargo.toml",
];

#[test]
fn hand_written_domain_serde_is_absent() -> Result<(), DomainSerializationPolicyTestError> {
    let root = workspace_root()?;
    let mut rust_files = Vec::new();
    for source_root in DOMAIN_SOURCE_ROOTS {
        collect_rust_files(&root.join(source_root), &mut rust_files)?;
    }

    let mut actual = BTreeSet::new();
    for path in rust_files {
        let contents =
            std::fs::read_to_string(&path).map_err(|_| DomainSerializationPolicyTestError::Io)?;
        if SERDE_MARKERS.iter().any(|marker| contents.contains(marker)) {
            actual.insert(path);
        }
    }

    let expected = ALLOWED_SERDE_FILES
        .iter()
        .map(|path| root.join(path))
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(DomainSerializationPolicyTestError::UnexpectedSerdeSurface);
    }

    validate_removed_dependencies(&root)?;
    Ok(())
}

fn validate_removed_dependencies(root: &Path) -> Result<(), DomainSerializationPolicyTestError> {
    for manifest in MANIFESTS_WITHOUT_DOMAIN_SERDE {
        let contents = std::fs::read_to_string(root.join(manifest))
            .map_err(|_| DomainSerializationPolicyTestError::Io)?;
        if contents.lines().any(|line| {
            let line = line.trim();
            line.starts_with("serde =") || line.starts_with("serde.workspace")
        }) {
            return Err(DomainSerializationPolicyTestError::UnexpectedSerdeDependency);
        }
    }
    Ok(())
}

fn collect_rust_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), DomainSerializationPolicyTestError> {
    let entries =
        std::fs::read_dir(directory).map_err(|_| DomainSerializationPolicyTestError::Io)?;
    for entry in entries {
        let entry = entry.map_err(|_| DomainSerializationPolicyTestError::Io)?;
        let file_type = entry
            .file_type()
            .map_err(|_| DomainSerializationPolicyTestError::Io)?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_rust_files(&path, files)?;
        } else if file_type.is_file() && path.extension().is_some_and(|value| value == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf, DomainSerializationPolicyTestError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(DomainSerializationPolicyTestError::InvalidWorkspace)
}

#[derive(Debug, thiserror::Error)]
enum DomainSerializationPolicyTestError {
    #[error("invalid_workspace")]
    InvalidWorkspace,
    #[error("io")]
    Io,
    #[error("unexpected_serde_dependency")]
    UnexpectedSerdeDependency,
    #[error("unexpected_serde_surface")]
    UnexpectedSerdeSurface,
}
