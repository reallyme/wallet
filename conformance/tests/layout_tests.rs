// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance layout smoke tests.

use std::path::{Path, PathBuf};

use reallyme_wallet_conformance::CONFORMANCE_LAYOUT_VERSION;

const REQUIRED_DIRECTORIES: &[&str] = &[
    "crates/wallet",
    "crates/proto",
    "crates/proto-codec",
    "crates/types",
    "crates/flows",
    "crates/lifecycle",
    "crates/inventory",
    "crates/consent",
    "crates/attestation",
    "crates/provider",
    "crates/runtime",
    "crates/storage",
    "crates/keystore",
    "crates/render",
    "crates/log",
    "crates/http",
    "crates/wallet-zk",
    "crates/proto/baselines",
    "contracts/compliance",
    "conformance",
    "fuzz",
    "vectors",
    "docs",
];

const RETIRED_PATHS: &[&str] = &[
    "src",
    "tests",
    "schema-baseline",
    "crates/proto/wallet",
    "crates/proto/codec",
    "compliance",
];

#[test]
fn conformance_layout_version_is_stable() {
    assert_eq!(CONFORMANCE_LAYOUT_VERSION, 1);
}

#[test]
fn repository_uses_the_standardized_wallet_shape() -> Result<(), LayoutTestError> {
    let root = repository_root()?;
    if REQUIRED_DIRECTORIES
        .iter()
        .any(|path| !root.join(path).is_dir())
    {
        return Err(LayoutTestError::MissingRequiredDirectory);
    }
    if RETIRED_PATHS.iter().any(|path| root.join(path).exists()) {
        return Err(LayoutTestError::RetiredPathPresent);
    }
    Ok(())
}

fn repository_root() -> Result<PathBuf, LayoutTestError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or(LayoutTestError::InvalidRepositoryRoot)
}

#[derive(Debug, thiserror::Error)]
enum LayoutTestError {
    #[error("invalid_repository_root")]
    InvalidRepositoryRoot,
    #[error("missing_required_directory")]
    MissingRequiredDirectory,
    #[error("retired_path_present")]
    RetiredPathPresent,
}
