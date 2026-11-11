// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! mdoc ownership boundary conformance checks.

use std::path::{Path, PathBuf};

const REMOVED_WALLET_PRESENTATION_IMPORT: &str =
    "import \"identity/presentation/v1/presentation.proto\";";
const REMOVED_WALLET_PRESENTATION_FIELD: &str =
    "identity.presentation.v1.Presentation presentation = 5;";

const FORBIDDEN_WALLET_PROTO_MESSAGES: &[&str] = &[
    "message MdocPresentation",
    "message MdocDeviceResponse",
    "message DeviceResponse",
    "message SessionTranscript",
    "message DeviceAuth",
    "message IssuerSigned",
    "message MobileSecurityObject",
];

const FORBIDDEN_WALLET_MANIFEST_DEPS: &[&str] = &[
    "reallyme-mdoc",
    "reallyme-openid4vp-formats",
    "reallyme-openid4vp-dc-api",
];

#[test]
fn wallet_leaves_mdoc_presentation_envelopes_in_identity() -> Result<(), MdocBoundaryTestError> {
    let root = repository_root()?;
    let wallet_proto = read(root.join("crates/proto/proto/reallyme/wallet/v1/wallet.proto"))?;
    // Compile against the linked registry source rather than an unrelated
    // sibling checkout whose revision may differ from Cargo.lock.
    let mut linked_mdoc =
        reallyme_ssi_proto::generated::proto::identity::presentation::v1::MdocPresentation::default(
        );
    linked_mdoc.device_response.push(1);
    if linked_mdoc.device_response.len() != 1 {
        return Err(MdocBoundaryTestError::MissingExpectedContract);
    }

    if wallet_proto.contains(REMOVED_WALLET_PRESENTATION_IMPORT)
        || wallet_proto.contains(REMOVED_WALLET_PRESENTATION_FIELD)
    {
        return Err(MdocBoundaryTestError::WalletImportsMdocPresentation);
    }

    for forbidden_message in FORBIDDEN_WALLET_PROTO_MESSAGES {
        if wallet_proto.contains(forbidden_message) {
            return Err(MdocBoundaryTestError::WalletRedefinesMdocEnvelope);
        }
    }

    Ok(())
}

#[test]
fn wallet_manifests_do_not_depend_on_mdoc_implementation_crates(
) -> Result<(), MdocBoundaryTestError> {
    let root = repository_root()?;
    let manifests = wallet_manifest_paths(&root)?;

    for manifest in manifests {
        let contents = read(manifest)?;
        if declares_mdoc_dependency(&contents) {
            return Err(MdocBoundaryTestError::WalletDependsOnMdocImplementation);
        }
    }

    Ok(())
}

// A Cargo source override changes where an existing indirect dependency is
// resolved; it does not introduce a Wallet dependency edge. Keep that distinct
// from dependency declarations, including renamed and target-specific entries.
fn declares_mdoc_dependency(contents: &str) -> bool {
    let mut source_override = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            source_override =
                line.starts_with("[patch.") || line == "[patch]" || line == "[replace]";
        }
        if !source_override
            && FORBIDDEN_WALLET_MANIFEST_DEPS
                .iter()
                .any(|name| line.contains(name))
        {
            return true;
        }
    }
    false
}

#[test]
fn source_overrides_do_not_authorize_direct_or_renamed_mdoc_dependencies() {
    assert!(!declares_mdoc_dependency(
        "[patch.crates-io]\nreallyme-mdoc = { path = \"../ssi/crates/envelopes/mdoc\" }\n"
    ));
    for source in [
        "[dependencies]\nreallyme-mdoc = \"0.6.1\"\n",
        "[dependencies]\nalias = { package = \"reallyme-mdoc\", version = \"0.6.1\" }\n",
        "[patch.crates-io]\nother = { path = \"../other\" }\n[target.'cfg(unix)'.dependencies]\nreallyme-mdoc = \"0.6.1\"\n",
    ] { assert!(declares_mdoc_dependency(source)); }
}

fn wallet_manifest_paths(root: &Path) -> Result<Vec<PathBuf>, MdocBoundaryTestError> {
    let mut manifests = vec![root.join("Cargo.toml"), root.join("conformance/Cargo.toml")];
    let crates_dir = root.join("crates");
    let entries = std::fs::read_dir(crates_dir).map_err(|_| MdocBoundaryTestError::Io)?;
    for entry in entries {
        let path = entry.map_err(|_| MdocBoundaryTestError::Io)?.path();
        let manifest = path.join("Cargo.toml");
        if manifest.exists() {
            manifests.push(manifest);
        }
    }
    Ok(manifests)
}

fn read(path: PathBuf) -> Result<String, MdocBoundaryTestError> {
    std::fs::read_to_string(path).map_err(|_| MdocBoundaryTestError::Io)
}

fn repository_root() -> Result<PathBuf, MdocBoundaryTestError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(MdocBoundaryTestError::InvalidRepositoryRoot)
}

#[derive(Debug, thiserror::Error)]
enum MdocBoundaryTestError {
    #[error("invalid_repository_root")]
    InvalidRepositoryRoot,
    #[error("io")]
    Io,
    #[error("missing_expected_contract")]
    MissingExpectedContract,
    #[error("wallet_redefines_mdoc_envelope")]
    WalletRedefinesMdocEnvelope,
    #[error("wallet_imports_mdoc_presentation")]
    WalletImportsMdocPresentation,
    #[error("wallet_depends_on_mdoc_implementation")]
    WalletDependsOnMdocImplementation,
}
