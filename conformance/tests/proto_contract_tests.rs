// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protobuf ownership boundary checks.

use std::path::{Path, PathBuf};

const REQUIRED_IMPORTS: &[&str] = &[
    "import \"reallyme/openid4vp/v1/openid4vp.proto\";",
    "import \"reallyme/crypto/v1/crypto.proto\";",
    "import \"reallyme/openid4vci/v1/openid4vci.proto\";",
];

const FORBIDDEN_LOCAL_DEFINITIONS: &[&str] = &["enum CredentialFormat", "enum SigningAlgorithm"];

const REMOVED_LEGACY_MESSAGE_NAMES: &[&str] = &[
    "QeaaCompliance",
    "QtspInfo",
    "QeaaPolicies",
    "IssuerCredential",
    "KeyManagement",
    "IdentityProofing",
    "AuditInfo",
    "RevocationPolicy",
    "IdentityError",
    "WalletCredentialStoreRequest",
    "WalletCredentialStoreResult",
    "WalletCredentialListRequest",
    "WalletCredentialListResult",
    "WalletArtifact",
    "WalletCard",
    "BatchPool",
];

#[test]
fn wallet_proto_imports_sibling_contracts_instead_of_redeclaring_them(
) -> Result<(), ProtoContractTestError> {
    let root = repository_root()?;
    let document =
        std::fs::read_to_string(root.join("crates/proto/proto/reallyme/wallet/v1/wallet.proto"))
            .map_err(|_| ProtoContractTestError::Io)?;

    for required_import in REQUIRED_IMPORTS {
        if !document.contains(required_import) {
            return Err(ProtoContractTestError::MissingImport);
        }
    }

    for forbidden_definition in FORBIDDEN_LOCAL_DEFINITIONS {
        if document.contains(forbidden_definition) {
            return Err(ProtoContractTestError::DuplicateSiblingContract);
        }
    }

    if !document.contains("reallyme.openid4vci.v1.CredentialFormat format = 3;") {
        return Err(ProtoContractTestError::MissingSiblingTypeUsage);
    }
    if !document.contains("reallyme.openid4vp.v1.AuthorizationRequest authorization_request = 1;") {
        return Err(ProtoContractTestError::MissingSiblingTypeUsage);
    }
    if !document.contains("reallyme.crypto.v1.SignatureAlgorithm algorithm = 2;") {
        return Err(ProtoContractTestError::MissingSiblingTypeUsage);
    }
    if !document.contains("reallyme.crypto.v1.AeadAlgorithm encryption_algorithm = 5;") {
        return Err(ProtoContractTestError::MissingSiblingTypeUsage);
    }
    Ok(())
}

#[test]
fn legacy_wallet_messages_are_absent_from_owned_and_canonical_contracts(
) -> Result<(), ProtoContractTestError> {
    let root = repository_root()?;
    let wallet = read_proto(&root, "crates/proto/proto/reallyme/wallet/v1/wallet.proto")?;
    let errors = read_proto(&root, "crates/proto/proto/reallyme/wallet/v1/errors.proto")?;

    for path in [
        "crates/proto/proto/reallyme/wallet/v1/wallet.proto",
        "crates/proto/proto/reallyme/wallet/v1/errors.proto",
        "crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto",
        "crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto",
        "crates/proto/proto/reallyme/wallet/v1/wallet_service.proto",
    ] {
        let schema = read_proto(&root, path)?;
        for legacy_name in REMOVED_LEGACY_MESSAGE_NAMES {
            if schema.contains(legacy_name) {
                return Err(ProtoContractTestError::LegacySchemaLeak);
            }
        }
    }

    if !wallet.contains("reserved 3;")
        || !wallet.contains("reserved \"algorithm\";")
        || errors.contains("message IdentityError")
    {
        return Err(ProtoContractTestError::LegacySchemaLeak);
    }

    Ok(())
}

#[test]
fn wallet_service_exposes_only_the_canonical_operation() -> Result<(), ProtoContractTestError> {
    let root = repository_root()?;
    let service = read_proto(
        &root,
        "crates/proto/proto/reallyme/wallet/v1/wallet_service.proto",
    )?;
    let rpc_count = service
        .lines()
        .filter(|line| line.trim().starts_with("rpc "))
        .count();

    if rpc_count != 1
        || !service.contains(
            "rpc WalletOperation(WalletOperationRequest) returns (WalletOperationResponse);",
        )
    {
        return Err(ProtoContractTestError::LegacySchemaLeak);
    }

    Ok(())
}

#[test]
fn foreign_service_snapshots_are_absent() -> Result<(), ProtoContractTestError> {
    let root = repository_root()?;
    for path in [
        "crates/proto/proto/reallyme/openid4vci/v1/openid4vci_service.proto",
        "crates/proto/proto/reallyme/openid4vp/v1/openid4vp_service.proto",
    ] {
        if root.join(path).exists() {
            return Err(ProtoContractTestError::ForeignServiceSnapshot);
        }
    }

    Ok(())
}

fn read_proto(root: &Path, path: &str) -> Result<String, ProtoContractTestError> {
    std::fs::read_to_string(root.join(path)).map_err(|_| ProtoContractTestError::Io)
}

fn repository_root() -> Result<PathBuf, ProtoContractTestError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or(ProtoContractTestError::InvalidRepositoryRoot)
}

#[derive(Debug, thiserror::Error)]
enum ProtoContractTestError {
    #[error("invalid_repository_root")]
    InvalidRepositoryRoot,
    #[error("io")]
    Io,
    #[error("missing_import")]
    MissingImport,
    #[error("duplicate_sibling_contract")]
    DuplicateSiblingContract,
    #[error("missing_sibling_type_usage")]
    MissingSiblingTypeUsage,
    #[error("legacy_schema_leak")]
    LegacySchemaLeak,
    #[error("foreign_service_snapshot")]
    ForeignServiceSnapshot,
}
