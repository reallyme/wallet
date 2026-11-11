// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed failures at the Wallet-to-ZK integration boundary.

use thiserror::Error;

/// Result type for Wallet ZK integration operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Wallet ZK error with a stable, non-sensitive reason.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet ZK integration failed: {reason}")]
pub struct Error {
    /// Stable reason code.
    pub reason: ErrorReason,
}

impl Error {
    /// Construct an integration error from its stable reason.
    #[must_use]
    pub const fn new(reason: ErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable Wallet ZK failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ErrorReason {
    /// A derivation was requested without an injected prover.
    #[error("prover_unavailable")]
    ProverUnavailable,
    /// Requested public inputs do not authenticate the selected session.
    #[error("session_binding_invalid")]
    SessionBindingInvalid,
    /// The prover returned a proof under different requested metadata.
    #[error("proof_metadata_mismatch")]
    ProofMetadataMismatch,
    /// The injected prover rejected the request without exposing backend details.
    #[error("proof_failed")]
    ProofFailed,
    /// The exact circuit is not in the reviewed source registry.
    #[error("unsupported_circuit")]
    UnsupportedCircuit,
    /// The proof suite does not hide the witness and cannot back a presentation.
    #[error("unsupported_proof_suite")]
    UnsupportedProofSuite,
    /// The artifact identifier or linked credential set is invalid.
    #[error("invalid_artifact_identity")]
    InvalidArtifactIdentity,
    /// The artifact's scope or lifecycle is inconsistent with its kind.
    #[error("invalid_artifact_scope")]
    InvalidArtifactScope,
    /// An encrypted record does not authenticate the canonical descriptor.
    #[error("artifact_binding_mismatch")]
    ArtifactBindingMismatch,
    /// A stored artifact is outside its trusted validity window.
    #[error("artifact_expired")]
    ArtifactExpired,
    /// A protobuf artifact record is malformed or noncanonical.
    #[error("invalid_artifact_encoding")]
    InvalidArtifactEncoding,
}
