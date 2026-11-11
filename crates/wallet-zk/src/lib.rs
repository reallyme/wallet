// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional zero-knowledge presentation derivation for ReallyMe Wallet.
//!
//! Wallet's core crates remain independent of ZK. Applications that require
//! derived presentations compose this crate with an injected prover.

#![forbid(unsafe_code)]

mod artifact;
mod error;
mod map_error_reason;
mod prove_presentation_derivation;

pub use artifact::{ZkArtifactDescriptor, ZkArtifactKind, ZkStoredArtifactRecord};
pub use error::{Error, ErrorReason, Result};
pub use map_error_reason::{map_zk_flow_error_reason, map_zk_wallet_error_reason};
pub use prove_presentation_derivation::{
    prove_presentation_derivation, PresentationDerivationContext,
};
