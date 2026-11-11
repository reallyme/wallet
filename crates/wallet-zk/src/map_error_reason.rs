// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Preserve the legacy wallet wire reasons at the optional ZK adapter boundary.

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

use crate::ErrorReason;

/// Map an optional ZK integration failure into the stable wallet reason.
#[must_use]
pub const fn map_zk_wallet_error_reason(reason: ErrorReason) -> pb::WalletErrorReason {
    match reason {
        ErrorReason::ProverUnavailable => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_ZK_PROVER_UNAVAILABLE
        }
        // A suite Wallet refuses to use is unsupported, not a failed proof.
        ErrorReason::UnsupportedProofSuite => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_UNSUPPORTED_ALGORITHM
        }
        ErrorReason::SessionBindingInvalid
        | ErrorReason::ProofMetadataMismatch
        | ErrorReason::ProofFailed
        | ErrorReason::UnsupportedCircuit
        | ErrorReason::InvalidArtifactIdentity
        | ErrorReason::InvalidArtifactScope
        | ErrorReason::ArtifactBindingMismatch
        | ErrorReason::ArtifactExpired
        | ErrorReason::InvalidArtifactEncoding => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_ZK_PROOF_FAILED
        }
    }
}

/// Map an optional ZK integration failure into the historical flow detail.
#[must_use]
pub const fn map_zk_flow_error_reason(reason: ErrorReason) -> pb::FlowErrorReason {
    match reason {
        ErrorReason::ProverUnavailable => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_ZK_PROVER_UNAVAILABLE
        }
        ErrorReason::SessionBindingInvalid
        | ErrorReason::ProofMetadataMismatch
        | ErrorReason::ProofFailed
        | ErrorReason::UnsupportedCircuit
        | ErrorReason::UnsupportedProofSuite
        | ErrorReason::InvalidArtifactIdentity
        | ErrorReason::InvalidArtifactScope
        | ErrorReason::ArtifactBindingMismatch
        | ErrorReason::ArtifactExpired
        | ErrorReason::InvalidArtifactEncoding => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_ZK_PROOF_FAILED
        }
    }
}

#[cfg(test)]
#[path = "map_error_reason_tests.rs"]
mod tests;
