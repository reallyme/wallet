// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{map_zk_flow_error_reason, map_zk_wallet_error_reason, pb};
use crate::ErrorReason;

#[test]
fn every_zk_failure_has_a_stable_wire_reason() {
    assert_eq!(
        map_zk_wallet_error_reason(ErrorReason::ProverUnavailable),
        pb::WalletErrorReason::WALLET_ERROR_REASON_ZK_PROVER_UNAVAILABLE
    );
    assert_eq!(
        map_zk_flow_error_reason(ErrorReason::ProverUnavailable),
        pb::FlowErrorReason::FLOW_ERROR_REASON_ZK_PROVER_UNAVAILABLE
    );
    assert_eq!(
        map_zk_wallet_error_reason(ErrorReason::UnsupportedProofSuite),
        pb::WalletErrorReason::WALLET_ERROR_REASON_UNSUPPORTED_ALGORITHM
    );
    for reason in [
        ErrorReason::SessionBindingInvalid,
        ErrorReason::ProofMetadataMismatch,
        ErrorReason::ProofFailed,
        ErrorReason::UnsupportedCircuit,
        ErrorReason::InvalidArtifactIdentity,
        ErrorReason::InvalidArtifactScope,
        ErrorReason::ArtifactBindingMismatch,
        ErrorReason::ArtifactExpired,
        ErrorReason::InvalidArtifactEncoding,
    ] {
        assert_eq!(
            map_zk_wallet_error_reason(reason),
            pb::WalletErrorReason::WALLET_ERROR_REASON_ZK_PROOF_FAILED
        );
        assert_eq!(
            map_zk_flow_error_reason(reason),
            pb::FlowErrorReason::FLOW_ERROR_REASON_ZK_PROOF_FAILED
        );
    }
}
