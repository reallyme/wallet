// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resumable wallet flow snapshot records.

use crate::{FlowSnapshotId, UnixTimestamp};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wallet flow state machine kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum FlowKind {
    /// OpenID4VCI issuance.
    Issuance,
    /// OpenID4VP presentation.
    Presentation,
}

/// Version of the kind-specific protobuf stored in a flow snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum FlowStateSchemaVersion {
    /// Initial issuance and presentation snapshot payload contract.
    V1,
}

impl FlowStateSchemaVersion {
    /// Numeric protobuf value for the versioned state envelope.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::V1 => 1,
        }
    }
}

/// Proto-first resumable flow state envelope.
///
/// `Clone` supports versioned compare-and-swap storage. Each copy owns and
/// zeroizes its protobuf state bytes independently.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct FlowSnapshot {
    /// Stable snapshot identifier.
    pub id: FlowSnapshotId,
    /// Flow state machine kind used to select the decoder.
    pub kind: FlowKind,
    /// Buffa/protobuf encoded state owned by the selected flow.
    pub state: Vec<u8>,
    /// Schema version used to interpret `state` for the selected flow kind.
    pub state_schema_version: FlowStateSchemaVersion,
    /// Last update time used for resumption and retention policy.
    pub updated_at: UnixTimestamp,
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
