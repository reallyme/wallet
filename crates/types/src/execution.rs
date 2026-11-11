// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable flow disposition and write-ahead side-effect records.
//!
//! Copies support compare-and-swap persistence; each copy zeroizes on drop and
//! cannot recreate the separate single-use effect capability.
use crate::{FlowKind, FlowSnapshotId, UnixTimestamp};
use zeroize::{Zeroize, ZeroizeOnDrop};
/// Maximum external effects reserved in one flow; exhaustion fails closed.
pub const MAX_FLOW_EFFECTS: usize = 32;
/// Maximum validated opaque protocol snapshot retained with the execution guard.
pub const MAX_EXECUTION_SNAPSHOT_BYTES: usize = 1_048_576;
/// Maximum canonical request bytes retained in one effect.
pub const MAX_FLOW_EFFECT_BYTES: usize = 1_048_576;
/// Aggregate payload budget for all retained effects in one flow.
pub const MAX_FLOW_EFFECT_TOTAL_BYTES: usize = 2_097_152;
/// Durable disposition. Terminal records must never be deleted to permit retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum FlowDisposition {
    /// New effects may be reserved subject to revision checks.
    Active,
    /// All expected effects completed.
    Completed,
    /// Cancelled before external submission.
    Cancelled,
    /// Known failure before external submission.
    Failed,
    /// Trusted deadline elapsed.
    Expired,
    /// A submission/commit was reserved and may have happened.
    DeliveryUnknown,
}
/// Purpose of a write-ahead reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum FlowEffectKind {
    /// Single-use holder authorization.
    Consent,
    /// Signing or once-only copy consumption.
    Signing,
    /// Network delivery of presentation or issuance request.
    Submission,
    /// Atomic credential/storage commit.
    StorageCommit,
}
/// Whether the host confirmed one reserved effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum FlowEffectState {
    /// Durable reservation must precede the effect. A restart cannot repeat it.
    Reserved,
    /// An authoritative successful result was durably recorded.
    Confirmed,
}
/// One exact effect identity and payload digest.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct FlowEffect {
    /// Exact canonical operation envelope, including target and payload binding.
    /// Persisted before I/O; never regenerated for an uncertain retry.
    pub request_bytes: Vec<u8>,
    /// Unique operation identity.
    pub id: [u8; 32],
    /// Digest of exact canonical bytes/intent; retries must not regenerate it.
    pub request_digest: [u8; 32],
    /// Type of effect.
    pub kind: FlowEffectKind,
    /// Durable state.
    pub state: FlowEffectState,
}
/// Atomic flow guard and opaque protocol-owned snapshot.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct FlowExecutionRecord {
    /// Stable flow identity.
    pub id: FlowSnapshotId,
    /// Protocol flow kind.
    pub kind: FlowKind,
    /// Digest of immutable launch/consent intent.
    pub intent_digest: [u8; 32],
    /// Current disposition.
    pub disposition: FlowDisposition,
    /// Reserved effects are retained after every terminal transition.
    pub effects: Vec<FlowEffect>,
    /// Validated protocol snapshot; the owning decoder must validate before use.
    pub snapshot: Vec<u8>,
    /// Trusted exclusive deadline.
    pub expires_at: UnixTimestamp,
    /// Trusted monotonic observation time.
    pub updated_at: UnixTimestamp,
}
