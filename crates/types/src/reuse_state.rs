// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, durable credential allocation records. Clones are independent CAS snapshots.
use crate::{
    CredentialRecordId, CredentialReusePolicySelection, NonEmptyIdentifier, UnixTimestamp,
};
use zeroize::ZeroizeOnDrop;

/// Maximum independently issued instances in one reuse cohort.
pub const MAX_REUSE_INSTANCES: usize = 128;
/// Durable attempt budget; reaching it requires retiring the cohort, never forgetting claims.
pub const MAX_REUSE_CLAIMS: usize = 512;

/// Authenticated inventory instance attached to one configuration and cohort.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ReuseInstance {
    /// Inventory identity; it must not be reused by another cohort.
    pub credential_id: CredentialRecordId,
    /// Authenticated validity start.
    pub valid_from: UnixTimestamp,
    /// Authenticated validity end (exclusive).
    pub valid_until: UnixTimestamp,
    /// Revoked, suspended, deleted, or replaced instances cannot be selected.
    pub retired: bool,
    /// Durable number of committed uses.
    pub uses: u64,
    /// Privacy-preserving, wallet-scoped relying-party binding.
    pub party_binding: Option<[u8; 32]>,
}
/// Exact attempt binding retained before signing or transmission.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ReuseClaim {
    /// Host-generated unpredictable operation identity.
    pub operation_id: [u8; 32],
    /// Digest of the exact consent, request, and session intent.
    pub request_digest: [u8; 32],
    /// Party binding used for this attempt.
    pub party_binding: [u8; 32],
    /// Selected credential identity.
    pub credential_id: CredentialRecordId,
    /// Trusted commit time.
    pub committed_at: UnixTimestamp,
}
/// Persisted replenishment intent. Issuer calls remain above Wallet.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ReplenishmentIntent {
    /// Stable retry identity.
    pub operation_id: [u8; 32],
    /// Time the threshold was observed.
    pub requested_at: UnixTimestamp,
    /// Fulfillment is a durable terminal acknowledgement, never a counter reset.
    pub fulfilled: bool,
}
/// Complete atomic reuse aggregate; old cohorts remain tombstoned after retirement.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct CredentialReuseState {
    /// Wallet-scoped immutable cohort identity.
    pub id: NonEmptyIdentifier,
    /// Issuer-selected, metadata-validated configuration policy.
    pub policy: CredentialReusePolicySelection,
    /// Independently issued instances in stable rotation order.
    pub instances: Vec<ReuseInstance>,
    /// Next rotation offset.
    pub next_index: u32,
    /// Claims are never evicted while the cohort can be addressed.
    pub claims: Vec<ReuseClaim>,
    /// At most one replenishment intent per cohort.
    pub replenishment: Option<ReplenishmentIntent>,
    /// Retirement prevents all future uses, including after replenishment.
    pub retired: bool,
    /// Trusted high-water mark prevents clock rollback.
    pub updated_at: UnixTimestamp,
}
