// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable context shown to and approved by the holder, without claim values.
//!
//! Receipt snapshots may be copied for atomic persistence; every owner zeroizes on
//! drop, and copying a receipt never creates an authorization capability.
use crate::{ConsentCapture, NonEmptyIdentifier, RelyingPartyId, UnixTimestamp};
use zeroize::ZeroizeOnDrop;

/// Maximum policy choices in a single receipt.
pub const MAX_CONSENT_POLICIES: usize = 16;
/// Retention terms whose semantics are authenticated by the host policy provider.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum ConsentRetention {
    /// The relying party commits to no retention.
    NoRetention,
    /// A concrete, approved retention deadline.
    Until(UnixTimestamp),
}
/// Explicit holder choice for one authenticated policy version.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ConsentPolicyChoice {
    /// Policy identity, resolved and rendered above Wallet.
    pub id: NonEmptyIdentifier,
    /// Exact policy version.
    pub version: NonEmptyIdentifier,
    /// Digest of the authenticated policy bytes.
    pub document_digest: [u8; 32],
    /// Mandatory terms cannot be declined.
    pub mandatory: bool,
    /// Exact choice shown to the holder.
    pub accepted: bool,
}
/// Exact asserted terms included in the holder's disclosure approval receipt.
///
/// Approval authorizes this disclosure; it does not establish the relying
/// party's authority to process the data. Policy interpretation belongs to
/// the injected policy verifier, independently of the holder's decision.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ConsentPolicyContext {
    /// Authenticated purpose identifier; display text remains above Wallet.
    pub purpose: NonEmptyIdentifier,
    /// Approved retention semantics.
    pub retention: ConsentRetention,
    /// Versioned choices in canonical identity order.
    pub policies: Vec<ConsentPolicyChoice>,
    /// Exact transaction assignment authenticated by the protocol owner.
    pub transaction_digest: [u8; 32],
}
/// Authenticated reader and session facts, never an ISO wire representation.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ReaderSessionBinding {
    /// Authenticated reader identity.
    pub reader_id: RelyingPartyId,
    /// Digest of the authenticated reader certificate.
    pub certificate_digest: [u8; 32],
    /// Digest supplied by the SSI-owned SessionTranscript verifier.
    pub session_digest: [u8; 32],
    /// Exact authenticated reader request digest.
    pub request_digest: [u8; 32],
    /// Evidence validity start.
    pub authenticated_at: UnixTimestamp,
    /// Evidence expiry (exclusive).
    pub valid_until: UnixTimestamp,
}
/// Durable single-use consent evidence; copies convey no authorization capability.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ConsentReceipt {
    /// Exact captured request, action, and holder decision.
    pub capture: ConsentCapture,
    /// Authenticated approved terms, if required by the selected profile.
    pub policy: Option<ConsentPolicyContext>,
    /// Reader/session binding for proximity requests.
    pub reader: Option<ReaderSessionBinding>,
}
