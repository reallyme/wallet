// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable single-use claim contract for Wallet consent capture.

use reallyme_wallet_types::{ConsentReceipt, NonEmptyIdentifier, RelyingPartyId, UnixTimestamp};
use thiserror::Error;

/// Fixed reasons returned by the injected durable consent-claim store.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConsentCaptureStoreErrorReason {
    /// The request binding has already been claimed.
    #[error("already_claimed")]
    AlreadyClaimed,
    /// The store could not make a durable claim.
    #[error("unavailable")]
    Unavailable,
    /// A receipt was supplied to a store that does not persist receipts.
    #[error("receipt_unsupported")]
    ReceiptUnsupported,
}

/// Typed failure from an atomic consent-claim attempt.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("consent capture store failed: {reason}")]
pub struct ConsentCaptureStoreError {
    /// Stable non-sensitive reason.
    pub reason: ConsentCaptureStoreErrorReason,
}

impl ConsentCaptureStoreError {
    /// Construct a fixed-reason store failure.
    #[must_use]
    pub const fn new(reason: ConsentCaptureStoreErrorReason) -> Self {
        Self { reason }
    }
}

/// One single-use consent claim, built by the consent crate.
#[derive(Clone, Copy)]
pub struct ConsentClaim<'a> {
    /// Namespace within which the nonce is single-use.
    ///
    /// For a verified OpenID4VP request this is derived from the request's
    /// `client_id`; otherwise it is the relying-party identifier. Plain and
    /// receipt captures of one request always carry the same namespace.
    pub namespace: &'a NonEmptyIdentifier,
    /// Relying party recorded in the captured consent.
    pub relying_party_id: &'a RelyingPartyId,
    /// Verifier nonce that the claim consumes.
    pub request_nonce: &'a NonEmptyIdentifier,
    /// Trusted time from which Wallet refuses every capture prepared against
    /// the same entitlement and registration check.
    ///
    /// Once the store's trusted clock reaches this time, the claim marker may
    /// be discarded. For a request without its own expiry, a later preparation
    /// against a freshly validated registration could reach the store again
    /// with the same nonce; that still needs a new user decision, but a store
    /// that must refuse it should keep the marker longer. A receipt stored with
    /// the claim follows its own retention policy.
    pub retain_until: UnixTimestamp,
}

/// Durable single-use boundary scoped to one Wallet Unit.
pub trait ConsentCaptureStore {
    /// Atomically claim the nonce before authorization escapes.
    ///
    /// Claims are keyed on `(namespace, request_nonce)` within one Wallet
    /// Unit. Reusing the nonce with a changed request digest must also return
    /// `AlreadyClaimed`, including after process restart, until
    /// `retain_until`. A failed write must leave no claim. Pruning must use
    /// trusted time, never a clock the user can set back.
    ///
    /// When a receipt is supplied, append it in the same transaction as the
    /// claim. Both forms use the same key. A store that does not persist
    /// receipts must return `ReceiptUnsupported` and leave no claim; it must
    /// never accept the claim and drop the receipt.
    fn claim_capture(
        &mut self,
        claim: &ConsentClaim<'_>,
        receipt: Option<&ConsentReceipt>,
    ) -> Result<(), ConsentCaptureStoreError>;
}
