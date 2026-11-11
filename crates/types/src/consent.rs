// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consent and relying-party authorization DTOs.

use crate::{AttributeName, NonEmptyIdentifier, RelyingPartyId, UnixTimestamp};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed length of a consent request transcript digest.
pub const CONSENT_REQUEST_DIGEST_BYTES: usize = 32;

/// Disclosure scope requested by a relying party.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ConsentScope {
    /// Attribute names requested from the wallet inventory.
    pub attributes: Vec<AttributeName>,
}

/// Result of evaluating RP entitlement and disclosure policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum DisclosurePolicyDecision {
    /// Disclosure is allowed if the user consents.
    Allowed,
    /// Disclosure is denied before user consent is requested.
    Denied,
    /// Disclosure is allowed if the user consents after being warned that the
    /// request asks for attributes the relying party did not register.
    ///
    /// The capture must carry this decision, so the warning is part of the
    /// captured consent and of any receipt built from it.
    AllowedWithUnregisteredRequest,
}

/// Relying-party entitlement to request a scope.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct VerifierEntitlement {
    /// Relying party identifier from validated registration evidence.
    pub relying_party_id: RelyingPartyId,
    /// Attributes this relying party is entitled to request.
    pub authorized_scope: ConsentScope,
    /// Registration evidence expiry.
    pub valid_until: UnixTimestamp,
}

/// Consent action shown to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum ConsentActionKind {
    /// Reveal the listed attributes directly.
    Disclose,
    /// Prove a statement; individual inputs specify any direct disclosure.
    Derive,
    /// Ask the user to authorize a qualified electronic signature operation.
    QualifiedSignature,
    /// Ask the user to authorize a qualified electronic seal operation.
    QualifiedSeal,
}

/// The verifier's requested treatment of one input to a derived presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum ConsentDerivationMode {
    /// Keep the source attribute hidden.
    Hidden,
    /// Reveal the source attribute in addition to any predicates.
    Reveal,
    /// Prove equality to an exact value.
    Eq,
    /// Prove a numeric lower bound.
    Gte,
    /// Prove a numeric upper bound.
    Lte,
    /// Prove membership in an inclusive numeric range.
    Range,
    /// Prove membership in an exact set of values.
    MemberOfSet,
}

/// Exact public predicate material shown with a derivation input.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum ConsentPredicateOperand {
    /// Hidden and revealed attributes have no predicate operand.
    None,
    /// Exact value required by an equality predicate.
    Value(Vec<u8>),
    /// Numeric comparison threshold.
    Threshold(u64),
    /// Inclusive numeric range.
    Range {
        /// Inclusive minimum.
        min: u64,
        /// Inclusive maximum.
        max: u64,
    },
    /// Exact allowed value set.
    Set(Vec<Vec<u8>>),
}

impl core::fmt::Debug for ConsentPredicateOperand {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ConsentPredicateOperand([redacted])")
    }
}

/// One input that must be explained before the user approves a derived proof.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ConsentDerivationInput {
    /// Attribute affected by this disclosure or predicate.
    pub attribute: AttributeName,
    /// Whether this attribute is revealed or constrained by a predicate.
    pub mode: ConsentDerivationMode,
    /// Exact public operand, if the mode is a predicate.
    pub operand: ConsentPredicateOperand,
}

impl core::fmt::Debug for ConsentDerivationInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ConsentDerivationInput([redacted])")
    }
}

/// One disclosure or derivation option available for consent.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ConsentAction {
    /// Action kind.
    pub kind: ConsentActionKind,
    /// Attribute scope covered by this action.
    pub scope: ConsentScope,
    /// Optional stable derivation or circuit identifier for derived proofs.
    pub derivation_id: Option<NonEmptyIdentifier>,
    /// Per-attribute semantics of a derived proof, including direct reveals.
    pub derivation_inputs: Vec<ConsentDerivationInput>,
}

/// Prepared consent request for identity to render to the user.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ConsentRequest {
    /// Relying party receiving the disclosure or proof.
    pub relying_party_id: RelyingPartyId,
    /// Requested scope shown to the user.
    pub requested_scope: ConsentScope,
    /// Policy result before user interaction.
    pub policy_decision: DisclosurePolicyDecision,
    /// Available disclosure or derivation actions.
    pub actions: Vec<ConsentAction>,
    /// Verifier-provided nonce binding this consent to one request.
    pub request_nonce: NonEmptyIdentifier,
    /// Digest of the canonical presentation request transcript.
    pub request_digest: [u8; CONSENT_REQUEST_DIGEST_BYTES],
    /// Request creation time.
    pub created_at: UnixTimestamp,
}

/// User consent decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum ConsentDecision {
    /// User approved the disclosure.
    Approved,
    /// User rejected the disclosure.
    Rejected,
}

/// Captured consent record persisted for transaction-log evidence.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ConsentCapture {
    /// Relying party receiving the disclosure.
    pub relying_party_id: RelyingPartyId,
    /// Requested scope shown to the user.
    pub requested_scope: ConsentScope,
    /// Exact action selected by the user, preserving derive-vs-disclose semantics.
    pub selected_action: ConsentAction,
    /// Nonce copied from the prepared request.
    pub request_nonce: NonEmptyIdentifier,
    /// Canonical request digest copied from the prepared request.
    pub request_digest: [u8; CONSENT_REQUEST_DIGEST_BYTES],
    /// Policy result before user interaction.
    pub policy_decision: DisclosurePolicyDecision,
    /// User decision.
    pub user_decision: ConsentDecision,
    /// Capture time.
    pub captured_at: UnixTimestamp,
}

#[cfg(test)]
#[path = "consent_tests.rs"]
mod tests;
