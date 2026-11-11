// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Evaluate relying-party attribute entitlements.

use std::collections::BTreeSet;

use reallyme_wallet_types::{
    AttributeName, ConsentScope, DisclosurePolicyDecision, UnixTimestamp, VerifierEntitlement,
};

use crate::{ConsentError, ConsentErrorReason, ConsentResult};

/// Maximum attributes accepted in one authorization decision.
pub const MAX_CONSENT_SCOPE_ATTRIBUTES: usize = 128;

/// Evaluate whether an entitlement covers a requested consent scope.
pub(crate) fn evaluate_entitlement(
    entitlement: &VerifierEntitlement,
    requested: &ConsentScope,
) -> ConsentResult<DisclosurePolicyDecision> {
    if entitlement.authorized_scope.attributes.len() > MAX_CONSENT_SCOPE_ATTRIBUTES
        || requested.attributes.len() > MAX_CONSENT_SCOPE_ATTRIBUTES
    {
        return Err(ConsentError::new(ConsentErrorReason::ScopeTooLarge));
    }
    let authorized = entitlement
        .authorized_scope
        .attributes
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    for requested_attribute in &requested.attributes {
        if !authorized.contains(requested_attribute) {
            return Err(ConsentError::new(
                ConsentErrorReason::AttributeNotAuthorized,
            ));
        }
    }

    Ok(DisclosurePolicyDecision::Allowed)
}

/// Evaluate whether an unexpired entitlement covers a requested scope.
///
/// This is a strict registration check: any requested attribute outside the
/// entitlement is refused. Consent preparation applies the Wallet Provider's
/// `UnregisteredAttributePolicy` instead, so use the prepare functions, not
/// this check, to decide whether a presentation may go ahead.
pub fn evaluate_entitlement_at(
    entitlement: &VerifierEntitlement,
    requested: &ConsentScope,
    now: UnixTimestamp,
) -> ConsentResult<DisclosurePolicyDecision> {
    // `valid_until` is exclusive everywhere consent checks it.
    if now >= entitlement.valid_until {
        return Err(ConsentError::new(ConsentErrorReason::EntitlementExpired));
    }
    if requested.attributes.is_empty() {
        return Err(ConsentError::new(ConsentErrorReason::EmptyRequestedScope));
    }

    evaluate_entitlement(entitlement, requested)
}

/// List requested attributes the relying party did not register.
///
/// ARF 3.0.0 EW-DM-44-027 (legacy RPRC_21) requires the Wallet Unit to warn
/// the user, while asking for approval, about requested attributes the
/// relying party did not register. What happens to those attributes is the
/// Wallet Provider's `UnregisteredAttributePolicy`. Expiry, empty scopes, and
/// size bounds fail closed. The result is sorted and duplicate-free.
pub fn unregistered_requested_attributes(
    entitlement: &VerifierEntitlement,
    requested: &ConsentScope,
    now: UnixTimestamp,
) -> ConsentResult<Vec<AttributeName>> {
    if now >= entitlement.valid_until {
        return Err(ConsentError::new(ConsentErrorReason::EntitlementExpired));
    }
    if requested.attributes.is_empty() {
        return Err(ConsentError::new(ConsentErrorReason::EmptyRequestedScope));
    }
    if entitlement.authorized_scope.attributes.len() > MAX_CONSENT_SCOPE_ATTRIBUTES
        || requested.attributes.len() > MAX_CONSENT_SCOPE_ATTRIBUTES
    {
        return Err(ConsentError::new(ConsentErrorReason::ScopeTooLarge));
    }
    let authorized = entitlement
        .authorized_scope
        .attributes
        .iter()
        .collect::<BTreeSet<_>>();
    Ok(requested
        .attributes
        .iter()
        .filter(|attribute| !authorized.contains(attribute))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .cloned()
        .collect())
}

#[cfg(test)]
#[path = "evaluate_tests.rs"]
mod tests;
