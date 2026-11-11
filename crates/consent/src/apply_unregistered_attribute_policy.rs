// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Apply the Wallet Provider's policy for attributes a relying party did not register.
//!
//! ARF 3.0.0 requirement EW-DM-44-027 (legacy RPRC_21) requires the Wallet
//! Unit to warn the User when a request asks for attributes outside the
//! registration certificate, and leaves the Wallet Provider to decide, from
//! its risk analysis, which of three outcomes applies.

use std::collections::BTreeSet;

use reallyme_wallet_types::{AttributeName, ConsentAction, ConsentScope};

use crate::{ConsentError, ConsentErrorReason, ConsentResult};

/// Wallet Provider decision for requested attributes that are not registered.
///
/// In every mode the unregistered attributes stay available through
/// `unregistered_attributes()` so the User can be warned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnregisteredAttributePolicy {
    /// Let the User approve or reject every requested attribute, including
    /// the unregistered ones, after the warning.
    WarnAndAllowAll,
    /// Let the User approve or reject only the registered attributes. The
    /// unregistered ones are removed from the request before consent.
    RegisteredOnly,
    /// Refuse the whole presentation when any requested attribute is not
    /// registered.
    RejectRequest,
}

/// Apply `policy` to the request scope and actions.
///
/// Under `RegisteredOnly`, an action that would be left with no attributes is
/// refused rather than silently dropped, because removing an action changes
/// what the User is asked to approve. A derived-proof action that covers an
/// unregistered attribute is refused too: its derivation inputs describe the
/// whole proof and cannot be narrowed attribute by attribute.
pub(crate) fn apply_unregistered_attribute_policy(
    policy: UnregisteredAttributePolicy,
    unregistered: &[AttributeName],
    requested_scope: &mut ConsentScope,
    actions: &mut [ConsentAction],
) -> ConsentResult<()> {
    if unregistered.is_empty() {
        return Ok(());
    }
    match policy {
        UnregisteredAttributePolicy::WarnAndAllowAll => Ok(()),
        UnregisteredAttributePolicy::RejectRequest => Err(ConsentError::new(
            ConsentErrorReason::AttributeNotAuthorized,
        )),
        UnregisteredAttributePolicy::RegisteredOnly => {
            // Narrowing must not hide a malformed request: refuse duplicate
            // attributes here, before removal could collapse them.
            let has_duplicates = |scope: &ConsentScope| {
                scope.attributes.iter().collect::<BTreeSet<_>>().len() != scope.attributes.len()
            };
            if has_duplicates(requested_scope)
                || actions.iter().any(|action| has_duplicates(&action.scope))
            {
                return Err(ConsentError::new(
                    ConsentErrorReason::RequestBindingMismatch,
                ));
            }
            let unregistered = unregistered.iter().collect::<BTreeSet<_>>();
            let narrows_derived_proof = actions.iter().any(|action| {
                (action.derivation_id.is_some() || !action.derivation_inputs.is_empty())
                    && action
                        .scope
                        .attributes
                        .iter()
                        .any(|attribute| unregistered.contains(attribute))
            });
            if narrows_derived_proof {
                return Err(ConsentError::new(
                    ConsentErrorReason::AttributeNotAuthorized,
                ));
            }
            requested_scope
                .attributes
                .retain(|attribute| !unregistered.contains(attribute));
            for action in actions.iter_mut() {
                action
                    .scope
                    .attributes
                    .retain(|attribute| !unregistered.contains(attribute));
            }
            if requested_scope.attributes.is_empty()
                || actions
                    .iter()
                    .any(|action| action.scope.attributes.is_empty())
            {
                return Err(ConsentError::new(
                    ConsentErrorReason::AttributeNotAuthorized,
                ));
            }
            Ok(())
        }
    }
}
