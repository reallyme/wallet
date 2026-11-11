// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consent preparation for presentation satisfaction plans.

use reallyme_disclosure_policy::SatisfactionPlan;
use reallyme_openid4vp_wallet::VerifiedWalletRequest;
use reallyme_wallet_consent::{
    consent_actions_for_satisfaction_plan, prepare_consent_request, PreparedConsentRequest,
    RegisteredVerifierEntitlement, UnregisteredAttributePolicy,
};
use reallyme_wallet_types::{
    AttributeName, ConsentAction, ConsentScope, NonEmptyIdentifier, UnixTimestamp,
};
use std::collections::BTreeSet;

use crate::{FlowError, FlowErrorReason, FlowResult};

/// Prepare presentation consent from an identity disclosure-policy plan.
///
/// DCQL matching and identity policy decide what can satisfy a request. This
/// helper turns that result into a wallet consent request. The protocol format
/// layer supplies the selected derivation identifier, keeping proof-system and
/// circuit selection outside shared disclosure policy. The consent nonce and
/// request digest are derived from `verified_request` by the consent crate.
/// `unregistered_policy` is the Wallet Provider's decision for requested
/// attributes the relying party did not register.
pub fn prepare_presentation_consent_from_satisfaction_plan(
    entitlement: &RegisteredVerifierEntitlement,
    verified_request: &VerifiedWalletRequest,
    plan: &SatisfactionPlan,
    derivation_id: Option<&NonEmptyIdentifier>,
    unregistered_policy: UnregisteredAttributePolicy,
    now: UnixTimestamp,
) -> FlowResult<PreparedConsentRequest> {
    let actions = consent_actions_for_satisfaction_plan(plan, derivation_id)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidPresentationSatisfaction))?;
    let requested_scope = requested_scope_for_actions(actions.as_slice())?;

    prepare_consent_request(
        entitlement,
        verified_request,
        requested_scope,
        actions,
        unregistered_policy,
        now,
    )
    .map_err(|_| FlowError::new(FlowErrorReason::InvalidPresentationSatisfaction))
}

fn requested_scope_for_actions(actions: &[ConsentAction]) -> FlowResult<ConsentScope> {
    let mut attributes: Vec<AttributeName> = Vec::new();
    let mut seen = BTreeSet::new();
    for action in actions {
        for attribute in &action.scope.attributes {
            if seen.insert(attribute.clone()) {
                attributes.push(attribute.clone());
            }
        }
    }

    if attributes.is_empty() {
        return Err(FlowError::new(
            FlowErrorReason::InvalidPresentationSatisfaction,
        ));
    }

    Ok(ConsentScope { attributes })
}

#[cfg(test)]
#[path = "prepare_presentation_consent_tests.rs"]
mod tests;
