// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSI satisfaction plans remain subject to the Wallet Provider's ARF policy.

use reallyme_disclosure_policy::{
    plan_satisfaction, DerivationInput, DerivationPlan, PredicateOperand, SatisfactionPlan,
    VpPolicy, VpPolicyError,
};
use reallyme_vp_core::DisclosureMode;
use reallyme_wallet_types::{
    ConsentDecision, ConsentScope, DisclosurePolicyDecision, WalletTypesError,
};

use super::{
    attr, capture_for_request, capture_prepared_consent, entitlement, id, timestamp, FixedClock,
};
use crate::capture::{prepare_consent_request_from_entitlement, PreparedConsentRequest};
use crate::{
    consent_actions_for_satisfaction_plan, ConsentError, ConsentErrorReason,
    UnregisteredAttributePolicy,
};

fn mixed_plan() -> Result<SatisfactionPlan, VpPolicyError> {
    plan_satisfaction(
        &VpPolicy::default()
            .require_claim("age_over_18", DisclosureMode::Reveal)
            .require_claim("family_name", DisclosureMode::Reveal),
    )
}

fn prepare(
    plan: &SatisfactionPlan,
    policy: UnregisteredAttributePolicy,
) -> Result<PreparedConsentRequest, TestError> {
    let derivation = if matches!(plan, SatisfactionPlan::Derive(_)) {
        Some(id("selected-proof")?)
    } else {
        None
    };
    let actions = consent_actions_for_satisfaction_plan(plan, derivation.as_ref())?;
    let scope = actions
        .first()
        .ok_or_else(|| ConsentError::new(ConsentErrorReason::EmptyRequestedScope))?
        .scope
        .clone();
    Ok(prepare_consent_request_from_entitlement(
        &entitlement()?,
        scope,
        actions,
        id("ssi-plan-request")?,
        [7; 32],
        policy,
        timestamp(10)?,
    )?)
}

#[test]
fn registered_only_narrows_ssi_disclosure_but_preserves_the_warning() -> Result<(), TestError> {
    let prepared = prepare(&mixed_plan()?, UnregisteredAttributePolicy::RegisteredOnly)?;
    assert_eq!(prepared.unregistered_attributes(), &[attr("family_name")?]);
    assert_eq!(
        prepared.request().requested_scope.attributes,
        vec![attr("age_over_18")?]
    );
    assert_eq!(
        prepared.request().policy_decision,
        DisclosurePolicyDecision::AllowedWithUnregisteredRequest
    );
    let mut capture = capture_for_request(&prepared, timestamp(11)?);
    capture.policy_decision = prepared.request().policy_decision;
    let authorization = capture_prepared_consent(prepared, capture, &FixedClock(timestamp(11)?))?;
    let result = authorization.authorize_scope(ConsentScope {
        attributes: vec![attr("age_over_18")?, attr("family_name")?],
    });
    assert!(
        matches!(result, Err(error) if error.reason == ConsentErrorReason::FinalDisclosureOutOfScope)
    );
    Ok(())
}

#[test]
fn warn_and_allow_all_preserves_ssi_scope_without_substituting_for_holder_approval(
) -> Result<(), TestError> {
    let prepared = prepare(&mixed_plan()?, UnregisteredAttributePolicy::WarnAndAllowAll)?;
    assert_eq!(prepared.request().requested_scope.attributes.len(), 2);
    assert!(prepared
        .request()
        .requested_scope
        .attributes
        .contains(&attr("family_name")?));
    assert_eq!(prepared.unregistered_attributes(), &[attr("family_name")?]);
    assert_eq!(
        prepared.request().policy_decision,
        DisclosurePolicyDecision::AllowedWithUnregisteredRequest
    );
    let mut capture = capture_for_request(&prepared, timestamp(11)?);
    capture.policy_decision = prepared.request().policy_decision;
    capture.user_decision = ConsentDecision::Rejected;
    let result = capture_prepared_consent(prepared, capture, &FixedClock(timestamp(11)?));
    assert!(matches!(result, Err(error) if error.reason == ConsentErrorReason::UserRejected));
    Ok(())
}

#[test]
fn reject_request_refuses_an_otherwise_satisfiable_ssi_plan() -> Result<(), TestError> {
    let result = prepare(&mixed_plan()?, UnregisteredAttributePolicy::RejectRequest);
    assert!(
        matches!(result, Err(TestError::Consent(error)) if error.reason == ConsentErrorReason::AttributeNotAuthorized)
    );
    Ok(())
}

#[test]
fn registered_only_cannot_remove_a_hidden_input_from_an_ssi_proof() -> Result<(), TestError> {
    let plan = SatisfactionPlan::Derive(DerivationPlan {
        inputs: vec![
            DerivationInput {
                claim_path: "age_over_18".to_owned(),
                mode: DisclosureMode::Reveal,
                operand: PredicateOperand::None,
            },
            DerivationInput {
                claim_path: "family_name".to_owned(),
                mode: DisclosureMode::Hidden,
                operand: PredicateOperand::None,
            },
        ],
    });
    let result = prepare(&plan, UnregisteredAttributePolicy::RegisteredOnly);
    assert!(
        matches!(result, Err(TestError::Consent(error)) if error.reason == ConsentErrorReason::AttributeNotAuthorized)
    );
    Ok(())
}

#[test]
fn all_three_provider_policies_allow_a_fully_registered_ssi_request() -> Result<(), TestError> {
    let plan = plan_satisfaction(
        &VpPolicy::default().require_claim("age_over_18", DisclosureMode::Reveal),
    )?;
    for policy in [
        UnregisteredAttributePolicy::WarnAndAllowAll,
        UnregisteredAttributePolicy::RegisteredOnly,
        UnregisteredAttributePolicy::RejectRequest,
    ] {
        let prepared = prepare(&plan, policy)?;
        assert!(prepared.unregistered_attributes().is_empty());
        assert_eq!(
            prepared.request().policy_decision,
            DisclosurePolicyDecision::Allowed
        );
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("consent")]
    Consent(#[from] ConsentError),
    #[error("wallet_types")]
    WalletTypes(#[from] WalletTypesError),
    #[error("ssi_policy")]
    SsiPolicy(#[from] VpPolicyError),
}
