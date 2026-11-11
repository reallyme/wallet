// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_disclosure_policy::{
    DerivationInput, DerivationPlan, PredicateOperand, RequiredClaim, SatisfactionPlan,
};
use reallyme_vp_core::DisclosureMode;
use reallyme_wallet_types::{
    AttributeName, ConsentActionKind, ConsentScope, NonEmptyIdentifier, UnixTimestamp,
    VerifierEntitlement, WalletTypesError,
};

use crate::{FlowError, FlowErrorReason, FlowResult};

fn attr(value: &str) -> Result<AttributeName, WalletTypesError> {
    AttributeName::new(value.to_owned())
}

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(value: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(value)
}

fn consent_request_from_plan_for_test(
    entitlement: &VerifierEntitlement,
    plan: &SatisfactionPlan,
    derivation_id: Option<&NonEmptyIdentifier>,
    now: UnixTimestamp,
) -> FlowResult<reallyme_wallet_types::ConsentRequest> {
    let actions =
        reallyme_wallet_consent::consent_actions_for_satisfaction_plan(plan, derivation_id)
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidPresentationSatisfaction))?;
    let requested_scope = super::requested_scope_for_actions(&actions)?;
    // Mirrors production preparation under the warn-and-allow-all policy.
    reallyme_wallet_consent::unregistered_requested_attributes(entitlement, &requested_scope, now)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidPresentationSatisfaction))?;
    let policy_decision = reallyme_wallet_types::DisclosurePolicyDecision::Allowed;
    Ok(reallyme_wallet_types::ConsentRequest {
        relying_party_id: entitlement.relying_party_id.clone(),
        requested_scope,
        policy_decision,
        actions,
        request_nonce: NonEmptyIdentifier::new("request-nonce-1".to_owned())
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidPresentationSatisfaction))?,
        request_digest: [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        created_at: now,
    })
}

fn entitlement(attribute: &str) -> Result<VerifierEntitlement, WalletTypesError> {
    Ok(VerifierEntitlement {
        relying_party_id: id("rp-1")?,
        authorized_scope: ConsentScope {
            attributes: vec![attr(attribute)?],
        },
        valid_until: timestamp(20)?,
    })
}

fn disclosure_plan(attribute: &str) -> SatisfactionPlan {
    SatisfactionPlan::Disclose(vec![RequiredClaim {
        claim_path: attribute.to_owned(),
        mode: DisclosureMode::Reveal,
        operand: PredicateOperand::None,
    }])
}

fn derivation_plan(attribute: &str) -> SatisfactionPlan {
    SatisfactionPlan::Derive(DerivationPlan {
        inputs: vec![DerivationInput {
            claim_path: attribute.to_owned(),
            mode: DisclosureMode::Gte,
            operand: PredicateOperand::Threshold(18),
        }],
    })
}

#[test]
fn satisfaction_plan_prepares_disclosure_consent() -> Result<(), TestError> {
    let plan = disclosure_plan("family_name");

    let request = consent_request_from_plan_for_test(
        &entitlement("family_name")?,
        &plan,
        None,
        timestamp(10)?,
    )?;

    assert!(matches!(
        request.actions.as_slice(),
        [action] if action.kind == ConsentActionKind::Disclose
            && action.scope.attributes[0].as_str() == "family_name"
    ));
    Ok(())
}

#[test]
fn satisfaction_plan_prepares_derivation_consent() -> Result<(), TestError> {
    let plan = derivation_plan("age_over_18");
    let derivation_id = id("reallyme.pid.age_over_18.v1")?;

    let request = consent_request_from_plan_for_test(
        &entitlement("age_over_18")?,
        &plan,
        Some(&derivation_id),
        timestamp(10)?,
    )?;

    assert!(matches!(
        request.actions.as_slice(),
        [action] if action.kind == ConsentActionKind::Derive
            && action.derivation_id.is_some()
            && action.scope.attributes[0].as_str() == "age_over_18"
    ));
    Ok(())
}

#[test]
fn satisfaction_plan_reports_unregistered_attribute() -> Result<(), TestError> {
    let plan = disclosure_plan("family_name");
    let actions = reallyme_wallet_consent::consent_actions_for_satisfaction_plan(&plan, None)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidPresentationSatisfaction))?;
    let requested_scope = super::requested_scope_for_actions(&actions)?;

    let unregistered = reallyme_wallet_consent::unregistered_requested_attributes(
        &entitlement("age_over_18")?,
        &requested_scope,
        timestamp(10)?,
    )
    .map_err(|_| FlowError::new(FlowErrorReason::InvalidPresentationSatisfaction))?;

    assert_eq!(unregistered, vec![attr("family_name")?]);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("flow")]
    Flow(#[from] FlowError),
    #[error("wallet_types")]
    WalletTypes(#[from] WalletTypesError),
}
