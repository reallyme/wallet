// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_disclosure_policy::{
    plan_satisfaction, DerivationInput, DerivationPlan, PredicateOperand, SatisfactionPlan,
    VpPolicy,
};
use reallyme_vp_core::DisclosureMode;

use super::consent_actions_for_satisfaction_plan;
use crate::ConsentErrorReason;
use reallyme_wallet_types::{
    ConsentActionKind, ConsentDerivationMode, ConsentPredicateOperand, NonEmptyIdentifier,
    WalletTypesError,
};

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

#[test]
fn renders_disclosure_plan_as_disclose_action() -> Result<(), TestError> {
    let policy = VpPolicy::default().require_claim("family_name", DisclosureMode::Reveal);
    let plan = plan_satisfaction(&policy)?;

    let actions = consent_actions_for_satisfaction_plan(&plan, None)?;

    assert!(matches!(
        actions.as_slice(),
        [action]
            if action.kind == ConsentActionKind::Disclose
                && action.derivation_id.is_none()
                && action.scope.attributes[0].as_str() == "family_name"
    ));
    Ok(())
}

#[test]
fn renders_explicit_derivation_plan_as_derive_action() -> Result<(), TestError> {
    let plan = SatisfactionPlan::Derive(DerivationPlan {
        inputs: vec![DerivationInput {
            claim_path: "age_over_18".to_owned(),
            mode: DisclosureMode::Reveal,
            operand: PredicateOperand::None,
        }],
    });
    let derivation_id = id("reallyme.pid.age_over_18.v1")?;

    let actions = consent_actions_for_satisfaction_plan(&plan, Some(&derivation_id))?;

    assert!(matches!(
        actions.as_slice(),
        [action]
            if action.kind == ConsentActionKind::Derive
                && action.derivation_id.is_some()
                && action.scope.attributes[0].as_str() == "age_over_18"
    ));
    Ok(())
}

#[test]
fn rejects_empty_disclosure_plan() {
    let result =
        consent_actions_for_satisfaction_plan(&SatisfactionPlan::Disclose(Vec::new()), None);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::EmptyRequestedScope
    ));
}

#[test]
fn rejects_derivation_without_protocol_selected_identifier() {
    let plan = SatisfactionPlan::Derive(DerivationPlan {
        inputs: vec![DerivationInput {
            claim_path: "age_over_18".to_owned(),
            mode: DisclosureMode::Gte,
            operand: PredicateOperand::Threshold(18),
        }],
    });

    let result = consent_actions_for_satisfaction_plan(&plan, None);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::InvalidSatisfactionPlan
    ));
}

#[test]
fn preserves_revealed_attribute_and_exact_predicate_in_one_plan() -> Result<(), TestError> {
    let plan = SatisfactionPlan::Derive(DerivationPlan {
        inputs: vec![
            DerivationInput {
                claim_path: "family_name".to_owned(),
                mode: DisclosureMode::Reveal,
                operand: PredicateOperand::None,
            },
            DerivationInput {
                claim_path: "birth_date".to_owned(),
                mode: DisclosureMode::Eq,
                operand: PredicateOperand::Value(b"2000-01-01".to_vec()),
            },
        ],
    });
    let actions = consent_actions_for_satisfaction_plan(&plan, Some(&id("predicate-proof")?))?;
    assert!(matches!(actions.as_slice(), [action]
        if action.kind == ConsentActionKind::Derive
            && action.derivation_inputs.len() == 2
            && action.derivation_inputs[0].mode == ConsentDerivationMode::Reveal
            && action.derivation_inputs[1].mode == ConsentDerivationMode::Eq
            && action.derivation_inputs[1].operand == ConsentPredicateOperand::Value(b"2000-01-01".to_vec())));
    Ok(())
}

#[test]
fn different_derivation_modes_remain_distinguishable() -> Result<(), TestError> {
    let reveal = SatisfactionPlan::Derive(DerivationPlan {
        inputs: vec![DerivationInput {
            claim_path: "age".to_owned(),
            mode: DisclosureMode::Reveal,
            operand: PredicateOperand::None,
        }],
    });
    let threshold = SatisfactionPlan::Derive(DerivationPlan {
        inputs: vec![DerivationInput {
            claim_path: "age".to_owned(),
            mode: DisclosureMode::Gte,
            operand: PredicateOperand::Threshold(18),
        }],
    });
    let derivation_id = id("age-proof")?;
    let reveal_actions = consent_actions_for_satisfaction_plan(&reveal, Some(&derivation_id))?;
    let threshold_actions =
        consent_actions_for_satisfaction_plan(&threshold, Some(&derivation_id))?;
    assert_ne!(reveal_actions, threshold_actions);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("consent")]
    Consent(#[from] crate::ConsentError),
    #[error("policy")]
    Policy(#[from] reallyme_disclosure_policy::VpPolicyError),
    #[error("wallet_types")]
    WalletTypes(#[from] WalletTypesError),
}
