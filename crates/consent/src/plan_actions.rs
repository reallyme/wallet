// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Convert identity disclosure-policy satisfaction plans into consent actions.

use reallyme_disclosure_policy::{
    DerivationInput, PredicateOperand, RequiredClaim, SatisfactionPlan,
};
use reallyme_vp_core::DisclosureMode;
use reallyme_wallet_types::{
    AttributeName, ConsentAction, ConsentActionKind, ConsentDerivationInput, ConsentDerivationMode,
    ConsentPredicateOperand, ConsentScope, NonEmptyIdentifier,
};

use crate::validate_actions::{MAX_PREDICATE_BYTES, MAX_PREDICATE_SET_VALUES};
use crate::{ConsentError, ConsentErrorReason, ConsentResult};

/// Build user-renderable wallet consent actions from an identity policy plan.
///
/// Identity decides whether disclosure or derivation can satisfy the verifier
/// request. Wallet-core converts that decision into typed consent options, but
/// does not inspect credential envelopes, construct witnesses, or call a prover.
pub fn consent_actions_for_satisfaction_plan(
    plan: &SatisfactionPlan,
    derivation_id: Option<&NonEmptyIdentifier>,
) -> ConsentResult<Vec<ConsentAction>> {
    match plan {
        SatisfactionPlan::Disclose(claims) => {
            if derivation_id.is_some() {
                return Err(ConsentError::new(
                    ConsentErrorReason::InvalidSatisfactionPlan,
                ));
            }
            Ok(vec![ConsentAction {
                kind: ConsentActionKind::Disclose,
                scope: scope_for_required_claims(claims)?,
                derivation_id: None,
                derivation_inputs: Vec::new(),
            }])
        }
        SatisfactionPlan::Derive(derivation) => {
            let selected_derivation = derivation_id
                .ok_or_else(|| ConsentError::new(ConsentErrorReason::InvalidSatisfactionPlan))?;
            Ok(vec![ConsentAction {
                kind: ConsentActionKind::Derive,
                scope: scope_for_derivation_inputs(derivation.inputs.as_slice())?,
                derivation_id: Some(selected_derivation.clone()),
                derivation_inputs: derivation
                    .inputs
                    .iter()
                    .map(derivation_input)
                    .collect::<ConsentResult<Vec<_>>>()?,
            }])
        }
        // SatisfactionPlan is owned by SSI and intentionally non-exhaustive.
        // Wallet must reject future plan kinds until their consent semantics
        // are reviewed rather than silently treating them as disclosure.
        _ => Err(ConsentError::new(
            ConsentErrorReason::InvalidSatisfactionPlan,
        )),
    }
}

fn derivation_input(input: &DerivationInput) -> ConsentResult<ConsentDerivationInput> {
    let mode = match input.mode {
        DisclosureMode::Hidden => ConsentDerivationMode::Hidden,
        DisclosureMode::Reveal => ConsentDerivationMode::Reveal,
        DisclosureMode::Eq => ConsentDerivationMode::Eq,
        DisclosureMode::Gte => ConsentDerivationMode::Gte,
        DisclosureMode::Lte => ConsentDerivationMode::Lte,
        DisclosureMode::Range => ConsentDerivationMode::Range,
        DisclosureMode::MemberOfSet => ConsentDerivationMode::MemberOfSet,
        _ => {
            return Err(ConsentError::new(
                ConsentErrorReason::InvalidSatisfactionPlan,
            ))
        }
    };
    let operand = match &input.operand {
        PredicateOperand::None => ConsentPredicateOperand::None,
        PredicateOperand::Value(value)
            if !value.is_empty() && value.len() <= MAX_PREDICATE_BYTES =>
        {
            ConsentPredicateOperand::Value(value.clone())
        }
        PredicateOperand::Threshold(value) => ConsentPredicateOperand::Threshold(*value),
        PredicateOperand::Range { min, max } if min <= max => ConsentPredicateOperand::Range {
            min: *min,
            max: *max,
        },
        PredicateOperand::Set(values)
            if !values.is_empty()
                && values.len() <= MAX_PREDICATE_SET_VALUES
                && values
                    .iter()
                    .all(|value| !value.is_empty() && value.len() <= MAX_PREDICATE_BYTES) =>
        {
            ConsentPredicateOperand::Set(values.clone())
        }
        _ => {
            return Err(ConsentError::new(
                ConsentErrorReason::InvalidSatisfactionPlan,
            ))
        }
    };
    let matching = matches!(
        (mode, &operand),
        (
            ConsentDerivationMode::Hidden | ConsentDerivationMode::Reveal,
            ConsentPredicateOperand::None
        ) | (ConsentDerivationMode::Eq, ConsentPredicateOperand::Value(_))
            | (
                ConsentDerivationMode::Gte | ConsentDerivationMode::Lte,
                ConsentPredicateOperand::Threshold(_)
            )
            | (
                ConsentDerivationMode::Range,
                ConsentPredicateOperand::Range { .. }
            )
            | (
                ConsentDerivationMode::MemberOfSet,
                ConsentPredicateOperand::Set(_)
            )
    );
    if !matching {
        return Err(ConsentError::new(
            ConsentErrorReason::InvalidSatisfactionPlan,
        ));
    }
    Ok(ConsentDerivationInput {
        attribute: attribute_name(input.claim_path.as_str())?,
        mode,
        operand,
    })
}

fn scope_for_required_claims(claims: &[RequiredClaim]) -> ConsentResult<ConsentScope> {
    if claims.is_empty() {
        return Err(ConsentError::new(ConsentErrorReason::EmptyRequestedScope));
    }
    if claims.len() > crate::MAX_CONSENT_SCOPE_ATTRIBUTES {
        return Err(ConsentError::new(ConsentErrorReason::ScopeTooLarge));
    }

    let mut attributes = Vec::with_capacity(claims.len());
    for claim in claims {
        attributes.push(attribute_name(claim.claim_path.as_str())?);
    }

    Ok(ConsentScope { attributes })
}

fn scope_for_derivation_inputs(inputs: &[DerivationInput]) -> ConsentResult<ConsentScope> {
    if inputs.is_empty() {
        return Err(ConsentError::new(
            ConsentErrorReason::InvalidSatisfactionPlan,
        ));
    }
    if inputs.len() > crate::MAX_CONSENT_SCOPE_ATTRIBUTES {
        return Err(ConsentError::new(ConsentErrorReason::ScopeTooLarge));
    }

    let mut attributes = Vec::with_capacity(inputs.len());
    for input in inputs {
        attributes.push(attribute_name(input.claim_path.as_str())?);
    }

    Ok(ConsentScope { attributes })
}

fn attribute_name(value: &str) -> ConsentResult<AttributeName> {
    AttributeName::new(value.to_owned())
        .map_err(|_| ConsentError::new(ConsentErrorReason::InvalidSatisfactionPlan))
}

#[cfg(test)]
#[path = "plan_actions_tests.rs"]
mod tests;
