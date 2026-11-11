// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate the permitted disclosure and derivation actions for consent.

use std::collections::BTreeSet;

use reallyme_wallet_types::{
    ConsentAction, ConsentActionKind, ConsentDerivationMode, ConsentPredicateOperand, ConsentScope,
};

use crate::{ConsentError, ConsentErrorReason, ConsentResult};

pub(crate) const MAX_CONSENT_ACTIONS: usize = 128;
pub(crate) const MAX_PREDICATE_BYTES: usize = 4_096;
pub(crate) const MAX_PREDICATE_SET_VALUES: usize = 32;

pub(crate) fn validate_actions(
    actions: &[ConsentAction],
    requested: &ConsentScope,
) -> ConsentResult<()> {
    if actions.is_empty() {
        return Err(ConsentError::new(ConsentErrorReason::MissingConsentAction));
    }
    if actions.len() > MAX_CONSENT_ACTIONS {
        return Err(ConsentError::new(ConsentErrorReason::ScopeTooLarge));
    }

    let requested_attributes = requested.attributes.iter().collect::<BTreeSet<_>>();
    if requested_attributes.len() != requested.attributes.len() {
        return Err(ConsentError::new(
            ConsentErrorReason::RequestBindingMismatch,
        ));
    }

    for action in actions {
        if action.scope.attributes.is_empty() {
            return Err(ConsentError::new(ConsentErrorReason::EmptyRequestedScope));
        }
        let action_attributes = action.scope.attributes.iter().collect::<BTreeSet<_>>();
        if action_attributes.len() != action.scope.attributes.len() {
            return Err(ConsentError::new(
                ConsentErrorReason::RequestBindingMismatch,
            ));
        }
        if action
            .scope
            .attributes
            .iter()
            .any(|attribute| !requested_attributes.contains(attribute))
        {
            return Err(ConsentError::new(
                ConsentErrorReason::AttributeNotAuthorized,
            ));
        }
        match action.kind {
            ConsentActionKind::Derive
                if action.derivation_id.is_none()
                    || action.derivation_inputs.len() != action.scope.attributes.len() =>
            {
                return Err(ConsentError::new(
                    ConsentErrorReason::DerivationIdentifierMissing,
                ));
            }
            ConsentActionKind::Disclose
            | ConsentActionKind::QualifiedSignature
            | ConsentActionKind::QualifiedSeal
                if action.derivation_id.is_some() || !action.derivation_inputs.is_empty() =>
            {
                return Err(ConsentError::new(
                    ConsentErrorReason::DisclosureDerivationIdentifierPresent,
                ));
            }
            ConsentActionKind::Disclose
            | ConsentActionKind::Derive
            | ConsentActionKind::QualifiedSignature
            | ConsentActionKind::QualifiedSeal => {}
        }
        if action.kind == ConsentActionKind::Derive {
            let mut input_attributes = BTreeSet::new();
            for input in &action.derivation_inputs {
                if !action_attributes.contains(&input.attribute)
                    || !input_attributes.insert(&input.attribute)
                    || !valid_predicate(input.mode, &input.operand)
                {
                    return Err(ConsentError::new(
                        ConsentErrorReason::InvalidSatisfactionPlan,
                    ));
                }
            }
        }
    }

    Ok(())
}

fn valid_predicate(mode: ConsentDerivationMode, operand: &ConsentPredicateOperand) -> bool {
    match (mode, operand) {
        (
            ConsentDerivationMode::Hidden | ConsentDerivationMode::Reveal,
            ConsentPredicateOperand::None,
        ) => true,
        (ConsentDerivationMode::Eq, ConsentPredicateOperand::Value(value)) => {
            !value.is_empty() && value.len() <= MAX_PREDICATE_BYTES
        }
        (
            ConsentDerivationMode::Gte | ConsentDerivationMode::Lte,
            ConsentPredicateOperand::Threshold(_),
        ) => true,
        (ConsentDerivationMode::Range, ConsentPredicateOperand::Range { min, max }) => min <= max,
        (ConsentDerivationMode::MemberOfSet, ConsentPredicateOperand::Set(values)) => {
            !values.is_empty()
                && values.len() <= MAX_PREDICATE_SET_VALUES
                && values
                    .iter()
                    .all(|value| !value.is_empty() && value.len() <= MAX_PREDICATE_BYTES)
        }
        _ => false,
    }
}
