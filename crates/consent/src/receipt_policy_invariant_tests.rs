// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holder approval binds the asserted terms; it does not establish processing authority.

use super::{capture, context, prepared, scope, time, Clock, Policy, Store, TestError};
use crate::{bind_receipt_policy, capture_receipt_consent, ConsentErrorReason};
use reallyme_wallet_types::{ConsentPolicyContext, ConsentRetention, NonEmptyIdentifier};

#[derive(Clone, Copy, Debug)]
enum ChangedTerm {
    Purpose,
    Retention,
    PolicyId,
    Version,
    Document,
    Mandatory,
    OptionalChoice,
    Transaction,
}

const CHANGED_TERMS: [ChangedTerm; 8] = [
    ChangedTerm::Purpose,
    ChangedTerm::Retention,
    ChangedTerm::PolicyId,
    ChangedTerm::Version,
    ChangedTerm::Document,
    ChangedTerm::Mandatory,
    ChangedTerm::OptionalChoice,
    ChangedTerm::Transaction,
];

#[test]
fn authenticated_policy_never_substitutes_for_holder_approval() -> Result<(), TestError> {
    let prepared = bind_receipt_policy(prepared()?, context()?, &Policy(true), time(20)?)?;
    let mut rejected = capture(&prepared);
    rejected.user_decision = reallyme_wallet_types::ConsentDecision::Rejected;
    let digest = *prepared.context_digest();
    let reader = prepared.reader().cloned();
    let mut store = Store::default();
    let result = capture_receipt_consent(
        prepared,
        rejected,
        digest,
        reader.as_ref(),
        &Clock(time(20)?),
        &mut store,
    );
    assert!(matches!(result, Err(e) if e.reason == ConsentErrorReason::UserRejected));
    assert!(store.claims.is_empty());
    assert!(store.receipts.is_empty());
    Ok(())
}

fn changed_context(term: ChangedTerm) -> Result<ConsentPolicyContext, TestError> {
    let mut value = context()?;
    match term {
        ChangedTerm::Purpose => value.purpose = NonEmptyIdentifier::new("another-purpose".into())?,
        ChangedTerm::Retention => value.retention = ConsentRetention::Until(time(80)?),
        ChangedTerm::PolicyId => {
            value.policies[0].id = NonEmptyIdentifier::new("other-terms".into())?
        }
        ChangedTerm::Version => value.policies[0].version = NonEmptyIdentifier::new("2".into())?,
        ChangedTerm::Document => value.policies[0].document_digest = [0x91; 32],
        ChangedTerm::Mandatory => value.policies[0].mandatory = false,
        ChangedTerm::OptionalChoice => {
            value.policies[0].mandatory = false;
            value.policies[0].accepted = false;
        }
        ChangedTerm::Transaction => value.transaction_digest = [0x92; 32],
    }
    Ok(value)
}

#[test]
fn approval_of_displayed_terms_cannot_capture_a_different_policy_context() -> Result<(), TestError>
{
    let displayed = bind_receipt_policy(prepared()?, context()?, &Policy(true), time(20)?)?;
    assert!(displayed.policy() == Some(&context()?));
    let approved_digest = *displayed.context_digest();

    for term in CHANGED_TERMS {
        let replacement = bind_receipt_policy(
            prepared()?,
            changed_context(term)?,
            &Policy(true),
            time(20)?,
        )?;
        let decision = capture(&replacement);
        let reader = replacement.reader().cloned();
        let mut store = Store::default();
        let result = capture_receipt_consent(
            replacement,
            decision,
            approved_digest,
            reader.as_ref(),
            &Clock(time(20)?),
            &mut store,
        );
        assert!(
            matches!(result, Err(e) if e.reason == ConsentErrorReason::PolicyContextMismatch),
            "{term:?}"
        );
        assert!(store.claims.is_empty(), "{term:?}");
        assert!(store.receipts.is_empty(), "{term:?}");
    }
    Ok(())
}

#[test]
fn changed_terms_after_capture_cannot_reuse_approval_or_rewrite_the_receipt(
) -> Result<(), TestError> {
    for term in CHANGED_TERMS {
        let prepared = bind_receipt_policy(prepared()?, context()?, &Policy(true), time(20)?)?;
        let decision = capture(&prepared);
        let reader = prepared.reader().cloned();
        let digest = *prepared.context_digest();
        let mut store = Store::default();
        let authorization = capture_receipt_consent(
            prepared,
            decision,
            digest,
            reader.as_ref(),
            &Clock(time(20)?),
            &mut store,
        )?;
        assert!(authorization.receipt().policy.as_ref() == Some(&context()?));
        let changed = bind_receipt_policy(
            super::prepared()?,
            changed_context(term)?,
            &Policy(true),
            time(20)?,
        )?;
        let result = authorization.authorize_final_disclosure(
            None,
            scope()?,
            *changed.context_digest(),
            &Clock(time(21)?),
        );
        assert!(
            matches!(result, Err(e) if e.reason == ConsentErrorReason::PolicyContextMismatch),
            "{term:?}"
        );
        assert_eq!(store.claims.len(), 1);
        assert_eq!(store.receipts.len(), 1);
        assert!(store.receipts[0].policy.as_ref() == Some(&context()?));
    }
    Ok(())
}
