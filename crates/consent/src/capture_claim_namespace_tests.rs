// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use super::{
    capture_for_request, disclose_action, entitlement, prepare_consent_request, timestamp,
    FixedClock, PreparedConsentRequest, TestError,
};
use crate::{
    capture_prepared_consent, capture_receipt_consent, prepare_online_receipt_consent,
    ConsentCaptureStore, ConsentCaptureStoreError, ConsentCaptureStoreErrorReason, ConsentClaim,
    ConsentError, ConsentErrorReason, ConsentResult,
};
use reallyme_wallet_types::ConsentReceipt;

#[derive(Default)]
struct ReceiptCapableStore(BTreeSet<(String, String)>);

impl ConsentCaptureStore for ReceiptCapableStore {
    fn claim_capture(
        &mut self,
        claim: &ConsentClaim<'_>,
        _receipt: Option<&ConsentReceipt>,
    ) -> Result<(), ConsentCaptureStoreError> {
        if self.0.insert((
            claim.namespace.as_str().to_owned(),
            claim.request_nonce.as_str().to_owned(),
        )) {
            Ok(())
        } else {
            Err(ConsentCaptureStoreError::new(
                ConsentCaptureStoreErrorReason::AlreadyClaimed,
            ))
        }
    }
}

fn prepared() -> Result<PreparedConsentRequest, TestError> {
    let action = disclose_action()?;
    let mut prepared = prepare_consent_request(
        &entitlement()?,
        action.scope.clone(),
        vec![action],
        timestamp(10)?,
    )?;
    let client = reallyme_openid4vp_types::ClientIdentifier::parse("x509_san_dns:verifier.example")
        .map_err(|_| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
    prepared.claim_scope = Some(crate::bind_verified_request::derive_consent_claim_scope(
        &client,
    )?);
    Ok(prepared)
}

fn capture_form(
    prepared: PreparedConsentRequest,
    with_receipt: bool,
    store: &mut ReceiptCapableStore,
) -> ConsentResult<()> {
    let now = prepared.request().created_at;
    let capture = capture_for_request(&prepared, now);
    if with_receipt {
        let prepared = prepare_online_receipt_consent(prepared);
        let digest = *prepared.context_digest();
        capture_receipt_consent(prepared, capture, digest, None, &FixedClock(now), store)
            .map(|_| ())
    } else {
        capture_prepared_consent(prepared, capture, &FixedClock(now), store).map(|_| ())
    }
}

#[test]
fn online_capture_is_single_use_across_both_capture_forms() -> Result<(), TestError> {
    for receipt_first in [false, true] {
        let mut store = ReceiptCapableStore::default();
        capture_form(prepared()?, receipt_first, &mut store)?;
        assert!(matches!(
            capture_form(prepared()?, !receipt_first, &mut store),
            Err(error) if error.reason == ConsentErrorReason::CaptureAlreadyUsed
        ));
        assert_eq!(store.0.len(), 1);
    }
    Ok(())
}
