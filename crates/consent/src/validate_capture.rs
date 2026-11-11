// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate one approval against the authenticated preparation before any write.

use reallyme_wallet_types::ConsentCapture;

use super::{
    actions_match, capture_consent, scopes_match, PreparedConsentRequest, TrustedConsentClock,
};
use crate::{ConsentError, ConsentErrorReason, ConsentResult};

pub(crate) fn validate_prepared_capture(
    prepared: &PreparedConsentRequest,
    capture: ConsentCapture,
    clock: &dyn TrustedConsentClock,
) -> ConsentResult<ConsentCapture> {
    let now = clock.now();
    if now >= prepared.entitlement_valid_until {
        return Err(ConsentError::new(ConsentErrorReason::EntitlementExpired));
    }
    if prepared
        .request_expires_at
        .is_some_and(|deadline| now >= deadline)
    {
        return Err(ConsentError::new(ConsentErrorReason::RequestExpired));
    }
    if prepared
        .registration_freshness
        .as_ref()
        .is_some_and(|freshness| now < freshness.validated_at || now >= freshness.fresh_until)
    {
        return Err(ConsentError::new(
            ConsentErrorReason::RegistrationCertificateStale,
        ));
    }
    let request = prepared.request();
    if now < request.created_at || capture.captured_at != now {
        return Err(ConsentError::new(
            ConsentErrorReason::RequestBindingMismatch,
        ));
    }
    if capture.relying_party_id != request.relying_party_id {
        return Err(ConsentError::new(ConsentErrorReason::RelyingPartyMismatch));
    }
    if prepared
        .bound_relying_party_id
        .as_ref()
        .is_some_and(|bound_id| &capture.relying_party_id != bound_id)
    {
        return Err(ConsentError::new(ConsentErrorReason::ClientBindingMismatch));
    }
    if !scopes_match(&capture.requested_scope, &request.requested_scope) {
        return Err(ConsentError::new(
            ConsentErrorReason::AttributeNotAuthorized,
        ));
    }
    if capture.request_nonce != request.request_nonce
        || capture.request_digest != request.request_digest
        || !request
            .actions
            .iter()
            .any(|action| actions_match(action, &capture.selected_action))
    {
        return Err(ConsentError::new(
            ConsentErrorReason::RequestBindingMismatch,
        ));
    }
    if capture.policy_decision != request.policy_decision {
        return Err(ConsentError::new(ConsentErrorReason::PolicyDenied));
    }

    capture_consent(capture)
}
