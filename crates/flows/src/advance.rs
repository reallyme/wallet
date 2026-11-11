// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! State transition helpers for wallet flows.

use crate::state::PresentationStep;
use crate::{FlowError, FlowErrorReason, FlowResult, IssuanceState, PresentationState};
use reallyme_openid4vp_wallet::VerifiedWalletRequest;
use reallyme_wallet_consent::{ConsentErrorReason, TrustedConsentClock};
use reallyme_wallet_types::ConsentScope;

/// Advance issuance from offer received to consent captured.
pub fn capture_issuance_consent(state: IssuanceState) -> FlowResult<IssuanceState> {
    match state {
        IssuanceState::OfferReceived => Ok(IssuanceState::ConsentCaptured),
        IssuanceState::ConsentCaptured
        | IssuanceState::Authorized
        | IssuanceState::TokenExchanged
        | IssuanceState::Deferred
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

/// Advance presentation from request received to DCQL matched.
pub fn mark_presentation_matched(state: PresentationState) -> FlowResult<PresentationState> {
    match state.0 {
        PresentationStep::RequestReceived => Ok(PresentationState(PresentationStep::Matched)),
        PresentationStep::Matched
        | PresentationStep::ConsentCaptured { .. }
        | PresentationStep::ResponseReady { .. }
        | PresentationStep::Logged { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

/// Authorize the actual response attributes against the captured user decision.
pub fn authorize_presentation_response(
    state: PresentationState,
    request: &VerifiedWalletRequest,
    disclosed_scope: ConsentScope,
    clock: &dyn TrustedConsentClock,
) -> FlowResult<PresentationState> {
    match state.0 {
        PresentationStep::ConsentCaptured { consent } => consent
            .authorize_final_disclosure(request, disclosed_scope, clock)
            .map(|authorization| {
                PresentationState(PresentationStep::ResponseReady { authorization })
            })
            .map_err(|error| {
                FlowError::new(match error.reason {
                    ConsentErrorReason::EntitlementExpired | ConsentErrorReason::RequestExpired => {
                        FlowErrorReason::PresentationConsentExpired
                    }
                    ConsentErrorReason::RequestBindingMismatch => {
                        FlowErrorReason::PresentationRequestMismatch
                    }
                    _ => FlowErrorReason::InvalidPresentationSatisfaction,
                })
            }),
        PresentationStep::RequestReceived
        | PresentationStep::Matched
        | PresentationStep::ResponseReady { .. }
        | PresentationStep::Logged { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}
