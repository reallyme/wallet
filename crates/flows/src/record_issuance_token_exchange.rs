// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Records OpenID4VCI token endpoint completion.

use crate::issue::OpenId4VciIssuanceSession;
use crate::{FlowError, FlowErrorReason, FlowResult, IssuanceState};
use reallyme_wallet_types::NonEmptyIdentifier;

/// Record that the OAuth token endpoint succeeded.
pub fn record_openid4vci_token_exchanged(
    mut session: OpenId4VciIssuanceSession,
    token_handle_id: NonEmptyIdentifier,
) -> FlowResult<OpenId4VciIssuanceSession> {
    match session.state {
        IssuanceState::ConsentCaptured | IssuanceState::Authorized => {
            session.state = IssuanceState::TokenExchanged;
            // The pre-authorized code remains encapsulated by the validated
            // issuance object and is never copied into Wallet snapshots.
            session.access_token_binding_handle = Some(token_handle_id);
            Ok(session)
        }
        IssuanceState::OfferReceived
        | IssuanceState::TokenExchanged
        | IssuanceState::Deferred
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}
