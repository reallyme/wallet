// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exchanges OpenID4VCI pre-authorized codes through injected transport.

use reallyme_openid4vci_wallet::{PreAuthorizedTokenRequest, TransactionCode};
use reallyme_openid_oauth::AttestationClientAuthentication;
use reallyme_wallet_types::NonEmptyIdentifier;

use crate::build_openid4vci_pre_authorized_token_request;
use crate::issue::OpenId4VciIssuanceSession;
use crate::record_openid4vci_token_exchanged;
use crate::{FlowError, FlowErrorReason, FlowResult};

/// Opaque handle for an access token owned by the injected issuer transport.
///
/// Wallet-core never stores bearer token bytes. SDKs or service adapters keep
/// token material in their own protected runtime and hand wallet-core only this
/// non-secret correlation handle for subsequent credential endpoint calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenId4VciAccessTokenHandle {
    /// Non-secret handle identifier owned by the injected transport.
    id: NonEmptyIdentifier,
    credential_issuer: Option<String>,
}

impl OpenId4VciAccessTokenHandle {
    /// Construct an unbound handle returned by an injected token transport.
    #[must_use]
    pub const fn from_transport(id: NonEmptyIdentifier) -> Self {
        Self {
            id,
            credential_issuer: None,
        }
    }

    /// Borrow the transport-owned opaque handle identifier.
    #[must_use]
    pub const fn id(&self) -> &NonEmptyIdentifier {
        &self.id
    }

    fn bind_to_session(&mut self, session: &OpenId4VciIssuanceSession) {
        self.credential_issuer = Some(session.credential_issuer.clone());
    }

    pub(crate) fn validate_for_session(
        &self,
        session: &OpenId4VciIssuanceSession,
    ) -> FlowResult<()> {
        if session.access_token_binding_handle.as_ref() != Some(&self.id)
            || self
                .credential_issuer
                .as_deref()
                .is_none_or(|issuer| issuer != session.credential_issuer)
        {
            return Err(FlowError::new(FlowErrorReason::AccessTokenSessionMismatch));
        }
        Ok(())
    }
}

/// Injected OpenID4VCI token transport.
pub trait OpenId4VciTokenExchanger {
    /// Exchange a holder-built pre-authorized-code token request.
    fn exchange_pre_authorized_token(
        &mut self,
        request: &PreAuthorizedTokenRequest,
        attestation_client_authentication: Option<&AttestationClientAuthentication>,
    ) -> FlowResult<OpenId4VciAccessTokenHandle>;
}

/// Bind an opaque access-token handle returned by an authorization-code transport.
///
/// The transport owns token validation and token bytes. Wallet-core accepts only
/// an unbound, non-secret handle, binds it to this issuer session, and advances
/// the state atomically so it cannot be replayed across issuers.
pub fn bind_openid4vci_authorization_code_token(
    session: &OpenId4VciIssuanceSession,
    mut token_handle: OpenId4VciAccessTokenHandle,
) -> FlowResult<(OpenId4VciIssuanceSession, OpenId4VciAccessTokenHandle)> {
    if session.grant_type != reallyme_openid4vci_wallet::CredentialOfferGrantType::AuthorizationCode
    {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }
    // The authorization-code grant must have completed authorization first.
    if session.state != crate::IssuanceState::Authorized {
        return Err(FlowError::new(FlowErrorReason::InvalidTransition));
    }
    validate_token_handle(&token_handle)?;
    if token_handle.credential_issuer.is_some() {
        return Err(FlowError::new(FlowErrorReason::AccessTokenSessionMismatch));
    }
    token_handle.bind_to_session(session);
    let session = record_openid4vci_token_exchanged(session.clone(), token_handle.id.clone())?;
    Ok((session, token_handle))
}

/// Build and exchange a pre-authorized-code token request, then advance state.
///
/// The input session is borrowed so failed transport calls cannot consume the
/// caller's resumable state. Callers persist the returned session only after the
/// injected transport has accepted the token request.
pub fn exchange_openid4vci_pre_authorized_token(
    session: &OpenId4VciIssuanceSession,
    transaction_code: Option<&TransactionCode>,
    client_id: Option<String>,
    attestation_client_authentication: Option<AttestationClientAuthentication>,
    exchanger: &mut dyn OpenId4VciTokenExchanger,
) -> FlowResult<(OpenId4VciIssuanceSession, OpenId4VciAccessTokenHandle)> {
    let request =
        build_openid4vci_pre_authorized_token_request(session, transaction_code, client_id)?;
    let mut token_handle = exchanger
        .exchange_pre_authorized_token(&request, attestation_client_authentication.as_ref())?;
    validate_token_handle(&token_handle)?;
    // As on the authorization-code path, a handle already bound to a session
    // is never re-bound to this one.
    if token_handle.credential_issuer.is_some() {
        return Err(FlowError::new(FlowErrorReason::AccessTokenSessionMismatch));
    }
    token_handle.bind_to_session(session);
    let session = record_openid4vci_token_exchanged(session.clone(), token_handle.id.clone())?;

    Ok((session, token_handle))
}

/// Restore a transport handle only when it exactly matches persisted session state.
pub fn restore_openid4vci_access_token_handle(
    session: &OpenId4VciIssuanceSession,
    id: NonEmptyIdentifier,
) -> FlowResult<OpenId4VciAccessTokenHandle> {
    if session.access_token_binding_handle.as_ref() != Some(&id) {
        return Err(FlowError::new(FlowErrorReason::AccessTokenSessionMismatch));
    }
    let mut handle = OpenId4VciAccessTokenHandle::from_transport(id);
    handle.bind_to_session(session);
    handle.validate_for_session(session)?;
    Ok(handle)
}

fn validate_token_handle(handle: &OpenId4VciAccessTokenHandle) -> FlowResult<()> {
    if handle.id.as_str().is_empty() {
        return Err(FlowError::new(
            FlowErrorReason::OpenId4VciIssuerTransportRejected,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "exchange_pre_authorized_token_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "exchange_pre_authorized_token_test_support.rs"]
pub(crate) mod test_support;
