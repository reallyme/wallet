// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Polls OpenID4VCI deferred credential endpoints through injected transport.

use openid4vci_types::{
    CredentialResponse, CredentialResponseEncryption, DeferredCredentialRequest,
};

use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp};

use crate::exchange_pre_authorized_token::OpenId4VciAccessTokenHandle;
use crate::issue::OpenId4VciIssuanceSession;
use crate::{
    record_openid4vci_deferred_credential_response, FlowError, FlowErrorReason, FlowResult,
    IssuanceState,
};

/// Injected OpenID4VCI deferred credential endpoint transport.
pub trait OpenId4VciDeferredCredentialRequester {
    /// Poll the deferred credential endpoint using transport-owned token material.
    fn request_deferred_credential(
        &mut self,
        token_handle: &OpenId4VciAccessTokenHandle,
        request: &DeferredCredentialRequest,
    ) -> FlowResult<CredentialResponse>;
}

/// Build a deferred credential request from wallet state.
pub fn build_openid4vci_deferred_credential_request(
    session: &OpenId4VciIssuanceSession,
    credential_response_encryption: Option<CredentialResponseEncryption>,
) -> FlowResult<DeferredCredentialRequest> {
    match session.state {
        IssuanceState::Deferred => {
            let Some(status) = session.deferred_issuance.as_ref() else {
                return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
            };
            let request = DeferredCredentialRequest {
                transaction_id: status.transaction_id.as_str().to_owned(),
                credential_response_encryption,
            };
            request
                .validate()
                .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            Ok(request)
        }
        IssuanceState::OfferReceived
        | IssuanceState::ConsentCaptured
        | IssuanceState::Authorized
        | IssuanceState::TokenExchanged
        | IssuanceState::CredentialReceived
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

/// Host-persisted pacing state for one deferred issuance.
///
/// The host stores this beside the issuance snapshot and passes it to every
/// poll. Each poll counts as an attempt before the transport is called, so a
/// failed or interrupted poll still consumes the interval and the budget.
///
/// The schedule is not covered by the issuance checkpoint seal, and `start`
/// or `restore` can recreate it. The attempt budget and maximum wait are
/// therefore pacing the host must keep faithfully, not a limit Wallet can
/// enforce against a host that resets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredPollSchedule {
    transaction_id: NonEmptyIdentifier,
    started_at: UnixTimestamp,
    last_polled_at: Option<UnixTimestamp>,
    attempts: u32,
}

impl DeferredPollSchedule {
    /// Maximum deferred-credential polls for one issuance.
    pub const MAX_ATTEMPTS: u32 = 64;
    /// Maximum time from the first deferred response until issuance is abandoned.
    pub const MAX_WAIT_SECONDS: i64 = 30 * 24 * 60 * 60;

    /// Start pacing when the issuer first answers with a deferred response.
    ///
    /// The schedule is bound to the session's deferred transaction, and the
    /// first poll waits the issuer's interval from `now`.
    pub fn start(session: &OpenId4VciIssuanceSession, now: UnixTimestamp) -> FlowResult<Self> {
        let transaction_id = session
            .deferred_issuance
            .as_ref()
            .map(|status| status.transaction_id.clone())
            .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        Ok(Self {
            transaction_id,
            started_at: now,
            last_polled_at: None,
            attempts: 0,
        })
    }

    /// Restore persisted pacing state after validating its consistency.
    pub fn restore(
        transaction_id: NonEmptyIdentifier,
        started_at: UnixTimestamp,
        last_polled_at: Option<UnixTimestamp>,
        attempts: u32,
    ) -> FlowResult<Self> {
        let consistent = match last_polled_at {
            None => attempts == 0,
            Some(last) => attempts > 0 && last >= started_at,
        };
        if !consistent || attempts > Self::MAX_ATTEMPTS {
            return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
        }
        Ok(Self {
            transaction_id,
            started_at,
            last_polled_at,
            attempts,
        })
    }

    /// Deferred transaction this schedule paces.
    #[must_use]
    pub const fn transaction_id(&self) -> &NonEmptyIdentifier {
        &self.transaction_id
    }

    /// Time the issuer first deferred this issuance.
    #[must_use]
    pub const fn started_at(&self) -> UnixTimestamp {
        self.started_at
    }

    /// Time of the most recent poll attempt, if any.
    #[must_use]
    pub const fn last_polled_at(&self) -> Option<UnixTimestamp> {
        self.last_polled_at
    }

    /// Number of poll attempts made so far.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    fn admit(&mut self, interval_seconds: u64, now: UnixTimestamp) -> FlowResult<()> {
        let waited = now
            .as_seconds()
            .checked_sub(self.started_at.as_seconds())
            .filter(|seconds| *seconds >= 0)
            .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        if self.attempts >= Self::MAX_ATTEMPTS || waited > Self::MAX_WAIT_SECONDS {
            return Err(FlowError::new(FlowErrorReason::DeferredIssuanceExpired));
        }
        // The issuer's interval applies before the first poll as well, measured
        // from the deferred response that started this schedule.
        let previous = self.last_polled_at.unwrap_or(self.started_at);
        let interval = i64::try_from(interval_seconds)
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        let since = now
            .as_seconds()
            .checked_sub(previous.as_seconds())
            .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        if since < interval {
            return Err(FlowError::new(FlowErrorReason::DeferredPollTooEarly));
        }
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or_else(|| FlowError::new(FlowErrorReason::DeferredIssuanceExpired))?;
        self.last_polled_at = Some(now);
        Ok(())
    }
}

/// Poll deferred issuance and record the resulting pending or final response.
///
/// `schedule` enforces the issuer's polling interval, at most
/// `DeferredPollSchedule::MAX_ATTEMPTS` polls, and at most
/// `DeferredPollSchedule::MAX_WAIT_SECONDS` of waiting. It is updated before the
/// transport call; persist it whether or not the poll succeeds.
pub fn poll_openid4vci_deferred_credential(
    session: &OpenId4VciIssuanceSession,
    token_handle: &OpenId4VciAccessTokenHandle,
    credential_response_encryption: Option<CredentialResponseEncryption>,
    schedule: &mut DeferredPollSchedule,
    now: UnixTimestamp,
    requester: &mut dyn OpenId4VciDeferredCredentialRequester,
) -> FlowResult<OpenId4VciIssuanceSession> {
    token_handle.validate_for_session(session)?;
    let request =
        build_openid4vci_deferred_credential_request(session, credential_response_encryption)?;
    let status = session
        .deferred_issuance
        .as_ref()
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    if status.transaction_id != schedule.transaction_id {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }
    schedule.admit(status.interval_seconds, now)?;
    let credential_response = requester.request_deferred_credential(token_handle, &request)?;

    record_openid4vci_deferred_credential_response(session.clone(), credential_response)
}

#[cfg(test)]
#[path = "poll_deferred_credential_tests.rs"]
mod tests;
