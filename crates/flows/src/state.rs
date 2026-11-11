// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resumable wallet flow states.

use reallyme_wallet_consent::{AuthorizedDisclosure, CapturedConsent};
use reallyme_wallet_types::{CredentialRecordId, TransactionLogEntry};
use zeroize::ZeroizeOnDrop;

/// Issuance flow state.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum IssuanceState {
    /// Offer has been received from a protocol crate.
    OfferReceived,
    /// User consent has been captured.
    ConsentCaptured,
    /// Authorization completed.
    Authorized,
    /// Credential token exchanged.
    TokenExchanged,
    /// Issuer returned a deferred transaction id and polling interval.
    Deferred,
    /// Issuer returned the final credential envelopes; receipt validation is pending.
    CredentialReceived,
    /// Credential imported and validated.
    CredentialStored {
        /// Stored credential ids. Batch issuance retains every credential as a
        /// separately selectable inventory record.
        credential_ids: Vec<CredentialRecordId>,
    },
}

/// Observable stage of a presentation flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationStage {
    /// Presentation request has been received from a protocol crate.
    RequestReceived,
    /// DCQL match has selected candidate credentials.
    Matched,
    /// User consent has been captured.
    ConsentCaptured,
    /// Presentation response was authorized against the captured decision.
    ResponseReady,
    /// User-visible transaction log entry was produced.
    Logged,
}

/// Presentation flow state.
///
/// The state is opaque: it starts at `PresentationState::received` and moves
/// only through the transition helpers, which accept each step from its
/// predecessor alone. Callers inspect progress through `stage`. Consent,
/// authorization, and log entries wipe themselves when dropped.
#[derive(PartialEq, Eq)]
pub struct PresentationState(pub(crate) PresentationStep);

// Debug reports only the stage: consent, authorization, and log entries carry
// relying-party identifiers and disclosed attribute names.
impl core::fmt::Debug for PresentationState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("PresentationState")
            .field(&self.stage())
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub(crate) enum PresentationStep {
    RequestReceived,
    Matched,
    ConsentCaptured { consent: CapturedConsent },
    ResponseReady { authorization: AuthorizedDisclosure },
    Logged { entry: TransactionLogEntry },
}

impl PresentationState {
    /// Start a presentation flow for a request received from a protocol crate.
    #[must_use]
    pub const fn received() -> Self {
        Self(PresentationStep::RequestReceived)
    }

    /// Return the current stage without exposing its sensitive payload.
    #[must_use]
    pub const fn stage(&self) -> PresentationStage {
        match &self.0 {
            PresentationStep::RequestReceived => PresentationStage::RequestReceived,
            PresentationStep::Matched => PresentationStage::Matched,
            PresentationStep::ConsentCaptured { .. } => PresentationStage::ConsentCaptured,
            PresentationStep::ResponseReady { .. } => PresentationStage::ResponseReady,
            PresentationStep::Logged { .. } => PresentationStage::Logged,
        }
    }

    /// Record the captured consent for a matched request.
    pub fn record_consent(self, consent: CapturedConsent) -> crate::FlowResult<Self> {
        match self.0 {
            PresentationStep::Matched => Ok(Self(PresentationStep::ConsentCaptured { consent })),
            PresentationStep::RequestReceived
            | PresentationStep::ConsentCaptured { .. }
            | PresentationStep::ResponseReady { .. }
            | PresentationStep::Logged { .. } => Err(crate::FlowError::new(
                crate::FlowErrorReason::InvalidTransition,
            )),
        }
    }

    /// Borrow the single-use response authorization while the response is ready.
    #[must_use]
    pub const fn authorization(&self) -> Option<&AuthorizedDisclosure> {
        match &self.0 {
            PresentationStep::ResponseReady { authorization } => Some(authorization),
            PresentationStep::RequestReceived
            | PresentationStep::Matched
            | PresentationStep::ConsentCaptured { .. }
            | PresentationStep::Logged { .. } => None,
        }
    }

    /// Record the user-visible log entry after the authorized response.
    ///
    /// The authorization is consumed here, so a logged flow cannot authorize
    /// another response.
    pub fn record_logged(self, entry: TransactionLogEntry) -> crate::FlowResult<Self> {
        match self.0 {
            PresentationStep::ResponseReady { authorization } => {
                drop(authorization);
                Ok(Self(PresentationStep::Logged { entry }))
            }
            PresentationStep::RequestReceived
            | PresentationStep::Matched
            | PresentationStep::ConsentCaptured { .. }
            | PresentationStep::Logged { .. } => Err(crate::FlowError::new(
                crate::FlowErrorReason::InvalidTransition,
            )),
        }
    }

    /// Borrow the log entry once the flow is logged.
    #[must_use]
    pub const fn log_entry(&self) -> Option<&TransactionLogEntry> {
        match &self.0 {
            PresentationStep::Logged { entry } => Some(entry),
            PresentationStep::RequestReceived
            | PresentationStep::Matched
            | PresentationStep::ConsentCaptured { .. }
            | PresentationStep::ResponseReady { .. } => None,
        }
    }
}

// Each sensitive step payload owns a ZeroizeOnDrop value. Keeping the state
// free of an outer Drop lets transitions move the single-use authorization
// without copying it.
impl ZeroizeOnDrop for PresentationState {}

#[cfg(test)]
#[path = "state_tests.rs"]
mod zeroization_tests;
