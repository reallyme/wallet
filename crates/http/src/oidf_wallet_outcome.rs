// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret-bearing outcome values returned by composed OIDF wallet flows.

use core::fmt;

use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::oidf_wallet_flow::{
    OidfWalletFlowError, OidfWalletFlowErrorReason, OidfWalletFlowStatus,
};

/// Maximum bytes accepted for a verifier-provided browser handoff URI.
///
/// The handoff can contain a one-time verifier secret in its fragment. Keeping
/// the limit close to practical browser URL limits bounds every retained copy.
pub const MAX_OIDF_BROWSER_HANDOFF_URI_BYTES: usize = 8 * 1024;

/// Validated front-channel destination returned after a direct-post response.
///
/// This value is intentionally distinct from the Authorization Request
/// `redirect_uri`. It is returned by the verifier only after accepting the
/// authorization response and may contain a secret fragment, so owners clear
/// it on drop and redact it from debug output.
#[derive(PartialEq, Eq)]
pub struct OidfBrowserHandoff {
    uri: String,
}

impl OidfBrowserHandoff {
    /// Validate an absolute HTTPS handoff URI while preserving its fragment.
    pub fn parse(uri: String) -> Result<Self, OidfWalletFlowError> {
        let mut uri = zeroize::Zeroizing::new(uri);
        if uri.is_empty() || uri.len() > MAX_OIDF_BROWSER_HANDOFF_URI_BYTES {
            return Err(OidfWalletFlowError::new(
                OidfWalletFlowErrorReason::ResponseSubmissionFailed,
            ));
        }
        let parsed = Url::parse(&uri).map_err(|_| {
            OidfWalletFlowError::new(OidfWalletFlowErrorReason::ResponseSubmissionFailed)
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.cannot_be_a_base()
        {
            return Err(OidfWalletFlowError::new(
                OidfWalletFlowErrorReason::ResponseSubmissionFailed,
            ));
        }
        Ok(Self {
            uri: core::mem::take(&mut *uri),
        })
    }

    /// Borrow the exact verifier-provided URI, including any fragment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    pub(crate) fn into_uri(mut self) -> String {
        core::mem::take(&mut self.uri)
    }
}

impl fmt::Debug for OidfBrowserHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OidfBrowserHandoff(<redacted>)")
    }
}

impl Zeroize for OidfBrowserHandoff {
    fn zeroize(&mut self) {
        self.uri.zeroize();
    }
}

impl Drop for OidfBrowserHandoff {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OidfBrowserHandoff {}

/// Successful composed-flow outcome.
pub struct OidfWalletFlowOutcome {
    status: OidfWalletFlowStatus,
    browser_handoff: Option<OidfBrowserHandoff>,
}

impl OidfWalletFlowOutcome {
    /// The wallet submitted an encrypted `direct_post.jwt` response.
    #[must_use]
    pub fn direct_post_jwt_submitted(browser_handoff: Option<OidfBrowserHandoff>) -> Self {
        Self {
            status: OidfWalletFlowStatus::DirectPostJwtSubmitted,
            browser_handoff,
        }
    }

    /// The wallet submitted an encrypted Digital Credentials API response.
    #[must_use]
    pub const fn dc_api_jwt_submitted() -> Self {
        Self {
            status: OidfWalletFlowStatus::DcApiJwtSubmitted,
            browser_handoff: None,
        }
    }

    /// Stable outcome status for audit and harness-session records.
    #[must_use]
    pub const fn status(&self) -> OidfWalletFlowStatus {
        self.status
    }

    pub(crate) fn into_parts(mut self) -> (OidfWalletFlowStatus, Option<String>) {
        let browser_handoff = self
            .browser_handoff
            .take()
            .map(OidfBrowserHandoff::into_uri);
        (self.status, browser_handoff)
    }
}

impl fmt::Debug for OidfWalletFlowOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidfWalletFlowOutcome")
            .field("status", &self.status)
            .field("has_browser_handoff", &self.browser_handoff.is_some())
            .finish()
    }
}

impl Zeroize for OidfWalletFlowOutcome {
    fn zeroize(&mut self) {
        self.browser_handoff.zeroize();
    }
}

impl Drop for OidfWalletFlowOutcome {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OidfWalletFlowOutcome {}
