// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed composition boundary for OIDF OpenID4VP wallet launches.

use std::net::IpAddr;

use reallyme_openid4vp_wallet::{
    parse_authorization_request_transport, AuthorizationRequestTransport, RequestTransportPolicy,
};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::oidf_wallet_outcome::OidfWalletFlowOutcome;
use super::strict_json_value::StrictJsonValue;
use super::{MAX_BROWSER_API_REQUESTS, MAX_HARNESS_BODY_BYTES};

/// Composed OpenID4VP wallet flow driver used by the OIDF harness.
///
/// Implementations belong in identity, app, or service binaries that link
/// wallet-core with OpenID4VP, identity, keystore, storage, JOSE, and HTTP
/// adapters. The runtime passes only the parsed launch transport; it does not
/// duplicate protocol resolution, presentation construction, or key handling.
pub trait OidfWalletFlowDriver: Send + Sync {
    /// Complete the launched wallet flow and submit the authorization response.
    fn drive_oidf_authorization_request(
        &self,
        request: OidfWalletFlowRequest,
    ) -> Result<OidfWalletFlowOutcome, OidfWalletFlowError>;
}

/// Parsed OIDF wallet launch passed to the composed flow driver.
pub struct OidfWalletFlowRequest {
    launch: Option<OidfWalletFlowLaunch>,
}

enum OidfWalletFlowLaunch {
    AuthorizationRequest {
        launch_input: Zeroizing<String>,
        transport: AuthorizationRequestTransport,
    },
    BrowserApi {
        request: OidfBrowserApiRequest,
        submit_url: Zeroizing<String>,
    },
}

/// Bounded Browser API request passed opaquely to the identity composition.
///
/// Wallet owns only the HTTP control-plane envelope. The identity driver parses
/// and verifies the standards-owned OpenID4VP request data.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidfBrowserApiRequest {
    requests: Vec<OidfBrowserApiProtocolRequest>,
}

impl OidfBrowserApiRequest {
    /// Protocol requests supplied by the browser.
    #[must_use]
    pub fn requests(&self) -> &[OidfBrowserApiProtocolRequest] {
        &self.requests
    }
}

impl core::fmt::Debug for OidfBrowserApiRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OidfBrowserApiRequest")
            .field("request_count", &self.requests.len())
            .field("request_data", &"<redacted>")
            .finish()
    }
}

impl Zeroize for OidfBrowserApiRequest {
    fn zeroize(&mut self) {
        self.requests.zeroize();
    }
}

impl Drop for OidfBrowserApiRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OidfBrowserApiRequest {}

/// One Browser API OpenID4VP protocol request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidfBrowserApiProtocolRequest {
    protocol: OidfBrowserApiProtocol,
    data: StrictJsonValue,
}

impl OidfBrowserApiProtocolRequest {
    /// OpenID4VP Browser API protocol variant.
    #[must_use]
    pub const fn protocol(&self) -> OidfBrowserApiProtocol {
        self.protocol
    }

    /// Opaque standards-owned request data for identity-layer parsing.
    #[must_use]
    pub const fn data(&self) -> &serde_json::Value {
        self.data.as_value()
    }
}

impl core::fmt::Debug for OidfBrowserApiProtocolRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OidfBrowserApiProtocolRequest")
            .field("protocol", &self.protocol)
            .field("data", &"<redacted>")
            .finish()
    }
}

impl Zeroize for OidfBrowserApiProtocolRequest {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for OidfBrowserApiProtocolRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OidfBrowserApiProtocolRequest {}

/// Supported OpenID4VP protocol identifiers for the Browser API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum OidfBrowserApiProtocol {
    /// Expanded unsigned OpenID4VP request.
    #[serde(rename = "openid4vp-v1-unsigned")]
    Unsigned,
    /// Compact signed Request Object.
    #[serde(rename = "openid4vp-v1-signed")]
    Signed,
    /// JWS JSON General Serialization Request Object.
    #[serde(rename = "openid4vp-v1-multisigned")]
    Multisigned,
}

impl core::fmt::Debug for OidfWalletFlowRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OidfWalletFlowRequest(<redacted>)")
    }
}

impl Drop for OidfWalletFlowRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OidfWalletFlowRequest {}

impl Zeroize for OidfWalletFlowRequest {
    fn zeroize(&mut self) {
        // Taking the launch drops its protocol-owned secret-bearing values.
        // Authorization transports and DC API request data zeroize their own
        // request objects, JWS values, nonces, and presentation parameters.
        self.launch = None;
    }
}

impl OidfWalletFlowRequest {
    /// Parse and validate a launch input for direct composed-driver use.
    ///
    /// The HTTP adapter normally constructs this value after enforcing its
    /// body limit. External compositions and tests must use this parser rather
    /// than supplying a transport independently, which prevents the raw launch
    /// input and parsed transport from disagreeing.
    pub fn parse(launch_input: String) -> Result<Self, OidfWalletFlowError> {
        let mut launch_input = zeroize::Zeroizing::new(launch_input);
        if launch_input.len() > MAX_HARNESS_BODY_BYTES {
            return Err(OidfWalletFlowError::new(
                OidfWalletFlowErrorReason::RequestResolutionFailed,
            ));
        }
        let transport =
            parse_authorization_request_transport(&launch_input, RequestTransportPolicy::default())
                .map_err(|_| {
                    OidfWalletFlowError::new(OidfWalletFlowErrorReason::RequestResolutionFailed)
                })?;
        Ok(Self::new_authorization_request(
            core::mem::take(&mut *launch_input),
            transport,
        ))
    }

    /// Construct a parsed flow request for the HTTP control plane.
    #[must_use]
    pub(super) fn new_authorization_request(
        launch_input: String,
        transport: AuthorizationRequestTransport,
    ) -> Self {
        Self {
            launch: Some(OidfWalletFlowLaunch::AuthorizationRequest {
                launch_input: Zeroizing::new(launch_input),
                transport,
            }),
        }
    }

    /// Construct a validated Digital Credentials API flow request.
    pub fn from_browser_api(
        request: OidfBrowserApiRequest,
        submit_url: String,
    ) -> Result<Self, OidfWalletFlowError> {
        validate_browser_api_request(&request, &submit_url)?;
        Ok(Self {
            launch: Some(OidfWalletFlowLaunch::BrowserApi {
                request,
                submit_url: Zeroizing::new(submit_url),
            }),
        })
    }

    /// Raw query string or launch URL for an authorization-request launch.
    #[must_use]
    pub fn authorization_request_input(&self) -> Option<&str> {
        match self.launch.as_ref() {
            Some(OidfWalletFlowLaunch::AuthorizationRequest { launch_input, .. }) => {
                Some(launch_input.as_str())
            }
            Some(OidfWalletFlowLaunch::BrowserApi { .. }) | None => None,
        }
    }

    /// Parsed OpenID4VP authorization request transport, when applicable.
    #[must_use]
    pub fn authorization_request_transport(&self) -> Option<&AuthorizationRequestTransport> {
        match self.launch.as_ref() {
            Some(OidfWalletFlowLaunch::AuthorizationRequest { transport, .. }) => Some(transport),
            Some(OidfWalletFlowLaunch::BrowserApi { .. }) | None => None,
        }
    }

    /// Validated Digital Credentials API request options, when applicable.
    #[must_use]
    pub fn browser_api_request(&self) -> Option<&OidfBrowserApiRequest> {
        match self.launch.as_ref() {
            Some(OidfWalletFlowLaunch::BrowserApi { request, .. }) => Some(request),
            Some(OidfWalletFlowLaunch::AuthorizationRequest { .. }) | None => None,
        }
    }

    /// OIDF callback URL for a Digital Credentials API response, when applicable.
    #[must_use]
    pub fn browser_api_submit_url(&self) -> Option<&str> {
        match self.launch.as_ref() {
            Some(OidfWalletFlowLaunch::BrowserApi { submit_url, .. }) => Some(submit_url.as_str()),
            Some(OidfWalletFlowLaunch::AuthorizationRequest { .. }) | None => None,
        }
    }
}

/// Stable successful composed-flow statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum OidfWalletFlowStatus {
    /// A DCQL-keyed `vp_token` was encrypted as `direct_post.jwt` and submitted
    /// to the verifier response endpoint.
    DirectPostJwtSubmitted,
    /// A `dc_api.jwt` response was submitted to the suite's browser callback.
    DcApiJwtSubmitted,
}

/// Typed composed-flow error.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("oidf wallet flow failed: {reason}")]
pub struct OidfWalletFlowError {
    reason: OidfWalletFlowErrorReason,
}

impl OidfWalletFlowError {
    /// Construct a composed-flow error from a stable, non-sensitive reason.
    #[must_use]
    pub const fn new(reason: OidfWalletFlowErrorReason) -> Self {
        Self { reason }
    }

    /// Stable, non-sensitive error reason.
    #[must_use]
    pub const fn reason(self) -> OidfWalletFlowErrorReason {
        self.reason
    }
}

/// Stable composed-flow failure reasons.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq, Serialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum OidfWalletFlowErrorReason {
    /// The composed harness was not installed.
    #[error("unsupported")]
    Unsupported,
    /// Request transport resolution failed.
    #[error("request_resolution_failed")]
    RequestResolutionFailed,
    /// Request Object signature, binding, metadata, or verifier checks failed.
    #[error("request_verification_failed")]
    RequestVerificationFailed,
    /// No wallet credential satisfied the DCQL request.
    #[error("credential_selection_failed")]
    CredentialSelectionFailed,
    /// Consent was rejected or unavailable.
    #[error("consent_rejected")]
    ConsentRejected,
    /// The DCQL-keyed `vp_token` could not be constructed.
    #[error("presentation_build_failed")]
    PresentationBuildFailed,
    /// Authorization response encryption failed.
    #[error("response_encryption_failed")]
    ResponseEncryptionFailed,
    /// Posting the authorization response failed.
    #[error("direct_post_failed")]
    DirectPostFailed,
    /// Submitting a non-direct-post response failed.
    #[error("response_submission_failed")]
    ResponseSubmissionFailed,
}

fn validate_browser_api_request(
    request: &OidfBrowserApiRequest,
    submit_url: &str,
) -> Result<(), OidfWalletFlowError> {
    if request.requests.is_empty() || request.requests.len() > MAX_BROWSER_API_REQUESTS {
        return Err(OidfWalletFlowError::new(
            OidfWalletFlowErrorReason::RequestResolutionFailed,
        ));
    }
    if request
        .requests
        .iter()
        .any(|protocol_request| !valid_protocol_data(protocol_request))
    {
        return Err(OidfWalletFlowError::new(
            OidfWalletFlowErrorReason::RequestVerificationFailed,
        ));
    }

    let url = Url::parse(submit_url).map_err(|_| {
        OidfWalletFlowError::new(OidfWalletFlowErrorReason::RequestResolutionFailed)
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
    {
        return Err(OidfWalletFlowError::new(
            OidfWalletFlowErrorReason::RequestResolutionFailed,
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        OidfWalletFlowError::new(OidfWalletFlowErrorReason::RequestResolutionFailed)
    })?;
    let secure_transport = url.scheme() == "https";
    let local_test_transport = url.scheme() == "http" && is_loopback_host(host);
    if !secure_transport && !local_test_transport {
        return Err(OidfWalletFlowError::new(
            OidfWalletFlowErrorReason::RequestResolutionFailed,
        ));
    }
    Ok(())
}

fn valid_protocol_data(request: &OidfBrowserApiProtocolRequest) -> bool {
    let Some(data) = request.data.as_value().as_object() else {
        return false;
    };
    match request.protocol {
        OidfBrowserApiProtocol::Unsigned => !data.is_empty(),
        OidfBrowserApiProtocol::Signed => {
            data.len() == 1
                && data
                    .get("request")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty())
        }
        OidfBrowserApiProtocol::Multisigned => {
            data.len() == 1
                && data
                    .get("request")
                    .is_some_and(serde_json::Value::is_object)
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}
