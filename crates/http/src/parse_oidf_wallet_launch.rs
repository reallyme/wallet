// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict decoding for OIDF authorization-request and Browser API launches.

use serde::Deserialize;
use url::form_urlencoded;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{OidfBrowserApiRequest, Problem};

const APPLICATION_JSON: &str = "application/json";
const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

pub(super) enum DecodedLaunch {
    AuthorizationRequest(String),
    BrowserApi {
        request: OidfBrowserApiRequest,
        submit_url: String,
    },
}

pub(super) fn decode_launch_body(
    content_type: Option<&str>,
    body: &[u8],
) -> Result<DecodedLaunch, Problem> {
    if content_type.is_some_and(|value| media_type_is(value, FORM_URLENCODED)) {
        return std::str::from_utf8(body)
            .map(|value| DecodedLaunch::AuthorizationRequest(value.to_owned()))
            .map_err(|_| Problem::InvalidRequest);
    }

    if content_type.is_some_and(|value| media_type_is(value, APPLICATION_JSON)) {
        let launch: LaunchRequestBody =
            serde_json::from_slice(body).map_err(|_| Problem::InvalidRequest)?;
        return launch.into_decoded_launch();
    }

    Err(Problem::InvalidRequest)
}

fn media_type_is(value: &str, expected: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchRequestBody {
    authorization_request: Option<String>,
    browser_api_request: Option<BrowserApiRequestBody>,
    submit_url: Option<String>,
    request: Option<String>,
    request_uri: Option<String>,
    request_uri_method: Option<String>,
    wallet_nonce: Option<String>,
    client_id: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserApiRequestBody {
    digital: OidfBrowserApiRequest,
}

impl Zeroize for LaunchRequestBody {
    fn zeroize(&mut self) {
        self.authorization_request.zeroize();
        self.browser_api_request = None;
        self.submit_url.zeroize();
        self.request.zeroize();
        self.request_uri.zeroize();
        self.request_uri_method.zeroize();
        self.wallet_nonce.zeroize();
        self.client_id.zeroize();
        self.state.zeroize();
    }
}

impl Drop for LaunchRequestBody {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for LaunchRequestBody {}

impl LaunchRequestBody {
    fn into_decoded_launch(mut self) -> Result<DecodedLaunch, Problem> {
        let has_authorization_fields = self.authorization_request.is_some()
            || self.request.is_some()
            || self.request_uri.is_some()
            || self.request_uri_method.is_some()
            || self.wallet_nonce.is_some()
            || self.client_id.is_some()
            || self.state.is_some();
        let has_browser_fields = self.browser_api_request.is_some() || self.submit_url.is_some();
        if has_authorization_fields && has_browser_fields {
            return Err(Problem::InvalidRequest);
        }

        if has_browser_fields {
            let browser_api_request = self
                .browser_api_request
                .take()
                .ok_or(Problem::InvalidRequest)?;
            let submit_url = self.submit_url.take().ok_or(Problem::InvalidRequest)?;
            return Ok(DecodedLaunch::BrowserApi {
                request: browser_api_request.digital,
                submit_url,
            });
        }

        if let Some(authorization_request) = self.authorization_request.take() {
            // A complete authorization request is exclusive. Sibling launch
            // parameters would otherwise be silently ignored.
            if self.request.is_some()
                || self.request_uri.is_some()
                || self.request_uri_method.is_some()
                || self.wallet_nonce.is_some()
                || self.client_id.is_some()
                || self.state.is_some()
            {
                return Err(Problem::InvalidRequest);
            }
            return Ok(DecodedLaunch::AuthorizationRequest(authorization_request));
        }

        let mut serializer = form_urlencoded::Serializer::new(String::new());
        append_optional_pair(&mut serializer, "request", self.request.as_deref());
        append_optional_pair(&mut serializer, "request_uri", self.request_uri.as_deref());
        append_optional_pair(
            &mut serializer,
            "request_uri_method",
            self.request_uri_method.as_deref(),
        );
        append_optional_pair(
            &mut serializer,
            "wallet_nonce",
            self.wallet_nonce.as_deref(),
        );
        append_optional_pair(&mut serializer, "client_id", self.client_id.as_deref());
        append_optional_pair(&mut serializer, "state", self.state.as_deref());

        let query = serializer.finish();
        if query.is_empty() {
            return Err(Problem::InvalidRequest);
        }
        Ok(DecodedLaunch::AuthorizationRequest(query))
    }
}

fn append_optional_pair(
    serializer: &mut form_urlencoded::Serializer<'_, String>,
    name: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        serializer.append_pair(name, value);
    }
}
