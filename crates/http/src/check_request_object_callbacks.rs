// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pre-verification callback check for by-value Request Objects.
//!
//! The composed driver verifies the Request Object signature. Before handing a
//! by-value request to it, the harness applies its callback-origin allowlist
//! to the claimed `response_uri` and `redirect_uri`, as it already does for
//! `request_uri`, so a launch cannot steer a conformance run toward an origin
//! outside the configured suite.

use reallyme_codec::base64url::base64url_to_bytes;
use serde_json::Value;
use zeroize::Zeroizing;

use super::strict_json_value::StrictJsonValue;

/// Return whether every callback claimed by the unverified JWT is allowlisted.
pub(super) fn request_object_callbacks_allowed(jwt: &str, allowed: impl Fn(&str) -> bool) -> bool {
    let mut segments = jwt.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    let Ok(bytes) = base64url_to_bytes(payload).map(Zeroizing::new) else {
        return false;
    };
    // Duplicate keys are refused, so the allowlist and the driver cannot read
    // different values for the same callback. The parsed value wipes itself.
    let Ok(parsed) = serde_json::from_slice::<StrictJsonValue>(&bytes) else {
        return false;
    };
    let Value::Object(claims) = parsed.as_value() else {
        return false;
    };
    ["response_uri", "redirect_uri"]
        .iter()
        .all(|field| match claims.get(*field) {
            None => true,
            Some(Value::String(uri)) => allowed(uri),
            Some(_) => false,
        })
}
