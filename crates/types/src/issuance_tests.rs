// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::OpenId4VciNotificationEndpoint;
use crate::WalletTypesErrorReason;

#[test]
fn notification_endpoint_accepts_canonical_same_origin_url() {
    let result = OpenId4VciNotificationEndpoint::new(
        "https://issuer.example/notify?id=1".to_owned(),
        "https://issuer.example",
    );
    assert!(matches!(
        result,
        Ok(endpoint) if endpoint.as_str() == "https://issuer.example/notify?id=1"
    ));
}

#[test]
fn notification_endpoint_rejects_noncanonical_aliases() {
    for value in [
        "https://ISSUER.example/notify",
        " https://issuer.example/notify ",
        "https://issuer.example\\@other.example/notify",
    ] {
        let result =
            OpenId4VciNotificationEndpoint::new(value.to_owned(), "https://issuer.example");
        assert!(matches!(
            result,
            Err(error) if error.reason == WalletTypesErrorReason::InvalidNotificationEndpoint
        ));
    }
}
