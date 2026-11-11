// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP token matching for content negotiation and content encoding.

use axum::http::header::HeaderName;
use axum::http::HeaderMap;

pub(super) fn header_token_contains(headers: &HeaderMap, name: HeaderName, needle: &str) -> bool {
    match headers.get(name).and_then(|value| value.to_str().ok()) {
        Some(value) => header_value_contains_token(value, needle),
        None => false,
    }
}

fn header_value_contains_token(value: &str, needle: &str) -> bool {
    value.split(',').any(|part| {
        part.trim()
            .split(';')
            .next()
            .is_some_and(|token| token.trim().eq_ignore_ascii_case(needle))
    })
}
