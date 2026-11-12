// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz bounded wallet identifier constructors on arbitrary UTF-8 text.
//! Property: storage, log, relying-party, and attribute identifiers must reject
//! empty or oversized input with typed errors and must never panic. Borrowed
//! provider-boundary identifiers must preserve the owned constructor's policy.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_wallet_types::{AttributeName, NonEmptyIdentifier};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        assert_eq!(
            NonEmptyIdentifier::new(text.to_owned()),
            NonEmptyIdentifier::try_from(text)
        );
        let _ = AttributeName::new(text.to_owned());
    }
});
