// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz-only identifier properties, separate from production source policy.

use reallyme_wallet_types::NonEmptyIdentifier;

// This module is compiled only by the isolated libFuzzer harness. A mismatch
// must terminate that test execution so the input is retained as a regression.
pub(super) fn check_constructor_equivalence(text: &str) {
    assert_eq!(
        NonEmptyIdentifier::new(text.to_owned()),
        NonEmptyIdentifier::try_from(text)
    );
}
