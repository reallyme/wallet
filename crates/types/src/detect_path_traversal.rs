// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Detect dot-segment traversal in identifiers, including encoded forms.

use zeroize::Zeroizing;

/// Rounds of percent-decoding examined. A backend that decodes a key more
/// than this many times is outside what an identifier check can protect.
const MAX_DECODE_ROUNDS: usize = 3;

/// Return whether `value` contains a `..` path segment, either directly or
/// after up to `MAX_DECODE_ROUNDS` rounds of percent-decoding.
///
/// Each round decodes every `%XX` hex escape, so nested forms such as
/// `%252e` or `%2%65` are found. Only the decoded copy is inspected; the
/// identifier itself keeps its encoding, so `%2F` inside a `redirect_uri:`
/// client identifier is accepted unless it produces a `..` segment.
pub(crate) fn contains_path_traversal(value: &str) -> bool {
    let mut current = Zeroizing::new(value.as_bytes().to_vec());
    for _round in 0..=MAX_DECODE_ROUNDS {
        if current
            .split(|byte| matches!(byte, b'/' | b'\\'))
            .any(|segment| segment == b"..")
        {
            return true;
        }
        let decoded = percent_decode(&current);
        if *decoded == *current {
            return false;
        }
        current = decoded;
    }
    // Still changing after the last round: refuse rather than guess.
    true
}

/// Decode every `%XX` hex escape once; other bytes are copied unchanged.
fn percent_decode(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut index = 0;
    while let Some(&byte) = input.get(index) {
        let escaped = match (
            byte,
            input.get(index.saturating_add(1)),
            input.get(index.saturating_add(2)),
        ) {
            (b'%', Some(&high), Some(&low)) => hex_value(high)
                .zip(hex_value(low))
                .map(|(high, low)| (high << 4) | low),
            _ => None,
        };
        match escaped {
            Some(value) => {
                decoded.push(value);
                index = index.saturating_add(3);
            }
            None => {
                decoded.push(byte);
                index = index.saturating_add(1);
            }
        }
    }
    decoded
}

const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}
