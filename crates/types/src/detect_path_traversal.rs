// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Detect dot-segment traversal in identifiers, including encoded forms.

use zeroize::Zeroizing;

use crate::identifiers::MAX_IDENTIFIER_BYTES;

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
    if value.len() > MAX_IDENTIFIER_BYTES {
        return true;
    }
    // Identifier validation also runs on rejected input. Keep both decoding
    // buffers bounded on the stack and wipe them on every return path.
    let mut current = Zeroizing::new([0_u8; MAX_IDENTIFIER_BYTES]);
    let mut decoded = Zeroizing::new([0_u8; MAX_IDENTIFIER_BYTES]);
    let Some(initial) = current.get_mut(..value.len()) else {
        return true;
    };
    initial.copy_from_slice(value.as_bytes());
    let mut current_len = value.len();
    for _round in 0..=MAX_DECODE_ROUNDS {
        let Some(bytes) = current.get(..current_len) else {
            return true;
        };
        if bytes
            .split(|byte| matches!(byte, b'/' | b'\\'))
            .any(|segment| segment == b"..")
        {
            return true;
        }
        let Some(decoded_len) = percent_decode(bytes, &mut decoded) else {
            return true;
        };
        let Some(decoded_bytes) = decoded.get(..decoded_len) else {
            return true;
        };
        if decoded_bytes == bytes {
            return false;
        }
        core::mem::swap(&mut current, &mut decoded);
        current_len = decoded_len;
    }
    // Still changing after the last round: refuse rather than guess.
    true
}

/// Decode one bounded pass, refusing an impossible output or offset.
fn percent_decode(input: &[u8], output: &mut [u8; MAX_IDENTIFIER_BYTES]) -> Option<usize> {
    let mut read_index = 0_usize;
    let mut written = 0_usize;
    while let Some(&byte) = input.get(read_index) {
        let escaped = match (
            byte,
            read_index.checked_add(1).and_then(|index| input.get(index)),
            read_index.checked_add(2).and_then(|index| input.get(index)),
        ) {
            (b'%', Some(&high), Some(&low)) => hex_value(high)
                .zip(hex_value(low))
                .map(|(high, low)| (high << 4) | low),
            _ => None,
        };
        let consumed = if escaped.is_some() { 3 } else { 1 };
        *output.get_mut(written)? = escaped.unwrap_or(byte);
        written = written.checked_add(1)?;
        read_index = read_index.checked_add(consumed)?;
    }
    Some(written)
}

const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}
