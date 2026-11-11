// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Carry key attestation evidence from secure-element or vault backends.

use reallyme_wallet_types::{KeyHandleId, UnixTimestamp};
use zeroize::ZeroizeOnDrop;

/// Required size of an unpredictable key-attestation challenge.
pub const KEY_ATTESTATION_CHALLENGE_BYTES: usize = 32;

/// Largest opaque key-attestation document accepted by Wallet boundaries.
pub const MAX_KEY_ATTESTATION_EVIDENCE_BYTES: usize = 65_536;

/// Key attestation evidence returned by the secure element or vault service.
///
/// Evidence bytes and their opaque key reference are never rendered through
/// `Debug`. Each owned copy wipes its buffers on drop.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct KeyAttestationEvidence {
    /// Key handle covered by this evidence.
    pub key_handle_id: KeyHandleId,
    /// Opaque attestation document bytes.
    pub evidence: Vec<u8>,
    /// Evidence issuance time.
    pub issued_at: UnixTimestamp,
    /// Caller-provided freshness challenge authenticated by the evidence.
    pub challenge: [u8; KEY_ATTESTATION_CHALLENGE_BYTES],
}

#[cfg(test)]
#[path = "attest_tests.rs"]
mod tests;
