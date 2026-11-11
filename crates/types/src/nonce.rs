// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable binding of an authenticated issuer nonce without retaining its plaintext.
use crate::UnixTimestamp;
use zeroize::ZeroizeOnDrop;
/// Authenticated nonce observation retained with the exact issuance session.
/// Clones are independently zeroized snapshot records, never authorization tokens.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct IssuerNonceBinding {
    /// SHA-256 of exact issuer nonce bytes authenticated by the provider.
    pub nonce_digest: [u8; 32],
    /// Wallet-computed binding to issuer, configuration, token and wallet-unit key.
    pub session_digest: [u8; 32],
    /// Trusted start of the authenticated nonce request.
    pub received_at: UnixTimestamp,
    /// Conservative exclusive local freshness deadline.
    pub expires_at: UnixTimestamp,
}
