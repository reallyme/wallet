// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque key-handle metadata for wallet keystore backends.

use reallyme_wallet_types::{KeyHandleId, UnixTimestamp};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Signature algorithm selected by protocol logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum SigningAlgorithm {
    /// ECDSA P-256 with SHA-256.
    Es256,
    /// Ed25519.
    Ed25519,
    /// ML-DSA-44.
    MlDsa44,
}

/// Custody class for the SDK-provided keystore backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum KeyCustodyKind {
    /// Platform secure element or operating-system secure area.
    PlatformSecureArea,
    /// Remote or local vault-service client selected by identity.
    VaultService,
}

/// Opaque key handle owned by a platform keystore.
///
/// The identifier is deliberately omitted from `Debug` and wiped on drop. A
/// clone is an independently owned platform reference and is wiped separately.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct KeyHandle {
    /// Stable key handle id.
    pub id: KeyHandleId,
    /// Signing algorithm for policy matching.
    pub algorithm: SigningAlgorithm,
    /// Creation time for rotation policy.
    pub created_at: UnixTimestamp,
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
