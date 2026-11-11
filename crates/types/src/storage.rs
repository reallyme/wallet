// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted storage record shapes shared with platform SDKs.
//!
//! Records use the versioned Wallet protobuf codec. Domain storage values do
//! not implement Serde, preventing accidental creation of a parallel JSON
//! persistence or SDK contract.

use crate::{KeyHandleId, WalletTypesError, WalletTypesErrorReason};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Nonce length for AES-256-GCM-SIV encrypted storage records.
pub const AES_256_GCM_SIV_NONCE_LENGTH: usize = 12;
/// Nonce length for XChaCha20-Poly1305 encrypted storage records.
pub const XCHACHA20_POLY1305_NONCE_LENGTH: usize = 24;

/// Authenticated-encryption algorithms approved for wallet storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum StorageEncryptionAlgorithm {
    /// AES-256-GCM-SIV with a 96-bit nonce.
    Aes256GcmSiv,
    /// XChaCha20-Poly1305 with a 192-bit nonce.
    XChaCha20Poly1305,
}

impl StorageEncryptionAlgorithm {
    /// Required nonce length for the selected algorithm.
    #[must_use]
    pub const fn nonce_length(self) -> usize {
        match self {
            Self::Aes256GcmSiv => AES_256_GCM_SIV_NONCE_LENGTH,
            Self::XChaCha20Poly1305 => XCHACHA20_POLY1305_NONCE_LENGTH,
        }
    }
}

/// Unix timestamp in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub struct UnixTimestamp(i64);

/// Largest integer represented exactly by JavaScript/ProtoJSON number values.
pub const MAX_SAFE_UNIX_TIMESTAMP_SECONDS: i64 = 9_007_199_254_740_991;

impl UnixTimestamp {
    /// Construct a timestamp from signed unix seconds.
    pub fn from_seconds(seconds: i64) -> Result<Self, WalletTypesError> {
        if !(0..=MAX_SAFE_UNIX_TIMESTAMP_SECONDS).contains(&seconds) {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::TimestampOutOfRange,
            ));
        }

        Ok(Self(seconds))
    }

    /// Return unix seconds.
    #[must_use]
    pub const fn as_seconds(self) -> i64 {
        self.0
    }
}

/// Metadata needed to route an encrypted record without decrypting it.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct EncryptedRecordHeader {
    /// Schema version for forward-compatible decoding.
    pub schema_version: u16,
    /// Opaque key handle used by the platform keystore.
    pub key_handle_id: KeyHandleId,
    /// AEAD algorithm selected by the platform store.
    pub algorithm: StorageEncryptionAlgorithm,
    /// Creation time used for retention and rotation policy.
    pub created_at: UnixTimestamp,
}

/// Encrypted wallet record owned by the platform storage backend.
///
/// `Clone` is deliberate: versioned storage and compare-and-swap traits return
/// owned ciphertext snapshots. Every copy owns and zeroizes its byte buffers;
/// no plaintext or private key is exposed by cloning this type.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct EncryptedRecord {
    /// Non-secret routing metadata.
    pub header: EncryptedRecordHeader,
    /// Nonce or IV bytes for the encrypted payload.
    pub nonce: Vec<u8>,
    /// Additional authenticated data digest or encoded AAD.
    pub aad: Vec<u8>,
    /// Ciphertext including authentication tag where the selected scheme stores it.
    pub ciphertext: Vec<u8>,
}
