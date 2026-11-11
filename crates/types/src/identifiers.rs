// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strong identifier wrappers used across wallet crates.

use core::fmt;

use crate::detect_path_traversal::contains_path_traversal;
use crate::{WalletTypesError, WalletTypesErrorReason};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const MAX_IDENTIFIER_BYTES: usize = 256;
/// Maximum exact issuer-claim length accepted by the SD-JWT receipt boundary.
pub const MAX_SIGNED_CREDENTIAL_ISSUER_BYTES: usize = 2_048;

/// A validated non-empty identifier suitable for logs and storage keys.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ZeroizeOnDrop)]
pub struct NonEmptyIdentifier(String);

impl fmt::Debug for NonEmptyIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NonEmptyIdentifier(<redacted>)")
    }
}

impl NonEmptyIdentifier {
    /// Validate and construct a bounded identifier.
    pub fn new(value: String) -> Result<Self, WalletTypesError> {
        // Validation failures must wipe the input owner as well as successful
        // identifiers; otherwise malformed personal data survives deallocation.
        let mut value = Zeroizing::new(value);
        if value.is_empty() {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::EmptyIdentifier,
            ));
        }

        if value.len() > MAX_IDENTIFIER_BYTES {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::IdentifierTooLong,
            ));
        }

        // Identifiers cross storage and display boundaries. Reject control and
        // direction-changing characters and `..` segments before either use,
        // including segments hidden behind percent-encoding. Other encoding,
        // such as `%2F` in a `redirect_uri:` client identifier, is kept.
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
            || contains_path_traversal(&value)
        {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::InvalidIdentifier,
            ));
        }

        Ok(Self(core::mem::take(&mut *value)))
    }

    /// Borrow the identifier value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Identifier for a credential stored in wallet inventory.
pub type CredentialRecordId = NonEmptyIdentifier;

/// Identifier for a once-only presentation copy.
pub type PresentationCopyId = NonEmptyIdentifier;

/// Identifier for a relying party or verifier.
pub type RelyingPartyId = NonEmptyIdentifier;

/// Identifier for an issuer.
pub type IssuerId = NonEmptyIdentifier;

/// Exact issuer claim authenticated from a signed credential.
///
/// This is deliberately distinct from [`IssuerId`]. OpenID Credential Issuer
/// metadata identifiers and credential-level issuer claims can be different
/// identifiers, even when they resolve to the same deployment. Callers must
/// preserve the verified claim byte-for-byte rather than normalize or infer it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ZeroizeOnDrop)]
pub struct SignedCredentialIssuer(String);

impl fmt::Debug for SignedCredentialIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedCredentialIssuer(<redacted>)")
    }
}

impl SignedCredentialIssuer {
    /// Validate and construct an exact, bounded credential issuer claim.
    pub fn new(value: String) -> Result<Self, WalletTypesError> {
        // Validation failures must wipe the input owner as well as successful
        // identifiers; otherwise malformed personal data survives deallocation.
        let mut value = Zeroizing::new(value);
        if value.is_empty() {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::EmptyIdentifier,
            ));
        }
        if value.len() > MAX_SIGNED_CREDENTIAL_ISSUER_BYTES {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::IdentifierTooLong,
            ));
        }
        if !value.as_bytes().iter().all(u8::is_ascii_graphic) {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::InvalidIdentifier,
            ));
        }
        Ok(Self(core::mem::take(&mut *value)))
    }

    /// Borrow the issuer claim without applying identifier normalization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Identifier for a keystore-held key handle.
///
/// This is intentionally distinct from credential, issuer, and flow
/// identifiers. Key handles cross storage and provider boundaries, so accepting
/// an identifier from another domain through a type alias would defeat the
/// compile-time binding that those boundaries rely on.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ZeroizeOnDrop)]
pub struct KeyHandleId(String);

impl fmt::Debug for KeyHandleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyHandleId(<redacted>)")
    }
}

impl KeyHandleId {
    /// Validate and construct a bounded opaque key handle.
    pub fn new(value: String) -> Result<Self, WalletTypesError> {
        // Validation failures must wipe the input owner as well as successful
        // identifiers; otherwise malformed personal data survives deallocation.
        let mut value = Zeroizing::new(value);
        if value.is_empty() {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::EmptyIdentifier,
            ));
        }
        if value.len() > MAX_IDENTIFIER_BYTES {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::IdentifierTooLong,
            ));
        }
        // Key handles reach storage and provider boundaries too, so they get
        // the same separator and traversal checks as other identifiers.
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
            || contains_path_traversal(&value)
        {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::InvalidIdentifier,
            ));
        }
        Ok(Self(core::mem::take(&mut *value)))
    }

    /// Borrow the opaque provider handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Identifier for a wallet unit attestation.
pub type WalletUnitAttestationId = NonEmptyIdentifier;

/// Identifier for a transaction log entry.
pub type TransactionLogEntryId = NonEmptyIdentifier;

/// Identifier for a resumable wallet flow snapshot.
pub type FlowSnapshotId = NonEmptyIdentifier;

/// Credential attribute name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ZeroizeOnDrop)]
pub struct AttributeName(String);

impl fmt::Debug for AttributeName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttributeName(<redacted>)")
    }
}

impl AttributeName {
    /// Validate and construct an attribute name.
    pub fn new(value: String) -> Result<Self, WalletTypesError> {
        // Validation failures must wipe the input owner as well as successful
        // identifiers; otherwise malformed personal data survives deallocation.
        let mut value = Zeroizing::new(value);
        if value.is_empty() {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::EmptyAttributeName,
            ));
        }

        if value.len() > MAX_IDENTIFIER_BYTES {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::IdentifierTooLong,
            ));
        }

        // Attribute names become display labels and map keys; keep their
        // namespace grammar narrow and independent of path or URL syntax.
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
            || value.contains("..")
        {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::InvalidIdentifier,
            ));
        }

        Ok(Self(core::mem::take(&mut *value)))
    }

    /// Borrow the attribute name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
#[path = "identifiers_tests.rs"]
mod tests;
