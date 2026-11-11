// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque storage revisions shared by runtime and provider ports.

/// Opaque provider revision used for compare-and-swap mutations.
///
/// Revisions are monotonically increasing within one record and provider
/// instance. Wallet core rejects a successful compare-and-swap response that
/// does not advance the observed generation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordRevision(u64);

impl RecordRevision {
    /// Construct a revision from a provider-owned generation value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the provider-owned generation value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Domain value paired with the revision observed by its provider read.
///
/// The generic owner deliberately omits `Debug`, serialization, and cloning so
/// wrapping a secret- or privacy-bearing value cannot add those capabilities.
pub struct Versioned<T> {
    value: T,
    revision: RecordRevision,
}

impl<T> Versioned<T> {
    /// Bind a domain value to the revision returned by its provider read.
    #[must_use]
    pub const fn new(value: T, revision: RecordRevision) -> Self {
        Self { value, revision }
    }

    /// Consume the owner into the domain value and observed revision.
    #[must_use]
    pub fn into_parts(self) -> (T, RecordRevision) {
        (self.value, self.revision)
    }

    /// Borrow only the provider revision without exposing the wrapped value.
    #[must_use]
    pub const fn revision(&self) -> RecordRevision {
        self.revision
    }
}
