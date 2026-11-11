// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Claim once-only presentation copies from batch pools.

use std::collections::BTreeSet;

use reallyme_wallet_types::{BatchCopyState, CredentialRecordId, OnceOnlyPresentationCopy};

use crate::{InventoryError, InventoryErrorReason, InventoryResult};

/// In-memory selection state for one credential's presentation copies.
///
/// This type does not perform a durable claim. Prepared private-persona
/// presentations require the platform's atomic `PresentationCopyStore` claim
/// before a proof or one-time signing key leaves the wallet.
#[derive(PartialEq, Eq)]
pub struct BatchPool {
    credential_id: CredentialRecordId,
    copies: Vec<OnceOnlyPresentationCopy>,
}

impl BatchPool {
    /// Create a pool for a credential after validating copy identity.
    ///
    /// Duplicate copy ids are rejected because copy identity is the local guard
    /// against verifier-linkable reuse. A duplicate would make audit trails and
    /// persistence reconciliation ambiguous.
    pub fn try_new(
        credential_id: CredentialRecordId,
        copies: Vec<OnceOnlyPresentationCopy>,
    ) -> InventoryResult<Self> {
        if copies
            .iter()
            .any(|copy| copy.credential_id != credential_id)
        {
            return Err(InventoryError::new(
                InventoryErrorReason::CredentialMismatch,
            ));
        }
        if has_duplicate_copy_id(&copies) {
            return Err(InventoryError::new(
                InventoryErrorReason::DuplicatePresentationCopy,
            ));
        }

        Ok(Self {
            credential_id,
            copies,
        })
    }

    /// Return the credential id this pool serves.
    #[must_use]
    pub fn credential_id(&self) -> &CredentialRecordId {
        &self.credential_id
    }

    /// Count copies that remain available.
    #[must_use]
    pub fn available_count(&self) -> usize {
        self.copies
            .iter()
            .filter(|copy| copy.state == BatchCopyState::Available)
            .count()
    }

    /// Mark the next copy claimed within this in-memory snapshot.
    ///
    /// The credential id check keeps allocation bound to the pool owner. That is
    /// deliberately repeated here, even when storage already keys pools by
    /// credential id. The durable storage boundary must separately commit the
    /// unavailable state before returning a private prepared token.
    pub fn claim_for(
        &mut self,
        credential_id: &CredentialRecordId,
    ) -> InventoryResult<OnceOnlyPresentationCopy> {
        if &self.credential_id != credential_id {
            return Err(InventoryError::new(
                InventoryErrorReason::CredentialMismatch,
            ));
        }

        for copy in &mut self.copies {
            if copy.state == BatchCopyState::Available {
                copy.state = BatchCopyState::Claimed;
                return Ok(copy.clone());
            }
        }

        Err(InventoryError::new(
            InventoryErrorReason::BatchPoolExhausted,
        ))
    }
}

fn has_duplicate_copy_id(copies: &[OnceOnlyPresentationCopy]) -> bool {
    let mut seen = BTreeSet::new();
    !copies.iter().all(|copy| seen.insert(copy.id.as_str()))
}

#[cfg(test)]
#[path = "claim_tests.rs"]
mod tests;
