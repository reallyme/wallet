// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded in-memory record of copies this backend instance has released.

use std::collections::{BTreeSet, VecDeque};

use reallyme_wallet_types::{CredentialRecordId, PresentationCopyId};

/// Most recent claimed copy identifiers retained per backend instance.
///
/// The durable provider store is the once-only guard. This window only catches
/// a provider that returns the same copy twice to one backend instance, so it
/// keeps a fixed number of recent identifiers instead of growing without bound.
pub(crate) const MAX_TRACKED_CLAIMED_COPIES: usize = 4_096;

type ClaimedCopyKey = (CredentialRecordId, PresentationCopyId);

/// Copy identifiers are unique only within one credential's pool, so the
/// window keys on the credential and the copy together.
#[derive(Default)]
pub(crate) struct ClaimedCopyWindow {
    order: VecDeque<ClaimedCopyKey>,
    members: BTreeSet<ClaimedCopyKey>,
}

impl ClaimedCopyWindow {
    /// Record a released copy; return `false` if it is already in the window.
    pub(crate) fn insert(
        &mut self,
        credential_id: CredentialRecordId,
        copy_id: PresentationCopyId,
    ) -> bool {
        let key = (credential_id, copy_id);
        if !self.members.insert(key.clone()) {
            return false;
        }
        self.order.push_back(key);
        if self.order.len() > MAX_TRACKED_CLAIMED_COPIES {
            if let Some(oldest) = self.order.pop_front() {
                self.members.remove(&oldest);
            }
        }
        true
    }
}

#[cfg(test)]
#[path = "track_claimed_copies_tests.rs"]
mod tests;
