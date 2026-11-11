// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Retire a reuse-cohort instance whose credential is no longer active.

use reallyme_wallet_storage::CredentialReuseStore;
use reallyme_wallet_types::{
    CredentialRecord, CredentialStatus, NonEmptyIdentifier, RecordRevision, UnixTimestamp,
};

use crate::enforce_reuse::error;
use crate::{validate_reuse_state, ReuseError, ReuseErrorReason};

/// Mark the cohort instance for `credential` retired once it is revoked or deleted.
///
/// Replenishment counts only usable instances. Without retirement, a revoked
/// or deleted credential would still count as usable and hide exhaustion.
/// Retirement is monotonic, so a suspended credential is not retired: its
/// suspension can be lifted, and claims already refuse it while it lasts.
/// Retiring an already retired instance, or any instance of a retired
/// cohort, is a no-op that returns the current revision.
///
/// Pass `credential` as last read from inventory storage. This function
/// cannot tell a stored record from a constructed one; a constructed inactive
/// record can only retire an instance early, which lowers the reported
/// capacity and removes that instance from rotation, but never makes a
/// credential usable.
pub fn retire_reuse_instance(
    store: &mut dyn CredentialReuseStore,
    cohort: &NonEmptyIdentifier,
    credential: &CredentialRecord,
    now: UnixTimestamp,
) -> Result<RecordRevision, ReuseError> {
    if !matches!(
        credential.status(),
        CredentialStatus::Revoked | CredentialStatus::Deleted
    ) {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    let (mut state, revision) = store.get_reuse_state(cohort)?.into_parts();
    validate_reuse_state(&state)?;
    if &state.id != cohort {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    if state.retired {
        return Ok(revision);
    }
    if now < state.updated_at {
        return Err(error(ReuseErrorReason::TimeRollback));
    }
    let instance = state
        .instances
        .iter_mut()
        .find(|instance| instance.credential_id == credential.id)
        .ok_or_else(|| error(ReuseErrorReason::InvalidState))?;
    if instance.retired {
        return Ok(revision);
    }
    instance.retired = true;
    state.updated_at = now;
    let committed = store.compare_and_swap_reuse_state(revision, state)?;
    if committed <= revision {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    Ok(committed)
}
