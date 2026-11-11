// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Require an active parent credential before releasing presentation material.

use reallyme_wallet_types::{CredentialRecordId, CredentialStatus};

use crate::{RuntimeError, RuntimeErrorReason, RuntimeResult, WalletRuntimeBackend};

/// Fail closed unless the stored credential exists and is currently active.
///
/// Suspended, revoked, and deleted credentials must never yield a
/// presentation copy, whichever claim policy the request selected.
///
/// `inactive` is the reason returned when the record is missing or inactive,
/// so the caller can say whether a copy was already burned.
pub(crate) fn require_active_credential<B>(
    backend: &mut B,
    credential_id: &CredentialRecordId,
    inactive: RuntimeErrorReason,
) -> RuntimeResult<()>
where
    B: WalletRuntimeBackend + ?Sized,
{
    let (record, _revision) = match backend.get_credential_record(credential_id) {
        Ok(found) => found.into_parts(),
        Err(error) if error.reason == RuntimeErrorReason::RecordNotFound => {
            return Err(RuntimeError::new(inactive));
        }
        Err(error) => return Err(error),
    };
    if &record.id != credential_id || record.status() != CredentialStatus::Active {
        return Err(RuntimeError::new(inactive));
    }
    Ok(())
}
