// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Import already validated credential records into wallet inventory.

use reallyme_wallet_types::{CredentialRecord, CredentialStatus};

use crate::{
    validate_record::validate_credential_record, InventoryError, InventoryErrorReason,
    InventoryResult,
};

/// Validate that an imported credential has already passed receipt checks.
pub fn import_validated_credential(record: CredentialRecord) -> InventoryResult<CredentialRecord> {
    if record.status() != CredentialStatus::Active {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidImportStatus,
        ));
    }
    validate_credential_record(&record)?;

    Ok(record)
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
