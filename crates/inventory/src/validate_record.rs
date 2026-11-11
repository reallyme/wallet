// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate wallet inventory records before lifecycle transitions.

use reallyme_wallet_types::{CredentialRecord, EncryptedRecord};

use crate::{InventoryError, InventoryErrorReason, InventoryResult};

const AEAD_AUTHENTICATION_TAG_LENGTH: usize = 16;

/// Validate encrypted credential material without decrypting it.
pub(crate) fn validate_encrypted_record(record: &EncryptedRecord) -> InventoryResult<()> {
    if record.header.schema_version == 0
        || record.nonce.len() != record.header.algorithm.nonce_length()
        || record.ciphertext.len() < AEAD_AUTHENTICATION_TAG_LENGTH
    {
        return Err(InventoryError::new(
            InventoryErrorReason::InvalidEncryptedPayload,
        ));
    }

    Ok(())
}

/// Validate inventory shape shared by import and replacement transitions.
pub(crate) fn validate_credential_record(record: &CredentialRecord) -> InventoryResult<()> {
    validate_encrypted_record(&record.encrypted_payload)
}
