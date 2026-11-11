// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{CredentialRecordId, WalletTypesError};

use super::valid_stored_ids;

fn id(value: &str) -> Result<CredentialRecordId, WalletTypesError> {
    CredentialRecordId::new(value.to_owned())
}

#[test]
fn stored_credential_ids_match_receipt_count_and_are_unique() -> Result<(), WalletTypesError> {
    let first = id("credential-1")?;
    let second = id("credential-2")?;
    assert!(valid_stored_ids(&[first.clone(), second], 2));
    assert!(!valid_stored_ids(&[], 1));
    assert!(!valid_stored_ids(std::slice::from_ref(&first), 2));
    assert!(!valid_stored_ids(&[first.clone(), first], 2));
    Ok(())
}
