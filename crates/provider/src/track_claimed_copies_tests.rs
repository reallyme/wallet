// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{CredentialRecordId, PresentationCopyId, WalletTypesError};

use super::{ClaimedCopyWindow, MAX_TRACKED_CLAIMED_COPIES};

fn id(index: usize) -> Result<PresentationCopyId, WalletTypesError> {
    PresentationCopyId::new(format!("copy-{index}"))
}

fn credential(name: &str) -> Result<CredentialRecordId, WalletTypesError> {
    CredentialRecordId::new(name.to_owned())
}

#[test]
fn window_rejects_repeats_and_stays_bounded() -> Result<(), WalletTypesError> {
    let mut window = ClaimedCopyWindow::default();
    assert!(window.insert(credential("credential-1")?, id(0)?));
    assert!(!window.insert(credential("credential-1")?, id(0)?));
    for index in 1..=MAX_TRACKED_CLAIMED_COPIES {
        assert!(window.insert(credential("credential-1")?, id(index)?));
    }
    assert_eq!(window.order.len(), MAX_TRACKED_CLAIMED_COPIES);
    assert!(!window.insert(credential("credential-1")?, id(MAX_TRACKED_CLAIMED_COPIES)?));
    Ok(())
}

#[test]
fn same_copy_id_under_another_credential_is_distinct() -> Result<(), WalletTypesError> {
    let mut window = ClaimedCopyWindow::default();
    assert!(window.insert(credential("credential-x")?, id(0)?));
    assert!(window.insert(credential("credential-y")?, id(0)?));
    assert!(!window.insert(credential("credential-x")?, id(0)?));
    Ok(())
}
