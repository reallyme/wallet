// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::ZeroizeOnDrop;

use super::{IssuanceState, PresentationState};
use crate::{ContactMessageParts, DeferredIssuanceStatus};

#[test]
fn resumable_states_advertise_drop_time_zeroization() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<IssuanceState>();
    assert_zeroize_on_drop::<PresentationState>();
    assert_zeroize_on_drop::<ContactMessageParts>();
    assert_zeroize_on_drop::<DeferredIssuanceStatus>();
}

#[test]
fn presentation_state_moves_only_from_its_predecessor() -> Result<(), crate::FlowError> {
    use super::PresentationStage;
    use crate::{mark_presentation_matched, FlowErrorReason};

    let entry = || -> Result<reallyme_wallet_types::TransactionLogEntry, crate::FlowError> {
        Ok(reallyme_wallet_types::TransactionLogEntry {
            id: reallyme_wallet_types::TransactionLogEntryId::new("log-1".to_owned())
                .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidTransition))?,
            purpose: reallyme_wallet_types::TransactionPurpose::Presentation,
            relying_party_id: None,
            disclosed_attributes: Vec::new(),
            occurred_at: reallyme_wallet_types::UnixTimestamp::from_seconds(1)
                .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidTransition))?,
            sequence: 1,
            previous_entry_hash: [0; 32],
            entry_hash: [0; 32],
        })
    };

    let received = PresentationState::received();
    assert_eq!(received.stage(), PresentationStage::RequestReceived);
    assert!(received.authorization().is_none());
    assert!(matches!(
        PresentationState::received().record_logged(entry()?),
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));

    let matched = mark_presentation_matched(received)?;
    assert_eq!(matched.stage(), PresentationStage::Matched);
    assert!(matches!(
        mark_presentation_matched(matched),
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    let matched = mark_presentation_matched(PresentationState::received())?;
    assert!(matches!(
        matched.record_logged(entry()?),
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    Ok(())
}
