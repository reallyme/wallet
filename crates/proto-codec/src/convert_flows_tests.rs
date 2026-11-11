// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{Message, MessageField};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;

use super::validate_flow_state_payload;

fn presentation(snapshot: &pb::OpenId4VpPresentationSnapshot) -> bool {
    validate_flow_state_payload(wallet::FlowKind::Presentation, &snapshot.encode_to_vec()).is_ok()
}

fn with_request() -> pb::OpenId4VpPresentationSnapshot {
    let mut snapshot = pb::OpenId4VpPresentationSnapshot::default();
    snapshot.authorization_request = MessageField::some(Default::default());
    snapshot
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn presentation_snapshot_requires_stages_in_order() {
    let received = with_request();
    assert!(presentation(&received));

    let mut selected = with_request();
    selected.selected_query_id = "pid".to_owned();
    selected.credential_record_ids = vec!["credential-1".to_owned()];
    assert!(presentation(&selected));

    let mut consent_without_request = pb::OpenId4VpPresentationSnapshot::default();
    consent_without_request.consent = MessageField::some(Default::default());
    assert!(!presentation(&consent_without_request));

    let mut half_selected = with_request();
    half_selected.selected_query_id = "pid".to_owned();
    assert!(!presentation(&half_selected));

    let mut consent_without_selection = with_request();
    consent_without_selection.consent = MessageField::some(Default::default());
    assert!(!presentation(&consent_without_selection));

    let mut response_without_consent = selected.clone();
    response_without_consent.authorization_response = MessageField::some(Default::default());
    assert!(!presentation(&response_without_consent));
}
