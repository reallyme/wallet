// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn records_deferred_issuance_metadata() -> Result<(), TestError> {
    let session = token_exchanged_session_with_attestation()?;
    let session = record_openid4vci_credential_request(session, &request()?, timestamp(15)?)?;
    let response = CredentialResponse::deferred("txn-1".to_owned(), 30)?;

    let session = record_openid4vci_credential_response(session, response)?;

    assert!(matches!(session.state, IssuanceState::Deferred));
    assert!(matches!(
        session.deferred_issuance,
        Some(status)
            if status.transaction_id.as_str() == "txn-1"
                && status.interval_seconds == 30
    ));
    Ok(())
}
