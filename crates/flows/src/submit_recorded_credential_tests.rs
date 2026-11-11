// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    nonce_bound_session, nonce_request, timestamp, token_handle, AcceptRequester, LostRequester,
    NonceProofVerifier, TestError,
};
use crate::{
    record_openid4vci_credential_request, submit_recorded_openid4vci_credential_request,
    FlowErrorReason, IssuanceState,
};

#[test]
fn recorded_dispatch_revalidates_nonce_and_attestation_before_transport() -> Result<(), TestError> {
    for (dispatch_at, expected) in [
        (25, FlowErrorReason::CredentialProofNonceBindingUnavailable),
        (31, FlowErrorReason::InvalidWalletUnitAttestation),
    ] {
        let session = nonce_bound_session()?;
        let token = token_handle(&session)?;
        let request = nonce_request(&session)?;
        let verifier = NonceProofVerifier(Some([7; 32]));
        let recorded =
            record_openid4vci_credential_request(session, &request, timestamp(20)?, &verifier)?;
        let mut transport = LostRequester { calls: 0 };

        let result = submit_recorded_openid4vci_credential_request(
            &recorded,
            &token,
            &request,
            timestamp(dispatch_at)?,
            &verifier,
            &mut transport,
        );
        assert!(matches!(result, Err(error) if error.reason == expected));
        assert_eq!(transport.calls, 0);

        assert!(!recorded
            .credential_submission_started
            .load(std::sync::atomic::Ordering::Acquire));
    }
    Ok(())
}

#[test]
fn recorded_dispatch_accepts_a_fresh_retained_request() -> Result<(), TestError> {
    let session = nonce_bound_session()?;
    let token = token_handle(&session)?;
    let request = nonce_request(&session)?;
    let verifier = NonceProofVerifier(Some([7; 32]));
    let recorded =
        record_openid4vci_credential_request(session, &request, timestamp(20)?, &verifier)?;
    let received = submit_recorded_openid4vci_credential_request(
        &recorded,
        &token,
        &request,
        timestamp(21)?,
        &verifier,
        &mut AcceptRequester,
    )?;
    assert_eq!(received.state(), &IssuanceState::CredentialReceived);
    Ok(())
}

#[test]
fn a_spent_request_stays_uncertain_after_its_nonce_and_attestation_expire() -> Result<(), TestError>
{
    let session = nonce_bound_session()?;
    let token = token_handle(&session)?;
    let request = nonce_request(&session)?;
    let verifier = NonceProofVerifier(Some([7; 32]));
    let recorded =
        record_openid4vci_credential_request(session, &request, timestamp(20)?, &verifier)?;
    let mut transport = LostRequester { calls: 0 };
    for dispatch_at in [20, 31] {
        let result = submit_recorded_openid4vci_credential_request(
            &recorded,
            &token,
            &request,
            timestamp(dispatch_at)?,
            &verifier,
            &mut transport,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason == FlowErrorReason::CredentialSubmissionUncertain
        ));
    }
    assert_eq!(transport.calls, 1);
    Ok(())
}
