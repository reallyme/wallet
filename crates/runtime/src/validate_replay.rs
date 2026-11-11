// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Check that a journaled response answers the operation being retried.

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

/// Return whether a replayed response may be released for `operation`.
///
/// A replay record is matched to its request only by digest, and the journal
/// lives in provider storage. Before releasing stored bytes, the runtime also
/// requires the stored outcome to be an error or the result variant for this
/// exact operation. A successful once-only presentation-copy claim is never
/// replayed with its copy: those commit a terminal claim marker instead.
pub(crate) fn replay_answers_operation(
    operation: &pb::wallet_operation_request::Operation,
    response: &pb::WalletOperationResponse,
) -> bool {
    use pb::wallet_operation_request::Operation as Request;
    use pb::wallet_operation_result::Result as Result_;

    let result = match response.outcome.as_ref() {
        Some(pb::wallet_operation_response::Outcome::Error(_)) => return true,
        Some(pb::wallet_operation_response::Outcome::Result(result)) => result.result.as_ref(),
        None => return false,
    };
    matches!(
        (operation, result),
        (
            Request::PutWalletLifecycleRecord(_),
            Some(Result_::PutWalletLifecycleRecord(_))
        ) | (
            Request::GetWalletLifecycleRecord(_),
            Some(Result_::GetWalletLifecycleRecord(_))
        ) | (
            Request::ApplyWalletLifecycleEvent(_),
            Some(Result_::ApplyWalletLifecycleEvent(_))
        ) | (
            Request::AppendWalletLifecycleEvidence(_),
            Some(Result_::AppendWalletLifecycleEvidence(_))
        ) | (
            Request::PutCredentialRecord(_),
            Some(Result_::PutCredentialRecord(_))
        ) | (
            Request::GetCredentialRecord(_),
            Some(Result_::GetCredentialRecord(_))
        ) | (
            Request::ApplyCredentialStatusEvidence(_),
            Some(Result_::ApplyCredentialStatusEvidence(_))
        ) | (
            Request::DeleteCredentialRecord(_),
            Some(Result_::DeleteCredentialRecord(_))
        ) | (
            Request::EvaluateVerifierEntitlement(_),
            Some(Result_::EvaluateVerifierEntitlement(_))
        ) | (
            Request::SaveFlowSnapshot(_),
            Some(Result_::SaveFlowSnapshot(_))
        ) | (
            Request::GetFlowSnapshot(_),
            Some(Result_::GetFlowSnapshot(_))
        ) | (
            Request::AppendTransactionLog(_),
            Some(Result_::AppendTransactionLog(_))
        ) | (
            Request::AppendQtspDecision(_),
            Some(Result_::AppendQtspDecision(_))
        )
    )
}

#[cfg(test)]
#[path = "validate_replay_tests.rs"]
mod tests;
