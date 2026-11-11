// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provider-backend evidence for Wallet-owned DID/key persistence calls.

// Hardened generated owners implement Drop and cannot use struct-update
// syntax without moving their hidden unknown-field owner.
#![allow(clippy::field_reassign_with_default)]

use buffa::MessageField;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::decode::decode_wallet_provider_request;
use reallyme_wallet_proto_codec::encode::encode_wallet_provider_response;
use reallyme_wallet_provider::{
    build_provider_descriptor, ProviderContractError, ProviderExecutorId, ProviderInvocationMode,
    ProviderTransport, ProviderTransportError, ProviderTransportErrorReason,
    ProviderTransportResult, SynchronousProtobufProviderBackend,
};
use reallyme_wallet_runtime::{RecordRevision, RuntimeErrorReason};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum SaveResponse {
    Exact,
    WrongRecord,
}

struct DidStorageTransport {
    response: SaveResponse,
    calls: usize,
}

impl ProviderTransport for DidStorageTransport {
    fn invoke(
        &mut self,
        request_bytes: &[u8],
        max_response_bytes: usize,
    ) -> ProviderTransportResult<Zeroizing<Vec<u8>>> {
        self.calls = self.calls.saturating_add(1);
        let request = decode_wallet_provider_request(request_bytes).map_err(|_| rejected())?;
        let record_id = match request.request.as_ref() {
            Some(pb::wallet_provider_request::Request::SaveDidStorageRecord(save)) => save
                .record
                .as_option()
                .map(|record| record.record_id.as_str())
                .ok_or_else(rejected)?,
            Some(_) | None => return Err(rejected()),
        };

        let mut saved = pb::SaveDidStorageRecordProviderResponse::default();
        saved.record_id = match self.response {
            SaveResponse::Exact => record_id.to_owned(),
            SaveResponse::WrongRecord => "wrong-record".to_owned(),
        };
        saved.revision = MessageField::some(pb::RecordRevision {
            value: 1,
            ..Default::default()
        });
        let mut result = pb::WalletProviderResult::default();
        result.result = saved.into();
        let mut response = pb::WalletProviderResponse::default();
        response.contract_version = request.contract_version;
        response.executor_id = request.executor_id;
        response.request_id = request.request_id;
        response.outcome = Some(pb::wallet_provider_response::Outcome::Result(Box::new(
            result,
        )));
        let encoded = encode_wallet_provider_response(&response).map_err(|_| rejected())?;
        if encoded.len() > max_response_bytes {
            return Err(ProviderTransportError::new(
                ProviderTransportErrorReason::ResponseTooLarge,
            ));
        }
        Ok(encoded)
    }
}

#[test]
fn save_did_storage_rejects_backward_revision() -> Result<(), ProviderContractError> {
    let mut backend = backend(SaveResponse::Exact)?;
    let result = backend.save_did_storage_record(did_record(), Some(RecordRevision::new(2)));
    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::KeyStorageRejected
    ));
    Ok(())
}

#[test]
fn key_storage_calls_reject_revision_zero_before_the_provider() -> Result<(), ProviderContractError>
{
    let mut backend = backend(SaveResponse::Exact)?;
    let save = backend.save_did_storage_record(did_record(), Some(RecordRevision::new(0)));
    assert!(matches!(
        save,
        Err(error) if error.reason == RuntimeErrorReason::KeyStorageRejected
    ));
    let delete = backend.delete_did_storage_record("did-record-provider-1", RecordRevision::new(0));
    assert!(matches!(
        delete,
        Err(error) if error.reason == RuntimeErrorReason::KeyStorageRejected
    ));
    assert_eq!(backend.transport().calls, 0);
    Ok(())
}

#[test]
fn save_did_storage_validates_input_and_exact_provider_identity(
) -> Result<(), ProviderContractError> {
    let mut exact = backend(SaveResponse::Exact)?;
    let revision = exact
        .save_did_storage_record(did_record(), None)
        .map_err(|_| contract_assertion())?;
    assert_eq!(revision.value(), 1);
    assert_eq!(exact.transport().calls, 1);

    let mut invalid = backend(SaveResponse::Exact)?;
    let mut invalid_record = did_record();
    invalid_record.document = MessageField::none();
    let error = match invalid.save_did_storage_record(invalid_record, None) {
        Err(error) => error,
        Ok(_) => return Err(contract_assertion()),
    };
    assert_eq!(error.reason, RuntimeErrorReason::KeyStorageRejected);
    assert_eq!(invalid.transport().calls, 0);

    let mut substituted = backend(SaveResponse::WrongRecord)?;
    let error = match substituted.save_did_storage_record(did_record(), None) {
        Err(error) => error,
        Ok(_) => return Err(contract_assertion()),
    };
    assert_eq!(error.reason, RuntimeErrorReason::KeyStorageRejected);
    assert_eq!(substituted.transport().calls, 1);
    Ok(())
}

fn backend(
    response: SaveResponse,
) -> Result<SynchronousProtobufProviderBackend<DidStorageTransport>, ProviderContractError> {
    let descriptor = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    SynchronousProtobufProviderBackend::new(
        DidStorageTransport { response, calls: 0 },
        &descriptor,
        ProviderExecutorId::new(81)?,
    )
}

#[allow(clippy::field_reassign_with_default)]
fn did_record() -> pb::DidStorageRecord {
    let mut record = pb::DidStorageRecord::default();
    record.record_id = "did-record-provider-1".to_owned();
    record.document = MessageField::some(Default::default());
    if let Some(document) = record.document.as_option_mut() {
        document.id = "did:example:provider-holder".to_owned();
    }
    record.updated_at = MessageField::some(pb::UnixTimestamp {
        seconds: 1,
        ..Default::default()
    });
    record
}

fn rejected() -> ProviderTransportError {
    ProviderTransportError::new(ProviderTransportErrorReason::Rejected)
}

fn contract_assertion() -> ProviderContractError {
    ProviderContractError::new(
        reallyme_wallet_provider::ProviderContractErrorReason::ResponseResultMismatch,
    )
}
