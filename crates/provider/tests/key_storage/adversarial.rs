// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An untrusted persistence provider cannot substitute key records or revisions.
#![allow(clippy::field_reassign_with_default)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::decode::{
    decode_did_storage_record, decode_hardware_key_binding_record,
    decode_portable_key_storage_record, decode_wallet_provider_request,
};
use reallyme_wallet_proto_codec::ProtoError;
use reallyme_wallet_provider::{
    build_provider_descriptor, ProviderContractError, ProviderExecutorId, ProviderInvocationMode,
    ProviderTransport, ProviderTransportError, ProviderTransportErrorReason,
    ProviderTransportResult, SynchronousProtobufProviderBackend,
};
use reallyme_wallet_runtime::{RecordRevision, RuntimeError, RuntimeErrorReason};
use zeroize::Zeroizing;

// This source-only integration test consumes the canonical Wallet wire vectors,
// so it cannot accidentally test a separately invented key or custody schema.
const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/wallet-key-storage-v1-golden.txt"
));
const FAMILIES: [Family; 3] = [Family::Did, Family::Portable, Family::Hardware];

#[derive(Clone, Copy)]
enum Family {
    Did,
    Portable,
    Hardware,
}
#[derive(Clone, Copy)]
enum Operation {
    Save,
    Read,
    Delete,
}
#[derive(Clone, Copy)]
enum Reply {
    Normal,
    WrongIdentity,
    MalformedRecord,
    MissingRecord,
    Revision(Option<u64>),
    WrongOperation,
    Error(pb::WalletProviderErrorReason),
}
struct Transport {
    family: Family,
    reply: Reply,
    calls: u32,
}
type Backend = SynchronousProtobufProviderBackend<Transport>;

impl Family {
    const fn id(self) -> &'static str {
        match self {
            Self::Did => "did-record-1",
            Self::Portable => "portable-key-1",
            Self::Hardware => "hardware-key-1",
        }
    }
    fn bytes(self) -> Result<Zeroizing<Vec<u8>>, TestError> {
        let field = match self {
            Self::Did => "did_storage_record",
            Self::Portable => "portable_key_storage_record",
            Self::Hardware => "hardware_key_binding_record",
        };
        let hex = VECTORS
            .lines()
            .find_map(|line| {
                line.split_once('=')
                    .and_then(|(name, value)| (name == field).then_some(value))
            })
            .ok_or(TestError::Fixture)?;
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(TestError::Fixture);
        }
        let bytes = pairs
            .iter()
            .map(|pair| {
                let pair = core::str::from_utf8(pair).map_err(|_| TestError::Fixture)?;
                u8::from_str_radix(pair, 16).map_err(|_| TestError::Fixture)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Zeroizing::new(bytes))
    }
    fn save(
        self,
        backend: &mut Backend,
        expected: Option<RecordRevision>,
        malformed: bool,
    ) -> Result<RecordRevision, TestError> {
        let bytes = self.bytes()?;
        Ok(match self {
            Self::Did => {
                let mut record = decode_did_storage_record(&bytes)?;
                if malformed {
                    record.record_id.clear();
                }
                backend.save_did_storage_record(record, expected)?
            }
            Self::Portable => {
                let mut record = decode_portable_key_storage_record(&bytes)?;
                if malformed {
                    record.record_id.clear();
                }
                backend.save_portable_key_storage_record(record, expected)?
            }
            Self::Hardware => {
                let mut record = decode_hardware_key_binding_record(&bytes)?;
                if malformed {
                    record.record_id.clear();
                }
                backend.save_hardware_key_binding_record(record, expected)?
            }
        })
    }
    fn read(self, backend: &mut Backend, id: &str) -> Result<RecordRevision, TestError> {
        Ok(match self {
            Self::Did => backend.get_did_storage_record(id)?.into_parts().1,
            Self::Portable => backend.get_portable_key_storage_record(id)?.into_parts().1,
            Self::Hardware => backend.get_hardware_key_binding_record(id)?.into_parts().1,
        })
    }
    fn delete(
        self,
        backend: &mut Backend,
        id: &str,
        revision: RecordRevision,
    ) -> Result<(), TestError> {
        match self {
            Self::Did => backend.delete_did_storage_record(id, revision)?,
            Self::Portable => backend.delete_portable_key_storage_record(id, revision)?,
            Self::Hardware => backend.delete_hardware_key_binding_record(id, revision)?,
        }
        Ok(())
    }
    fn read_reply(self, reply: Reply) -> Result<pb::wallet_provider_result::Result, TestError> {
        let bytes = self.bytes()?;
        let id = match reply {
            Reply::WrongIdentity => "substituted-record",
            Reply::MalformedRecord => "",
            _ => self.id(),
        };
        let revision = revision(reply);
        Ok(match self {
            Self::Did => {
                let mut record = decode_did_storage_record(&bytes)?;
                record.record_id = id.to_owned();
                let mut response = pb::GetDidStorageRecordProviderResponse::default();
                if !matches!(reply, Reply::MissingRecord) {
                    response.record = MessageField::some(record);
                }
                response.revision = revision;
                response.into()
            }
            Self::Portable => {
                let mut record = decode_portable_key_storage_record(&bytes)?;
                record.record_id = id.to_owned();
                let mut response = pb::GetPortableKeyStorageRecordProviderResponse::default();
                if !matches!(reply, Reply::MissingRecord) {
                    response.record = MessageField::some(record);
                }
                response.revision = revision;
                response.into()
            }
            Self::Hardware => {
                let mut record = decode_hardware_key_binding_record(&bytes)?;
                record.record_id = id.to_owned();
                let mut response = pb::GetHardwareKeyBindingRecordProviderResponse::default();
                if !matches!(reply, Reply::MissingRecord) {
                    response.record = MessageField::some(record);
                }
                response.revision = revision;
                response.into()
            }
        })
    }
    fn result(
        self,
        operation: Operation,
        reply: Reply,
    ) -> Result<pb::wallet_provider_result::Result, TestError> {
        if matches!(reply, Reply::WrongOperation) {
            let mut response = pb::ReadTrustedTimeProviderResponse::default();
            response.observed_at = MessageField::some(pb::UnixTimestamp {
                seconds: 1,
                ..Default::default()
            });
            return Ok(response.into());
        }
        if matches!(operation, Operation::Read) {
            return self.read_reply(reply);
        }
        let id = if matches!(reply, Reply::WrongIdentity) {
            "substituted-record"
        } else {
            self.id()
        };
        let revision = revision(reply);
        Ok(match (self, operation) {
            (Self::Did, Operation::Save) => {
                let mut response = pb::SaveDidStorageRecordProviderResponse::default();
                response.record_id = id.to_owned();
                response.revision = revision;
                response.into()
            }
            (Self::Portable, Operation::Save) => {
                let mut response = pb::SavePortableKeyStorageRecordProviderResponse::default();
                response.record_id = id.to_owned();
                response.revision = revision;
                response.into()
            }
            (Self::Hardware, Operation::Save) => {
                let mut response = pb::SaveHardwareKeyBindingRecordProviderResponse::default();
                response.record_id = id.to_owned();
                response.revision = revision;
                response.into()
            }
            (Self::Did, Operation::Delete) => {
                pb::DeleteDidStorageRecordProviderResponse::default().into()
            }
            (Self::Portable, Operation::Delete) => {
                pb::DeletePortableKeyStorageRecordProviderResponse::default().into()
            }
            (Self::Hardware, Operation::Delete) => {
                pb::DeleteHardwareKeyBindingRecordProviderResponse::default().into()
            }
            (_, Operation::Read) => return Err(TestError::Fixture),
        })
    }
}

fn revision(reply: Reply) -> MessageField<pb::RecordRevision, buffa::Inline<pb::RecordRevision>> {
    let value = match reply {
        Reply::Revision(value) => value,
        _ => Some(1),
    };
    value
        .map(|value| pb::RecordRevision {
            value,
            ..Default::default()
        })
        .map_or_else(MessageField::none, MessageField::some)
}
impl ProviderTransport for Transport {
    fn invoke(
        &mut self,
        bytes: &[u8],
        maximum: usize,
    ) -> ProviderTransportResult<Zeroizing<Vec<u8>>> {
        self.calls = self.calls.checked_add(1).ok_or_else(super::rejected)?;
        let request = decode_wallet_provider_request(bytes).map_err(|_| super::rejected())?;
        use pb::wallet_provider_request::Request;
        let operation = match (self.family, request.request.as_ref()) {
            (Family::Did, Some(Request::SaveDidStorageRecord(_)))
            | (Family::Portable, Some(Request::SavePortableKeyStorageRecord(_)))
            | (Family::Hardware, Some(Request::SaveHardwareKeyBindingRecord(_))) => Operation::Save,
            (Family::Did, Some(Request::GetDidStorageRecord(_)))
            | (Family::Portable, Some(Request::GetPortableKeyStorageRecord(_)))
            | (Family::Hardware, Some(Request::GetHardwareKeyBindingRecord(_))) => Operation::Read,
            (Family::Did, Some(Request::DeleteDidStorageRecord(_)))
            | (Family::Portable, Some(Request::DeletePortableKeyStorageRecord(_)))
            | (Family::Hardware, Some(Request::DeleteHardwareKeyBindingRecord(_))) => {
                Operation::Delete
            }
            _ => return Err(super::rejected()),
        };
        let mut response = pb::WalletProviderResponse::default();
        response.contract_version = request.contract_version;
        response.executor_id = request.executor_id;
        response.request_id = request.request_id;
        response.outcome = Some(match self.reply {
            Reply::Error(reason) => {
                let mut error = pb::WalletProviderError::default();
                error.reason = EnumValue::from(reason);
                pb::wallet_provider_response::Outcome::Error(Box::new(error))
            }
            _ => {
                let mut result = pb::WalletProviderResult::default();
                result.result = Some(
                    self.family
                        .result(operation, self.reply)
                        .map_err(|_| super::rejected())?,
                );
                pb::wallet_provider_response::Outcome::Result(Box::new(result))
            }
        });
        // Deliberately bypass the safe encoder: a hostile host can return bytes
        // that violate the record contract. The production decoder must refuse them.
        let bytes = Zeroizing::new(response.encode_to_vec());
        if bytes.len() > maximum {
            return Err(ProviderTransportError::new(
                ProviderTransportErrorReason::ResponseTooLarge,
            ));
        }
        Ok(bytes)
    }
}
fn backend(family: Family, reply: Reply) -> Result<Backend, ProviderContractError> {
    SynchronousProtobufProviderBackend::new(
        Transport {
            family,
            reply,
            calls: 0,
        },
        &build_provider_descriptor(ProviderInvocationMode::SynchronousNative),
        ProviderExecutorId::new(82)?,
    )
}
fn rejected<T>(result: Result<T, TestError>, reason: RuntimeErrorReason) {
    assert!(matches!(result, Err(TestError::Runtime(error)) if error.reason == reason));
}
#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("fixture")]
    Fixture,
    #[error("contract")]
    Contract(#[from] ProviderContractError),
    #[error("proto")]
    Proto(#[from] ProtoError),
    #[error("runtime")]
    Runtime(#[from] RuntimeError),
}

#[test]
fn all_key_record_families_round_trip_through_the_provider_boundary() -> Result<(), TestError> {
    for family in FAMILIES {
        let mut provider = backend(family, Reply::Normal)?;
        assert_eq!(family.save(&mut provider, None, false)?.value(), 1);
        assert_eq!(family.read(&mut provider, family.id())?.value(), 1);
        family.delete(&mut provider, family.id(), RecordRevision::new(1))?;
        assert_eq!(provider.transport().calls, 3);
    }
    Ok(())
}
#[test]
fn provider_cannot_substitute_saved_or_loaded_key_record_identity() -> Result<(), TestError> {
    for family in FAMILIES {
        let mut provider = backend(family, Reply::WrongIdentity)?;
        rejected(
            family.save(&mut provider, None, false),
            RuntimeErrorReason::KeyStorageRejected,
        );
        rejected(
            family.read(&mut provider, family.id()),
            RuntimeErrorReason::KeyStorageRejected,
        );
        assert_eq!(provider.transport().calls, 2);
    }
    Ok(())
}
#[test]
fn provider_cannot_promote_malformed_or_unversioned_records() -> Result<(), TestError> {
    for family in FAMILIES {
        for reply in [
            Reply::MalformedRecord,
            Reply::MissingRecord,
            Reply::Revision(None),
            Reply::Revision(Some(0)),
        ] {
            let mut provider = backend(family, reply)?;
            rejected(
                family.read(&mut provider, family.id()),
                RuntimeErrorReason::KeyStorageRejected,
            );
            assert_eq!(provider.transport().calls, 1);
        }
    }
    Ok(())
}
#[test]
fn updates_require_a_strictly_newer_provider_revision() -> Result<(), TestError> {
    for family in FAMILIES {
        for (expected, observed) in [
            (5, Some(4)),
            (5, Some(5)),
            (5, None),
            (5, Some(0)),
            (u64::MAX, Some(u64::MAX)),
        ] {
            let mut provider = backend(family, Reply::Revision(observed))?;
            rejected(
                family.save(&mut provider, Some(RecordRevision::new(expected)), false),
                RuntimeErrorReason::KeyStorageRejected,
            );
        }
        let mut provider = backend(family, Reply::Revision(Some(6)))?;
        assert_eq!(
            family
                .save(&mut provider, Some(RecordRevision::new(5)), false)?
                .value(),
            6
        );
    }
    Ok(())
}
#[test]
fn invalid_writes_and_zero_revision_deletes_never_reach_the_provider() -> Result<(), TestError> {
    for family in FAMILIES {
        let mut provider = backend(family, Reply::Normal)?;
        rejected(
            family.save(&mut provider, Some(RecordRevision::new(0)), false),
            RuntimeErrorReason::KeyStorageRejected,
        );
        rejected(
            family.save(&mut provider, None, true),
            RuntimeErrorReason::KeyStorageRejected,
        );
        rejected(
            family.delete(&mut provider, family.id(), RecordRevision::new(0)),
            RuntimeErrorReason::KeyStorageRejected,
        );
        assert_eq!(provider.transport().calls, 0);
    }
    Ok(())
}
#[test]
fn provider_refusals_remain_typed_without_a_fallback() -> Result<(), TestError> {
    use pb::WalletProviderErrorReason as Reason;
    for family in FAMILIES {
        let mut unsupported = backend(
            family,
            Reply::Error(Reason::WALLET_PROVIDER_ERROR_REASON_UNSUPPORTED_CAPABILITY),
        )?;
        rejected(
            family.save(&mut unsupported, None, false),
            RuntimeErrorReason::ProviderCapabilityUnsupported,
        );
        rejected(
            family.read(&mut unsupported, family.id()),
            RuntimeErrorReason::ProviderCapabilityUnsupported,
        );
        rejected(
            family.delete(&mut unsupported, family.id(), RecordRevision::new(1)),
            RuntimeErrorReason::ProviderCapabilityUnsupported,
        );
        assert_eq!(unsupported.transport().calls, 3);
        let mut missing = backend(
            family,
            Reply::Error(Reason::WALLET_PROVIDER_ERROR_REASON_NOT_FOUND),
        )?;
        rejected(
            family.read(&mut missing, family.id()),
            RuntimeErrorReason::RecordNotFound,
        );
        let mut conflict = backend(
            family,
            Reply::Error(Reason::WALLET_PROVIDER_ERROR_REASON_REVISION_CONFLICT),
        )?;
        rejected(
            family.save(&mut conflict, Some(RecordRevision::new(1)), false),
            RuntimeErrorReason::KeyStorageRevisionConflict,
        );
        rejected(
            family.delete(&mut conflict, family.id(), RecordRevision::new(1)),
            RuntimeErrorReason::KeyStorageRevisionConflict,
        );
    }
    Ok(())
}
#[test]
fn a_result_from_another_operation_cannot_acknowledge_key_deletion() -> Result<(), TestError> {
    for family in FAMILIES {
        let mut provider = backend(family, Reply::WrongOperation)?;
        rejected(
            family.delete(&mut provider, family.id(), RecordRevision::new(1)),
            RuntimeErrorReason::KeyStorageRejected,
        );
    }
    Ok(())
}
#[test]
fn invalid_read_and_delete_identities_are_refused_before_provider_effects() -> Result<(), TestError>
{
    let oversized = "k".repeat(257);
    for family in FAMILIES {
        for id in [
            "",
            "../record",
            "folder/%2e%2e/record",
            "folder/%252e%252e/record",
            "nul\0byte",
            "line\nbreak",
            "record\\slot",
            oversized.as_str(),
        ] {
            let mut provider = backend(family, Reply::Normal)?;
            rejected(
                family.read(&mut provider, id),
                RuntimeErrorReason::KeyStorageRejected,
            );
            rejected(
                family.delete(&mut provider, id, RecordRevision::new(1)),
                RuntimeErrorReason::KeyStorageRejected,
            );
            assert_eq!(provider.transport().calls, 0);
        }
    }
    Ok(())
}
