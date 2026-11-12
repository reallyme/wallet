// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed provider calls for Wallet-owned DID and key storage records.
//!
//! These are storage primitives. They check record shape, identity, and
//! revision but apply no lifecycle policy; the composing layer checks the
//! Wallet Unit's lifecycle state before calling them.

use buffa::MessageField;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::{
    validate_did_storage_record, validate_hardware_key_binding_record,
    validate_portable_key_storage_record,
};
use reallyme_wallet_runtime::{RecordRevision, RuntimeResult};
use reallyme_wallet_types::NonEmptyIdentifier;

use crate::provider_backend::ProtobufProviderBackend;
use crate::provider_call_support::{
    provider_request, require_revision, revision_to_proto, runtime_rejected,
};
use crate::{ProviderMethod, ProviderTransport};

/// A generated Wallet storage record paired with its provider revision.
///
/// The owner deliberately implements neither `Debug` nor serialization so a
/// key record cannot be copied into diagnostics through this adapter wrapper.
pub struct VersionedKeyStorageRecord<T> {
    record: T,
    revision: RecordRevision,
}

impl<T> VersionedKeyStorageRecord<T> {
    const fn new(record: T, revision: RecordRevision) -> Self {
        Self { record, revision }
    }

    /// Consume the owner into the generated record and observed revision.
    #[must_use]
    pub fn into_parts(self) -> (T, RecordRevision) {
        (self.record, self.revision)
    }
}

// Hardened generated owners implement Drop, so request builders must assign
// privacy-sensitive fields after `Default` construction.
#[allow(clippy::field_reassign_with_default)]
impl<T, M> ProtobufProviderBackend<T, M>
where
    T: ProviderTransport,
{
    /// Create or compare-and-swap a Wallet-owned DID projection.
    pub fn save_did_storage_record(
        &mut self,
        record: pb::DidStorageRecord,
        expected_revision: Option<RecordRevision>,
    ) -> RuntimeResult<RecordRevision> {
        require_stored_revision(expected_revision, ProviderMethod::SaveDidStorageRecord)?;
        validate_did_storage_record(&record)
            .map_err(|_| runtime_rejected(ProviderMethod::SaveDidStorageRecord))?;
        let expected_id = record.record_id.clone();
        let request = pb::SaveDidStorageRecordProviderRequest {
            record: MessageField::some(record),
            expected_revision: optional_revision(expected_revision),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::SaveDidStorageRecord(response)
                if response.record_id == expected_id =>
            {
                let revision = require_changed_revision(
                    &response.revision,
                    expected_revision,
                    ProviderMethod::SaveDidStorageRecord,
                )?;
                Ok(revision)
            }
            _ => Err(runtime_rejected(ProviderMethod::SaveDidStorageRecord)),
        }
    }

    /// Load and validate a Wallet-owned DID projection.
    pub fn get_did_storage_record(
        &mut self,
        record_id: &str,
    ) -> RuntimeResult<VersionedKeyStorageRecord<pb::DidStorageRecord>> {
        let record_id = require_record_id(record_id, ProviderMethod::GetDidStorageRecord)?;
        let mut request = pb::GetDidStorageRecordProviderRequest::default();
        request.record_id = record_id.as_str().to_owned();
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::GetDidStorageRecord(response) => {
                let record = response
                    .record
                    .as_option()
                    .cloned()
                    .ok_or_else(|| runtime_rejected(ProviderMethod::GetDidStorageRecord))?;
                validate_did_storage_record(&record)
                    .map_err(|_| runtime_rejected(ProviderMethod::GetDidStorageRecord))?;
                if record.record_id != record_id.as_str() {
                    return Err(runtime_rejected(ProviderMethod::GetDidStorageRecord));
                }
                let revision =
                    require_revision(&response.revision, ProviderMethod::GetDidStorageRecord)?;
                Ok(VersionedKeyStorageRecord::new(record, revision))
            }
            _ => Err(runtime_rejected(ProviderMethod::GetDidStorageRecord)),
        }
    }

    /// Delete a DID projection only at the exact observed revision.
    pub fn delete_did_storage_record(
        &mut self,
        record_id: &str,
        expected_revision: RecordRevision,
    ) -> RuntimeResult<()> {
        require_stored_revision(
            Some(expected_revision),
            ProviderMethod::DeleteDidStorageRecord,
        )?;
        let record_id = require_record_id(record_id, ProviderMethod::DeleteDidStorageRecord)?;
        let mut request = pb::DeleteDidStorageRecordProviderRequest::default();
        request.record_id = record_id.as_str().to_owned();
        request.expected_revision = MessageField::some(revision_to_proto(expected_revision));
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::DeleteDidStorageRecord(_) => Ok(()),
            _ => Err(runtime_rejected(ProviderMethod::DeleteDidStorageRecord)),
        }
    }

    /// Create or compare-and-swap an already-wrapped portable key record.
    pub fn save_portable_key_storage_record(
        &mut self,
        record: pb::PortableKeyStorageRecord,
        expected_revision: Option<RecordRevision>,
    ) -> RuntimeResult<RecordRevision> {
        require_stored_revision(
            expected_revision,
            ProviderMethod::SavePortableKeyStorageRecord,
        )?;
        validate_portable_key_storage_record(&record)
            .map_err(|_| runtime_rejected(ProviderMethod::SavePortableKeyStorageRecord))?;
        let expected_id = record.record_id.clone();
        let request = pb::SavePortableKeyStorageRecordProviderRequest {
            record: MessageField::some(record),
            expected_revision: optional_revision(expected_revision),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::SavePortableKeyStorageRecord(response)
                if response.record_id == expected_id =>
            {
                let revision = require_changed_revision(
                    &response.revision,
                    expected_revision,
                    ProviderMethod::SavePortableKeyStorageRecord,
                )?;
                Ok(revision)
            }
            _ => Err(runtime_rejected(
                ProviderMethod::SavePortableKeyStorageRecord,
            )),
        }
    }

    /// Load and validate an already-wrapped portable key record.
    pub fn get_portable_key_storage_record(
        &mut self,
        record_id: &str,
    ) -> RuntimeResult<VersionedKeyStorageRecord<pb::PortableKeyStorageRecord>> {
        let record_id = require_record_id(record_id, ProviderMethod::GetPortableKeyStorageRecord)?;
        let mut request = pb::GetPortableKeyStorageRecordProviderRequest::default();
        request.record_id = record_id.as_str().to_owned();
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::GetPortableKeyStorageRecord(response) => {
                let record =
                    response.record.as_option().cloned().ok_or_else(|| {
                        runtime_rejected(ProviderMethod::GetPortableKeyStorageRecord)
                    })?;
                validate_portable_key_storage_record(&record)
                    .map_err(|_| runtime_rejected(ProviderMethod::GetPortableKeyStorageRecord))?;
                if record.record_id != record_id.as_str() {
                    return Err(runtime_rejected(
                        ProviderMethod::GetPortableKeyStorageRecord,
                    ));
                }
                let revision = require_revision(
                    &response.revision,
                    ProviderMethod::GetPortableKeyStorageRecord,
                )?;
                Ok(VersionedKeyStorageRecord::new(record, revision))
            }
            _ => Err(runtime_rejected(
                ProviderMethod::GetPortableKeyStorageRecord,
            )),
        }
    }

    /// Delete a portable key record only at the exact observed revision.
    pub fn delete_portable_key_storage_record(
        &mut self,
        record_id: &str,
        expected_revision: RecordRevision,
    ) -> RuntimeResult<()> {
        require_stored_revision(
            Some(expected_revision),
            ProviderMethod::DeletePortableKeyStorageRecord,
        )?;
        let record_id =
            require_record_id(record_id, ProviderMethod::DeletePortableKeyStorageRecord)?;
        let mut request = pb::DeletePortableKeyStorageRecordProviderRequest::default();
        request.record_id = record_id.as_str().to_owned();
        request.expected_revision = MessageField::some(revision_to_proto(expected_revision));
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::DeletePortableKeyStorageRecord(_) => Ok(()),
            _ => Err(runtime_rejected(
                ProviderMethod::DeletePortableKeyStorageRecord,
            )),
        }
    }

    /// Create or compare-and-swap an installation-bound hardware binding.
    pub fn save_hardware_key_binding_record(
        &mut self,
        record: pb::HardwareKeyBindingRecord,
        expected_revision: Option<RecordRevision>,
    ) -> RuntimeResult<RecordRevision> {
        require_stored_revision(
            expected_revision,
            ProviderMethod::SaveHardwareKeyBindingRecord,
        )?;
        validate_hardware_key_binding_record(&record)
            .map_err(|_| runtime_rejected(ProviderMethod::SaveHardwareKeyBindingRecord))?;
        let expected_id = record.record_id.clone();
        let request = pb::SaveHardwareKeyBindingRecordProviderRequest {
            record: MessageField::some(record),
            expected_revision: optional_revision(expected_revision),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::SaveHardwareKeyBindingRecord(response)
                if response.record_id == expected_id =>
            {
                let revision = require_changed_revision(
                    &response.revision,
                    expected_revision,
                    ProviderMethod::SaveHardwareKeyBindingRecord,
                )?;
                Ok(revision)
            }
            _ => Err(runtime_rejected(
                ProviderMethod::SaveHardwareKeyBindingRecord,
            )),
        }
    }

    /// Load and validate an installation-bound hardware binding.
    pub fn get_hardware_key_binding_record(
        &mut self,
        record_id: &str,
    ) -> RuntimeResult<VersionedKeyStorageRecord<pb::HardwareKeyBindingRecord>> {
        let record_id = require_record_id(record_id, ProviderMethod::GetHardwareKeyBindingRecord)?;
        let mut request = pb::GetHardwareKeyBindingRecordProviderRequest::default();
        request.record_id = record_id.as_str().to_owned();
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::GetHardwareKeyBindingRecord(response) => {
                let record =
                    response.record.as_option().cloned().ok_or_else(|| {
                        runtime_rejected(ProviderMethod::GetHardwareKeyBindingRecord)
                    })?;
                validate_hardware_key_binding_record(&record)
                    .map_err(|_| runtime_rejected(ProviderMethod::GetHardwareKeyBindingRecord))?;
                if record.record_id != record_id.as_str() {
                    return Err(runtime_rejected(
                        ProviderMethod::GetHardwareKeyBindingRecord,
                    ));
                }
                let revision = require_revision(
                    &response.revision,
                    ProviderMethod::GetHardwareKeyBindingRecord,
                )?;
                Ok(VersionedKeyStorageRecord::new(record, revision))
            }
            _ => Err(runtime_rejected(
                ProviderMethod::GetHardwareKeyBindingRecord,
            )),
        }
    }

    /// Delete a hardware binding only at the exact observed revision.
    pub fn delete_hardware_key_binding_record(
        &mut self,
        record_id: &str,
        expected_revision: RecordRevision,
    ) -> RuntimeResult<()> {
        require_stored_revision(
            Some(expected_revision),
            ProviderMethod::DeleteHardwareKeyBindingRecord,
        )?;
        let record_id =
            require_record_id(record_id, ProviderMethod::DeleteHardwareKeyBindingRecord)?;
        let mut request = pb::DeleteHardwareKeyBindingRecordProviderRequest::default();
        request.record_id = record_id.as_str().to_owned();
        request.expected_revision = MessageField::some(revision_to_proto(expected_revision));
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::DeleteHardwareKeyBindingRecord(_) => Ok(()),
            _ => Err(runtime_rejected(
                ProviderMethod::DeleteHardwareKeyBindingRecord,
            )),
        }
    }
}

// A provider acknowledgement cannot authorize an invalid storage identity.
// Use the shared bounded identifier before allocating or sending the request.
fn require_record_id(record_id: &str, method: ProviderMethod) -> RuntimeResult<NonEmptyIdentifier> {
    NonEmptyIdentifier::try_from(record_id).map_err(|_| runtime_rejected(method))
}

fn require_changed_revision<P>(
    revision: &MessageField<pb::RecordRevision, P>,
    expected_revision: Option<RecordRevision>,
    method: ProviderMethod,
) -> RuntimeResult<RecordRevision>
where
    P: buffa::ProtoBox<pb::RecordRevision>,
{
    let revision = require_revision(revision, method)?;
    if expected_revision.is_some_and(|expected| revision <= expected) {
        return Err(runtime_rejected(method));
    }
    Ok(revision)
}

/// Revision zero never names a stored record, so a compare-and-swap against it
/// is malformed rather than a create.
fn require_stored_revision(
    expected_revision: Option<RecordRevision>,
    method: ProviderMethod,
) -> RuntimeResult<()> {
    if expected_revision.is_some_and(|revision| revision.value() == 0) {
        return Err(runtime_rejected(method));
    }
    Ok(())
}

fn optional_revision(
    revision: Option<RecordRevision>,
) -> MessageField<pb::RecordRevision, buffa::Inline<pb::RecordRevision>> {
    revision
        .map(revision_to_proto)
        .map_or_else(MessageField::none, MessageField::some)
}
