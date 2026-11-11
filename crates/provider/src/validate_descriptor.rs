// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate complete provider descriptors before adapter handle creation.

use buffa::EnumValue;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES;

use crate::{ProviderContractError, ProviderContractErrorReason, ProviderContractResult};

/// Version of the Wallet provider request/response protocol.
pub const WALLET_PROVIDER_CONTRACT_VERSION: u32 = 1;

const REQUIRED_CAPABILITY_COUNT: usize = 25;
const MAX_PROVIDER_RESPONSE_BYTES_U32: u32 = 2_162_688;

/// Complete capability set required by a version-1 Wallet executor.
pub const REQUIRED_PROVIDER_CAPABILITIES: [pb::WalletProviderCapability;
    REQUIRED_CAPABILITY_COUNT] = [
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_BEGIN_OPERATION,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_COMMIT_OPERATION,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_CREATE_WALLET_LIFECYCLE,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_WALLET_LIFECYCLE,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_COMPARE_AND_SWAP_WALLET_LIFECYCLE,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_CREATE_CREDENTIAL,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_CREDENTIAL,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_COMPARE_AND_SWAP_CREDENTIAL,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_DELETE_CREDENTIAL,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_CLAIM_PRESENTATION_COPY,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_SAVE_DID_STORAGE_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_DID_STORAGE_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_DELETE_DID_STORAGE_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_SAVE_PORTABLE_KEY_STORAGE_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_PORTABLE_KEY_STORAGE_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_DELETE_PORTABLE_KEY_STORAGE_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_SAVE_HARDWARE_KEY_BINDING_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_HARDWARE_KEY_BINDING_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_DELETE_HARDWARE_KEY_BINDING_RECORD,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_SAVE_FLOW_SNAPSHOT,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_FLOW_SNAPSHOT,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_APPEND_TRANSACTION_LOG,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_APPEND_QTSP_DECISION,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_READ_TRUSTED_TIME,
    pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_VERIFY_LIFECYCLE_AUTHORITY,
];

/// Adapter invocation model selected during handle creation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProviderInvocationMode {
    /// An owning SDK adapter invokes one provider callback synchronously.
    SynchronousNative,
    /// Browser and other hosts complete provider requests asynchronously.
    AsynchronousHost,
}

impl ProviderInvocationMode {
    const fn to_proto(self) -> pb::WalletProviderInvocationMode {
        match self {
            Self::SynchronousNative => {
                pb::WalletProviderInvocationMode::WALLET_PROVIDER_INVOCATION_MODE_SYNCHRONOUS_NATIVE
            }
            Self::AsynchronousHost => {
                pb::WalletProviderInvocationMode::WALLET_PROVIDER_INVOCATION_MODE_ASYNCHRONOUS_HOST
            }
        }
    }
}

/// Validated provider descriptor safe to bind to an executor handle.
pub struct ValidatedProviderDescriptor {
    invocation_mode: ProviderInvocationMode,
    max_response_bytes: usize,
}

impl ValidatedProviderDescriptor {
    /// Return the validated adapter invocation model.
    #[must_use]
    pub const fn invocation_mode(&self) -> ProviderInvocationMode {
        self.invocation_mode
    }

    /// Return the exact version-1 provider response ceiling.
    #[must_use]
    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

/// Build the complete descriptor an adapter must send during handle creation.
#[must_use]
pub fn build_provider_descriptor(mode: ProviderInvocationMode) -> pb::WalletProviderDescriptor {
    pb::WalletProviderDescriptor {
        contract_version: WALLET_PROVIDER_CONTRACT_VERSION,
        invocation_mode: EnumValue::from(mode.to_proto()),
        capabilities: REQUIRED_PROVIDER_CAPABILITIES
            .iter()
            .copied()
            .map(EnumValue::from)
            .collect(),
        max_response_bytes: MAX_PROVIDER_RESPONSE_BYTES_U32,
        ..Default::default()
    }
}

/// Validate a descriptor against the adapter's required invocation model.
pub fn validate_provider_descriptor(
    descriptor: &pb::WalletProviderDescriptor,
    required_mode: ProviderInvocationMode,
) -> ProviderContractResult<ValidatedProviderDescriptor> {
    if descriptor.contract_version != WALLET_PROVIDER_CONTRACT_VERSION {
        return Err(ProviderContractError::new(
            ProviderContractErrorReason::UnsupportedContractVersion,
        ));
    }
    if descriptor.invocation_mode.as_known() != Some(required_mode.to_proto()) {
        return Err(ProviderContractError::new(
            ProviderContractErrorReason::InvocationModeMismatch,
        ));
    }
    let max_response_bytes = usize::try_from(descriptor.max_response_bytes).map_err(|_| {
        ProviderContractError::new(ProviderContractErrorReason::ResponseLimitInvalid)
    })?;
    if max_response_bytes != MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES {
        return Err(ProviderContractError::new(
            ProviderContractErrorReason::ResponseLimitInvalid,
        ));
    }

    let mut seen = [false; REQUIRED_CAPABILITY_COUNT];
    for value in &descriptor.capabilities {
        let capability = value.as_known().ok_or(ProviderContractError::new(
            ProviderContractErrorReason::CapabilityUnknown,
        ))?;
        let index = capability_index(capability).ok_or(ProviderContractError::new(
            ProviderContractErrorReason::CapabilityUnknown,
        ))?;
        if seen[index] {
            return Err(ProviderContractError::new(
                ProviderContractErrorReason::CapabilityDuplicate,
            ));
        }
        seen[index] = true;
    }
    if seen.iter().any(|present| !present) {
        return Err(ProviderContractError::new(
            ProviderContractErrorReason::CapabilityMissing,
        ));
    }

    Ok(ValidatedProviderDescriptor {
        invocation_mode: required_mode,
        max_response_bytes,
    })
}

const fn capability_index(capability: pb::WalletProviderCapability) -> Option<usize> {
    match capability {
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_BEGIN_OPERATION => Some(0),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_COMMIT_OPERATION => Some(1),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_CREATE_WALLET_LIFECYCLE => Some(2),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_WALLET_LIFECYCLE => Some(3),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_COMPARE_AND_SWAP_WALLET_LIFECYCLE => Some(4),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_APPEND_WALLET_LIFECYCLE_EVIDENCE => None,
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_CREATE_CREDENTIAL => Some(5),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_CREDENTIAL => Some(6),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_COMPARE_AND_SWAP_CREDENTIAL => Some(7),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_DELETE_CREDENTIAL => Some(8),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_CLAIM_PRESENTATION_COPY => Some(9),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_SAVE_DID_STORAGE_RECORD => Some(10),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_DID_STORAGE_RECORD => Some(11),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_DELETE_DID_STORAGE_RECORD => Some(12),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_SAVE_PORTABLE_KEY_STORAGE_RECORD => Some(13),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_PORTABLE_KEY_STORAGE_RECORD => Some(14),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_DELETE_PORTABLE_KEY_STORAGE_RECORD => Some(15),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_SAVE_HARDWARE_KEY_BINDING_RECORD => Some(16),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_HARDWARE_KEY_BINDING_RECORD => Some(17),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_DELETE_HARDWARE_KEY_BINDING_RECORD => Some(18),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_SAVE_FLOW_SNAPSHOT => Some(19),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_GET_FLOW_SNAPSHOT => Some(20),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_APPEND_TRANSACTION_LOG => Some(21),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_APPEND_QTSP_DECISION => Some(22),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_READ_TRUSTED_TIME => Some(23),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_VERIFY_LIFECYCLE_AUTHORITY => Some(24),
        pb::WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_UNSPECIFIED => None,
    }
}
