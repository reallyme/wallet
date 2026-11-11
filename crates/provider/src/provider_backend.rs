// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated provider transport ownership and invocation.

use core::marker::PhantomData;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::decode::decode_wallet_provider_response;
use reallyme_wallet_proto_codec::encode::encode_wallet_provider_request;
use reallyme_wallet_runtime::RuntimeResult;
use reallyme_wallet_types::NonEmptyIdentifier;

use crate::provider_call_support::{map_provider_error, runtime_rejected};
use crate::track_claimed_copies::ClaimedCopyWindow;
use crate::{
    validate_provider_descriptor, validate_provider_exchange, ProviderContractError,
    ProviderExecutorId, ProviderInvocationMode, ProviderMethod, ProviderRequestSequence,
    ProviderTransport, ProviderTrustedClock, ValidatedProviderDescriptor, ValidatedProviderOutcome,
    WalletLifecycleAuthorityVerifier,
};

/// Marker preventing native and asynchronous-host descriptors from being
/// interchanged after construction.
pub struct SynchronousNativeProviderMode;

/// Marker preventing asynchronous-host descriptors from entering native
/// callback adapters.
pub struct AsynchronousHostProviderMode;

/// Runtime backend that invokes one versioned protobuf provider transport.
///
/// The mode parameter is deliberately zero-sized. Its only purpose is to keep
/// a descriptor validated for one host invocation model from being moved into
/// an adapter for the other model.
pub struct ProtobufProviderBackend<T, M> {
    transport: T,
    descriptor: ValidatedProviderDescriptor,
    sequence: ProviderRequestSequence,
    pub(crate) claimed_presentation_copy_ids: ClaimedCopyWindow,
    pub(crate) wallet_instance_id: Option<NonEmptyIdentifier>,
    pub(crate) trusted_clock: Option<Box<dyn ProviderTrustedClock>>,
    pub(crate) lifecycle_authority: Option<Box<dyn WalletLifecycleAuthorityVerifier>>,
    mode: PhantomData<M>,
}

/// Synchronous provider backend consumed by an owning SDK adapter.
pub type SynchronousProtobufProviderBackend<T> =
    ProtobufProviderBackend<T, SynchronousNativeProviderMode>;

/// Provider backend for a replay-safe asynchronous host turn transport.
pub type AsynchronousHostProtobufProviderBackend<T> =
    ProtobufProviderBackend<T, AsynchronousHostProviderMode>;

impl<T> ProtobufProviderBackend<T, SynchronousNativeProviderMode>
where
    T: ProviderTransport,
{
    /// Validate and bind a complete synchronous provider to one executor.
    pub fn new(
        transport: T,
        descriptor: &pb::WalletProviderDescriptor,
        executor_id: ProviderExecutorId,
    ) -> Result<Self, ProviderContractError> {
        Self::new_for_mode(
            transport,
            descriptor,
            executor_id,
            ProviderInvocationMode::SynchronousNative,
        )
    }

    /// Bind a synchronous provider to the Wallet Unit it stores.
    ///
    /// The host must construct the transport for this same Wallet Unit; the
    /// runtime reloads its lifecycle record before each regulated operation.
    pub fn new_for_wallet(
        transport: T,
        descriptor: &pb::WalletProviderDescriptor,
        executor_id: ProviderExecutorId,
        wallet_instance_id: NonEmptyIdentifier,
    ) -> Result<Self, ProviderContractError> {
        let mut backend = Self::new_for_mode(
            transport,
            descriptor,
            executor_id,
            ProviderInvocationMode::SynchronousNative,
        )?;
        backend.wallet_instance_id = Some(wallet_instance_id);
        Ok(backend)
    }
}

impl<T> ProtobufProviderBackend<T, AsynchronousHostProviderMode>
where
    T: ProviderTransport,
{
    /// Validate and bind a complete asynchronous-host provider turn transport.
    ///
    /// The transport itself remains synchronous because each call only emits
    /// or replays one provider protocol turn. The WASM/TypeScript adapter owns
    /// awaiting the host provider between turns.
    pub fn new(
        transport: T,
        descriptor: &pb::WalletProviderDescriptor,
        executor_id: ProviderExecutorId,
    ) -> Result<Self, ProviderContractError> {
        Self::new_for_mode(
            transport,
            descriptor,
            executor_id,
            ProviderInvocationMode::AsynchronousHost,
        )
    }

    /// Bind an asynchronous host provider to the Wallet Unit it stores.
    pub fn new_for_wallet(
        transport: T,
        descriptor: &pb::WalletProviderDescriptor,
        executor_id: ProviderExecutorId,
        wallet_instance_id: NonEmptyIdentifier,
    ) -> Result<Self, ProviderContractError> {
        let mut backend = Self::new_for_mode(
            transport,
            descriptor,
            executor_id,
            ProviderInvocationMode::AsynchronousHost,
        )?;
        backend.wallet_instance_id = Some(wallet_instance_id);
        Ok(backend)
    }
}

impl<T, M> ProtobufProviderBackend<T, M>
where
    T: ProviderTransport,
{
    fn new_for_mode(
        transport: T,
        descriptor: &pb::WalletProviderDescriptor,
        executor_id: ProviderExecutorId,
        required_mode: ProviderInvocationMode,
    ) -> Result<Self, ProviderContractError> {
        let descriptor = validate_provider_descriptor(descriptor, required_mode)?;
        Ok(Self {
            transport,
            descriptor,
            sequence: ProviderRequestSequence::new(executor_id),
            claimed_presentation_copy_ids: ClaimedCopyWindow::default(),
            wallet_instance_id: None,
            trusted_clock: None,
            lifecycle_authority: None,
            mode: PhantomData,
        })
    }

    /// Attach the host's trusted clock.
    ///
    /// Rust hosts can attach a local capability in place of the provider
    /// transport turn. Both paths must supply trusted time.
    #[must_use]
    pub fn with_trusted_clock(mut self, clock: Box<dyn ProviderTrustedClock>) -> Self {
        self.trusted_clock = Some(clock);
        self
    }

    /// Attach the host's verifier for authority-bearing lifecycle evidence.
    ///
    /// Rust hosts can attach a local capability in place of the provider
    /// transport turn. Both paths must authenticate the lifecycle evidence.
    #[must_use]
    pub fn with_lifecycle_authority_verifier(
        mut self,
        verifier: Box<dyn WalletLifecycleAuthorityVerifier>,
    ) -> Self {
        self.lifecycle_authority = Some(verifier);
        self
    }

    /// Borrow the bound transport for package-level diagnostics and tests.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutably borrow the bound transport for controlled package integration.
    #[must_use]
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub(crate) fn call(
        &mut self,
        request: pb::WalletProviderRequest,
    ) -> RuntimeResult<pb::wallet_provider_result::Result> {
        let method = ProviderMethod::from_request(&request)
            .map_err(|_| runtime_rejected(ProviderMethod::BeginOperation))?;
        let mut correlated = request;
        self.sequence
            .assign(&mut correlated)
            .map_err(|_| runtime_rejected(method))?;
        let encoded =
            encode_wallet_provider_request(&correlated).map_err(|_| runtime_rejected(method))?;
        let response_bytes = self
            .transport
            .invoke(&encoded, self.descriptor.max_response_bytes())
            .map_err(|_| runtime_rejected(method))?;
        if response_bytes.len() > self.descriptor.max_response_bytes() {
            return Err(runtime_rejected(method));
        }
        let mut response = decode_wallet_provider_response(&response_bytes)
            .map_err(|_| runtime_rejected(method))?;
        match validate_provider_exchange(&correlated, &response)
            .map_err(|_| runtime_rejected(method))?
        {
            ValidatedProviderOutcome::Error(reason) => {
                return Err(map_provider_error(method, reason));
            }
            ValidatedProviderOutcome::Success => {}
        }
        match response.outcome.take() {
            Some(pb::wallet_provider_response::Outcome::Result(mut result)) => {
                result.result.take().ok_or_else(|| runtime_rejected(method))
            }
            Some(pb::wallet_provider_response::Outcome::Error(_)) | None => {
                Err(runtime_rejected(method))
            }
        }
    }
}
