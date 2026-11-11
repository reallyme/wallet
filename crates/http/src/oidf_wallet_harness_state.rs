// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::{Arc, Mutex};

use axum::http::header::{AUTHORIZATION, HOST};
use axum::http::HeaderMap;
use reallyme_openid4vp_wallet::AuthorizationRequestTransport;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    OidfWalletFlowDriver, OidfWalletFlowErrorReason, OidfWalletFlowStatus, OidfWalletHarnessError,
    Problem, DEFAULT_HARNESS_MAX_BODY_BYTES, MAX_CONCURRENT_HARNESS_LAUNCHES,
    MAX_HARNESS_BODY_BYTES,
};

const BEARER_PREFIX: &str = "Bearer ";

/// Shared Axum state for the conformance wallet harness.
#[derive(Clone)]
pub struct OidfWalletHarnessState {
    inner: Arc<Mutex<OidfWalletHarnessMemory>>,
    max_body_bytes: usize,
    flow_driver: Option<Arc<dyn OidfWalletFlowDriver>>,
    allowed_callback_origins: Arc<Vec<String>>,
    allowed_hosts: Arc<Vec<String>>,
    control_token_digest: Option<[u8; 32]>,
    launch_slots: Arc<Semaphore>,
}

impl OidfWalletHarnessState {
    /// Create a harness state using the default request body limit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(OidfWalletHarnessMemory::default())),
            max_body_bytes: DEFAULT_HARNESS_MAX_BODY_BYTES,
            flow_driver: None,
            allowed_callback_origins: Arc::new(Vec::new()),
            allowed_hosts: Arc::new(vec!["127.0.0.1:8787".to_owned()]),
            control_token_digest: None,
            launch_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_HARNESS_LAUNCHES)),
        }
    }

    /// Create a harness state with a composed flow driver.
    #[must_use]
    pub fn with_flow_driver<D>(flow_driver: D) -> Self
    where
        D: OidfWalletFlowDriver + 'static,
    {
        Self {
            inner: Arc::new(Mutex::new(OidfWalletHarnessMemory::default())),
            max_body_bytes: DEFAULT_HARNESS_MAX_BODY_BYTES,
            flow_driver: Some(Arc::new(flow_driver)),
            allowed_callback_origins: Arc::new(Vec::new()),
            allowed_hosts: Arc::new(vec!["127.0.0.1:8787".to_owned()]),
            control_token_digest: None,
            launch_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_HARNESS_LAUNCHES)),
        }
    }

    /// Create a harness state using an explicit request body limit.
    pub fn with_max_body_bytes(max_body_bytes: usize) -> Result<Self, OidfWalletHarnessError> {
        if max_body_bytes == 0 || max_body_bytes > MAX_HARNESS_BODY_BYTES {
            return Err(OidfWalletHarnessError::InvalidBodyLimit);
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(OidfWalletHarnessMemory::default())),
            max_body_bytes,
            flow_driver: None,
            allowed_callback_origins: Arc::new(Vec::new()),
            allowed_hosts: Arc::new(vec!["127.0.0.1:8787".to_owned()]),
            control_token_digest: None,
            launch_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_HARNESS_LAUNCHES)),
        })
    }

    /// Create a harness state using an explicit request body limit and flow driver.
    pub fn with_max_body_bytes_and_flow_driver<D>(
        max_body_bytes: usize,
        flow_driver: D,
    ) -> Result<Self, OidfWalletHarnessError>
    where
        D: OidfWalletFlowDriver + 'static,
    {
        if max_body_bytes == 0 || max_body_bytes > MAX_HARNESS_BODY_BYTES {
            return Err(OidfWalletHarnessError::InvalidBodyLimit);
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(OidfWalletHarnessMemory::default())),
            max_body_bytes,
            flow_driver: Some(Arc::new(flow_driver)),
            allowed_callback_origins: Arc::new(Vec::new()),
            allowed_hosts: Arc::new(vec!["127.0.0.1:8787".to_owned()]),
            control_token_digest: None,
            launch_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_HARNESS_LAUNCHES)),
        })
    }

    /// Restrict request-object retrieval and Browser API submission to exact origins.
    pub fn with_allowed_callback_origins(
        mut self,
        origins: &[&str],
    ) -> Result<Self, OidfWalletHarnessError> {
        if origins.is_empty() {
            return Err(OidfWalletHarnessError::InvalidCallbackOrigin);
        }
        let mut validated = Vec::with_capacity(origins.len());
        for origin in origins {
            let url =
                Url::parse(origin).map_err(|_| OidfWalletHarnessError::InvalidCallbackOrigin)?;
            if url.origin().is_tuple()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
            {
                validated.push(url.origin().ascii_serialization());
            } else {
                return Err(OidfWalletHarnessError::InvalidCallbackOrigin);
            }
        }
        validated.sort();
        validated.dedup();
        self.allowed_callback_origins = Arc::new(validated);
        Ok(self)
    }

    /// Restrict all launch and control requests to explicit HTTP Host values.
    pub fn with_allowed_hosts(mut self, hosts: &[&str]) -> Result<Self, OidfWalletHarnessError> {
        if hosts.is_empty() {
            return Err(OidfWalletHarnessError::InvalidHost);
        }
        let mut validated = Vec::with_capacity(hosts.len());
        for host in hosts {
            if host.is_empty()
                || host.len() > 253
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".:-[]".contains(&byte))
            {
                return Err(OidfWalletHarnessError::InvalidHost);
            }
            validated.push(host.to_ascii_lowercase());
        }
        validated.sort();
        validated.dedup();
        self.allowed_hosts = Arc::new(validated);
        Ok(self)
    }

    /// Bind control-plane access to a high-entropy token supplied by the host.
    pub fn with_control_token(
        mut self,
        token: Zeroizing<String>,
    ) -> Result<Self, OidfWalletHarnessError> {
        if token.len() < 32 || token.len() > 256 || !token.is_ascii() {
            return Err(OidfWalletHarnessError::InvalidControlToken);
        }
        self.control_token_digest = Some(crypto_sha2_256::digest(token.as_bytes()).into_bytes());
        Ok(self)
    }

    pub(super) fn allows_host(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(HOST).iter();
        let Some(host) = values.next().and_then(|value| value.to_str().ok()) else {
            return false;
        };
        values.next().is_none()
            && self
                .allowed_hosts
                .binary_search(&host.to_ascii_lowercase())
                .is_ok()
    }

    pub(super) fn authorizes_control(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = self.control_token_digest else {
            return false;
        };
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let Some(value) = values.next().and_then(|value| value.to_str().ok()) else {
            return false;
        };
        // The authentication scheme is case-insensitive (RFC 7235).
        let Some(token) = value
            .get(..BEARER_PREFIX.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(BEARER_PREFIX))
            .and_then(|_| value.get(BEARER_PREFIX.len()..))
        else {
            return false;
        };
        if values.next().is_some() || token.len() < 32 || token.len() > 256 {
            return false;
        }
        let actual = crypto_sha2_256::digest(token.as_bytes()).into_bytes();
        bool::from(expected.ct_eq(&actual))
    }

    pub(super) fn allows_callback_url(&self, value: &str) -> bool {
        Url::parse(value).is_ok_and(|url| {
            self.allowed_callback_origins
                .binary_search(&url.origin().ascii_serialization())
                .is_ok()
        })
    }

    /// Reserve one of the bounded launch slots, or `None` when all are busy.
    ///
    /// Each launch runs the composed driver on a blocking thread that cannot
    /// be cancelled once started, so the bound keeps a flood of launches from
    /// exhausting the blocking pool.
    pub(super) fn try_reserve_launch(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.launch_slots).try_acquire_owned().ok()
    }

    pub(super) fn flow_driver(&self) -> Option<Arc<dyn OidfWalletFlowDriver>> {
        self.flow_driver.clone()
    }

    pub(super) const fn has_flow_driver(&self) -> bool {
        self.flow_driver.is_some()
    }

    pub(super) const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Return the reset epoch a launch starts in.
    ///
    /// A launch records itself as the latest session only if no reset happened
    /// while it ran, so a reset is never undone by an in-flight launch.
    pub(super) fn launch_epoch(&self) -> Result<u64, Problem> {
        let inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        Ok(inner.epoch)
    }

    pub(super) fn record(
        &self,
        epoch: u64,
        transport: AuthorizationRequestTransport,
        status: LaunchStatus,
        flow: Option<FlowRecord>,
        failure_reason: Option<OidfWalletFlowErrorReason>,
    ) -> Result<LaunchRecord, Problem> {
        let mut inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        let store = inner.epoch == epoch;
        inner.record_transport(
            TransportRecord::from_transport(transport),
            status,
            flow,
            failure_reason,
            store,
        )
    }

    pub(super) fn record_browser_api(
        &self,
        epoch: u64,
        request_count: usize,
        status: LaunchStatus,
        flow: Option<FlowRecord>,
        failure_reason: Option<OidfWalletFlowErrorReason>,
    ) -> Result<LaunchRecord, Problem> {
        let mut inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        let store = inner.epoch == epoch;
        inner.record_transport(
            TransportRecord::BrowserApi { request_count },
            status,
            flow,
            failure_reason,
            store,
        )
    }

    pub(super) fn latest(&self) -> Result<Option<LaunchRecord>, Problem> {
        let inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        Ok(inner.latest.clone())
    }

    pub(super) fn latest_failure_reason(
        &self,
    ) -> Result<Option<OidfWalletFlowErrorReason>, Problem> {
        let inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        Ok(inner.latest.as_ref().and_then(|record| {
            if record.status == LaunchStatus::Failed {
                record.failure_reason
            } else {
                None
            }
        }))
    }

    pub(super) fn reset(&self) -> Result<(), Problem> {
        let mut inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        inner.reset();
        Ok(())
    }
}

impl Default for OidfWalletHarnessState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct OidfWalletHarnessMemory {
    next_session_id: u64,
    latest: Option<LaunchRecord>,
    epoch: u64,
}

impl OidfWalletHarnessMemory {
    fn record_transport(
        &mut self,
        transport: TransportRecord,
        status: LaunchStatus,
        flow: Option<FlowRecord>,
        failure_reason: Option<OidfWalletFlowErrorReason>,
        store: bool,
    ) -> Result<LaunchRecord, Problem> {
        let session_id = self.next_session_id;
        self.next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or(Problem::ServerError)?;
        let record = LaunchRecord {
            session_id,
            status,
            transport,
            flow,
            failure_reason,
        };
        let mut returned = record;
        let handoff = returned
            .flow
            .as_mut()
            .and_then(|flow| flow.redirect_uri.take());
        // The callback fragment is needed for this one response only. Keep the
        // durable latest-session view free of the verifier's one-time secret.
        if store {
            self.latest = Some(returned.clone());
        }
        if let Some(flow) = returned.flow.as_mut() {
            flow.redirect_uri = handoff;
        }
        Ok(returned)
    }

    fn reset(&mut self) {
        self.latest = None;
        self.epoch = self.epoch.wrapping_add(1);
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, ZeroizeOnDrop)]
pub(super) struct LaunchRecord {
    session_id: u64,
    status: LaunchStatus,
    transport: TransportRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow: Option<FlowRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<OidfWalletFlowErrorReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LaunchStatus {
    Completed,
    Failed,
    Unsupported,
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub(super) struct FlowRecord {
    pub(super) status: OidfWalletFlowStatus,
    /// Front-channel handoff returned to the launch caller only. It is
    /// stripped before the record is stored, so session reads never see it.
    pub(super) redirect_uri: Option<Zeroizing<String>>,
}

impl Serialize for FlowRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = if self.redirect_uri.is_some() { 2 } else { 1 };
        let mut record = serializer.serialize_struct("FlowRecord", field_count)?;
        record.serialize_field("status", &self.status)?;
        if let Some(redirect_uri) = self.redirect_uri.as_ref() {
            record.serialize_field("redirect_uri", redirect_uri.as_str())?;
        }
        record.end()
    }
}

impl FlowRecord {
    pub(super) fn from_outcome(outcome: super::OidfWalletFlowOutcome) -> Self {
        let (status, redirect_uri) = outcome.into_parts();
        Self {
            status,
            redirect_uri: redirect_uri.map(Zeroizing::new),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, ZeroizeOnDrop)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum TransportRecord {
    RequestJwt {
        request_object_bytes: usize,
        expected_client_id_present: bool,
        expected_wallet_nonce_present: bool,
    },
    RequestUri {
        request_uri_bytes: usize,
        method: RequestUriMethodRecord,
        wallet_nonce_present: bool,
        expected_client_id_present: bool,
    },
    InlineParams {
        parameter_count: usize,
    },
    BrowserApi {
        request_count: usize,
    },
}

impl TransportRecord {
    fn from_transport(mut transport: AuthorizationRequestTransport) -> Self {
        match &mut transport {
            AuthorizationRequestTransport::RequestJwt {
                jwt,
                expected_client_id,
                expected_wallet_nonce,
            } => Self::RequestJwt {
                request_object_bytes: jwt.len(),
                expected_client_id_present: expected_client_id.is_some(),
                expected_wallet_nonce_present: expected_wallet_nonce.is_some(),
            },
            AuthorizationRequestTransport::RequestUri {
                uri,
                method,
                wallet_nonce,
                expected_client_id,
            } => Self::RequestUri {
                // The full request URI can contain correlation material; the
                // transport owner wipes it after only the size is recorded.
                request_uri_bytes: uri.len(),
                method: RequestUriMethodRecord::from_method(*method),
                wallet_nonce_present: wallet_nonce.is_some(),
                expected_client_id_present: expected_client_id.is_some(),
            },
            AuthorizationRequestTransport::InlineParams { params } => Self::InlineParams {
                parameter_count: params.len(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RequestUriMethodRecord {
    Get,
    Post,
}

impl RequestUriMethodRecord {
    fn from_method(method: reallyme_openid4vp_types::RequestUriMethod) -> Self {
        match method {
            reallyme_openid4vp_types::RequestUriMethod::Get => Self::Get,
            reallyme_openid4vp_types::RequestUriMethod::Post => Self::Post,
        }
    }
}
