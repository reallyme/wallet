// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resumable wallet flow state machines; callers inject I/O, user interaction, storage, and keys.

mod advance;
mod bind_issuer_nonce;
mod build_pre_authorized_token_request;
mod contact_model;
mod credential_request_proof;
mod error;
mod exchange_pre_authorized_token;
mod fragment_contact;
mod guard_execution;
mod import_issued_credentials;
mod issue;
mod poll_deferred_credential;
mod prepare_credential_request;
mod prepare_presentation_consent;
mod reassemble_contact;
mod record_issuance_credential_request;
mod record_issuance_token_exchange;
mod restore_issuance;
mod seal_issuance_checkpoint;
mod state;
mod submit_credential_request;
#[cfg(test)]
mod test_support;
mod validate_contact;
mod validate_contact_kind;
mod validate_credential_request;

pub use advance::{
    authorize_presentation_response, capture_issuance_consent, mark_presentation_matched,
};
pub use bind_issuer_nonce::{
    bind_openid4vci_issuer_nonce, issuer_nonce_session_digest, MAX_ISSUER_NONCE_AGE_SECONDS,
};
pub use build_pre_authorized_token_request::build_openid4vci_pre_authorized_token_request;
pub use contact_model::{
    ContactFrame, ContactLimits, ContactMessage, ContactMessageParts, ContactPayloadKind,
    ContactProtocolVersion, CONTACT_OTHER_KIND_MAX_BYTES, CONTACT_SESSION_ID_LEN,
    CONTACT_TRANSCRIPT_HASH_LEN,
};
pub use credential_request_proof::{
    CredentialProofBinding, CredentialRequestProofBinding, CredentialRequestProofVerifier,
};
pub use error::{FlowError, FlowErrorReason, FlowResult};
pub use exchange_pre_authorized_token::{
    bind_openid4vci_authorization_code_token, exchange_openid4vci_pre_authorized_token,
    restore_openid4vci_access_token_handle, OpenId4VciAccessTokenHandle, OpenId4VciTokenExchanger,
};
pub use fragment_contact::fragment_contact_message;
pub use guard_execution::{
    confirm_flow_effect, create_flow_execution, execution_resume_decision, reserve_flow_effect,
    terminate_flow_execution, validate_execution_record, ExecutionError, ExecutionErrorReason,
    ExecutionResumeDecision, ReservedFlowEffect, MAX_EXECUTION_SNAPSHOT_BYTES,
};
pub use import_issued_credentials::{
    import_openid4vci_issued_credential, import_openid4vci_issued_credentials,
    IssuedCredentialVerifier,
};
pub use issue::{
    bind_openid4vci_wallet_unit_attestation, present_openid4vci_wallet_unit_attestation,
    record_openid4vci_authorized, record_openid4vci_consent, start_openid4vci_issuance,
    start_openid4vci_issuance_from_offer_uri,
    start_openid4vci_issuance_from_offer_uri_with_reuse_capabilities,
    start_openid4vci_issuance_from_offer_uri_with_verified_metadata_profile,
    start_openid4vci_issuance_with_reuse_capabilities,
    start_openid4vci_issuance_with_verified_metadata_profile, DeferredIssuanceStatus,
    IssuanceConsentDecision, IssuanceConsentProvider, IssuanceConsentRequest,
    OpenId4VciIssuanceSession,
};
pub(crate) use issue::{
    record_openid4vci_credential_response, record_openid4vci_deferred_credential_response,
};
pub use poll_deferred_credential::{
    build_openid4vci_deferred_credential_request, poll_openid4vci_deferred_credential,
    DeferredPollSchedule, OpenId4VciDeferredCredentialRequester,
};
pub use prepare_credential_request::{
    prepare_openid4vci_credential_request, prepare_openid4vci_zk_credential_request,
    PreparedOpenId4VciCredentialRequest,
};
pub use prepare_presentation_consent::prepare_presentation_consent_from_satisfaction_plan;
pub use reassemble_contact::reassemble_contact_frames;
pub use record_issuance_credential_request::record_openid4vci_credential_request;
pub(crate) use record_issuance_token_exchange::record_openid4vci_token_exchanged;
pub use restore_issuance::{
    restore_openid4vci_issuance_session, restore_openid4vci_issuance_session_with_nonce_binding,
    restore_openid4vci_issuance_session_with_verified_metadata_profile,
};
pub use seal_issuance_checkpoint::{IssuanceCheckpointKey, IssuanceResumeProof};
pub use state::{IssuanceState, PresentationStage, PresentationState};
pub use submit_credential_request::{
    submit_openid4vci_credential_request, submit_recorded_openid4vci_credential_request,
    OpenId4VciCredentialRequester,
};
pub use validate_contact::validate_contact_message;
