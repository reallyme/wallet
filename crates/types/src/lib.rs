// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared wallet DTOs with no protocol orchestration logic.
//!
//! This crate owns stable records that cross the SDK boundary: credential
//! inventory records, encrypted storage payloads, consent records, transaction
//! log entries, and typed identifiers. It deliberately avoids HTTP, protocol
//! wire parsing, and key material.

mod consent;
mod credential;
mod credential_reuse;
mod detect_path_traversal;
mod distribution;
mod error;
mod flow;
mod identifiers;
mod issuance;
mod issuer_metadata_profile;
mod log;
mod revision;
mod storage;

pub use consent::{
    ConsentAction, ConsentActionKind, ConsentCapture, ConsentDecision, ConsentDerivationInput,
    ConsentDerivationMode, ConsentPredicateOperand, ConsentRequest, ConsentScope,
    DisclosurePolicyDecision, VerifierEntitlement, CONSENT_REQUEST_DIGEST_BYTES,
};
pub use credential::{
    BatchCopyState, CredentialFormat, CredentialMutationError, CredentialMutationErrorReason,
    CredentialRecord, CredentialStatus, CredentialStatusEvidence, CredentialStatusEvidenceMethod,
    CredentialStatusReference, CredentialStatusUpdate, OnceOnlyPresentationCopy,
};
pub use credential_reuse::{CredentialReuseMethod, CredentialReusePolicySelection};
pub use distribution::{
    DistributionBarcode, DistributionBarcodeFormat, DistributionCard, DistributionField,
};
pub use error::{WalletTypesError, WalletTypesErrorReason};
pub use flow::{FlowKind, FlowSnapshot, FlowStateSchemaVersion};
pub use identifiers::{
    AttributeName, CredentialRecordId, FlowSnapshotId, IssuerId, KeyHandleId, NonEmptyIdentifier,
    PresentationCopyId, RelyingPartyId, SignedCredentialIssuer, TransactionLogEntryId,
    WalletUnitAttestationId, MAX_SIGNED_CREDENTIAL_ISSUER_BYTES,
};
pub use issuance::{
    OpenId4VciNotificationDeliveryState, OpenId4VciNotificationEndpoint,
    OpenId4VciNotificationOutboxEntry, MAX_NOTIFICATION_ENDPOINT_BYTES,
    OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES,
};
pub use issuer_metadata_profile::OpenId4VciIssuerMetadataProfile;
pub use log::{
    DecisionOutcome, DisclosedAttribute, QtspDecisionKind, QtspDecisionRecord, TransactionLogEntry,
    TransactionPurpose, TRANSACTION_LOG_HASH_BYTES,
};
pub use revision::{RecordRevision, Versioned};
pub use storage::{
    EncryptedRecord, EncryptedRecordHeader, StorageEncryptionAlgorithm, UnixTimestamp,
    AES_256_GCM_SIV_NONCE_LENGTH, MAX_SAFE_UNIX_TIMESTAMP_SECONDS, XCHACHA20_POLY1305_NONCE_LENGTH,
};

mod reuse_state;

mod consent_receipt;

mod history;

mod execution;

pub use consent_receipt::{
    ConsentPolicyChoice, ConsentPolicyContext, ConsentReceipt, ConsentRetention,
    ReaderSessionBinding, MAX_CONSENT_POLICIES,
};
pub use execution::{
    FlowDisposition, FlowEffect, FlowEffectKind, FlowEffectState, FlowExecutionRecord,
    MAX_EXECUTION_SNAPSHOT_BYTES, MAX_FLOW_EFFECTS, MAX_FLOW_EFFECT_BYTES,
    MAX_FLOW_EFFECT_TOTAL_BYTES,
};
pub use history::{
    HistoryCursor, HistoryFailureReason, HistoryOutcome, HistoryPurpose, TransactionHistoryRecord,
    MAX_HISTORY_ATTRIBUTES, MAX_HISTORY_CREDENTIALS, MAX_HISTORY_PAGE_SIZE,
};
pub use reuse_state::{
    CredentialReuseState, ReplenishmentIntent, ReuseClaim, ReuseInstance, MAX_REUSE_CLAIMS,
    MAX_REUSE_INSTANCES,
};

mod nonce;
pub use nonce::IssuerNonceBinding;
