// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_attestation::AttestationErrorReason;
use reallyme_wallet_consent::ConsentErrorReason;
use reallyme_wallet_flows::FlowErrorReason;
use reallyme_wallet_inventory::InventoryErrorReason;
use reallyme_wallet_keystore::KeystoreErrorReason;
use reallyme_wallet_lifecycle::LifecycleErrorReason;
use reallyme_wallet_log::WalletLogErrorReason;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    self as pb, WalletErrorReason,
};
use reallyme_wallet_storage::StorageErrorReason;
use reallyme_wallet_types::WalletTypesErrorReason;

use super::wallet_error;

/// Map flow reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_flow_detail_reason(reason: FlowErrorReason) -> pb::FlowErrorReason {
    match reason {
        FlowErrorReason::InvalidTransition => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_TRANSITION
        }
        FlowErrorReason::InvalidOpenId4VciState => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_OPENID4VCI_STATE
        }
        FlowErrorReason::InvalidCredentialReusePolicy => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_CREDENTIAL_REUSE_POLICY
        }
        FlowErrorReason::UnsupportedCredentialReusePolicy => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_UNSUPPORTED_CREDENTIAL_REUSE_POLICY
        }
        FlowErrorReason::InvalidIssuerMetadataProfile => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_ISSUER_METADATA_PROFILE
        }
        FlowErrorReason::CredentialOfferResolutionRequired => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CREDENTIAL_OFFER_RESOLUTION_REQUIRED
        }
        FlowErrorReason::PreAuthorizedCodeGrantRequired => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_PRE_AUTHORIZED_CODE_GRANT_REQUIRED
        }
        FlowErrorReason::TransactionCodeRequired => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_TRANSACTION_CODE_REQUIRED
        }
        FlowErrorReason::TransactionCodeUnexpected => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_TRANSACTION_CODE_UNEXPECTED
        }
        FlowErrorReason::TransactionCodeInvalidForOffer => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_TRANSACTION_CODE_INVALID_FOR_OFFER
        }
        FlowErrorReason::OpenId4VciIssuerTransportRejected => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_OPENID4VCI_ISSUER_TRANSPORT_REJECTED
        }
        FlowErrorReason::CredentialSubmissionUncertain => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CREDENTIAL_SUBMISSION_UNCERTAIN
        }
        FlowErrorReason::DeferredPollTooEarly => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_DEFERRED_POLL_TOO_EARLY
        }
        FlowErrorReason::DeferredIssuanceExpired => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_DEFERRED_ISSUANCE_EXPIRED
        }
        FlowErrorReason::AccessTokenSessionMismatch => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_ACCESS_TOKEN_SESSION_MISMATCH
        }
        FlowErrorReason::CredentialProofNonceBindingUnavailable => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CREDENTIAL_PROOF_NONCE_BINDING_UNAVAILABLE
        }
        FlowErrorReason::WalletUnitAttestationRequired => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_WALLET_UNIT_ATTESTATION_REQUIRED
        }
        FlowErrorReason::InvalidWalletUnitAttestation => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_WALLET_UNIT_ATTESTATION
        }
        FlowErrorReason::InvalidCredentialReceipt => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_CREDENTIAL_RECEIPT
        }
        FlowErrorReason::InvalidPresentationSatisfaction => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_PRESENTATION_SATISFACTION
        }
        FlowErrorReason::PresentationConsentExpired => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_PRESENTATION_CONSENT_EXPIRED
        }
        FlowErrorReason::PresentationRequestMismatch => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_PRESENTATION_REQUEST_MISMATCH
        }
        FlowErrorReason::InvalidContactLimits => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_CONTACT_LIMITS
        }
        FlowErrorReason::InvalidContactInput => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_INVALID_CONTACT_INPUT
        }
        FlowErrorReason::ContactMessageTooLarge => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CONTACT_MESSAGE_TOO_LARGE
        }
        FlowErrorReason::ContactAllocationFailed => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CONTACT_ALLOCATION_FAILED
        }
        FlowErrorReason::ContactFrameTooLarge => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CONTACT_FRAME_TOO_LARGE
        }
        FlowErrorReason::ContactTooManyFrames => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CONTACT_TOO_MANY_FRAMES
        }
        FlowErrorReason::ContactSessionTranscriptMismatch => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CONTACT_SESSION_TRANSCRIPT_MISMATCH
        }
        FlowErrorReason::ContactMessageExpired => {
            pb::FlowErrorReason::FLOW_ERROR_REASON_CONTACT_MESSAGE_EXPIRED
        }
    }
}

/// Build the public generated wallet error envelope for flow failures.
#[must_use]
pub fn flow_error_to_proto(reason: FlowErrorReason) -> pb::WalletError {
    wallet_error(
        map_flow_error_reason(reason),
        pb::wallet_error::Detail::Flow(map_flow_detail_reason(reason).into()),
    )
}

/// Map wallet DTO validation reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_wallet_types_error_reason(reason: WalletTypesErrorReason) -> WalletErrorReason {
    match reason {
        WalletTypesErrorReason::EmptyIdentifier
        | WalletTypesErrorReason::IdentifierTooLong
        | WalletTypesErrorReason::InvalidIdentifier
        | WalletTypesErrorReason::EmptyAttributeName
        | WalletTypesErrorReason::TimestampOutOfRange
        | WalletTypesErrorReason::InvalidDistributionCard
        | WalletTypesErrorReason::InvalidNotificationEndpoint
        | WalletTypesErrorReason::InvalidCredentialReusePolicy => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT
        }
        WalletTypesErrorReason::TooManyDistributionFields
        | WalletTypesErrorReason::DistributionTextTooLong
        | WalletTypesErrorReason::DistributionBarcodeTooLarge => {
            WalletErrorReason::WALLET_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
        }
    }
}

/// Map platform storage reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_storage_error_reason(reason: StorageErrorReason) -> WalletErrorReason {
    match reason {
        StorageErrorReason::RecordNotFound => {
            WalletErrorReason::WALLET_ERROR_REASON_RECORD_NOT_FOUND
        }
        StorageErrorReason::RecordAlreadyExists => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE
        }
        StorageErrorReason::RevisionConflict => {
            WalletErrorReason::WALLET_ERROR_REASON_REVISION_CONFLICT
        }
        StorageErrorReason::InvalidIdempotencyKey => {
            WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_KEY_INVALID
        }
        StorageErrorReason::IdempotencyConflict => {
            WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_CONFLICT
        }
        StorageErrorReason::OperationInProgress => {
            WalletErrorReason::WALLET_ERROR_REASON_OPERATION_IN_PROGRESS
        }
        StorageErrorReason::WriteRejected
        | StorageErrorReason::ReadRejected
        | StorageErrorReason::DeleteRejected
        | StorageErrorReason::JournalRejected
        | StorageErrorReason::InvalidReservation => {
            WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE
        }
    }
}

/// Map keystore-boundary reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_keystore_error_reason(reason: KeystoreErrorReason) -> WalletErrorReason {
    match reason {
        KeystoreErrorReason::UnsupportedAlgorithm => {
            WalletErrorReason::WALLET_ERROR_REASON_UNSUPPORTED_ALGORITHM
        }
        KeystoreErrorReason::AttestationKeyHandleMismatch
        | KeystoreErrorReason::AttestationAlgorithmMismatch
        | KeystoreErrorReason::AttestationIssuedInFuture
        | KeystoreErrorReason::AttestationChallengeMismatch
        | KeystoreErrorReason::AttestationStale => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_ATTESTATION_EVIDENCE
        }
        KeystoreErrorReason::KeyHandleNotFound
        | KeystoreErrorReason::OperationRefused
        | KeystoreErrorReason::AttestationUnavailable => {
            WalletErrorReason::WALLET_ERROR_REASON_KEYSTORE_UNAVAILABLE
        }
        KeystoreErrorReason::WalletNotActive => {
            WalletErrorReason::WALLET_ERROR_REASON_WALLET_NOT_ACTIVE
        }
        KeystoreErrorReason::InvalidSigningInput => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT
        }
    }
}

/// Map inventory reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_inventory_error_reason(reason: InventoryErrorReason) -> WalletErrorReason {
    match reason {
        InventoryErrorReason::BatchPoolExhausted => {
            WalletErrorReason::WALLET_ERROR_REASON_BATCH_POOL_EXHAUSTED
        }
        InventoryErrorReason::CredentialMismatch | InventoryErrorReason::IssuerMismatch => {
            WalletErrorReason::WALLET_ERROR_REASON_CREDENTIAL_MISMATCH
        }
        InventoryErrorReason::DuplicatePresentationCopy => {
            WalletErrorReason::WALLET_ERROR_REASON_DUPLICATE_PRESENTATION_COPY
        }
        InventoryErrorReason::StaleStatusEvidence => {
            WalletErrorReason::WALLET_ERROR_REASON_STALE_STATUS_EVIDENCE
        }
        InventoryErrorReason::InvalidStatusEvidence => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATUS_EVIDENCE
        }
        InventoryErrorReason::InvalidImportStatus
        | InventoryErrorReason::InvalidEncryptedPayload
        | InventoryErrorReason::InvalidRefreshEvidence => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_CREDENTIAL_RECEIPT
        }
        InventoryErrorReason::CredentialRevoked => {
            WalletErrorReason::WALLET_ERROR_REASON_CREDENTIAL_REVOKED
        }
        InventoryErrorReason::CredentialDeleted => {
            WalletErrorReason::WALLET_ERROR_REASON_CREDENTIAL_DELETED
        }
    }
}

/// Map consent and relying-party entitlement reasons to the public protobuf enum.
#[must_use]
pub const fn map_consent_error_reason(reason: ConsentErrorReason) -> WalletErrorReason {
    match reason {
        ConsentErrorReason::ReaderAuthenticationRejected => {
            WalletErrorReason::WALLET_ERROR_REASON_RELYING_PARTY_MISMATCH
        }
        ConsentErrorReason::PolicyUnsupported => {
            WalletErrorReason::WALLET_ERROR_REASON_POLICY_DENIED
        }
        ConsentErrorReason::PolicyContextMismatch => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT
        }
        ConsentErrorReason::ReceiptStoreUnavailable => {
            WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE
        }

        ConsentErrorReason::EntitlementExpired => {
            WalletErrorReason::WALLET_ERROR_REASON_ENTITLEMENT_EXPIRED
        }
        // The verifier must send a new request, and the user must consent again.
        ConsentErrorReason::RequestExpired => {
            WalletErrorReason::WALLET_ERROR_REASON_CONSENT_REQUIRED
        }
        ConsentErrorReason::EmptyRequestedScope
        | ConsentErrorReason::ScopeTooLarge
        | ConsentErrorReason::RequestBindingMismatch => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT
        }
        ConsentErrorReason::AttributeNotAuthorized => {
            WalletErrorReason::WALLET_ERROR_REASON_ATTRIBUTE_NOT_AUTHORIZED
        }
        ConsentErrorReason::RegistrationCertificateInvalid => {
            WalletErrorReason::WALLET_ERROR_REASON_REGISTRATION_CERTIFICATE_INVALID
        }
        ConsentErrorReason::RegistrationCertificateStale => {
            WalletErrorReason::WALLET_ERROR_REASON_REGISTRATION_CERTIFICATE_INVALID
        }
        ConsentErrorReason::CaptureAlreadyUsed => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE
        }
        ConsentErrorReason::CaptureStoreUnavailable => {
            WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE
        }
        ConsentErrorReason::FinalDisclosureOutOfScope => {
            WalletErrorReason::WALLET_ERROR_REASON_ATTRIBUTE_NOT_AUTHORIZED
        }
        ConsentErrorReason::ClientBindingMismatch => {
            WalletErrorReason::WALLET_ERROR_REASON_RELYING_PARTY_MISMATCH
        }
        ConsentErrorReason::RegistrationCertificateRelyingPartyMismatch
        | ConsentErrorReason::RelyingPartyMismatch => {
            WalletErrorReason::WALLET_ERROR_REASON_RELYING_PARTY_MISMATCH
        }
        ConsentErrorReason::PolicyDenied => WalletErrorReason::WALLET_ERROR_REASON_POLICY_DENIED,
        ConsentErrorReason::UserRejected => WalletErrorReason::WALLET_ERROR_REASON_USER_REJECTED,
        ConsentErrorReason::MissingConsentAction => {
            WalletErrorReason::WALLET_ERROR_REASON_CONSENT_REQUIRED
        }
        ConsentErrorReason::DerivationIdentifierMissing
        | ConsentErrorReason::DisclosureDerivationIdentifierPresent
        | ConsentErrorReason::InvalidSatisfactionPlan => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_SATISFACTION_PLAN
        }
    }
}

/// Map attestation lifecycle reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_attestation_error_reason(reason: AttestationErrorReason) -> WalletErrorReason {
    match reason {
        AttestationErrorReason::InvalidAttestationEvidence
        | AttestationErrorReason::AttestationChallengeStale
        | AttestationErrorReason::InvalidValidityWindow
        | AttestationErrorReason::WalletUnitAttestationNotYetValid
        | AttestationErrorReason::ProviderBindingMismatch
        | AttestationErrorReason::AttestationSignatureInvalid => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_ATTESTATION_EVIDENCE
        }
        AttestationErrorReason::WalletUnitAttestationExpired => {
            WalletErrorReason::WALLET_ERROR_REASON_ATTESTATION_EXPIRED
        }
        AttestationErrorReason::ReplacementNotAvailable
        | AttestationErrorReason::KeyContinuityMismatch => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE
        }
    }
}

/// Map user-visible transaction-log reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_log_error_reason(reason: WalletLogErrorReason) -> WalletErrorReason {
    match reason {
        WalletLogErrorReason::AppendRejected | WalletLogErrorReason::InvalidTransactionChain => {
            WalletErrorReason::WALLET_ERROR_REASON_LOG_APPEND_REJECTED
        }
        WalletLogErrorReason::MissingRelyingParty => {
            WalletErrorReason::WALLET_ERROR_REASON_MISSING_RELYING_PARTY
        }
        WalletLogErrorReason::MissingDecisionDigest => {
            WalletErrorReason::WALLET_ERROR_REASON_MISSING_DECISION_DIGEST
        }
        WalletLogErrorReason::InvalidDecisionDigest => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_DECISION_DIGEST
        }
        WalletLogErrorReason::DecisionDigestTooLong
        | WalletLogErrorReason::TransactionTranscriptTooLarge => {
            WalletErrorReason::WALLET_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
        }
    }
}

/// Map Wallet Unit lifecycle reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_lifecycle_error_reason(reason: LifecycleErrorReason) -> WalletErrorReason {
    match reason {
        LifecycleErrorReason::InvalidTransition => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_TRANSITION
        }
        LifecycleErrorReason::ClockRollback => WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE,
        LifecycleErrorReason::WalletNotActive => {
            WalletErrorReason::WALLET_ERROR_REASON_WALLET_NOT_ACTIVE
        }
        LifecycleErrorReason::WalletWithdrawn => {
            WalletErrorReason::WALLET_ERROR_REASON_WALLET_WITHDRAWN
        }
        LifecycleErrorReason::WalletDeleted => {
            WalletErrorReason::WALLET_ERROR_REASON_WALLET_DELETED
        }
        LifecycleErrorReason::InvalidEvidence | LifecycleErrorReason::EvidenceDigestRequired => {
            WalletErrorReason::WALLET_ERROR_REASON_LIFECYCLE_EVIDENCE_INVALID
        }
        LifecycleErrorReason::EvidenceDigestTooLarge => {
            WalletErrorReason::WALLET_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
        }
    }
}

/// Map issuance, presentation, contact-delivery, and ZK flow reasons to proto.
#[must_use]
pub const fn map_flow_error_reason(reason: FlowErrorReason) -> WalletErrorReason {
    match reason {
        FlowErrorReason::InvalidTransition => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_TRANSITION
        }
        FlowErrorReason::InvalidOpenId4VciState => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE
        }
        FlowErrorReason::InvalidCredentialReusePolicy => {
            WalletErrorReason::WALLET_ERROR_REASON_CREDENTIAL_REUSE_POLICY_INVALID
        }
        FlowErrorReason::UnsupportedCredentialReusePolicy => {
            WalletErrorReason::WALLET_ERROR_REASON_CREDENTIAL_REUSE_POLICY_UNSUPPORTED
        }
        FlowErrorReason::InvalidIssuerMetadataProfile => {
            WalletErrorReason::WALLET_ERROR_REASON_ISSUER_METADATA_PROFILE_INVALID
        }
        FlowErrorReason::CredentialOfferResolutionRequired => {
            WalletErrorReason::WALLET_ERROR_REASON_CREDENTIAL_OFFER_RESOLUTION_REQUIRED
        }
        FlowErrorReason::PreAuthorizedCodeGrantRequired => {
            WalletErrorReason::WALLET_ERROR_REASON_PRE_AUTHORIZED_CODE_GRANT_REQUIRED
        }
        FlowErrorReason::TransactionCodeRequired => {
            WalletErrorReason::WALLET_ERROR_REASON_TRANSACTION_CODE_REQUIRED
        }
        FlowErrorReason::TransactionCodeUnexpected
        | FlowErrorReason::TransactionCodeInvalidForOffer => {
            WalletErrorReason::WALLET_ERROR_REASON_TRANSACTION_CODE_INVALID
        }
        FlowErrorReason::OpenId4VciIssuerTransportRejected => {
            WalletErrorReason::WALLET_ERROR_REASON_ISSUER_TRANSPORT_REJECTED
        }
        // The request may have reached the issuer; this needs reconciliation,
        // not a blind retry, so it is a state problem rather than a rejection.
        FlowErrorReason::CredentialSubmissionUncertain
        | FlowErrorReason::AccessTokenSessionMismatch
        | FlowErrorReason::DeferredPollTooEarly
        | FlowErrorReason::DeferredIssuanceExpired => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE
        }
        FlowErrorReason::CredentialProofNonceBindingUnavailable => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE
        }
        FlowErrorReason::WalletUnitAttestationRequired => {
            WalletErrorReason::WALLET_ERROR_REASON_WALLET_UNIT_ATTESTATION_REQUIRED
        }
        FlowErrorReason::InvalidWalletUnitAttestation => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_ATTESTATION_EVIDENCE
        }
        FlowErrorReason::InvalidCredentialReceipt => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_CREDENTIAL_RECEIPT
        }
        FlowErrorReason::InvalidPresentationSatisfaction => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_SATISFACTION_PLAN
        }
        FlowErrorReason::PresentationConsentExpired => {
            WalletErrorReason::WALLET_ERROR_REASON_CONSENT_REQUIRED
        }
        FlowErrorReason::PresentationRequestMismatch => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT
        }
        FlowErrorReason::InvalidContactLimits | FlowErrorReason::InvalidContactInput => {
            WalletErrorReason::WALLET_ERROR_REASON_CONTACT_DELIVERY_INVALID
        }
        FlowErrorReason::ContactMessageTooLarge
        | FlowErrorReason::ContactFrameTooLarge
        | FlowErrorReason::ContactTooManyFrames => {
            WalletErrorReason::WALLET_ERROR_REASON_CONTACT_DELIVERY_TOO_LARGE
        }
        FlowErrorReason::ContactAllocationFailed => {
            WalletErrorReason::WALLET_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
        }
        FlowErrorReason::ContactSessionTranscriptMismatch => {
            WalletErrorReason::WALLET_ERROR_REASON_CONTACT_SESSION_BINDING_FAILED
        }
        FlowErrorReason::ContactMessageExpired => {
            WalletErrorReason::WALLET_ERROR_REASON_CONTACT_MESSAGE_EXPIRED
        }
    }
}
