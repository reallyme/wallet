// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_attestation::AttestationErrorReason;
use reallyme_wallet_consent::ConsentErrorReason;
use reallyme_wallet_inventory::InventoryErrorReason;
use reallyme_wallet_keystore::KeystoreErrorReason;
use reallyme_wallet_lifecycle::LifecycleErrorReason;
use reallyme_wallet_log::WalletLogErrorReason;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_storage::StorageErrorReason;
use reallyme_wallet_types::WalletTypesErrorReason;

use super::{
    map_attestation_error_reason, map_consent_error_reason, map_inventory_error_reason,
    map_keystore_error_reason, map_lifecycle_error_reason, map_log_error_reason,
    map_storage_error_reason, map_wallet_types_error_reason, wallet_error,
};

/// Map wallet DTO validation reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_wallet_types_detail_reason(
    reason: WalletTypesErrorReason,
) -> pb::WalletTypesErrorReason {
    match reason {
        WalletTypesErrorReason::EmptyIdentifier => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_EMPTY_IDENTIFIER
        }
        WalletTypesErrorReason::IdentifierTooLong => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_IDENTIFIER_TOO_LONG
        }
        WalletTypesErrorReason::InvalidIdentifier => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_INVALID_IDENTIFIER
        }
        WalletTypesErrorReason::EmptyAttributeName => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_EMPTY_ATTRIBUTE_NAME
        }
        WalletTypesErrorReason::TimestampOutOfRange => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_TIMESTAMP_OUT_OF_RANGE
        }
        WalletTypesErrorReason::InvalidDistributionCard => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_INVALID_DISTRIBUTION_CARD
        }
        WalletTypesErrorReason::TooManyDistributionFields => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_TOO_MANY_DISTRIBUTION_FIELDS
        }
        WalletTypesErrorReason::DistributionTextTooLong => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_DISTRIBUTION_TEXT_TOO_LONG
        }
        WalletTypesErrorReason::DistributionBarcodeTooLarge => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_DISTRIBUTION_BARCODE_TOO_LARGE
        }
        WalletTypesErrorReason::InvalidNotificationEndpoint => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_INVALID_NOTIFICATION_ENDPOINT
        }
        WalletTypesErrorReason::InvalidCredentialReusePolicy => {
            pb::WalletTypesErrorReason::WALLET_TYPES_ERROR_REASON_INVALID_CREDENTIAL_REUSE_POLICY
        }
    }
}

/// Build the public generated wallet error envelope for DTO validation.
#[must_use]
pub fn wallet_types_error_to_proto(reason: WalletTypesErrorReason) -> pb::WalletError {
    wallet_error(
        map_wallet_types_error_reason(reason),
        pb::wallet_error::Detail::WalletTypes(map_wallet_types_detail_reason(reason).into()),
    )
}

/// Map storage reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_storage_detail_reason(reason: StorageErrorReason) -> pb::StorageErrorReason {
    match reason {
        StorageErrorReason::RecordNotFound => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_RECORD_NOT_FOUND
        }
        StorageErrorReason::WriteRejected => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_WRITE_REJECTED
        }
        StorageErrorReason::ReadRejected => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_READ_REJECTED
        }
        StorageErrorReason::DeleteRejected => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_DELETE_REJECTED
        }
        StorageErrorReason::RecordAlreadyExists => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_RECORD_ALREADY_EXISTS
        }
        StorageErrorReason::RevisionConflict => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_REVISION_CONFLICT
        }
        StorageErrorReason::InvalidIdempotencyKey => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_INVALID_IDEMPOTENCY_KEY
        }
        StorageErrorReason::IdempotencyConflict => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_IDEMPOTENCY_CONFLICT
        }
        StorageErrorReason::OperationInProgress => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_OPERATION_IN_PROGRESS
        }
        StorageErrorReason::JournalRejected | StorageErrorReason::InvalidReservation => {
            pb::StorageErrorReason::STORAGE_ERROR_REASON_JOURNAL_REJECTED
        }
    }
}

/// Build the public generated wallet error envelope for storage failures.
#[must_use]
pub fn storage_error_to_proto(reason: StorageErrorReason) -> pb::WalletError {
    wallet_error(
        map_storage_error_reason(reason),
        pb::wallet_error::Detail::Storage(map_storage_detail_reason(reason).into()),
    )
}

/// Map keystore reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_keystore_detail_reason(reason: KeystoreErrorReason) -> pb::KeystoreErrorReason {
    match reason {
        KeystoreErrorReason::KeyHandleNotFound => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_KEY_HANDLE_NOT_FOUND
        }
        KeystoreErrorReason::UnsupportedAlgorithm => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
        }
        KeystoreErrorReason::OperationRefused => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_OPERATION_REFUSED
        }
        KeystoreErrorReason::WalletNotActive => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_WALLET_NOT_ACTIVE
        }
        KeystoreErrorReason::InvalidSigningInput => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_INVALID_SIGNING_INPUT
        }
        KeystoreErrorReason::AttestationUnavailable => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_ATTESTATION_UNAVAILABLE
        }
        KeystoreErrorReason::AttestationKeyHandleMismatch => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_ATTESTATION_KEY_HANDLE_MISMATCH
        }
        KeystoreErrorReason::AttestationIssuedInFuture => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_ATTESTATION_ISSUED_IN_FUTURE
        }
        KeystoreErrorReason::AttestationChallengeMismatch => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_ATTESTATION_CHALLENGE_MISMATCH
        }
        KeystoreErrorReason::AttestationAlgorithmMismatch => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_ATTESTATION_ALGORITHM_MISMATCH
        }
        KeystoreErrorReason::AttestationStale => {
            pb::KeystoreErrorReason::KEYSTORE_ERROR_REASON_ATTESTATION_STALE
        }
    }
}

/// Build the public generated wallet error envelope for keystore failures.
#[must_use]
pub fn keystore_error_to_proto(reason: KeystoreErrorReason) -> pb::WalletError {
    wallet_error(
        map_keystore_error_reason(reason),
        pb::wallet_error::Detail::Keystore(map_keystore_detail_reason(reason).into()),
    )
}

/// Map inventory reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_inventory_detail_reason(reason: InventoryErrorReason) -> pb::InventoryErrorReason {
    match reason {
        InventoryErrorReason::BatchPoolExhausted => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_BATCH_POOL_EXHAUSTED
        }
        InventoryErrorReason::CredentialMismatch => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_CREDENTIAL_MISMATCH
        }
        InventoryErrorReason::DuplicatePresentationCopy => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_DUPLICATE_PRESENTATION_COPY
        }
        InventoryErrorReason::StaleStatusEvidence => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_STALE_STATUS_EVIDENCE
        }
        InventoryErrorReason::InvalidStatusEvidence => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_INVALID_STATUS_EVIDENCE
        }
        InventoryErrorReason::InvalidImportStatus => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_INVALID_IMPORT_STATUS
        }
        InventoryErrorReason::InvalidEncryptedPayload => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_INVALID_ENCRYPTED_PAYLOAD
        }
        InventoryErrorReason::InvalidRefreshEvidence => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_INVALID_REFRESH_EVIDENCE
        }
        InventoryErrorReason::IssuerMismatch => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_ISSUER_MISMATCH
        }
        InventoryErrorReason::CredentialRevoked => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_CREDENTIAL_REVOKED
        }
        InventoryErrorReason::CredentialDeleted => {
            pb::InventoryErrorReason::INVENTORY_ERROR_REASON_CREDENTIAL_DELETED
        }
    }
}

/// Build the public generated wallet error envelope for inventory failures.
#[must_use]
pub fn inventory_error_to_proto(reason: InventoryErrorReason) -> pb::WalletError {
    wallet_error(
        map_inventory_error_reason(reason),
        pb::wallet_error::Detail::Inventory(map_inventory_detail_reason(reason).into()),
    )
}

/// Map consent reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_consent_detail_reason(reason: ConsentErrorReason) -> pb::ConsentErrorReason {
    match reason {
        ConsentErrorReason::ReaderAuthenticationRejected => pb::ConsentErrorReason::CONSENT_ERROR_REASON_READER_AUTHENTICATION_REJECTED,
        ConsentErrorReason::PolicyUnsupported => pb::ConsentErrorReason::CONSENT_ERROR_REASON_POLICY_UNSUPPORTED,
        ConsentErrorReason::PolicyContextMismatch => pb::ConsentErrorReason::CONSENT_ERROR_REASON_POLICY_CONTEXT_MISMATCH,
        ConsentErrorReason::ReceiptStoreUnavailable => pb::ConsentErrorReason::CONSENT_ERROR_REASON_RECEIPT_STORE_UNAVAILABLE,
        ConsentErrorReason::EntitlementExpired => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_ENTITLEMENT_EXPIRED
        }
        ConsentErrorReason::RequestExpired => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_REQUEST_EXPIRED
        }
        ConsentErrorReason::EmptyRequestedScope => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_EMPTY_REQUESTED_SCOPE
        }
        ConsentErrorReason::ScopeTooLarge => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_ATTRIBUTE_NOT_AUTHORIZED
        }
        ConsentErrorReason::AttributeNotAuthorized => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_ATTRIBUTE_NOT_AUTHORIZED
        }
        ConsentErrorReason::RegistrationCertificateInvalid => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_REGISTRATION_CERTIFICATE_INVALID
        }
        ConsentErrorReason::RegistrationCertificateStale => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_REGISTRATION_CERTIFICATE_STALE
        }
        ConsentErrorReason::CaptureAlreadyUsed => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_CAPTURE_ALREADY_USED
        }
        ConsentErrorReason::CaptureStoreUnavailable => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_CAPTURE_STORE_UNAVAILABLE
        }
        ConsentErrorReason::FinalDisclosureOutOfScope => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_FINAL_DISCLOSURE_OUT_OF_SCOPE
        }
        ConsentErrorReason::ClientBindingMismatch => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_CLIENT_BINDING_MISMATCH
        }
        ConsentErrorReason::RegistrationCertificateRelyingPartyMismatch => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_REGISTRATION_CERTIFICATE_RELYING_PARTY_MISMATCH
        }
        ConsentErrorReason::PolicyDenied => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_POLICY_DENIED
        }
        ConsentErrorReason::UserRejected => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_USER_REJECTED
        }
        ConsentErrorReason::RelyingPartyMismatch => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_RELYING_PARTY_MISMATCH
        }
        ConsentErrorReason::MissingConsentAction => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_MISSING_CONSENT_ACTION
        }
        ConsentErrorReason::RequestBindingMismatch => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_RELYING_PARTY_MISMATCH
        }
        ConsentErrorReason::DerivationIdentifierMissing => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_DERIVATION_IDENTIFIER_MISSING
        }
        ConsentErrorReason::DisclosureDerivationIdentifierPresent => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_DISCLOSURE_DERIVATION_IDENTIFIER_PRESENT
        }
        ConsentErrorReason::InvalidSatisfactionPlan => {
            pb::ConsentErrorReason::CONSENT_ERROR_REASON_INVALID_SATISFACTION_PLAN
        }
    }
}

/// Build the public generated wallet error envelope for consent failures.
#[must_use]
pub fn consent_error_to_proto(reason: ConsentErrorReason) -> pb::WalletError {
    wallet_error(
        map_consent_error_reason(reason),
        pb::wallet_error::Detail::Consent(map_consent_detail_reason(reason).into()),
    )
}

/// Map attestation reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_attestation_detail_reason(
    reason: AttestationErrorReason,
) -> pb::AttestationErrorReason {
    match reason {
        AttestationErrorReason::InvalidAttestationEvidence
        | AttestationErrorReason::AttestationChallengeStale => {
            pb::AttestationErrorReason::ATTESTATION_ERROR_REASON_INVALID_ATTESTATION_EVIDENCE
        }
        AttestationErrorReason::InvalidValidityWindow => {
            pb::AttestationErrorReason::ATTESTATION_ERROR_REASON_INVALID_VALIDITY_WINDOW
        }
        AttestationErrorReason::WalletUnitAttestationNotYetValid => {
            pb::AttestationErrorReason::ATTESTATION_ERROR_REASON_WALLET_UNIT_ATTESTATION_NOT_YET_VALID
        }
        AttestationErrorReason::WalletUnitAttestationExpired => {
            pb::AttestationErrorReason::ATTESTATION_ERROR_REASON_WALLET_UNIT_ATTESTATION_EXPIRED
        }
        AttestationErrorReason::ReplacementNotAvailable => {
            pb::AttestationErrorReason::ATTESTATION_ERROR_REASON_REPLACEMENT_NOT_AVAILABLE
        }
        AttestationErrorReason::ProviderBindingMismatch
        | AttestationErrorReason::AttestationSignatureInvalid => {
            pb::AttestationErrorReason::ATTESTATION_ERROR_REASON_INVALID_ATTESTATION_EVIDENCE
        }
        AttestationErrorReason::KeyContinuityMismatch => {
            pb::AttestationErrorReason::ATTESTATION_ERROR_REASON_REPLACEMENT_NOT_AVAILABLE
        }
    }
}

/// Build the public generated wallet error envelope for attestation failures.
#[must_use]
pub fn attestation_error_to_proto(reason: AttestationErrorReason) -> pb::WalletError {
    wallet_error(
        map_attestation_error_reason(reason),
        pb::wallet_error::Detail::Attestation(map_attestation_detail_reason(reason).into()),
    )
}

/// Map log reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_log_detail_reason(reason: WalletLogErrorReason) -> pb::WalletLogErrorReason {
    match reason {
        WalletLogErrorReason::AppendRejected | WalletLogErrorReason::InvalidTransactionChain => {
            pb::WalletLogErrorReason::WALLET_LOG_ERROR_REASON_APPEND_REJECTED
        }
        WalletLogErrorReason::MissingRelyingParty => {
            pb::WalletLogErrorReason::WALLET_LOG_ERROR_REASON_MISSING_RELYING_PARTY
        }
        WalletLogErrorReason::MissingDecisionDigest => {
            pb::WalletLogErrorReason::WALLET_LOG_ERROR_REASON_MISSING_DECISION_DIGEST
        }
        WalletLogErrorReason::InvalidDecisionDigest => {
            pb::WalletLogErrorReason::WALLET_LOG_ERROR_REASON_INVALID_DECISION_DIGEST
        }
        WalletLogErrorReason::DecisionDigestTooLong
        | WalletLogErrorReason::TransactionTranscriptTooLarge => {
            pb::WalletLogErrorReason::WALLET_LOG_ERROR_REASON_DECISION_DIGEST_TOO_LONG
        }
    }
}

/// Build the public generated wallet error envelope for log failures.
#[must_use]
pub fn log_error_to_proto(reason: WalletLogErrorReason) -> pb::WalletError {
    wallet_error(
        map_log_error_reason(reason),
        pb::wallet_error::Detail::Log(map_log_detail_reason(reason).into()),
    )
}

/// Map lifecycle reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_lifecycle_detail_reason(reason: LifecycleErrorReason) -> pb::LifecycleErrorReason {
    match reason {
        LifecycleErrorReason::InvalidTransition => {
            pb::LifecycleErrorReason::LIFECYCLE_ERROR_REASON_INVALID_TRANSITION
        }
        LifecycleErrorReason::ClockRollback => {
            pb::LifecycleErrorReason::LIFECYCLE_ERROR_REASON_CLOCK_ROLLBACK
        }
        LifecycleErrorReason::WalletNotActive => {
            pb::LifecycleErrorReason::LIFECYCLE_ERROR_REASON_WALLET_NOT_ACTIVE
        }
        LifecycleErrorReason::WalletWithdrawn => {
            pb::LifecycleErrorReason::LIFECYCLE_ERROR_REASON_WALLET_WITHDRAWN
        }
        LifecycleErrorReason::WalletDeleted => {
            pb::LifecycleErrorReason::LIFECYCLE_ERROR_REASON_WALLET_DELETED
        }
        LifecycleErrorReason::InvalidEvidence => {
            pb::LifecycleErrorReason::LIFECYCLE_ERROR_REASON_INVALID_EVIDENCE
        }
        LifecycleErrorReason::EvidenceDigestRequired => {
            pb::LifecycleErrorReason::LIFECYCLE_ERROR_REASON_EVIDENCE_DIGEST_REQUIRED
        }
        LifecycleErrorReason::EvidenceDigestTooLarge => {
            pb::LifecycleErrorReason::LIFECYCLE_ERROR_REASON_EVIDENCE_DIGEST_TOO_LARGE
        }
    }
}

/// Build the public generated wallet error envelope for lifecycle failures.
#[must_use]
pub fn lifecycle_error_to_proto(reason: LifecycleErrorReason) -> pb::WalletError {
    wallet_error(
        map_lifecycle_error_reason(reason),
        pb::wallet_error::Detail::Lifecycle(map_lifecycle_detail_reason(reason).into()),
    )
}
