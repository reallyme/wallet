// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    self as pb, WalletErrorReason,
};
use reallyme_wallet_proto_codec::convert::ConvertErrorReason;
use reallyme_wallet_proto_codec::ProtoErrorReason;
#[cfg(feature = "render")]
use reallyme_wallet_render::RenderErrorReason;
use reallyme_wallet_runtime::RuntimeErrorReason;

use super::wallet_error;

/// Map render reasons to the public protobuf reason enum.
#[cfg(feature = "render")]
#[must_use]
pub const fn map_render_error_reason(reason: RenderErrorReason) -> WalletErrorReason {
    match reason {
        RenderErrorReason::UnsupportedRenderTarget => {
            WalletErrorReason::WALLET_ERROR_REASON_RENDER_TARGET_UNSUPPORTED
        }
        RenderErrorReason::ExpiredDelivery => {
            WalletErrorReason::WALLET_ERROR_REASON_DELIVERY_EXPIRED
        }
        RenderErrorReason::PayloadTooLarge => {
            WalletErrorReason::WALLET_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
        }
        RenderErrorReason::InvalidDeliveryLimits
        | RenderErrorReason::InvalidUrl
        | RenderErrorReason::InvalidDistributionCard
        | RenderErrorReason::InvalidRenderConfig => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT
        }
        // No signer was configured: a missing provider, not a failed signature.
        RenderErrorReason::SignerRequired => {
            WalletErrorReason::WALLET_ERROR_REASON_BACKEND_UNAVAILABLE
        }
        RenderErrorReason::UnsupportedUrlScheme | RenderErrorReason::UnsupportedBarcodePayload => {
            WalletErrorReason::WALLET_ERROR_REASON_UNSUPPORTED_FORMAT
        }
        RenderErrorReason::InvalidRenderAsset => {
            WalletErrorReason::WALLET_ERROR_REASON_RENDER_ARTIFACT_INVALID
        }
        RenderErrorReason::SigningFailed => WalletErrorReason::WALLET_ERROR_REASON_SIGNING_FAILED,
        RenderErrorReason::PackagingFailed => {
            WalletErrorReason::WALLET_ERROR_REASON_PACKAGING_FAILED
        }
        RenderErrorReason::SerializationFailed => {
            WalletErrorReason::WALLET_ERROR_REASON_SERIALIZATION_FAILED
        }
    }
}

/// Map render reasons to their exact generated protobuf enum.
#[cfg(feature = "render")]
#[must_use]
pub const fn map_render_detail_reason(reason: RenderErrorReason) -> pb::RenderErrorReason {
    match reason {
        RenderErrorReason::UnsupportedRenderTarget => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_UNSUPPORTED_RENDER_TARGET
        }
        RenderErrorReason::ExpiredDelivery => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_EXPIRED_DELIVERY
        }
        RenderErrorReason::PayloadTooLarge => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_PAYLOAD_TOO_LARGE
        }
        RenderErrorReason::InvalidDeliveryLimits => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_INVALID_DELIVERY_LIMITS
        }
        RenderErrorReason::InvalidUrl => pb::RenderErrorReason::RENDER_ERROR_REASON_INVALID_URL,
        RenderErrorReason::UnsupportedUrlScheme => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_UNSUPPORTED_URL_SCHEME
        }
        RenderErrorReason::InvalidDistributionCard => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_INVALID_DISTRIBUTION_CARD
        }
        RenderErrorReason::InvalidRenderConfig => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_INVALID_RENDER_CONFIG
        }
        RenderErrorReason::SignerRequired => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_SIGNER_REQUIRED
        }
        RenderErrorReason::InvalidRenderAsset => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_INVALID_RENDER_ASSET
        }
        RenderErrorReason::UnsupportedBarcodePayload => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_UNSUPPORTED_BARCODE_PAYLOAD
        }
        RenderErrorReason::SigningFailed => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_SIGNING_FAILED
        }
        RenderErrorReason::PackagingFailed => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_PACKAGING_FAILED
        }
        RenderErrorReason::SerializationFailed => {
            pb::RenderErrorReason::RENDER_ERROR_REASON_SERIALIZATION_FAILED
        }
    }
}

/// Build the public generated wallet error envelope for render failures.
#[cfg(feature = "render")]
#[must_use]
pub fn render_error_to_proto(reason: RenderErrorReason) -> pb::WalletError {
    wallet_error(
        map_render_error_reason(reason),
        pb::wallet_error::Detail::Render(map_render_detail_reason(reason).into()),
    )
}

/// Map generated protobuf conversion reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_convert_error_reason(reason: ConvertErrorReason) -> WalletErrorReason {
    match reason {
        ConvertErrorReason::MissingRequiredField
        | ConvertErrorReason::InvalidIdentifier
        | ConvertErrorReason::InvalidTimestamp
        | ConvertErrorReason::IntegerOutOfRange
        | ConvertErrorReason::InvalidLifecycleEvidence
        | ConvertErrorReason::InvalidDistributionCard
        | ConvertErrorReason::InvalidNotificationEndpoint
        | ConvertErrorReason::InvalidIdempotencyKey
        | ConvertErrorReason::InvalidIssuanceCommit
        | ConvertErrorReason::InvalidAttestationEvidence
        | ConvertErrorReason::InvalidConsentAction
        | ConvertErrorReason::InvalidZkArtifact
        | ConvertErrorReason::InvalidFlowStatePayload => {
            WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT
        }
        ConvertErrorReason::InvalidCredentialReusePolicy => {
            WalletErrorReason::WALLET_ERROR_REASON_CREDENTIAL_REUSE_POLICY_INVALID
        }
        ConvertErrorReason::InvalidEnumValue => {
            WalletErrorReason::WALLET_ERROR_REASON_UNSUPPORTED_FORMAT
        }
        ConvertErrorReason::UnsupportedSchema
        | ConvertErrorReason::UnsupportedFlowStateSchemaVersion => {
            WalletErrorReason::WALLET_ERROR_REASON_PROTO_UNSUPPORTED_SCHEMA
        }
    }
}

/// Map generated DTO conversion reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_convert_detail_reason(reason: ConvertErrorReason) -> pb::ConvertErrorReason {
    match reason {
        ConvertErrorReason::MissingRequiredField => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_MISSING_REQUIRED_FIELD
        }
        ConvertErrorReason::InvalidIdentifier => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_IDENTIFIER
        }
        ConvertErrorReason::InvalidTimestamp => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_TIMESTAMP
        }
        ConvertErrorReason::InvalidEnumValue => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_ENUM_VALUE
        }
        ConvertErrorReason::IntegerOutOfRange => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INTEGER_OUT_OF_RANGE
        }
        ConvertErrorReason::UnsupportedSchema => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_UNSUPPORTED_SCHEMA
        }
        ConvertErrorReason::UnsupportedFlowStateSchemaVersion => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_UNSUPPORTED_FLOW_STATE_SCHEMA_VERSION
        }
        ConvertErrorReason::InvalidLifecycleEvidence => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_LIFECYCLE_EVIDENCE
        }
        ConvertErrorReason::InvalidDistributionCard => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_DISTRIBUTION_CARD
        }
        ConvertErrorReason::InvalidFlowStatePayload => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_FLOW_STATE_PAYLOAD
        }
        ConvertErrorReason::InvalidNotificationEndpoint => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_NOTIFICATION_ENDPOINT
        }
        ConvertErrorReason::InvalidIdempotencyKey => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_IDEMPOTENCY_KEY
        }
        ConvertErrorReason::InvalidIssuanceCommit => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_ISSUANCE_COMMIT
        }
        ConvertErrorReason::InvalidAttestationEvidence => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_ATTESTATION_EVIDENCE
        }
        ConvertErrorReason::InvalidConsentAction => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_CONSENT_ACTION
        }
        ConvertErrorReason::InvalidZkArtifact => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_ZK_ARTIFACT
        }
        ConvertErrorReason::InvalidCredentialReusePolicy => {
            pb::ConvertErrorReason::CONVERT_ERROR_REASON_INVALID_CREDENTIAL_REUSE_POLICY
        }
    }
}

/// Build the public generated wallet error envelope for conversion failures.
#[must_use]
pub fn convert_error_to_proto(reason: ConvertErrorReason) -> pb::WalletError {
    wallet_error(
        map_convert_error_reason(reason),
        pb::wallet_error::Detail::Convert(map_convert_detail_reason(reason).into()),
    )
}

/// Map protobuf codec reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_proto_error_reason(reason: ProtoErrorReason) -> WalletErrorReason {
    reallyme_wallet_proto_codec::map_proto_error_reason(reason)
}

/// Map protobuf codec reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_proto_detail_reason(reason: ProtoErrorReason) -> pb::ProtoErrorReason {
    reallyme_wallet_proto_codec::map_proto_detail_reason(reason)
}

/// Build the public generated wallet error envelope for protobuf codec failures.
#[must_use]
pub fn proto_error_to_proto(reason: ProtoErrorReason) -> pb::WalletError {
    reallyme_wallet_proto_codec::proto_error_to_proto(reason)
}

/// Map runtime adapter reasons to the public protobuf reason enum.
#[must_use]
pub const fn map_runtime_error_reason(reason: RuntimeErrorReason) -> WalletErrorReason {
    reallyme_wallet_runtime::map_runtime_error_reason(reason)
}

/// Map runtime reasons to their exact generated protobuf enum.
#[must_use]
pub const fn map_runtime_detail_reason(reason: RuntimeErrorReason) -> pb::RuntimeErrorReason {
    reallyme_wallet_runtime::map_runtime_detail_reason(reason)
}

/// Build the public generated wallet error envelope for runtime failures.
#[must_use]
pub fn runtime_error_to_proto(reason: RuntimeErrorReason) -> pb::WalletError {
    reallyme_wallet_runtime::runtime_error_to_proto(reason)
}
