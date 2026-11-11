// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Credential Offer URI resolution for issuance startup.

use openid4vci_profiles::ReuseMethodSet;
use openid4vci_types::IssuerMetadata;
use reallyme_openid4vci_wallet::{
    resolve_credential_offer_uri, CredentialOfferFetcher, CredentialOfferGrantType,
    VerifiedSignedIssuerMetadata, WalletStatus,
};
use reallyme_wallet_types::OpenId4VciIssuerMetadataProfile;

use super::{
    start_openid4vci_issuance_with_reuse_capabilities,
    start_openid4vci_issuance_with_verified_metadata_profile, OpenId4VciIssuanceSession,
};
use crate::{FlowError, FlowErrorReason, FlowResult};

const MAX_CREDENTIAL_OFFER_URI_BYTES: usize = 65_536;

/// Resolve a Credential Offer URI and start issuance.
pub fn start_openid4vci_issuance_from_offer_uri(
    credential_offer_uri: &str,
    fetcher: Option<&dyn CredentialOfferFetcher>,
    issuer_metadata: &IssuerMetadata,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
) -> FlowResult<OpenId4VciIssuanceSession> {
    let supported = ReuseMethodSet::new(0)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidCredentialReusePolicy))?;
    start_openid4vci_issuance_from_offer_uri_with_reuse_capabilities(
        credential_offer_uri,
        fetcher,
        issuer_metadata,
        grant_type,
        authorization_server,
        supported,
    )
}

/// Resolve an offer URI and start issuance with explicit reuse capabilities.
pub fn start_openid4vci_issuance_from_offer_uri_with_reuse_capabilities(
    credential_offer_uri: &str,
    fetcher: Option<&dyn CredentialOfferFetcher>,
    issuer_metadata: &IssuerMetadata,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
) -> FlowResult<OpenId4VciIssuanceSession> {
    validate_offer_uri(credential_offer_uri)?;
    let offer = resolve_offer(credential_offer_uri, fetcher)?;
    start_openid4vci_issuance_with_reuse_capabilities(
        offer,
        issuer_metadata,
        grant_type,
        authorization_server,
        supported_reuse_methods,
    )
}

/// Resolve an offer URI and start an ETSI-profiled issuance.
pub fn start_openid4vci_issuance_from_offer_uri_with_verified_metadata_profile(
    credential_offer_uri: &str,
    fetcher: Option<&dyn CredentialOfferFetcher>,
    verified_issuer_metadata: &VerifiedSignedIssuerMetadata,
    issuer_metadata_profile: OpenId4VciIssuerMetadataProfile,
    grant_type: CredentialOfferGrantType,
    authorization_server: String,
    supported_reuse_methods: ReuseMethodSet,
) -> FlowResult<OpenId4VciIssuanceSession> {
    validate_offer_uri(credential_offer_uri)?;
    let offer = resolve_offer(credential_offer_uri, fetcher)?;
    start_openid4vci_issuance_with_verified_metadata_profile(
        offer,
        verified_issuer_metadata,
        issuer_metadata_profile,
        grant_type,
        authorization_server,
        supported_reuse_methods,
    )
}

fn resolve_offer(
    credential_offer_uri: &str,
    fetcher: Option<&dyn CredentialOfferFetcher>,
) -> FlowResult<openid4vci_types::CredentialOffer> {
    resolve_credential_offer_uri(credential_offer_uri, fetcher).map_err(|error| {
        if error.status() == WalletStatus::OfferResolutionRequired {
            FlowError::new(FlowErrorReason::CredentialOfferResolutionRequired)
        } else {
            FlowError::new(FlowErrorReason::InvalidOpenId4VciState)
        }
    })
}

fn validate_offer_uri(value: &str) -> FlowResult<()> {
    if value.len() > MAX_CREDENTIAL_OFFER_URI_BYTES || has_percent_encoded_query_key(value) {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }
    Ok(())
}

fn has_percent_encoded_query_key(value: &str) -> bool {
    let Some((_base, query)) = value.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        pair.split_once('=')
            .map_or(pair, |(key, _value)| key)
            .contains('%')
    })
}
