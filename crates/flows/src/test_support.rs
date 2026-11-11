// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use openid4vci_types::{CredentialOffer, IssuerMetadata, Proofs};
use reallyme_openid4vci_wallet::CredentialOfferGrantType;

use crate::{
    prepare_openid4vci_credential_request, start_openid4vci_issuance, FlowError, FlowErrorReason,
    FlowResult, IssuanceConsentDecision, IssuanceConsentProvider, IssuanceConsentRequest,
    OpenId4VciIssuanceSession, PreparedOpenId4VciCredentialRequest,
};

pub(crate) struct ApprovedIssuanceConsentProvider;

impl IssuanceConsentProvider for ApprovedIssuanceConsentProvider {
    fn capture_issuance_consent(
        &mut self,
        request: IssuanceConsentRequest<'_>,
    ) -> FlowResult<IssuanceConsentDecision> {
        if request.credential_issuer() != "https://issuer.example"
            || request.credential_configuration_ids() != ["pid"]
        {
            return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
        }
        Ok(IssuanceConsentDecision::Approved)
    }
}

pub(crate) fn issuer_metadata() -> FlowResult<IssuerMetadata> {
    IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "credential_endpoint":"https://issuer.example/credential",
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
    )
    .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))
}

pub(crate) fn start_authorization_code_issuance(
    offer: CredentialOffer,
) -> FlowResult<OpenId4VciIssuanceSession> {
    start_openid4vci_issuance(
        offer,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )
}

pub(crate) fn start_pre_authorized_code_issuance(
    offer: CredentialOffer,
) -> FlowResult<OpenId4VciIssuanceSession> {
    start_openid4vci_issuance(
        offer,
        &issuer_metadata()?,
        CredentialOfferGrantType::PreAuthorizedCode,
        "https://issuer.example".to_owned(),
    )
}

pub(crate) fn prepared_credential_request(
    proofs: Option<Proofs>,
    dpop_proof_jwt: Option<String>,
) -> FlowResult<PreparedOpenId4VciCredentialRequest> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
    .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let session = start_authorization_code_issuance(offer)?;
    prepare_openid4vci_credential_request(&session, "pid".to_owned(), proofs, None, dpop_proof_jwt)
}
