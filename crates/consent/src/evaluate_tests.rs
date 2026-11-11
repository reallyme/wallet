// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{evaluate_entitlement, evaluate_entitlement_at};
use crate::ConsentErrorReason;
use reallyme_wallet_types::{
    AttributeName, ConsentScope, NonEmptyIdentifier, UnixTimestamp, VerifierEntitlement,
    WalletTypesError,
};

fn attr(value: &str) -> Result<AttributeName, WalletTypesError> {
    AttributeName::new(value.to_owned())
}

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

#[test]
fn rejects_attribute_outside_entitlement() -> Result<(), WalletTypesError> {
    let valid_until = UnixTimestamp::from_seconds(1)?;
    let entitlement = VerifierEntitlement {
        relying_party_id: id("rp-1")?,
        authorized_scope: ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        valid_until,
    };
    let requested = ConsentScope {
        attributes: vec![attr("family_name")?],
    };

    let result = evaluate_entitlement(&entitlement, &requested);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::AttributeNotAuthorized
    ));
    Ok(())
}

#[test]
fn rejects_expired_entitlement() -> Result<(), WalletTypesError> {
    let entitlement = VerifierEntitlement {
        relying_party_id: id("rp-1")?,
        authorized_scope: ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        valid_until: UnixTimestamp::from_seconds(10)?,
    };
    let requested = ConsentScope {
        attributes: vec![attr("age_over_18")?],
    };

    let result =
        evaluate_entitlement_at(&entitlement, &requested, UnixTimestamp::from_seconds(11)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::EntitlementExpired
    ));
    Ok(())
}

#[test]
fn rejects_attribute_alias_attack() -> Result<(), WalletTypesError> {
    let valid_until = UnixTimestamp::from_seconds(1)?;
    let entitlement = VerifierEntitlement {
        relying_party_id: id("rp-1")?,
        authorized_scope: ConsentScope {
            attributes: vec![attr("familyName")?],
        },
        valid_until,
    };
    let requested = ConsentScope {
        attributes: vec![attr("family_name")?],
    };

    let result = evaluate_entitlement(&entitlement, &requested);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::AttributeNotAuthorized
    ));
    Ok(())
}
