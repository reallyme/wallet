// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::ZeroizeOnDrop;

use super::{ConsentAction, ConsentCapture, ConsentRequest, ConsentScope, VerifierEntitlement};

#[test]
fn consent_owners_advertise_drop_time_zeroization() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<ConsentScope>();
    assert_zeroize_on_drop::<VerifierEntitlement>();
    assert_zeroize_on_drop::<ConsentAction>();
    assert_zeroize_on_drop::<ConsentRequest>();
    assert_zeroize_on_drop::<ConsentCapture>();
}
