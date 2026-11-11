// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::ZeroizeOnDrop;

use super::{DisclosedAttribute, QtspDecisionRecord, TransactionLogEntry};

#[test]
fn log_owners_advertise_drop_time_zeroization() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<DisclosedAttribute>();
    assert_zeroize_on_drop::<TransactionLogEntry>();
    assert_zeroize_on_drop::<QtspDecisionRecord>();
}
