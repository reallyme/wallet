// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{OperationIdempotencyKey, OPERATION_IDEMPOTENCY_KEY_LENGTH};
use crate::{StorageError, StorageErrorReason};

#[test]
fn idempotency_key_accepts_exact_nonzero_bytes() -> Result<(), StorageError> {
    let key = OperationIdempotencyKey::from_slice(&[0xA5; OPERATION_IDEMPOTENCY_KEY_LENGTH])?;

    assert_eq!(key.as_bytes(), &[0xA5; OPERATION_IDEMPOTENCY_KEY_LENGTH]);
    Ok(())
}

#[test]
fn idempotency_key_rejects_invalid_lengths_and_all_zero() {
    for value in [
        vec![0xA5; OPERATION_IDEMPOTENCY_KEY_LENGTH - 1],
        vec![0_u8; OPERATION_IDEMPOTENCY_KEY_LENGTH],
        vec![0xA5; OPERATION_IDEMPOTENCY_KEY_LENGTH + 1],
    ] {
        let result = OperationIdempotencyKey::from_slice(&value);
        assert!(matches!(
            result,
            Err(error) if error.reason == StorageErrorReason::InvalidIdempotencyKey
        ));
    }
}
