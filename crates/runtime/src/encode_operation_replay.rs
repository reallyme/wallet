// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encode and validate request-bound records in the operation journal.

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types::PresentationCopyId;
use zeroize::Zeroizing;

use crate::{
    OperationRequestDigest, RuntimeError, RuntimeErrorReason, OPERATION_IDEMPOTENCY_KEY_LENGTH,
};

const REPLAY_RECORD_MAGIC: &[u8; 8] = b"RMWRP001";
const ONCE_ONLY_REPLAY_MAGIC: &[u8; 8] = b"RMWRP002";
const REPLAY_RECORD_HEADER_BYTES: usize =
    REPLAY_RECORD_MAGIC.len() + OPERATION_IDEMPOTENCY_KEY_LENGTH;
const ONCE_ONLY_ID_LENGTH_BYTES: usize = 2;

pub(crate) fn claimed_copy_id(response: &pb::WalletOperationResponse) -> Option<&str> {
    let pb::wallet_operation_response::Outcome::Result(result) = response.outcome.as_ref()? else {
        return None;
    };
    let pb::wallet_operation_result::Result::ClaimPresentationCopy(claim) =
        result.result.as_ref()?
    else {
        return None;
    };
    claim.copy.as_option().map(|copy| copy.id.as_str())
}

pub(crate) fn encode_once_only_replay_record(
    request_digest: &OperationRequestDigest,
    copy_id: &str,
) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
    // The domain identifier is bounded, but encode the length explicitly so
    // corrupted journal bytes cannot be mistaken for a successful response.
    let id = PresentationCopyId::new(copy_id.to_owned())
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected))?;
    let id_bytes = id.as_str().as_bytes();
    let length = u16::try_from(id_bytes.len())
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected))?;
    let capacity = REPLAY_RECORD_HEADER_BYTES
        .checked_add(ONCE_ONLY_ID_LENGTH_BYTES)
        .and_then(|size| size.checked_add(id_bytes.len()))
        .ok_or(RuntimeError::new(
            RuntimeErrorReason::IdempotencyStoreRejected,
        ))?;
    let mut record = Zeroizing::new(Vec::new());
    record
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected))?;
    record.extend_from_slice(ONCE_ONLY_REPLAY_MAGIC);
    record.extend_from_slice(request_digest.as_bytes());
    record.extend_from_slice(&length.to_le_bytes());
    record.extend_from_slice(id_bytes);
    Ok(record)
}

pub(crate) fn encode_replay_record(
    request_digest: &OperationRequestDigest,
    response: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
    let capacity = REPLAY_RECORD_HEADER_BYTES
        .checked_add(response.len())
        .ok_or(RuntimeError::new(
            RuntimeErrorReason::IdempotencyStoreRejected,
        ))?;
    let mut record = Zeroizing::new(Vec::new());
    record
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected))?;
    record.extend_from_slice(REPLAY_RECORD_MAGIC);
    record.extend_from_slice(request_digest.as_bytes());
    record.extend_from_slice(response);
    Ok(record)
}

pub(crate) enum ReplayRecord<'a> {
    Response(&'a [u8]),
    OnceOnlyClaim,
}

pub(crate) fn decode_replay_record<'a>(
    record: &'a [u8],
    expected_digest: &OperationRequestDigest,
) -> Result<ReplayRecord<'a>, RuntimeError> {
    if record.len() <= REPLAY_RECORD_HEADER_BYTES
        || record.get(REPLAY_RECORD_MAGIC.len()..REPLAY_RECORD_HEADER_BYTES)
            != Some(expected_digest.as_bytes())
    {
        return Err(RuntimeError::new(
            RuntimeErrorReason::IdempotencyStoreRejected,
        ));
    }
    match record.get(..REPLAY_RECORD_MAGIC.len()) {
        Some(magic) if magic == REPLAY_RECORD_MAGIC => record
            .get(REPLAY_RECORD_HEADER_BYTES..)
            .map(ReplayRecord::Response)
            .ok_or(RuntimeError::new(
                RuntimeErrorReason::IdempotencyStoreRejected,
            )),
        Some(magic) if magic == ONCE_ONLY_REPLAY_MAGIC => {
            let length_end = REPLAY_RECORD_HEADER_BYTES
                .checked_add(ONCE_ONLY_ID_LENGTH_BYTES)
                .ok_or(RuntimeError::new(
                    RuntimeErrorReason::IdempotencyStoreRejected,
                ))?;
            let length_bytes: [u8; ONCE_ONLY_ID_LENGTH_BYTES] = record
                .get(REPLAY_RECORD_HEADER_BYTES..length_end)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(RuntimeError::new(
                    RuntimeErrorReason::IdempotencyStoreRejected,
                ))?;
            let id_length = usize::from(u16::from_le_bytes(length_bytes));
            let id_bytes = record.get(length_end..).ok_or(RuntimeError::new(
                RuntimeErrorReason::IdempotencyStoreRejected,
            ))?;
            if id_bytes.len() != id_length || id_bytes.is_empty() {
                return Err(RuntimeError::new(
                    RuntimeErrorReason::IdempotencyStoreRejected,
                ));
            }
            let id = core::str::from_utf8(id_bytes)
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected))?;
            let _validated = PresentationCopyId::new(id.to_owned())
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected))?;
            Ok(ReplayRecord::OnceOnlyClaim)
        }
        _ => Err(RuntimeError::new(
            RuntimeErrorReason::IdempotencyStoreRejected,
        )),
    }
}
