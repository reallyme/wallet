// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate user-visible wallet log records before append.

use reallyme_wallet_types::{
    QtspDecisionRecord, TransactionLogEntry, TransactionPurpose, TRANSACTION_LOG_HASH_BYTES,
};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

use crate::{WalletLogError, WalletLogErrorReason, WalletLogResult};

const SHA256_B64URL_LEN: usize = 43;
const TRANSACTION_CHAIN_DOMAIN: &[u8] = b"reallyme.wallet.transaction-log.v1\0";
/// Maximum disclosed attributes recorded by one transaction log entry.
pub const MAX_TRANSACTION_LOG_DISCLOSED_ATTRIBUTES: usize = 256;

/// Validate a transaction log entry before it is appended.
pub fn validate_transaction_log_entry(entry: &TransactionLogEntry) -> WalletLogResult<()> {
    if entry.disclosed_attributes.len() > MAX_TRANSACTION_LOG_DISCLOSED_ATTRIBUTES {
        return Err(WalletLogError::new(
            WalletLogErrorReason::TransactionTranscriptTooLarge,
        ));
    }
    if entry.purpose == TransactionPurpose::Presentation && entry.relying_party_id.is_none() {
        return Err(WalletLogError::new(
            WalletLogErrorReason::MissingRelyingParty,
        ));
    }
    if entry.sequence == 0
        || (entry.sequence == 1 && entry.previous_entry_hash != [0; TRANSACTION_LOG_HASH_BYTES])
        || (entry.sequence > 1 && entry.previous_entry_hash == [0; TRANSACTION_LOG_HASH_BYTES])
        || transaction_entry_hash(entry)? != entry.entry_hash
    {
        return Err(WalletLogError::new(
            WalletLogErrorReason::InvalidTransactionChain,
        ));
    }

    Ok(())
}

/// Bind a transaction entry to its durable one-based sequence and predecessor hash.
pub fn chain_transaction_log_entry(
    mut entry: TransactionLogEntry,
    sequence: u64,
    previous_entry_hash: [u8; TRANSACTION_LOG_HASH_BYTES],
) -> WalletLogResult<TransactionLogEntry> {
    entry.sequence = sequence;
    entry.previous_entry_hash = previous_entry_hash;
    entry.entry_hash = transaction_entry_hash(&entry)?;
    validate_transaction_log_entry(&entry)?;
    Ok(entry)
}

/// Verify a complete ordered transaction-log segment beginning at genesis.
///
/// Entries must be contiguous, hash-linked, and uniquely identified. Their
/// times record when each event happened, which need not follow append order,
/// so time order is not checked. A chain check alone cannot detect a dropped
/// tail; use `validate_transaction_log_chain_to_head` with the durable head to
/// detect a shortened chain.
pub fn validate_transaction_log_chain(entries: &[TransactionLogEntry]) -> WalletLogResult<()> {
    let mut expected_sequence = 1_u64;
    let mut previous_hash = [0_u8; TRANSACTION_LOG_HASH_BYTES];
    let mut identifiers = BTreeSet::new();
    for entry in entries {
        if entry.sequence != expected_sequence
            || entry.previous_entry_hash != previous_hash
            || !identifiers.insert(entry.id.as_str())
        {
            return Err(WalletLogError::new(
                WalletLogErrorReason::InvalidTransactionChain,
            ));
        }
        validate_transaction_log_entry(entry)?;
        previous_hash = entry.entry_hash;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            WalletLogError::new(WalletLogErrorReason::TransactionTranscriptTooLarge)
        })?;
    }
    Ok(())
}

/// Verify a complete chain and require it to end at the trusted durable head.
///
/// `expected_head` is the `(sequence, entry_hash)` pair read from the
/// append-only store's head, or `(0, [0; 32])` for an empty log. A chain that
/// is valid but shorter than the head, such as one with dropped recent
/// entries, is rejected. A head read from the same store cannot reveal a
/// rollback of the whole store; that needs a head kept where the store cannot
/// rewrite it.
pub fn validate_transaction_log_chain_to_head(
    entries: &[TransactionLogEntry],
    expected_head: (u64, [u8; TRANSACTION_LOG_HASH_BYTES]),
) -> WalletLogResult<()> {
    validate_transaction_log_chain(entries)?;
    let actual_head = entries
        .last()
        .map_or((0, [0; TRANSACTION_LOG_HASH_BYTES]), |entry| {
            (entry.sequence, entry.entry_hash)
        });
    if actual_head != expected_head {
        return Err(WalletLogError::new(
            WalletLogErrorReason::InvalidTransactionChain,
        ));
    }
    Ok(())
}

fn transaction_entry_hash(
    entry: &TransactionLogEntry,
) -> WalletLogResult<[u8; TRANSACTION_LOG_HASH_BYTES]> {
    let mut transcript = Zeroizing::new(Vec::new());
    // Reserve the complete transcript before copying RP and attribute bytes.
    // A later Vec reallocation could otherwise retain those values in freed
    // memory even though the final allocation is wiped on drop.
    transcript
        .try_reserve_exact(transcript_length(entry)?)
        .map_err(|_| WalletLogError::new(WalletLogErrorReason::TransactionTranscriptTooLarge))?;
    append_bytes(&mut transcript, TRANSACTION_CHAIN_DOMAIN)?;
    append_bytes(&mut transcript, entry.id.as_str().as_bytes())?;
    transcript.push(match entry.purpose {
        TransactionPurpose::Issuance => 1,
        TransactionPurpose::Presentation => 2,
        TransactionPurpose::Refresh => 3,
        TransactionPurpose::Deletion => 4,
    });
    match entry.relying_party_id.as_ref() {
        Some(relying_party_id) => {
            transcript.push(1);
            append_bytes(&mut transcript, relying_party_id.as_str().as_bytes())?;
        }
        None => transcript.push(0),
    }
    let attribute_count = u32::try_from(entry.disclosed_attributes.len())
        .map_err(|_| WalletLogError::new(WalletLogErrorReason::TransactionTranscriptTooLarge))?;
    transcript.extend_from_slice(&attribute_count.to_be_bytes());
    for attribute in &entry.disclosed_attributes {
        append_bytes(&mut transcript, attribute.name.as_str().as_bytes())?;
    }
    transcript.extend_from_slice(&entry.occurred_at.as_seconds().to_be_bytes());
    transcript.extend_from_slice(&entry.sequence.to_be_bytes());
    transcript.extend_from_slice(&entry.previous_entry_hash);
    Ok(crypto_sha2_256::digest(transcript.as_slice()).into_bytes())
}

fn transcript_length(entry: &TransactionLogEntry) -> WalletLogResult<usize> {
    const FIXED_BYTES: usize = 1 + 1 + 4 + 8 + 8 + TRANSACTION_LOG_HASH_BYTES;
    let mut length = FIXED_BYTES;
    for value in [TRANSACTION_CHAIN_DOMAIN, entry.id.as_str().as_bytes()] {
        length = append_framed_length(length, value)?;
    }
    if let Some(relying_party_id) = &entry.relying_party_id {
        length = append_framed_length(length, relying_party_id.as_str().as_bytes())?;
    }
    let _attribute_count = u32::try_from(entry.disclosed_attributes.len())
        .map_err(|_| WalletLogError::new(WalletLogErrorReason::TransactionTranscriptTooLarge))?;
    for attribute in &entry.disclosed_attributes {
        length = append_framed_length(length, attribute.name.as_str().as_bytes())?;
    }
    Ok(length)
}

fn append_framed_length(current: usize, value: &[u8]) -> WalletLogResult<usize> {
    let _encoded_length = u32::try_from(value.len())
        .map_err(|_| WalletLogError::new(WalletLogErrorReason::TransactionTranscriptTooLarge))?;
    current
        .checked_add(core::mem::size_of::<u32>())
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| WalletLogError::new(WalletLogErrorReason::TransactionTranscriptTooLarge))
}

fn append_bytes(transcript: &mut Vec<u8>, value: &[u8]) -> WalletLogResult<()> {
    let value_length = u32::try_from(value.len())
        .map_err(|_| WalletLogError::new(WalletLogErrorReason::TransactionTranscriptTooLarge))?;
    transcript.extend_from_slice(&value_length.to_be_bytes());
    transcript.extend_from_slice(value);
    Ok(())
}

/// Validate a QTSP or qualified-trust decision record before append.
pub fn validate_qtsp_decision_record(record: &QtspDecisionRecord) -> WalletLogResult<()> {
    if record.input_sha256_b64url.is_empty() {
        return Err(WalletLogError::new(
            WalletLogErrorReason::MissingDecisionDigest,
        ));
    }
    if record.input_sha256_b64url.len() > SHA256_B64URL_LEN {
        return Err(WalletLogError::new(
            WalletLogErrorReason::DecisionDigestTooLong,
        ));
    }
    let decoded = Zeroizing::new(
        reallyme_codec::base64url::base64url_to_bytes(&record.input_sha256_b64url)
            .map_err(|_| WalletLogError::new(WalletLogErrorReason::InvalidDecisionDigest))?,
    );
    let canonical = Zeroizing::new(reallyme_codec::base64url::bytes_to_base64url(&decoded));
    if decoded.len() != TRANSACTION_LOG_HASH_BYTES
        || canonical.as_str() != record.input_sha256_b64url
    {
        return Err(WalletLogError::new(
            WalletLogErrorReason::InvalidDecisionDigest,
        ));
    }

    Ok(())
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod tests;
