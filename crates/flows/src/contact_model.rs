// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contact delivery DTOs for NFC/BLE-style handoff.

use reallyme_wallet_types::UnixTimestamp;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session id length for contact delivery.
pub const CONTACT_SESSION_ID_LEN: usize = 16;
/// SHA-256 transcript binding length.
pub const CONTACT_TRANSCRIPT_HASH_LEN: usize = 32;
const DEFAULT_MAX_MESSAGE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_FRAME_PAYLOAD_BYTES: usize = 1024;
const DEFAULT_MAX_FRAMES: usize = 256;

/// Maximum bytes for a future contact payload kind label.
pub const CONTACT_OTHER_KIND_MAX_BYTES: usize = 64;
/// Maximum byte length of an optional contact payload content type.
pub(crate) const CONTACT_CONTENT_TYPE_MAX_BYTES: usize = 128;
/// Maximum lifetime of one contact message, from creation to expiry.
pub(crate) const CONTACT_MESSAGE_MAX_LIFETIME_SECONDS: i64 = 3_600;

/// Contact delivery protocol versions accepted by wallet-core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum ContactProtocolVersion {
    /// Version 1.0 of the bounded contact frame contract.
    V1,
}

impl ContactProtocolVersion {
    /// Stable adapter-facing wire value for the selected version.
    #[must_use]
    pub const fn wire_value(self) -> &'static str {
        match self {
            Self::V1 => "1.0",
        }
    }
}

/// What kind of protocol payload is carried over the contact channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactPayloadKind {
    /// Initial engagement or handover payload.
    Engagement,
    /// Request payload, such as OpenID4VP request bytes.
    Request,
    /// Response payload, such as mdoc DeviceResponse bytes.
    Response,
    /// Opaque future payload.
    Other(String),
}

impl Zeroize for ContactPayloadKind {
    fn zeroize(&mut self) {
        if let ContactPayloadKind::Other(value) = self {
            value.zeroize();
        }
    }
}

impl Drop for ContactPayloadKind {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ContactPayloadKind {}

/// Bounds for contact delivery fragmentation and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactLimits {
    /// Maximum bytes in the full reassembled message payload.
    pub max_message_bytes: usize,
    /// Maximum raw chunk bytes carried by a single frame.
    pub max_frame_payload_bytes: usize,
    /// Maximum number of frames allowed per message.
    pub max_frames: usize,
}

impl Default for ContactLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_frame_payload_bytes: DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            max_frames: DEFAULT_MAX_FRAMES,
        }
    }
}

/// Transport-neutral contact message.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct ContactMessage {
    /// Contact delivery version.
    pub version: ContactProtocolVersion,
    /// Inner payload kind.
    pub kind: ContactPayloadKind,
    /// 16-byte session identifier.
    pub session_id: [u8; CONTACT_SESSION_ID_LEN],
    /// SHA-256 hash of the session transcript bytes.
    pub session_transcript_sha256: [u8; CONTACT_TRANSCRIPT_HASH_LEN],
    /// Deterministic message id.
    pub message_id: u32,
    /// Optional content type for the inner protocol payload.
    pub content_type: Option<String>,
    /// Creation time.
    pub created_at: UnixTimestamp,
    /// Expiry time.
    pub expires_at: UnixTimestamp,
    /// Opaque protocol payload bytes.
    pub payload: Vec<u8>,
}

/// A single contact delivery frame.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct ContactFrame {
    /// Contact delivery version.
    pub version: ContactProtocolVersion,
    /// 16-byte session identifier.
    pub session_id: [u8; CONTACT_SESSION_ID_LEN],
    /// Deterministic message id shared by all frames.
    pub message_id: u32,
    /// Zero-based sequence number.
    pub sequence: u16,
    /// Total number of frames, at least one.
    pub total: u16,
    /// Raw payload chunk bytes.
    pub chunk: Vec<u8>,
}

/// Input parts for constructing a contact message with the supported version.
///
/// The parts remain an independent sensitive owner until consumed by
/// `ContactMessage::from_parts`, so early-return paths wipe payload and session
/// binding material instead of relying on the final message owner.
#[derive(ZeroizeOnDrop)]
pub struct ContactMessageParts {
    /// Inner payload kind.
    pub kind: ContactPayloadKind,
    /// 16-byte session identifier.
    pub session_id: [u8; CONTACT_SESSION_ID_LEN],
    /// SHA-256 hash of the session transcript bytes.
    pub session_transcript_sha256: [u8; CONTACT_TRANSCRIPT_HASH_LEN],
    /// Deterministic message id.
    pub message_id: u32,
    /// Optional content type for the inner protocol payload.
    pub content_type: Option<String>,
    /// Creation time.
    pub created_at: UnixTimestamp,
    /// Expiry time.
    pub expires_at: UnixTimestamp,
    /// Opaque protocol payload bytes.
    pub payload: Vec<u8>,
}

impl ContactMessage {
    /// Create a contact message with the supported version marker.
    #[must_use]
    pub fn from_parts(mut parts: ContactMessageParts) -> Self {
        Self {
            version: ContactProtocolVersion::V1,
            kind: core::mem::replace(&mut parts.kind, ContactPayloadKind::Engagement),
            session_id: parts.session_id,
            session_transcript_sha256: parts.session_transcript_sha256,
            message_id: parts.message_id,
            content_type: parts.content_type.take(),
            created_at: parts.created_at,
            expires_at: parts.expires_at,
            payload: core::mem::take(&mut parts.payload),
        }
    }
}
