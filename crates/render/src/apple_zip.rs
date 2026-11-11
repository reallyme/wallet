// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded stored-ZIP packaging for signed Apple Wallet passes.

use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::{RenderError, RenderErrorReason, RenderResult};

const ZIP_VERSION_STORED: u16 = 20;
const ZIP_METHOD_STORED: u16 = 0;
const ZIP_FLAG_NONE: u16 = 0;
const ZIP_TIME_ZERO: u16 = 0;
const ZIP_DATE_ZERO: u16 = 0;
const ZIP_DISK_ZERO: u16 = 0;
const ZIP_ATTR_ZERO: u16 = 0;
const ZIP_EXTERNAL_ATTR_ZERO: u32 = 0;
const CRC32_POLYNOMIAL: u32 = 0xedb8_8320;

pub(super) fn package_pkpass_zip(
    files: &BTreeMap<String, Zeroizing<Vec<u8>>>,
    manifest_json: &[u8],
    signature: &[u8],
) -> RenderResult<Vec<u8>> {
    let mut entries = Vec::new();
    for (name, bytes) in files {
        entries.push(ZipEntryInput {
            name: name.as_str(),
            bytes: bytes.as_slice(),
        });
    }
    entries.push(ZipEntryInput {
        name: "manifest.json",
        bytes: manifest_json,
    });
    entries.push(ZipEntryInput {
        name: "signature",
        bytes: signature,
    });

    write_stored_zip(&entries)
}

struct ZipEntryInput<'a> {
    name: &'a str,
    bytes: &'a [u8],
}

struct CentralDirectoryRecord {
    name: Vec<u8>,
    crc32: u32,
    size: u32,
    local_header_offset: u32,
}

fn write_stored_zip(entries: &[ZipEntryInput<'_>]) -> RenderResult<Vec<u8>> {
    let total_size = entries.iter().try_fold(22_usize, |total, entry| {
        total
            .checked_add(30)
            .and_then(|value| value.checked_add(entry.name.len()))
            .and_then(|value| value.checked_add(entry.bytes.len()))
            .and_then(|value| value.checked_add(46))
            .and_then(|value| value.checked_add(entry.name.len()))
            .ok_or(RenderError::new(RenderErrorReason::PayloadTooLarge))
    })?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(total_size)
        .map_err(|_| RenderError::new(RenderErrorReason::PayloadTooLarge))?;
    let mut central = Vec::new();

    for entry in entries {
        let name = entry.name.as_bytes();
        let name_len = u16::try_from(name.len())
            .map_err(|_| RenderError::new(RenderErrorReason::InvalidRenderAsset))?;
        let size = u32::try_from(entry.bytes.len())
            .map_err(|_| RenderError::new(RenderErrorReason::PayloadTooLarge))?;
        let offset = u32::try_from(output.len())
            .map_err(|_| RenderError::new(RenderErrorReason::PayloadTooLarge))?;
        let crc32 = crc32(entry.bytes);

        put_u32(&mut output, 0x0403_4b50);
        put_u16(&mut output, ZIP_VERSION_STORED);
        put_u16(&mut output, ZIP_FLAG_NONE);
        put_u16(&mut output, ZIP_METHOD_STORED);
        put_u16(&mut output, ZIP_TIME_ZERO);
        put_u16(&mut output, ZIP_DATE_ZERO);
        put_u32(&mut output, crc32);
        put_u32(&mut output, size);
        put_u32(&mut output, size);
        put_u16(&mut output, name_len);
        put_u16(&mut output, 0);
        output.extend_from_slice(name);
        output.extend_from_slice(entry.bytes);

        central.push(CentralDirectoryRecord {
            name: name.to_vec(),
            crc32,
            size,
            local_header_offset: offset,
        });
    }

    let central_offset = u32::try_from(output.len())
        .map_err(|_| RenderError::new(RenderErrorReason::PayloadTooLarge))?;
    for record in &central {
        let name_len = u16::try_from(record.name.len())
            .map_err(|_| RenderError::new(RenderErrorReason::InvalidRenderAsset))?;

        put_u32(&mut output, 0x0201_4b50);
        put_u16(&mut output, ZIP_VERSION_STORED);
        put_u16(&mut output, ZIP_VERSION_STORED);
        put_u16(&mut output, ZIP_FLAG_NONE);
        put_u16(&mut output, ZIP_METHOD_STORED);
        put_u16(&mut output, ZIP_TIME_ZERO);
        put_u16(&mut output, ZIP_DATE_ZERO);
        put_u32(&mut output, record.crc32);
        put_u32(&mut output, record.size);
        put_u32(&mut output, record.size);
        put_u16(&mut output, name_len);
        put_u16(&mut output, 0);
        put_u16(&mut output, 0);
        put_u16(&mut output, ZIP_DISK_ZERO);
        put_u16(&mut output, ZIP_ATTR_ZERO);
        put_u32(&mut output, ZIP_EXTERNAL_ATTR_ZERO);
        put_u32(&mut output, record.local_header_offset);
        output.extend_from_slice(&record.name);
    }

    let central_size = u32::try_from(
        output
            .len()
            .checked_sub(
                usize::try_from(central_offset)
                    .map_err(|_| RenderError::new(RenderErrorReason::PayloadTooLarge))?,
            )
            .ok_or(RenderError::new(RenderErrorReason::PayloadTooLarge))?,
    )
    .map_err(|_| RenderError::new(RenderErrorReason::PayloadTooLarge))?;
    let entry_count = u16::try_from(central.len())
        .map_err(|_| RenderError::new(RenderErrorReason::PayloadTooLarge))?;

    put_u32(&mut output, 0x0605_4b50);
    put_u16(&mut output, ZIP_DISK_ZERO);
    put_u16(&mut output, ZIP_DISK_ZERO);
    put_u16(&mut output, entry_count);
    put_u16(&mut output, entry_count);
    put_u32(&mut output, central_size);
    put_u32(&mut output, central_offset);
    put_u16(&mut output, 0);

    Ok(core::mem::take(&mut *output))
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC32_POLYNOMIAL & mask);
        }
    }

    !crc
}
