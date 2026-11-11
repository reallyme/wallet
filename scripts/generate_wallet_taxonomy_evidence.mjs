#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, lstatSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

const MAX_METADATA_BYTES = 16 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;
const REVISION = /^[a-f0-9]{40}$/u;
const REPOSITORY = "reallyme/wallet";
const digest = (value) => typeof value === "string" && SHA256.test(value);
const revision = (value) => typeof value === "string" && REVISION.test(value);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Fixed, non-sensitive generator failures. */
export class WalletEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = "WalletEvidenceError";
    this.code = code;
  }
}
const fail = (code) => {
  throw new WalletEvidenceError(code);
};
const object = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Disposition the exact assigned inventory without claiming platform implementation. */
export function buildWalletLedger(inventory, sourceRevision) {
  if (
    !object(inventory) ||
    inventory.schema !==
      "reallyme.identity.conformance_requirement_inventory.v1" ||
    !object(inventory.taxonomy_version) ||
    !digest(inventory.taxonomy_source_sha256) ||
    !Array.isArray(inventory.requirements) ||
    !revision(sourceRevision)
  )
    fail("invalid_inventory");
  if (
    Object.keys(inventory.taxonomy_version).sort().join(",") !==
      "major,minor,patch" ||
    Object.values(inventory.taxonomy_version).some(
      (value) =>
        !Number.isSafeInteger(value) || value < 0 || value > 0xffffffff,
    )
  )
    fail("invalid_version");
  const seen = new Set();
  const rows = [];
  for (const requirement of inventory.requirements) {
    if (
      !object(requirement) ||
      typeof requirement.requirement_id !== "string" ||
      !digest(requirement.requirement_sha256) ||
      typeof requirement.owner_repository !== "string" ||
      seen.has(requirement.requirement_id)
    )
      fail("invalid_requirement");
    seen.add(requirement.requirement_id);
    if (requirement.owner_repository !== REPOSITORY) continue;
    // Platform command ownership must be reconciled in Taxonomy. Fail if new
    // Wallet-domain requirements arrive instead of classifying them by default.
    if (
      requirement.obligation !== "conditional" ||
      !/^command:identity\.(?:ble|nfc|proximity|transport)\.[a-z_]+$/u.test(
        requirement.requirement_id,
      )
    )
      fail("unreviewed_requirement");
    rows.push({
      requirement_id: requirement.requirement_id,
      requirement_sha256: requirement.requirement_sha256,
      status: "not_applicable",
      reason_code: "capability_not_selected",
      evidence: [],
    });
  }
  rows.sort((a, b) =>
    a.requirement_id < b.requirement_id
      ? -1
      : a.requirement_id > b.requirement_id
        ? 1
        : 0,
  );
  if (rows.length === 0) fail("empty_wallet_inventory");
  return {
    schema: "reallyme.identity.conformance_ledger_evidence.v1",
    taxonomy_version: inventory.taxonomy_version,
    taxonomy_source_sha256: inventory.taxonomy_source_sha256,
    repository: REPOSITORY,
    generated_by: {
      command: "node scripts/generate_wallet_taxonomy_evidence.mjs",
      source_revision: sourceRevision,
    },
    artifacts: [],
    requirements: rows,
  };
}
function readJson(path) {
  try {
    const stat = lstatSync(path);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.size > MAX_METADATA_BYTES
    )
      fail("invalid_file");
    // Evidence maps use a JSON-compatible YAML body with an SPDX comment prelude.
    const source = readFileSync(path, "utf8").replace(
      /^(?:#[^\n]*\n|\n)+/u,
      "",
    );
    return JSON.parse(source);
  } catch (error) {
    if (error instanceof WalletEvidenceError) throw error;
    fail("metadata_read_failed");
  }
}
function run() {
  const args = process.argv.slice(2);
  if (args.length > 1 || args.some((arg) => arg !== "--check"))
    fail("invalid_argument");
  const lock = readJson(resolve(ROOT, "contracts/coverage/taxonomy.lock.json"));
  if (
    !object(lock) ||
    lock.schema !== "reallyme.identity.taxonomy_source_lock.v1" ||
    lock.repository !== "reallyme/identity-taxonomy" ||
    !revision(lock.revision) ||
    lock.inventory_path !== "conformance/inventory/requirements.json" ||
    !digest(lock.inventory_sha256)
  )
    fail("invalid_lock");
  let raw;
  let sourceRevision;
  try {
    raw = execFileSync(
      "git",
      [
        "-C",
        resolve(ROOT, "../identity-taxonomy"),
        "show",
        `${lock.revision}:${lock.inventory_path}`,
      ],
      { maxBuffer: MAX_METADATA_BYTES, stdio: ["ignore", "pipe", "ignore"] },
    );
    sourceRevision = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    fail("source_unavailable");
  }
  if (hash(raw) !== lock.inventory_sha256) fail("inventory_digest_mismatch");
  let inventory;
  try {
    inventory = JSON.parse(raw.toString("utf8"));
  } catch {
    fail("invalid_inventory");
  }
  const ledger = buildWalletLedger(inventory, sourceRevision);
  const map = readJson(
    resolve(ROOT, "contracts/coverage/conformance-evidence.yaml"),
  );
  if (
    !object(map) ||
    map.schema !== "reallyme.identity.conformance_evidence_map.v1" ||
    map.repository !== REPOSITORY ||
    !object(map.requirements)
  )
    fail("invalid_map");
  if (Object.keys(map.requirements).length !== ledger.requirements.length)
    fail("mapping_inventory_mismatch");
  for (const row of ledger.requirements) {
    const reviewed = map.requirements[row.requirement_id];
    if (
      !object(reviewed) ||
      reviewed.accepted_requirement_sha256 !== row.requirement_sha256 ||
      reviewed.status !== row.status ||
      reviewed.reason_code !== row.reason_code ||
      !Array.isArray(reviewed.evidence) ||
      reviewed.evidence.length !== 0
    )
      fail("unreviewed_mapping");
  }
  const output = resolve(
    ROOT,
    "conformance/taxonomy/conformance-ledger-evidence.json",
  );
  const bytes = JSON.stringify(ledger, null, 2) + "\n";
  if (args.includes("--check")) {
    if (readFileSync(output, "utf8") !== bytes) fail("stale_ledger");
  } else writeFileSync(output, bytes);
  process.stdout.write("Wallet taxonomy producer evidence verified.\n");
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    run();
  } catch (error) {
    process.stderr.write(
      `Wallet taxonomy evidence: ${error instanceof WalletEvidenceError ? error.code : "operation_failed"}\n`,
    );
    process.exitCode = 1;
  }
}
