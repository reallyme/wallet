// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import test from "node:test";
import assert from "node:assert/strict";
import {
  buildWalletLedger,
  WalletEvidenceError,
} from "./generate_wallet_taxonomy_evidence.mjs";
const revision = "1".repeat(40);
const inventory = () => ({
  schema: "reallyme.identity.conformance_requirement_inventory.v1",
  taxonomy_version: { major: 0, minor: 1, patch: 0 },
  taxonomy_source_sha256: "2".repeat(64),
  requirements: [
    {
      requirement_id: "command:identity.ble.connect",
      requirement_sha256: "3".repeat(64),
      owner_repository: "reallyme/wallet",
      obligation: "conditional",
    },
  ],
});
test("platform delegation never becomes implementation evidence", () => {
  const ledger = buildWalletLedger(inventory(), revision);
  assert.equal(ledger.requirements.length, 1);
  assert.equal(ledger.requirements[0].status, "not_applicable");
  assert.deepEqual(ledger.requirements[0].evidence, []);
});
test("new requirements, duplicate identities and tampered hashes fail closed", () => {
  for (const mutate of [
    (doc) => {
      doc.requirements[0].requirement_id = "command:identity.wallets.new";
    },
    (doc) => {
      doc.requirements.push(doc.requirements[0]);
    },
    (doc) => {
      doc.requirements[0].requirement_sha256 = "bad";
    },
    (doc) => {
      doc.requirements[0].obligation = "required";
    },
  ]) {
    const doc = inventory();
    mutate(doc);
    assert.throws(() => buildWalletLedger(doc, revision), WalletEvidenceError);
  }
});
test("malformed inventories cannot manufacture a ledger", () => {
  for (const doc of [null, [], {}, { requirements: [] }])
    assert.throws(() => buildWalletLedger(doc, revision), WalletEvidenceError);
  assert.throws(
    () => buildWalletLedger(inventory(), "uncommitted"),
    WalletEvidenceError,
  );
});
