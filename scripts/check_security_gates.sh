#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

require_tool() {
  local tool_name="$1"
  if ! command -v "${tool_name}" >/dev/null 2>&1; then
    printf 'required tool is missing: %s\n' "${tool_name}" >&2
    exit 127
  fi
}

require_tool cargo
require_tool buf
require_tool node
require_tool npm

if ! cargo audit --version >/dev/null 2>&1; then
  printf 'required cargo subcommand is missing: cargo-audit\n' >&2
  exit 127
fi

if ! cargo deny --version >/dev/null 2>&1; then
  printf 'required cargo subcommand is missing: cargo-deny\n' >&2
  exit 127
fi

buf lint
node scripts/check-proto-first-boundaries.mjs
cargo fmt --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
node scripts/check_rust_release_policy.mjs --check-wasm
cargo deny check
scripts/audit_committed_lockfiles.sh
node scripts/check_rust_package_surfaces.mjs
npm exec --yes --ignore-scripts --package=github:reallyme/release-readiness#9cf40c7da1def8a8d809af51789284097c572dd5 -- \
  reallyme-release-readiness

if ! cargo fuzz --version >/dev/null 2>&1; then
  printf 'required cargo subcommand is missing: cargo-fuzz\n' >&2
  exit 127
fi
cargo +nightly-2026-09-15 fuzz build -Z cargo-lints
