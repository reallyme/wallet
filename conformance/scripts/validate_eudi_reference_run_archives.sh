#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
node "${root}/conformance/scripts/validate_eudi_reference_run_archives.mjs" \
  "${1:-conformance/eudi/reference-run-manifest.json}"
