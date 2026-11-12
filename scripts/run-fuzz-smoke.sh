#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly binary_directory="${WALLET_FUZZ_BINARY_DIRECTORY:?WALLET_FUZZ_BINARY_DIRECTORY is required}"
readonly selected_target="${WALLET_FUZZ_TARGET:-}"
readonly run_count="${WALLET_FUZZ_RUNS:-}"
readonly max_total_time="${WALLET_FUZZ_MAX_TOTAL_TIME:-300}"
readonly rss_limit_mb="${WALLET_FUZZ_RSS_LIMIT_MB:-4096}"
readonly -a all_targets=(wallet_proto_decode wallet_proto_json wallet_identifier wallet_state_machine)

validate_uint() {
  local value="$1"
  local name="$2"
  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s must be a positive integer\n' "${name}" >&2
    exit 64
  fi
}

is_known_target() {
  local candidate="$1"
  local target
  for target in "${all_targets[@]}"; do
    if [[ "${candidate}" == "${target}" ]]; then
      return 0
    fi
  done
  return 1
}

run_target() {
  local target="$1"
  local binary_path="${binary_directory}/${target}"
  local artifact_directory="fuzz/artifacts/${target}"
  if ! is_known_target "${target}"; then
    printf 'unknown Wallet fuzz target\n' >&2
    exit 64
  fi
  if [[ ! -f "${binary_path}" || -L "${binary_path}" || ! -x "${binary_path}" ]]; then
    printf 'validated fuzz executable is unavailable for %s\n' "${target}" >&2
    exit 66
  fi
  # Git does not retain the generated binary/identifier corpus directories.
  # A clean CI checkout must also support starting those targets without seeds.
  mkdir -p "${artifact_directory}" "fuzz/corpus/${target}"
  if [[ -n "${run_count}" ]]; then
    validate_uint "${run_count}" "WALLET_FUZZ_RUNS"
    "${binary_path}" \
      "-runs=${run_count}" \
      "-rss_limit_mb=${rss_limit_mb}" \
      "-artifact_prefix=${artifact_directory}/" \
      "fuzz/corpus/${target}"
  else
    validate_uint "${max_total_time}" "WALLET_FUZZ_MAX_TOTAL_TIME"
    "${binary_path}" \
      "-max_total_time=${max_total_time}" \
      "-rss_limit_mb=${rss_limit_mb}" \
      "-artifact_prefix=${artifact_directory}/" \
      "fuzz/corpus/${target}"
  fi
}

validate_uint "${rss_limit_mb}" "WALLET_FUZZ_RSS_LIMIT_MB"
if [[ -n "${selected_target}" ]]; then
  run_target "${selected_target}"
else
  for target in "${all_targets[@]}"; do
    run_target "${target}"
  done
fi
