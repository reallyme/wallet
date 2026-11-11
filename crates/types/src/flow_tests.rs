// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::FlowStateSchemaVersion;

#[test]
fn flow_state_schema_version_one_has_stable_wire_value() {
    assert_eq!(FlowStateSchemaVersion::V1.as_u32(), 1);
}
