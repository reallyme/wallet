// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticate, reconcile, and atomically commit lifecycle transitions.

use crate::{
    RuntimeError, RuntimeErrorReason, RuntimeResult, WalletCoreRuntime, WalletRuntimeBackend,
};
use buffa::MessageField;
use reallyme_wallet_lifecycle::{
    apply_reconciled_wallet_lifecycle_retry, apply_wallet_lifecycle_event,
    is_wallet_lifecycle_retry, lifecycle_event_requires_verified_authority,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    wallet_lifecycle_event_from_proto, wallet_lifecycle_evidence_record_from_proto,
    wallet_lifecycle_record_to_proto,
};
use reallyme_wallet_types::NonEmptyIdentifier;

impl<B: WalletRuntimeBackend> WalletCoreRuntime<B> {
    /// Handle the `ApplyWalletLifecycleEvent` operation variant.
    pub(crate) fn apply_wallet_lifecycle_event(
        &mut self,
        mut request: pb::ApplyWalletLifecycleEventRequest,
    ) -> RuntimeResult<pb::ApplyWalletLifecycleEventResponse> {
        let wallet_instance_id =
            NonEmptyIdentifier::new(core::mem::take(&mut request.wallet_instance_id))
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        self.require_bound_wallet(&wallet_instance_id)?;
        let event = wallet_lifecycle_event_from_proto(
            request
                .event
                .as_known()
                .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))?,
        )
        .map_err(RuntimeError::from)?;
        let evidence = request
            .evidence
            .as_option()
            .map(wallet_lifecycle_evidence_record_from_proto)
            .transpose()
            .map_err(RuntimeError::from)?;
        let evidence = evidence.ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        let trusted_now = self.backend_mut().trusted_now()?;
        // The provider clock bounds the evidence timestamp; the caller's now field
        // has no authority over the durable lifecycle watermark.
        const MAX_EVIDENCE_AGE_SECONDS: i64 = 60;
        let age = trusted_now
            .as_seconds()
            .checked_sub(evidence.occurred_at.as_seconds())
            .ok_or(RuntimeError::new(RuntimeErrorReason::LifecycleClockSkew))?;
        if !(0..=MAX_EVIDENCE_AGE_SECONDS).contains(&age) {
            return Err(RuntimeError::new(RuntimeErrorReason::LifecycleClockSkew));
        }
        let (record, revision) = self
            .backend_mut()
            .get_wallet_lifecycle_record(&wallet_instance_id)?
            .into_parts();
        if record.updated_at() > trusted_now {
            return Err(RuntimeError::new(RuntimeErrorReason::LifecycleClockSkew));
        }
        let current = record.clone();
        let retry = is_wallet_lifecycle_retry(&record, event);
        let record = if retry {
            let reconciliation = self.backend_mut().reconcile_wallet_lifecycle_retry(
                &current,
                event,
                &evidence,
                trusted_now,
            )?;
            let commit_now = self.backend_mut().trusted_now()?;
            apply_reconciled_wallet_lifecycle_retry(record, &evidence, reconciliation, commit_now)
        } else {
            apply_wallet_lifecycle_event(record, event, evidence.occurred_at, Some(&evidence))
        }
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        // Request evidence is caller-supplied. Every event other than
        // beginning initial provisioning commits only after the backend
        // authenticates the authority behind that evidence for this Wallet
        // Unit and event: forged restrictive events deny service or destroy
        // state just as forged granting events widen access.
        if !retry && lifecycle_event_requires_verified_authority(event) {
            self.backend_mut().verify_wallet_lifecycle_authority(
                &current,
                event,
                &evidence,
                trusted_now,
            )?;
        }
        let stored_id = self
            .backend_mut()
            .compare_and_swap_wallet_lifecycle_record(revision, &record, &evidence)?;
        if stored_id != wallet_instance_id {
            return Err(RuntimeError::new(
                RuntimeErrorReason::LifecycleStoreRejected,
            ));
        }

        Ok(pb::ApplyWalletLifecycleEventResponse {
            record: MessageField::some(wallet_lifecycle_record_to_proto(&record)),
            ..Default::default()
        })
    }
}
