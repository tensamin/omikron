//! Transport adapters for the durable Tau outbox. No call policy is stored here.
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use tau::calls::*;

use crate::{
    calls::{call_group::CallSecretEnvelope, repository::SqliteCallRepository},
    rho::rho_manager::RhoManager,
    services::call_state::next_call_lookup_id,
};

pub struct CallRuntime {
    pub repository: Arc<SqliteCallRepository>,
    pub rho: Arc<RhoManager>,
    pub principal_authority: CallAuthority,
}
static NEXT_EPOCH_BATCH: AtomicUsize = AtomicUsize::new(0);

impl CallRuntime {
    async fn iota_request(
        &self,
        recipient: &CallPrincipal,
        operation: CommunicationType,
        payload: Vec<u8>,
    ) -> Result<CommunicationValue, CallError> {
        if recipient.authority != self.principal_authority {
            return Err(CallError::NotAuthorized);
        }
        let rho = self
            .rho
            .get_for_user(recipient.user_id as i64)
            .await
            .ok_or(CallError::StorageUnavailable)?;
        let request = CommunicationValue::new(operation)
            .with_id(next_call_lookup_id())
            .add_typed_default(DataType::CallPayload, DataValue::Bytes(payload));
        let response = rho
            .get_iota_connection()
            .clone()
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(|_| CallError::StorageUnavailable)?;
        if !response.is_type(operation) {
            return Err(CallError::KeyEpochPending);
        }
        #[derive(serde::Deserialize)]
        struct Delivery {
            state: String,
        }
        let bytes = response
            .get_data(DataType::CallPayload)
            .and_then(|value| value.as_bytes())
            .ok_or(CallError::InvalidRequest)?;
        if bytes.len() > MAX_CALL_COMMAND_BYTES {
            return Err(CallError::InvalidRequest);
        }
        let delivery: Delivery =
            serde_json::from_slice(&bytes).map_err(|_| CallError::InvalidRequest)?;
        let expected = match operation {
            CommunicationType::CallKeyEnvelopeStage => {
                matches!(delivery.state.as_str(), "staged" | "available")
            }
            CommunicationType::CallKeyEnvelopeActivate => delivery.state == "available",
            CommunicationType::CallKeyEnvelopeRevoke => {
                matches!(delivery.state.as_str(), "revoked" | "expired")
            }
            _ => false,
        };
        if !expected {
            return Err(CallError::KeyEpochPending);
        }
        Ok(response)
    }

    pub async fn process_epoch_envelopes(self: &Arc<Self>) -> Result<(), CallError> {
        let mut pending = self.repository.pending_epoch_envelopes().await?;
        if pending.is_empty() {
            return Ok(());
        }
        let start = NEXT_EPOCH_BATCH.fetch_add(4, Ordering::Relaxed) % pending.len();
        pending.rotate_left(start);
        let mut tasks = tokio::task::JoinSet::new();
        for pending in pending.into_iter().take(4) {
            let runtime = self.clone();
            tasks.spawn(async move { runtime.deliver_epoch_envelope(pending).await });
        }
        let mut outcome = Ok(());
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result.unwrap_or(Err(CallError::StorageUnavailable)) {
                outcome = Err(error);
            }
        }
        outcome
    }

    async fn deliver_epoch_envelope(
        &self,
        pending: crate::calls::repository::PendingEpochEnvelope,
    ) -> Result<(), CallError> {
        if pending.recipient.authority == pending.call.owner_authority {
            // Guest ciphertext is hosted here, under a session-scoped principal.
            self.repository
                .epoch_envelope_staged(
                    pending.call.clone(),
                    pending.recipient.clone(),
                    pending.epoch,
                    pending.generation,
                )
                .await?;
            self.repository
                .epoch_envelope_activated(
                    pending.call,
                    pending.recipient,
                    pending.epoch,
                    pending.generation,
                )
                .await?;
            return Ok(());
        }
        if !pending.staged {
            self.iota_request(
                &pending.recipient,
                CommunicationType::CallKeyEnvelopeStage,
                pending.payload.clone(),
            )
            .await?;
            self.repository
                .epoch_envelope_staged(
                    pending.call.clone(),
                    pending.recipient.clone(),
                    pending.epoch,
                    pending.generation,
                )
                .await?;
        }
        if !pending.activated {
            // The owner validates the proposal generation before releasing ciphertext.
            self.repository
                .epoch_envelope_staged(
                    pending.call.clone(),
                    pending.recipient.clone(),
                    pending.epoch,
                    pending.generation,
                )
                .await?;
            let payload =
                epoch_mutation(&pending.call, &pending.recipient, pending.epoch, "activate")?;
            self.iota_request(
                &pending.recipient,
                CommunicationType::CallKeyEnvelopeActivate,
                payload,
            )
            .await?;
            self.repository
                .epoch_envelope_activated(
                    pending.call,
                    pending.recipient,
                    pending.epoch,
                    pending.generation,
                )
                .await?;
        }
        Ok(())
    }
}

fn epoch_mutation(
    call: &CallId,
    recipient: &CallPrincipal,
    epoch: u64,
    action: &str,
) -> Result<Vec<u8>, CallError> {
    let key = serde_json::to_vec(&(call, recipient, epoch, action))
        .map_err(|_| CallError::InvalidRequest)?;
    let digest = mtp::crypto::sha256(&key);
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    serde_json::to_vec(
        &serde_json::json!({ "operation_id": uuid::Uuid::from_bytes(id),
        "call_id": call, "recipient": recipient, "epoch": epoch }),
    )
    .map_err(|_| CallError::InvalidRequest)
}

impl CallEventPublisher for CallRuntime {
    fn publish(&self, current: Call, event: CallEvent) -> CallFuture<'_, ()> {
        Box::pin(async move {
            for recipient in event.audience.clone() {
                let latest = self.repository.read(current.id.clone()).await?;
                let actor = AuthenticatedCallActor::from_verified_session(recipient.clone())?;
                if event.kind != CallEventKind::Removed
                    && latest.snapshot(&actor, SystemCallClock.now_ms()?).is_err()
                {
                    continue;
                }
                let mut scoped = event.clone();
                scoped.audience = vec![recipient.clone()];
                let bytes = serde_json::to_vec(&scoped).map_err(|_| CallError::InvalidRequest)?;
                let operation = if matches!(
                    event.kind,
                    CallEventKind::KeyEpochAvailable | CallEventKind::KeyRotationRequired
                ) {
                    CommunicationType::CallKeyEpochChanged
                } else {
                    CommunicationType::CallStateChanged
                };
                let message = CommunicationValue::new(operation)
                    .with_receiver(recipient.user_id)
                    .add_typed_default(DataType::CallPayload, DataValue::Bytes(bytes));
                if recipient.authority == current.id.owner_authority {
                    if let Some(guest) =
                        crate::anonymous_clients::anonymous_manager::get_anonymous_user(
                            recipient.user_id,
                        )
                        .await
                    {
                        guest.send_message(&message).await;
                    }
                    continue;
                }
                if recipient.authority != self.principal_authority {
                    return Err(CallError::NotAuthorized);
                }
                let Some(rho) = self.rho.get_for_user(recipient.user_id as i64).await else {
                    continue;
                };
                for client in rho
                    .get_client_connections_for_user(recipient.user_id as i64)
                    .await
                {
                    if !client.supports_managed_calls() {
                        continue;
                    }
                    let _route = client.rho_connection.read().await;
                    if !rho.owns_client(&client) {
                        continue;
                    }
                    let latest = self.repository.read(current.id.clone()).await?;
                    if event.kind != CallEventKind::Removed
                        && latest.snapshot(&actor, SystemCallClock.now_ms()?).is_err()
                    {
                        continue;
                    }
                    client
                        .send_relay(&message)
                        .await
                        .map_err(|_| CallError::StorageUnavailable)?;
                }
                if matches!(event.kind, CallEventKind::Ending | CallEventKind::Removed) {
                    let legacy = CommunicationValue::new(CommunicationType::CallEnded)
                        .with_receiver(recipient.user_id)
                        .add_typed_default(
                            DataType::CallId,
                            DataValue::Str(current.id.id.to_string()),
                        );
                    rho.send_to_local_user(recipient.user_id, &legacy)
                        .await
                        .map_err(|_| CallError::StorageUnavailable)?;
                }
            }
            Ok(())
        })
    }
}

impl CallEnvelopeDirectory for CallRuntime {
    fn apply(&self, current: Call, effect: CallEffect) -> CallFuture<'_, ()> {
        Box::pin(async move {
            match effect {
                CallEffect::StageInvitation { principal, epoch } => {
                    if principal.authority != self.principal_authority {
                        return Err(CallError::NotAuthorized);
                    }
                    let latest = self.repository.read(current.id.clone()).await?;
                    let Some(invitation) =
                        latest.invitations.iter().find(|i| i.recipient == principal)
                    else {
                        return Ok(());
                    };
                    if invitation.delivery_ready {
                        return Ok(());
                    }
                    if latest.terminal()
                        || latest.banned(&principal)
                        || invitation.expires_at_ms <= SystemCallClock.now_ms()?
                    {
                        return Ok(());
                    }
                    if epoch != latest.key_epoch {
                        return Err(CallError::KeyEpochPending);
                    }
                    if latest.key_available_generation != latest.rotation_generation {
                        return Err(CallError::KeyEpochPending);
                    }
                    if epoch > 0 {
                        return Err(CallError::KeyEpochPending);
                    }
                    let payload = self
                        .repository
                        .legacy_envelope(current.id.clone(), principal.clone())
                        .await?
                        .ok_or(CallError::KeyEpochPending)?;
                    let envelope: CallSecretEnvelope =
                        serde_json::from_slice(&payload).map_err(|_| CallError::InvalidRequest)?;
                    let rho = self
                        .rho
                        .get_for_user(principal.user_id as i64)
                        .await
                        .ok_or(CallError::StorageUnavailable)?;
                    let response = rho
                        .get_iota_connection()
                        .clone()
                        .await_response(
                            &CommunicationValue::new(CommunicationType::CallEnvelopeStore)
                                .with_id(next_call_lookup_id())
                                .add_typed_default(
                                    DataType::ReceiverId,
                                    DataValue::SignedNumber(principal.user_id.into()),
                                )
                                .add_typed_default(
                                    DataType::CallInviterId,
                                    DataValue::SignedNumber(invitation.inviter.user_id.into()),
                                )
                                .add_typed_default(
                                    DataType::CallId,
                                    DataValue::Str(current.id.id.to_string()),
                                )
                                .add_typed_default(
                                    DataType::CreatedAt,
                                    DataValue::SignedNumber(
                                        self.repository
                                            .created_at(current.id.clone())
                                            .await?
                                            .into(),
                                    ),
                                )
                                .add_typed_default(DataType::CallSecret, envelope.to_data_value()),
                            Some(Duration::from_secs(20)),
                        )
                        .await
                        .map_err(|_| CallError::StorageUnavailable)?;
                    if !response.is_type(CommunicationType::Success) {
                        return Err(CallError::KeyEpochPending);
                    }
                    self.repository
                        .invitation_ready(current.id, principal, epoch)
                        .await
                }
                CallEffect::RevokeEnvelopesThrough {
                    principal,
                    max_epoch,
                } => {
                    self.repository
                        .clear_legacy_envelopes_through(
                            current.id.clone(),
                            principal.clone(),
                            max_epoch,
                        )
                        .await?;
                    if principal.authority == current.id.owner_authority {
                        return Ok(());
                    }
                    for epoch in self
                        .repository
                        .epoch_numbers(current.id.clone(), principal.clone())
                        .await?
                    {
                        if epoch > max_epoch {
                            continue;
                        }
                        self.iota_request(
                            &principal,
                            CommunicationType::CallKeyEnvelopeRevoke,
                            epoch_mutation(&current.id, &principal, epoch, "revoke")?,
                        )
                        .await?;
                    }
                    Ok(())
                }
                CallEffect::RevokeEnvelopes { .. } => Err(CallError::KeyEpochPending),
                // Existing legacy clients cannot supply a new membership key epoch.
                // Keep this durable effect pending until an explicit epoch arrives.
                CallEffect::RequestKeyRotation { generation } => {
                    if current.terminal() {
                        return Ok(());
                    }
                    if current.rotation_pending(SystemCallClock.now_ms()?)
                        || current.key_available_generation < generation
                    {
                        Err(CallError::KeyEpochPending)
                    } else {
                        Ok(())
                    }
                }
                // Guest capability revocation commits in the owner's transaction.
                CallEffect::RevokeLinks => Ok(()),
                _ => Err(CallError::InvalidRequest),
            }
        })
    }
}

pub fn start_effect_worker(
    engine: Arc<CallEngine>,
    runtime: Arc<CallRuntime>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut last_health = tokio::time::Instant::now();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                _ = interval.tick() => {
                    let (effects, epochs) = tokio::join!(engine.process_effects(4), runtime.process_epoch_envelopes());
                    if let Err(error) = effects {
                        crate::log_err!(0, crate::util::logger::PrintType::Call, "Call effect delivery failed: {error}");
                    }
                    if let Err(error) = epochs {
                        crate::log_err!(0, crate::util::logger::PrintType::Call, "Call epoch delivery pending: {error}");
                    }
                    if last_health.elapsed()>=Duration::from_secs(60) {
                        last_health=tokio::time::Instant::now();
                        if let Ok(now)=SystemCallClock.now_ms()
                            && let Ok(health)=runtime.repository.outbox_health(now).await {
                            let level=if health.expired_leases>0 || (health.pending_effects>0 && health.max_attempts>1) {
                                crate::util::logger::LogLevel::Warn
                            } else {crate::util::logger::LogLevel::Info};
                            crate::log_event!(0,crate::util::logger::PrintType::Call,level,"call.outbox_health",
                                "pending_effects={} expired_leases={} retries={} max_attempts={} pending_key_envelopes={}",
                                health.pending_effects,health.expired_leases,health.retries,health.max_attempts,health.pending_key_envelopes);
                        }
                    }
                }
            }
        }
    })
}
