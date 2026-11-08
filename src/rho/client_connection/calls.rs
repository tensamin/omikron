use super::*;

fn legacy_call_result(
    message_id: u32,
    result: &tau::calls::CallCommandResult,
) -> CommunicationValue {
    let status = match result.status {
        tau::calls::EnforcementStatus::Applied => "applied",
        tau::calls::EnforcementStatus::PendingEnforcement => "pending_enforcement",
    };
    CommunicationValue::new(CommunicationType::Success)
        .with_id(message_id)
        .add_typed_default(
            DataType::VersionNumber,
            DataValue::UnsignedNumber(result.revision.into()),
        )
        .add_typed_default(DataType::Description, DataValue::Str(status.into()))
}

pub(super) fn call_error_type(error: &CallServiceError) -> CommunicationType {
    match error {
        CallServiceError::NotFound => CommunicationType::ErrorNotFound,
        CallServiceError::NotAuthorized => CommunicationType::ErrorNotAuthenticated,
        CallServiceError::InvalidUser => CommunicationType::ErrorInvalidUserId,
        CallServiceError::InvalidRequest | CallServiceError::AuthorityMappingChanged { .. } => {
            CommunicationType::ErrorInvalidData
        }
        CallServiceError::ResourceLimit => CommunicationType::ErrorInternal,
        CallServiceError::TimedOut { .. } | CallServiceError::DeliveryFailed => {
            CommunicationType::ErrorInternal
        }
        CallServiceError::LiveKit(_) => CommunicationType::ErrorInternal,
    }
}

fn call_error_response(message_id: u32, error: &CallServiceError) -> CommunicationValue {
    let reason = match error {
        CallServiceError::TimedOut { .. } => "call_participant_timed_out",
        CallServiceError::DeliveryFailed => "call_delivery_failed",
        CallServiceError::ResourceLimit => "capacity_exhausted",
        CallServiceError::LiveKit(_) => "call_service_unavailable",
        CallServiceError::NotFound => "call_not_found",
        CallServiceError::NotAuthorized => "call_not_authorized",
        CallServiceError::InvalidUser => "invalid_user",
        CallServiceError::InvalidRequest => "invalid_request",
        CallServiceError::AuthorityMappingChanged { .. } => "authority_mapping_changed",
    };
    let response = CommunicationValue::new(call_error_type(error))
        .with_id(message_id)
        .add_typed_default(DataType::ErrorType, DataValue::Str(reason.into()));
    if let CallServiceError::TimedOut { until_ms } = error {
        response.add_typed_default(
            DataType::Timeout,
            DataValue::SignedNumber((*until_ms).into()),
        )
    } else {
        response
    }
}

impl ClientConnection {
    pub(super) async fn send_call_error(
        self: Arc<Self>,
        message_id: u32,
        error: &CallServiceError,
    ) {
        self.send_message(&call_error_response(message_id, error))
            .await;
    }

    pub(super) async fn handle_call_epoch(self: Arc<Self>, cv: CommunicationValue) {
        use tau::calls::*;
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Some(operation) = cv.get_comm_type_enum() else {
            return;
        };
        let outcome: Result<serde_json::Value, CallError> = async {
            let bytes = cv
                .get_data(DataType::CallPayload)
                .and_then(|value| value.as_bytes())
                .ok_or(CallError::InvalidRequest)?;
            if bytes.len() > MAX_CALL_COMMAND_BYTES {
                return Err(CallError::InvalidRequest);
            }
            let manager = &self.state.call_manager;
            let repository = manager
                .repository
                .as_ref()
                .ok_or(CallError::StorageUnavailable)?;
            if operation == CommunicationType::CallKeyEnvelopeStage {
                // The repository parses the strict Iota Stage schema, verifies the
                // proposer and current recipient set, and durably records ciphertext.
                #[derive(serde::Deserialize)]
                struct StageHeader {
                    call_id: CallId,
                }
                let header: StageHeader =
                    serde_json::from_slice(&bytes).map_err(|_| CallError::InvalidRequest)?;
                if header.call_id != manager.call_id(header.call_id.id)? {
                    return Err(CallError::NotFound);
                }
                repository
                    .stage_epoch_envelope(header.call_id, manager.actor(self.user_id)?, bytes)
                    .await?;
                return Ok(serde_json::json!({ "state": "staged" }));
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Request {
                version: u16,
                call: CallId,
                epoch: u64,
                generation: Option<u64>,
            }
            let request: Request =
                serde_json::from_slice(&bytes).map_err(|_| CallError::InvalidRequest)?;
            if request.version != CALL_PROTOCOL_VERSION {
                return Err(CallError::UnsupportedVersion);
            }
            manager.snapshot(self.user_id, request.call.clone()).await?;
            if operation == CommunicationType::CallKeyEnvelopeActivate {
                repository
                    .commit_epoch(
                        request.call,
                        manager.actor(self.user_id)?,
                        request.epoch,
                        request.generation.ok_or(CallError::InvalidRequest)?,
                    )
                    .await?;
                return Ok(serde_json::json!({ "state": "available", "installed": false }));
            }
            if request.epoch == 0 {
                return Err(CallError::KeyEpochPending);
            }
            let recipient = manager.principal(self.user_id)?;
            repository
                .read(request.call.clone())
                .await?
                .authorize_envelope_read(&recipient, request.epoch, SystemCallClock.now_ms()?)?;
            let payload = serde_json::to_vec(&serde_json::json!({ "call_id": request.call,
                "recipient": recipient, "epoch": request.epoch }))
            .map_err(|_| CallError::InvalidRequest)?;
            let rho = self
                .get_rho_connection()
                .await
                .ok_or(CallError::StorageUnavailable)?;
            let response = rho
                .get_iota_connection()
                .clone()
                .await_response(
                    &CommunicationValue::new(CommunicationType::CallKeyEnvelopeGet)
                        .with_id(next_policy_request_id())
                        .add_typed_default(DataType::CallPayload, DataValue::Bytes(payload)),
                    Some(Duration::from_secs(20)),
                )
                .await
                .map_err(|_| CallError::StorageUnavailable)?;
            if !response.is_type(CommunicationType::CallKeyEnvelopeGet) {
                return Err(CallError::KeyEpochPending);
            }
            // Recheck after the remote read so revocation cannot expose a cached envelope.
            repository
                .read(request.call)
                .await?
                .authorize_envelope_read(&recipient, request.epoch, SystemCallClock.now_ms()?)?;
            let payload = response
                .get_data(DataType::CallPayload)
                .and_then(|value| value.as_bytes())
                .ok_or(CallError::InvalidRequest)?;
            serde_json::from_slice(&payload).map_err(|_| CallError::InvalidRequest)
        }
        .await;
        let payload = match outcome {
            Ok(result) => serde_json::json!({ "version": CALL_PROTOCOL_VERSION, "result": result }),
            Err(error) => serde_json::json!({ "version": CALL_PROTOCOL_VERSION, "error": error }),
        };
        if let Ok(bytes) = serde_json::to_vec(&payload) {
            self.send_message(
                &CommunicationValue::new(operation)
                    .with_id(message_id)
                    .add_typed_default(DataType::CallPayload, DataValue::Bytes(bytes)),
            )
            .await;
        }
    }

    /// CallPayload never supplies the account actor. The authenticated session does.
    pub(super) async fn handle_managed_call(self: Arc<Self>, cv: CommunicationValue) {
        use tau::calls::*;
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let operation = cv.get_comm_type_enum();
        let reply_type = match operation {
            Some(CommunicationType::CallCommand) => CommunicationType::CallCommandResult,
            Some(CommunicationType::CallSnapshotGet) => CommunicationType::CallSnapshot,
            _ => CommunicationType::CallJoinGrant,
        };
        let result: Result<serde_json::Value, CallError> = async {
            let bytes = cv
                .get_data(DataType::CallPayload)
                .and_then(|v| v.as_bytes())
                .ok_or(CallError::InvalidRequest)?;
            if bytes.len() > MAX_CALL_COMMAND_BYTES {
                return Err(CallError::InvalidRequest);
            }
            if operation == Some(CommunicationType::CallCommand) {
                let request = decode_call_command(&bytes)?;
                let manager = &self.state.call_manager;
                if request.call != manager.call_id(request.call.id)? {
                    return Err(CallError::NotFound);
                }
                if let Some(result) = manager
                    .repository
                    .as_ref()
                    .ok_or(CallError::StorageUnavailable)?
                    .replay(manager.actor(self.user_id)?, request.clone())
                    .await?
                {
                    return serde_json::to_value(result).map_err(|_| CallError::StorageUnavailable);
                }
                if let CallCommand::Invite { target } = &request.command {
                    self.check_managed_invitation(target).await?;
                }
                let result = self
                    .state
                    .call_manager
                    .execute(self.user_id, request)
                    .await?;
                serde_json::to_value(result).map_err(|_| CallError::StorageUnavailable)
            } else {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Lookup {
                    version: u16,
                    call: CallId,
                }
                let request: Lookup =
                    serde_json::from_slice(&bytes).map_err(|_| CallError::InvalidRequest)?;
                if request.version != CALL_PROTOCOL_VERSION {
                    return Err(CallError::UnsupportedVersion);
                }
                if operation == Some(CommunicationType::CallSnapshotGet) {
                    let snapshot = self
                        .state
                        .call_manager
                        .snapshot(self.user_id, request.call)
                        .await?;
                    serde_json::to_value(snapshot).map_err(|_| CallError::StorageUnavailable)
                } else {
                    let grant = self
                        .state
                        .call_manager
                        .authorize_join(self.user_id, JoinRequest { call: request.call })
                        .await?;
                    serde_json::to_value(grant).map_err(|_| CallError::StorageUnavailable)
                }
            }
        }
        .await;
        let payload = match result {
            Ok(result) => serde_json::json!({ "version": CALL_PROTOCOL_VERSION, "result": result }),
            Err(error) => serde_json::json!({ "version": CALL_PROTOCOL_VERSION, "error": error }),
        };
        if let Ok(bytes) = serde_json::to_vec(&payload) {
            self.send_message(
                &CommunicationValue::new(reply_type)
                    .with_id(message_id)
                    .add_typed_default(DataType::CallPayload, DataValue::Bytes(bytes)),
            )
            .await;
        }
    }

    async fn check_managed_invitation(
        &self,
        target: &tau::calls::CallPrincipal,
    ) -> Result<(), tau::calls::CallError> {
        use tau::calls::CallError;
        if *target != self.state.call_manager.principal(target.user_id)? {
            return Err(CallError::NotAuthorized);
        }
        let sender = self
            .state
            .rho
            .get_for_user(self.user_id as i64)
            .await
            .ok_or(CallError::StorageUnavailable)?;
        let recipient = self
            .state
            .rho
            .get_for_user(target.user_id as i64)
            .await
            .ok_or(CallError::NotFound)?;
        let request = CommunicationValue::new(CommunicationType::CallContactCheck)
            .with_id(next_policy_request_id())
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(self.user_id.into()),
            )
            .add_typed_default(
                DataType::ReceiverId,
                DataValue::SignedNumber(target.user_id.into()),
            );
        let response = sender
            .get_iota_connection()
            .clone()
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(|_| CallError::StorageUnavailable)?;
        if !response.is_type(CommunicationType::CallContactCheck)
            || response.get_data(DataType::IsBlocked).as_bool() != Some(true)
        {
            return Err(CallError::NotFound);
        }
        let request = CommunicationValue::new(CommunicationType::UserBlockCheck)
            .with_id(next_policy_request_id())
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(self.user_id.into()),
            )
            .add_typed_default(
                DataType::ReceiverId,
                DataValue::SignedNumber(target.user_id.into()),
            );
        let response = recipient
            .get_iota_connection()
            .clone()
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(|_| CallError::StorageUnavailable)?;
        if !response.is_type(CommunicationType::UserBlockCheck)
            || response.get_data(DataType::IsBlocked).as_bool() != Some(false)
        {
            return Err(CallError::NotAuthorized);
        }
        Ok(())
    }

    /// Handle call invite
    pub(super) async fn handle_call_activate(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Some(id) = cv
            .get_data(DataType::CallId)
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok())
        else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let Some(secret) = call_invite_secret_from_cv(&cv) else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                .await;
            return;
        };
        let created_at = match self
            .state
            .call_manager
            .reservation_created_at(self.user_id, id)
            .await
        {
            Ok(created_at) => created_at,
            Err(error) => {
                self.send_call_error(message_id, &error).await;
                return;
            }
        };
        if self
            .store_call_envelope(self.user_id, self.user_id, id, created_at, &secret)
            .await
            .is_err()
        {
            self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                .await;
            return;
        }
        match self
            .state
            .call_manager
            .activate(self.user_id, id, created_at)
            .await
        {
            Ok(token) => {
                let created_at = self
                    .state
                    .call_manager
                    .get_call(id)
                    .await
                    .map(|group| group.created_at_ms)
                    .unwrap_or_default();
                let mut response = CommunicationValue::new(CommunicationType::CallActivate)
                    .with_id(message_id)
                    .add_typed_default(DataType::CallToken, DataValue::Str(token))
                    .add_typed_default(
                        DataType::CreatedAt,
                        DataValue::SignedNumber(created_at.into()),
                    )
                    .add_typed_default(
                        DataType::OmikronId,
                        DataValue::SignedNumber(
                            (self.state.call_manager.owner_omikron_id as i64).into(),
                        ),
                    );
                response = response
                    .add_data(
                        DataTypeId(189),
                        DataValue::Str(
                            self.state
                                .config
                                .livekit
                                .as_ref()
                                .map(|config| config.client_url.clone())
                                .unwrap_or_default(),
                        ),
                    )
                    .expect("CallEndpoint is defined in the type map");
                self.send_message(&response).await;
            }
            Err(error) => self.send_call_error(message_id, &error).await,
        }
    }

    pub(super) async fn store_call_envelope(
        &self,
        recipient: u64,
        inviter: u64,
        id: Uuid,
        created_at: i64,
        secret: &crate::calls::call_group::CallSecretEnvelope,
    ) -> Result<(), ()> {
        let manager = &self.state.call_manager;
        let repository = manager.repository.as_ref().ok_or(())?;
        repository
            .stage_legacy_envelope(
                manager.call_id(id).map_err(|_| ())?,
                manager.principal(recipient).map_err(|_| ())?,
                manager.principal(inviter).map_err(|_| ())?,
                serde_json::to_vec(secret).map_err(|_| ())?,
            )
            .await
            .map_err(|_| ())?;
        let rho = self
            .state
            .rho
            .get_for_user(recipient as i64)
            .await
            .ok_or(())?;
        let response = rho
            .get_iota_connection()
            .clone()
            .await_response(
                &CommunicationValue::new(CommunicationType::CallEnvelopeStore)
                    .with_id(next_policy_request_id())
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber((recipient as i64).into()),
                    )
                    .add_typed_default(
                        DataType::CallInviterId,
                        DataValue::SignedNumber((inviter as i64).into()),
                    )
                    .add_typed_default(DataType::CallId, DataValue::Str(id.to_string()))
                    .add_typed_default(
                        DataType::CreatedAt,
                        DataValue::SignedNumber(created_at.into()),
                    )
                    .add_typed_default(DataType::CallSecret, secret.to_data_value()),
                Some(Duration::from_secs(20)),
            )
            .await
            .map_err(|_| ())?;
        response
            .is_type(CommunicationType::Success)
            .then_some(())
            .ok_or(())
    }

    pub(super) async fn get_call_envelope(
        &self,
        recipient: u64,
        id: Uuid,
    ) -> Result<crate::calls::call_group::CallSecretEnvelope, ()> {
        use tau::calls::{CallClock, CallRepository, SystemCallClock};
        let manager = &self.state.call_manager;
        let repository = manager.repository.as_ref().ok_or(())?;
        let call = manager.call_id(id).map_err(|_| ())?;
        let principal = manager.principal(recipient).map_err(|_| ())?;
        repository
            .read(call.clone())
            .await
            .map_err(|_| ())?
            .authorize_envelope_read(&principal, 0, SystemCallClock.now_ms().map_err(|_| ())?)
            .map_err(|_| ())?;
        let rho = self
            .state
            .rho
            .get_for_user(recipient as i64)
            .await
            .ok_or(())?;
        let response = rho
            .get_iota_connection()
            .clone()
            .await_response(
                &CommunicationValue::new(CommunicationType::CallEnvelopeGet)
                    .with_id(next_policy_request_id())
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber((recipient as i64).into()),
                    )
                    .add_typed_default(DataType::CallId, DataValue::Str(id.to_string())),
                Some(Duration::from_secs(8)),
            )
            .await
            .map_err(|_| ())?;
        if !response.is_type(CommunicationType::CallEnvelopeGet) {
            return Err(());
        }
        repository
            .read(call)
            .await
            .map_err(|_| ())?
            .authorize_envelope_read(&principal, 0, SystemCallClock.now_ms().map_err(|_| ())?)
            .map_err(|_| ())?;
        crate::calls::call_group::CallSecretEnvelope::from_data_value(
            response.get_data(DataType::CallSecret).ok_or(())?,
        )
        .ok_or(())
    }

    pub(super) async fn handle_call_invite(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(receiver_id) = positive_data_i64(&cv, DataType::ReceiverId, "receiver_id") else {
            self.send_error_response(message_id, CommunicationType::ErrorNoUserId)
                .await;
            return;
        };

        let call_id = match cv.get_data(DataType::CallId) {
            Some(DataValue::Str(id_str)) => match Uuid::parse_str(id_str) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(message_id, CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        let secret = match call_invite_secret_from_cv(&cv) {
            Some(secret) => secret,
            None => {
                self.send_error_response(message_id, CommunicationType::BadRequest)
                    .await;
                return;
            }
        };
        // Resolve the recipient before creating call state. Without the
        // recipient Iota, policy cannot be evaluated and delivery must fail.
        let target_rho = match self.state.rho.get_for_user(receiver_id).await {
            Some(rho) => rho,
            None => {
                self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                    .await;
                return;
            }
        };
        let sender_id = self.get_user_id().await as i64;
        let Some(sender_rho) = self.state.rho.get_for_user(sender_id).await else {
            self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                .await;
            return;
        };
        let contact_response = sender_rho
            .get_iota_connection()
            .clone()
            .await_response(
                &CommunicationValue::new(CommunicationType::CallContactCheck)
                    .with_id(next_policy_request_id())
                    .add_typed_default(
                        DataType::SenderId,
                        DataValue::SignedNumber(sender_id.into()),
                    )
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber(receiver_id.into()),
                    ),
                Some(Duration::from_secs(20)),
            )
            .await;
        if !matches!(contact_response, Ok(ref response) if response.is_type(CommunicationType::CallContactCheck) && response.get_data(DataType::IsBlocked).as_bool() == Some(true))
        {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        }
        let policy_request = CommunicationValue::new(CommunicationType::UserBlockCheck)
            .with_id(next_policy_request_id())
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(sender_id.into()),
            )
            .add_typed_default(
                DataType::ReceiverId,
                DataValue::SignedNumber(receiver_id.into()),
            );
        let policy_response = target_rho
            .get_iota_connection()
            .clone()
            .await_response(&policy_request, Some(Duration::from_secs(20)))
            .await;
        let blocked = match &policy_response {
            Ok(response) if response.is_type(CommunicationType::UserBlockCheck) => {
                response.get_data(DataType::IsBlocked).as_bool()
            }
            _ => None,
        };
        match blocked {
            Some(true) => {
                self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                    .await;
                return;
            }
            Some(false) => {}
            None => {
                crate::log_event!(
                    0,
                    crate::util::logger::PrintType::Call,
                    crate::util::logger::LogLevel::Warn,
                    "call.invite_block_check_unavailable",
                    "call_id={} sender_user_id={} recipient_user_id={} response={:?}",
                    call_id,
                    sender_id,
                    receiver_id,
                    policy_response
                        .as_ref()
                        .map(|response| response.get_type_name())
                        .map_err(|error| error.as_str())
                );
                self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                    .await;
                return;
            }
        }
        let Some(group) = self.state.call_manager.get_call(call_id).await else {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        };
        let relation = match self
            .state
            .call_manager
            .check_invite(call_id, self.user_id, receiver_id as u64)
            .await
        {
            Ok((_, relation)) => relation,
            Err(error) => {
                self.send_call_error(message_id, &error).await;
                return;
            }
        };
        let forward_secret = match relation {
            crate::calls::call_manager::InviteRelation::New => {
                if self
                    .store_call_envelope(
                        receiver_id as u64,
                        self.user_id,
                        call_id,
                        group.created_at_ms,
                        &secret,
                    )
                    .await
                    .is_err()
                {
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                }
                if let Err(error) = self
                    .state
                    .call_manager
                    .add_invite(call_id, self.user_id, receiver_id.unsigned_abs())
                    .await
                {
                    self.send_call_error(message_id, &error).await;
                    return;
                }
                let manager = &self.state.call_manager;
                let ready = async {
                    let repository = manager
                        .repository
                        .as_ref()
                        .ok_or(tau::calls::CallError::StorageUnavailable)?;
                    let call = manager.call_id(call_id)?;
                    repository
                        .invitation_ready(call, manager.principal(receiver_id as u64)?, 0)
                        .await
                }
                .await;
                if ready.is_err() {
                    self.send_error_response(message_id, CommunicationType::ErrorInternal)
                        .await;
                    return;
                }
                secret
            }
            relation => {
                // Members and pending invitees already hold an envelope on
                // their Iota. A re-invite must replay exactly that ciphertext,
                // not freshly randomized bytes they cannot decrypt.
                if relation == crate::calls::call_manager::InviteRelation::Pending {
                    // Refresh the recorded inviter so the badge names the latest inviter.
                    if let Err(error) = self
                        .state
                        .call_manager
                        .add_invite(call_id, self.user_id, receiver_id.unsigned_abs())
                        .await
                    {
                        self.send_call_error(message_id, &error).await;
                        return;
                    }
                }
                match self.get_call_envelope(receiver_id as u64, call_id).await {
                    Ok(stored) => stored,
                    Err(()) => {
                        self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                            .await;
                        return;
                    }
                }
            }
        };

        if !self
            .state
            .call_manager
            .should_forward_invite(self.user_id, receiver_id.unsigned_abs())
        {
            let response = CommunicationValue::new(CommunicationType::Success).with_id(message_id);
            self.send_message(&response).await;
            return;
        }

        // Create and send call distribution message
        let forward = CommunicationValue::new(CommunicationType::CallInvite)
            .with_id(next_policy_request_id())
            .with_receiver(receiver_id.unsigned_abs())
            .with_sender(sender_id as u64)
            .add_typed_default(DataType::CallSecret, forward_secret.to_data_value())
            .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
            .add_typed_default(
                DataType::ReceiverId,
                DataValue::SignedNumber(receiver_id.into()),
            )
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(sender_id.into()),
            )
            .add_typed_default(
                DataType::OmikronId,
                DataValue::SignedNumber((self.state.call_manager.owner_omikron_id as i64).into()),
            );

        let response = CommunicationValue::new(CommunicationType::Success).with_id(message_id);
        self.clone().send_message(&response).await;

        // The invitation is durable. A stalled client must not delay the sender's acknowledgement.
        let manager = self.state.call_manager.clone();
        if let Err(error) = self.tasks.spawn_cancellable(async move {
            let Ok(id) = manager.call_id(call_id) else {
                return;
            };
            if !matches!(manager.snapshot(receiver_id.unsigned_abs(), id).await,
                Ok(snapshot) if snapshot.lifecycle == tau::calls::CallLifecycle::Active)
            {
                return;
            }
            match tokio::time::timeout(
                Duration::from_secs(8),
                target_rho.send_to_local_user(receiver_id.unsigned_abs(), &forward),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => crate::log_event!(
                    0,
                    crate::util::logger::PrintType::Call,
                    crate::util::logger::LogLevel::Warn,
                    "call.invite_live_delivery_failed",
                    "call_id={} recipient_user_id={} error={}",
                    call_id,
                    receiver_id,
                    error
                ),
                Err(_) => crate::log_event!(
                    0,
                    crate::util::logger::PrintType::Call,
                    crate::util::logger::LogLevel::Warn,
                    "call.invite_live_delivery_failed",
                    "call_id={} recipient_user_id={} error=timeout",
                    call_id,
                    receiver_id
                ),
            }
        }) {
            log_err!(
                self.user_id as i64,
                PrintType::Client,
                "Call invitation delivery task rejected: {}",
                error
            );
        }
    }

    /// Handle get call request
    pub(super) async fn handle_get_call(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let user_id = self.get_user_id().await;

        let call_id = match cv.get_data(DataType::CallId) {
            Some(DataValue::Str(id_str)) => match Uuid::parse_str(id_str) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(message_id, CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        let Some(group) = self.state.call_manager.get_call(call_id).await else {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        };
        if !group.is_related(user_id).await
            || self.get_call_envelope(user_id, call_id).await.is_err()
        {
            self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                .await;
            return;
        }
        let pending = group.member(user_id).await.is_none();
        if pending {
            let inviter = group
                .state
                .read()
                .await
                .pending_invites
                .get(&user_id)
                .map(|invite| invite.inviter_id);
            let Some(inviter) = inviter else {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
                return;
            };
            let Some(rho) = self.state.rho.get_for_user(user_id as i64).await else {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
                return;
            };
            let response = rho
                .get_iota_connection()
                .clone()
                .await_response(
                    &CommunicationValue::new(CommunicationType::CallContactAccept)
                        .with_id(next_policy_request_id())
                        .add_typed_default(
                            DataType::ReceiverId,
                            DataValue::SignedNumber(user_id.into()),
                        )
                        .add_typed_default(
                            DataType::CallInviterId,
                            DataValue::SignedNumber(inviter.into()),
                        ),
                    Some(Duration::from_secs(8)),
                )
                .await;
            if !matches!(response, Ok(response) if response.is_type(CommunicationType::Success)) {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
                return;
            }
        }

        match self
            .state
            .call_manager
            .get_call_token(user_id, call_id)
            .await
        {
            Ok(token) => {
                let created_at = self
                    .state
                    .call_manager
                    .get_call(call_id)
                    .await
                    .map(|group| group.created_at_ms)
                    .unwrap_or_default();
                let response = CommunicationValue::new(CommunicationType::CallToken)
                    .with_id(message_id)
                    .with_receiver(user_id as u64)
                    .add_typed_default(DataType::CallToken, DataValue::Str(token))
                    .add_typed_default(
                        DataType::CreatedAt,
                        DataValue::SignedNumber(created_at.into()),
                    )
                    .add_typed_default(
                        DataType::OmikronId,
                        DataValue::SignedNumber(
                            (self.state.call_manager.owner_omikron_id as i64).into(),
                        ),
                    )
                    .add_data(
                        DataTypeId(189),
                        DataValue::Str(
                            self.state
                                .config
                                .livekit
                                .as_ref()
                                .map(|config| config.client_url.clone())
                                .unwrap_or_default(),
                        ),
                    );
                match response {
                    Ok(response) => self.send_message(&response).await,
                    Err(_) => {
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await
                    }
                }
            }
            Err(error) => {
                crate::log_event!(
                    0,
                    crate::util::logger::PrintType::Call,
                    crate::util::logger::LogLevel::Warn,
                    "call.token_failed",
                    "message_id={} call_id={} user_id={} error={}",
                    message_id,
                    call_id,
                    user_id,
                    error
                );
                let error_cv = call_error_response(message_id, &error)
                    .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()));
                self.send_message(&error_cv).await;
            }
        }
    }
    pub(super) async fn handle_get_call_data(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let user_id = self.get_user_id().await;

        let call_id = match cv.get_data(DataType::CallId) {
            Some(DataValue::Str(id_str)) => match Uuid::parse_str(id_str) {
                Ok(id) => id,
                Err(_) => {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                        .await;
                    return;
                }
            },
            _ => {
                self.send_error_response(message_id, CommunicationType::ErrorNoCallId)
                    .await;
                return;
            }
        };

        let secret = match self.get_call_envelope(user_id, call_id).await {
            Ok(secret) => secret,
            Err(()) => {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
                return;
            }
        };
        match self.state.call_manager.call_data(call_id, user_id).await {
            Ok((member_ids, created_at)) => {
                let user_ids = member_ids
                    .into_iter()
                    .map(|id| DataValue::SignedNumber(id.into()))
                    .collect();
                let response = CommunicationValue::new(CommunicationType::CallData)
                    .with_id(message_id)
                    .with_receiver(user_id as u64)
                    .add_typed_default(DataType::UserIds, DataValue::Array(user_ids))
                    .add_typed_default(
                        DataType::CreatedAt,
                        DataValue::SignedNumber(created_at.into()),
                    )
                    .add_typed_default(DataType::CallSecret, secret.to_data_value());
                self.send_message(&response).await;
            }
            Err(error) => {
                self.send_call_error(message_id, &error).await;
            }
        }
    }

    pub(super) async fn handle_call_timeout_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let (Ok(user_id), Ok(untill)) = (
            positive_data_i64(&cv, DataType::UserId, "user_id"),
            positive_data_i64(&cv, DataType::Untill, "untill"),
        ) else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                .await;
            return;
        };
        match self
            .state
            .call_manager
            .timeout_user(call_id, self.user_id, user_id.unsigned_abs(), untill)
            .await
        {
            Ok(result) => {
                self.send_message(&legacy_call_result(message_id, &result))
                    .await
            }
            Err(error) => self.send_call_error(message_id, &error).await,
        }
    }
    pub(super) async fn handle_call_disconnect_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let Ok(user_id) = positive_data_i64(&cv, DataType::UserId, "user_id") else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidUserId)
                .await;
            return;
        };
        match self
            .state
            .call_manager
            .disconnect_user(call_id, self.user_id, user_id.unsigned_abs())
            .await
        {
            Ok(result) => {
                self.send_message(&legacy_call_result(message_id, &result))
                    .await
            }
            Err(error) => self.send_call_error(message_id, &error).await,
        }
    }
    pub(super) async fn handle_call_set_anonymous_joining(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(call_id) = Uuid::from_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
        else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        let enable = cv.get_data(DataType::Enabled).as_bool().unwrap_or(true);

        match self
            .state
            .call_manager
            .set_anonymous_joining(call_id, self.user_id, enable, &self.state.omega)
            .await
        {
            Ok(link) => {
                let mut response =
                    CommunicationValue::new(CommunicationType::CallSetAnonymousJoining)
                        .with_id(message_id)
                        .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
                        .add_typed_default(DataType::Enabled, DataValue::Bool(enable));
                if let Some(link) = link {
                    response = response.add_typed_default(DataType::Link, DataValue::Str(link));
                }
                self.send_message(&response).await;
            }
            Err(error) => self.send_call_error(message_id, &error).await,
        }
    }

    pub(super) async fn handle_end_call(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Some(id) = cv
            .get_data(DataType::CallId)
            .and_then(|value| value.as_str())
        else {
            self.send_error_response(message_id, CommunicationType::ErrorNoCallId)
                .await;
            return;
        };
        let Ok(call_id) = Uuid::parse_str(id) else {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        };
        match self
            .state
            .call_manager
            .end_call(call_id, self.user_id)
            .await
        {
            Ok(result) => {
                self.send_message(&legacy_call_result(message_id, &result))
                    .await
            }
            Err(error) => self.send_call_error(message_id, &error).await,
        }
    }
}
