use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::anonymous_clients::anonymous_manager::{self, generate_username};
use crate::app_state::AppState;
use crate::calls::call_group::call_invite_secret_from_cv;
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueExt, RequiredCommunicationFields,
    positive_data_i64,
};
use crate::util::data_type_id;
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_out};

pub struct AnonymousClientConnection {
    pub state: Arc<AppState>,
    _mtp_connection: Option<Arc<mtp::webserver::WebMTPConnection>>,
    user_id: u64,

    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub interested_users: Arc<RwLock<Vec<i64>>>,
    is_open: Arc<RwLock<bool>>,
    pub user_name: Arc<RwLock<String>>,
    pub display_name: Arc<RwLock<String>>,
    pub avatar: Arc<RwLock<String>>,
    message_slots: Arc<tokio::sync::Semaphore>,
    tasks: Arc<crate::rho::tasks::MessageTasks>,
}

impl AnonymousClientConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, user_id: u64) -> Arc<Self> {
        let username = generate_username(user_id);
        Arc::new(Self {
            state: general.state.clone(),
            _mtp_connection: Some(general.mtp_connection.clone()),
            user_id,

            interested_users: Arc::new(RwLock::new(Vec::new())),
            is_open: Arc::new(RwLock::new(true)),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            user_name: Arc::new(RwLock::new(username.to_lowercase())),
            display_name: Arc::new(RwLock::new(username)),
            avatar: Arc::new(RwLock::new(String::new())),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            tasks: Arc::new(crate::rho::tasks::MessageTasks::new(
                general.shutdown.subscribe(),
                general.state.config.message_drain,
            )),
        })
    }
    pub async fn run(self: Arc<Self>) {
        anonymous_manager::add_anonymous_user(self.clone());
        while let Some(Ok(cv)) = self
            .tasks
            .while_connected(&self.receiver, self.receiver.receive())
            .await
        {
            self.clone().handle_message(cv).await;
        }
        self.tasks.drain().await;
        crate::rho::tasks::finish_cleanup(self.state.config.cleanup_timeout, self.handle_close())
            .await;
    }

    /// Get the user ID
    pub fn get_user_id(&self) -> u64 {
        self.user_id
    }

    /// Get the user name
    pub async fn get_user_name(&self) -> String {
        self.user_name.read().await.clone()
    }

    /// Get the display name
    pub async fn get_display_name(&self) -> String {
        self.display_name.read().await.clone()
    }

    pub async fn set_display_name(&self, display: String) {
        *self.display_name.write().await = display;
    }

    /// Get the avatar
    pub async fn get_avatar(&self) -> String {
        self.avatar.read().await.clone()
    }

    /// Send a CommunicationValue to the client
    pub async fn send_message(self: Arc<Self>, cv: &CommunicationValue) {
        if !*self.is_open.read().await {
            log_out!(
                self.user_id as i64,
                PrintType::Client,
                "Attempted to send message to a closed connection."
            );
            return;
        }
        log_cv_out!(PrintType::Client, &cv);
        if let Err(e) = self.sender.send(cv).await {
            log_out!(
                self.user_id as i64,
                PrintType::Client,
                "Send failed: {:?}",
                e
            );
        }
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        let Some(Ok(permit)) = self
            .tasks
            .while_connected(&self.receiver, self.message_slots.clone().acquire_owned())
            .await
        else {
            return;
        };
        let tasks = self.tasks.clone();
        let sender = self.sender.clone();
        let user_id = self.user_id;
        if let Err(error) = tasks.spawn(async move {
            let _permit = permit;
            let message_id = match cv.require_id() {
                Ok(message_id) => message_id,
                Err(error) => {
                    let response =
                        CommunicationValue::new(CommunicationType::ErrorInvalidData).without_id();
                    log_out!(
                        self.user_id as i64,
                        PrintType::Client,
                        "Rejected malformed message: {}",
                        error
                    );
                    self.send_message(&response).await;
                    return;
                }
            };
            log_cv_in!(PrintType::Client, &cv);

            if cv.is_type(CommunicationType::CallJoinAuthorize) {
                self.handle_guest_join(cv).await;
                return;
            }
            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::CallSnapshotGet
                        | CommunicationType::CallKeyEnvelopeGet
                        | CommunicationType::CallCommand
                )
            ) {
                self.handle_guest_call(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::Relay) {
                self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                    .await;
                return;
            }

            if cv.is_type(CommunicationType::Identification) {
                let call_id = Uuid::parse_str(cv.get_data(DataType::CallId).as_str().unwrap_or(""))
                    .unwrap_or(Uuid::new_v4());

                let call = if let Some(call) = self.state.call_manager.get_call(call_id).await {
                    if call.is_anonymous().await {
                        call
                    } else {
                        self.send_error_response(
                            message_id,
                            CommunicationType::ErrorNotAuthenticated,
                        )
                        .await;
                        return;
                    }
                } else {
                    self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                        .await;
                    return;
                };

                let mut invited = Vec::new();
                for call_invitee in call.state.read().await.members.values().cloned() {
                    let Ok(call_invitee_cv) = self
                        .state
                        .omega
                        .clone()
                        .await_response(
                            &CommunicationValue::new(CommunicationType::GetUserData)
                                .with_sender(self.state.omega.omikron_id())
                                .add_typed_default(
                                    DataType::UserId,
                                    DataValue::SignedNumber(call_invitee.user_id.into()),
                                ),
                            Some(Duration::from_secs(2)),
                        )
                        .await
                    else {
                        continue;
                    };
                    let json_invitee = [
                        (
                            DataType::UserId,
                            call_invitee_cv
                                .get_data(DataType::UserId)
                                .cloned()
                                .unwrap_or(DataValue::Null),
                        ),
                        (
                            DataType::Username,
                            call_invitee_cv
                                .get_data(DataType::Username)
                                .cloned()
                                .unwrap_or(DataValue::Null),
                        ),
                        (
                            DataType::Display,
                            call_invitee_cv
                                .get_data(DataType::Display)
                                .cloned()
                                .unwrap_or(DataValue::Null),
                        ),
                        (
                            DataType::Avatar,
                            call_invitee_cv
                                .get_data(DataType::Avatar)
                                .cloned()
                                .unwrap_or(DataValue::Null),
                        ),
                    ];

                    invited.push(DataValue::Container(
                        json_invitee
                            .iter()
                            .map(|(k, v)| (data_type_id(*k, &TypeMap::latest()), v.clone()))
                            .collect(),
                    ));
                }

                let token = match call.create_anonymous_token(self.get_user_id()).await {
                    Ok(Some(token)) => token,
                    Ok(None) | Err(_) => return,
                };

                let serialized = [
                    (DataType::CallId, DataValue::Str(call_id.to_string())),
                    (DataType::CallInvited, DataValue::Array(invited.clone())),
                    (DataType::CallMembers, DataValue::Array(invited)),
                    (DataType::CallToken, DataValue::Str(token)),
                ];
                self.clone()
                    .send_message(
                        &CommunicationValue::new(CommunicationType::IdentificationResponse)
                            .with_id(message_id)
                            .add_typed_default(
                                DataType::UserId,
                                DataValue::SignedNumber(self.user_id.into()),
                            )
                            .add_typed_default(
                                DataType::Username,
                                DataValue::Str(self.clone().get_user_name().await),
                            )
                            .add_typed_default(
                                DataType::Display,
                                DataValue::Str(self.get_display_name().await),
                            )
                            .add_typed_default(
                                DataType::Avatar,
                                DataValue::Str(self.get_avatar().await),
                            )
                            .add_typed_default(
                                DataType::CallState,
                                DataValue::Container(
                                    serialized
                                        .iter()
                                        .map(|(k, v)| {
                                            (data_type_id(*k, &TypeMap::latest()), v.clone())
                                        })
                                        .collect(),
                                ),
                            ),
                    )
                    .await;
            }

            // Presence is account-scoped and anonymous sessions have no
            // persisted account preference to change.
            if cv.is_type(CommunicationType::ClientChanged) {
                self.send_error_response(message_id, CommunicationType::ErrorNoUserId)
                    .await;
                return;
            }

            // Handle call invites
            if cv.is_type(CommunicationType::CallInvite) {
                self.handle_call_invite(cv).await;
                return;
            }

            // Handle get call requests
            if cv.is_type(CommunicationType::CallToken) {
                self.handle_get_call(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallDisconnectUser) {
                self.handle_call_disconnect_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallTimeoutUser) {
                self.handle_call_timeout_user(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::ChangeUserData) {
                if let Some(display_name) = cv.get_data(DataType::Display).as_str() {
                    let _ = self.set_display_name(display_name.to_string()).await;
                }

                return;
            }

            if cv.is_type(CommunicationType::GetUserData)
                && let Some(anonymous) = {
                    if let Some(user_id) = cv
                        .get_data(DataType::UserId)
                        .as_signed_number()
                        .and_then(|id| u64::try_from(id).ok())
                        .filter(|id| *id > 0)
                    {
                        anonymous_manager::get_anonymous_user(user_id).await
                    } else if let Some(username) = cv.get_data(DataType::Username).as_str() {
                        anonymous_manager::get_anonymous_user_by_name(username.to_string()).await
                    } else {
                        None
                    }
                }
            {
                let response = CommunicationValue::new(CommunicationType::GetUserData)
                    .with_id(message_id)
                    .add_typed_default(
                        DataType::Username,
                        DataValue::Str(anonymous.get_user_name().await),
                    )
                    .add_typed_default(
                        DataType::UserId,
                        DataValue::SignedNumber(anonymous.user_id.into()),
                    )
                    .add_typed_default(
                        DataType::Display,
                        DataValue::Str(anonymous.get_display_name().await),
                    )
                    .add_typed_default(DataType::UserState, DataValue::Str("online".to_string()))
                    .add_typed_default(
                        DataType::Avatar,
                        DataValue::Str(anonymous.get_avatar().await),
                    );

                self.send_message(&response).await;

                return;
            }

            if cv.is_type(CommunicationType::GetUserData)
                || cv.is_type(CommunicationType::GetIotaData)
            {
                self.handle_omega_forward(cv).await;
            }
        }) {
            log_out!(
                user_id as i64,
                PrintType::Client,
                "Message task submission failed: {}",
                error
            );
            sender.close();
        }
    }
    async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let client_for_closure = self.clone();
        let tasks = self.tasks.clone();
        let sender = self.sender.clone();
        let user_id = self.user_id;
        if let Err(error) = tasks.spawn_cancellable(async move {
            let response_cv = self
                .state
                .omega
                .clone()
                .await_response(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
                .await;
            if let Ok(response_cv) = response_cv {
                client_for_closure.send_message(&response_cv).await;
            }
        }) {
            log_out!(
                user_id as i64,
                PrintType::Client,
                "Omega forward task submission failed: {}",
                error
            );
            sender.close();
        }
    }

    /// Handle call invite
    async fn handle_call_invite(self: Arc<Self>, cv: CommunicationValue) {
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
        let invited = self
            .state
            .call_manager
            .add_invite(call_id, self.user_id, receiver_id.unsigned_abs())
            .await;
        if invited.is_err() {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidCallId)
                .await;
            return;
        }

        // Find target RhoConnection
        let target_rho = match self.state.rho.get_for_user(receiver_id).await {
            Some(rho) => rho,
            _ => {
                // Get sender user ID
                let sender_id = self.get_user_id();

                // User is offline - send push notification for call invite
                let push_cv = CommunicationValue::new(CommunicationType::PushNotification)
                    .with_receiver(receiver_id.unsigned_abs())
                    .add_typed_default(
                        DataType::SenderId,
                        DataValue::SignedNumber(sender_id.into()),
                    )
                    .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
                    .add_typed_default(
                        DataType::Notifications,
                        DataValue::Str("call_invite".to_string()),
                    );

                let omega_conn = self.state.omega.clone();
                // Send fire-and-forget, don't await to avoid blocking
                if let Err(error) = self.tasks.spawn_cancellable(async move {
                    let _ = omega_conn.send_message(&push_cv).await;
                }) {
                    log_out!(
                        self.user_id as i64,
                        PrintType::Client,
                        "Call invite push task submission failed: {}",
                        error
                    );
                }

                let error_cv = CommunicationValue::new(CommunicationType::ErrorNotFound)
                    .with_id(message_id)
                    .add_typed_default(
                        DataType::ReceiverId,
                        DataValue::SignedNumber(receiver_id.into()),
                    );
                self.send_message(&error_cv).await;
                return;
            }
        };

        // Get sender user ID
        let sender_id = self.get_user_id();

        // Create and send call distribution message
        let forward = CommunicationValue::new(CommunicationType::CallInvite)
            .with_receiver(receiver_id.unsigned_abs())
            .with_sender(sender_id)
            .add_typed_default(DataType::CallSecret, secret.to_data_value())
            .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()))
            .add_typed_default(
                DataType::ReceiverId,
                DataValue::SignedNumber(receiver_id.into()),
            )
            .add_typed_default(
                DataType::SenderId,
                DataValue::SignedNumber(sender_id.into()),
            );

        target_rho.message_to_client(forward).await;

        let response = CommunicationValue::new(CommunicationType::Success).with_id(message_id);
        self.send_message(&response).await;
    }

    async fn handle_guest_call(self: Arc<Self>, cv: CommunicationValue) {
        use tau::calls::*;
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let operation = cv.get_comm_type_enum();
        let reply = match operation {
            Some(CommunicationType::CallCommand) => CommunicationType::CallCommandResult,
            Some(CommunicationType::CallSnapshotGet) => CommunicationType::CallSnapshot,
            _ => CommunicationType::CallKeyEnvelopeGet,
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
            let engine = manager
                .engine
                .as_ref()
                .ok_or(CallError::StorageUnavailable)?;
            if operation == Some(CommunicationType::CallCommand) {
                let request = decode_call_command(&bytes)?;
                if !matches!(
                    request.command,
                    CallCommand::Leave | CallCommand::AcknowledgeKeyEpoch { .. }
                ) {
                    return Err(CallError::NotAuthorized);
                }
                let actor = manager
                    .guest_actor(self.user_id, request.call.clone())
                    .await?;
                return serde_json::to_value(engine.execute(actor, request).await?)
                    .map_err(|_| CallError::StorageUnavailable);
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Lookup {
                version: u16,
                call: CallId,
                epoch: Option<u64>,
            }
            let request: Lookup =
                serde_json::from_slice(&bytes).map_err(|_| CallError::InvalidRequest)?;
            if request.version != CALL_PROTOCOL_VERSION {
                return Err(CallError::UnsupportedVersion);
            }
            let actor = manager
                .guest_actor(self.user_id, request.call.clone())
                .await?;
            let snapshot = engine.snapshot(actor.clone(), request.call.clone()).await?;
            if operation == Some(CommunicationType::CallSnapshotGet) {
                return serde_json::to_value(snapshot).map_err(|_| CallError::StorageUnavailable);
            }
            let epoch = request.epoch.ok_or(CallError::InvalidRequest)?;
            if epoch == 0 || epoch != snapshot.key_epoch {
                return Err(CallError::KeyEpochPending);
            }
            let payload = manager
                .repository
                .as_ref()
                .ok_or(CallError::StorageUnavailable)?
                .epoch_payload(request.call, actor.principal().clone(), epoch)
                .await?
                .ok_or(CallError::KeyEpochPending)?;
            let envelope: serde_json::Value =
                serde_json::from_slice(&payload).map_err(|_| CallError::StorageUnavailable)?;
            Ok(serde_json::json!({ "state": "available", "envelope": envelope }))
        }
        .await;
        let payload = match outcome {
            Ok(result) => serde_json::json!({ "version": CALL_PROTOCOL_VERSION, "result": result }),
            Err(error) => serde_json::json!({ "version": CALL_PROTOCOL_VERSION, "error": error }),
        };
        if let Ok(bytes) = serde_json::to_vec(&payload) {
            self.send_message(
                &CommunicationValue::new(reply)
                    .with_id(message_id)
                    .add_typed_default(DataType::CallPayload, DataValue::Bytes(bytes)),
            )
            .await;
        }
    }

    async fn handle_guest_join(self: Arc<Self>, cv: CommunicationValue) {
        use tau::calls::*;
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let outcome: Result<JoinGrant, CallError> = async {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Admission {
                version: u16,
                call: CallId,
                capability: String,
                operation_id: Uuid,
            }
            let bytes = cv
                .get_data(DataType::CallPayload)
                .and_then(|value| value.as_bytes())
                .ok_or(CallError::InvalidRequest)?;
            if bytes.len() > MAX_CALL_COMMAND_BYTES {
                return Err(CallError::InvalidRequest);
            }
            let request: Admission =
                serde_json::from_slice(&bytes).map_err(|_| CallError::InvalidRequest)?;
            if request.version != CALL_PROTOCOL_VERSION {
                return Err(CallError::UnsupportedVersion);
            }
            if request.operation_id.is_nil() {
                return Err(CallError::InvalidRequest);
            }
            self.state
                .call_manager
                .authorize_guest(
                    self.user_id,
                    request.call,
                    request.capability,
                    request.operation_id,
                )
                .await
        }
        .await;
        let payload = match outcome {
            Ok(grant) => serde_json::json!({ "version": CALL_PROTOCOL_VERSION, "result": grant }),
            Err(error) => serde_json::json!({ "version": CALL_PROTOCOL_VERSION, "error": error }),
        };
        if let Ok(bytes) = serde_json::to_vec(&payload) {
            self.send_message(
                &CommunicationValue::new(CommunicationType::CallJoinGrant)
                    .with_id(message_id)
                    .add_typed_default(DataType::CallPayload, DataValue::Bytes(bytes)),
            )
            .await;
        }
    }

    /// Handle get call request
    async fn handle_get_call(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let user_id = self.get_user_id();

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

        match self.state.call_manager.get_call(call_id).await {
            Some(call) => match call.create_anonymous_token(user_id).await {
                Ok(Some(token)) => {
                    let response = CommunicationValue::new(CommunicationType::CallToken)
                        .with_id(message_id)
                        .with_receiver(user_id)
                        .add_typed_default(DataType::CallToken, DataValue::Str(token));
                    self.send_message(&response).await;
                }
                Ok(None) => {
                    crate::log_event!(
                        0,
                        crate::util::logger::PrintType::Call,
                        crate::util::logger::LogLevel::Info,
                        "call.anonymous_join_denied",
                        "message_id={} call_id={} user_id={} reason=disabled",
                        message_id,
                        call_id,
                        user_id
                    );
                    let error_cv = CommunicationValue::new(CommunicationType::ErrorNoCallId)
                        .with_id(message_id)
                        .add_typed_default(DataType::CallId, DataValue::Str(call_id.to_string()));
                    self.send_message(&error_cv).await;
                }
                Err(error) => {
                    crate::log_event!(
                        0,
                        crate::util::logger::PrintType::Call,
                        crate::util::logger::LogLevel::Warn,
                        "call.anonymous_token_failed",
                        "message_id={} call_id={} user_id={} error={}",
                        message_id,
                        call_id,
                        user_id,
                        error
                    );
                    self.send_error_response(message_id, CommunicationType::ErrorInternal)
                        .await;
                }
            },
            None => {
                self.send_error_response(message_id, CommunicationType::ErrorNotFound)
                    .await;
            }
        }
    }
    async fn handle_call_timeout_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
            .await;
    }
    async fn handle_call_disconnect_user(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
            .await;
    }

    /// Send error response
    async fn send_error_response(self: Arc<Self>, message_id: u32, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(message_id);
        self.send_message(&error).await;
    }
    /// Close the connection
    #[allow(unused)]
    pub async fn close(&self) {
        let mut is_open_guard = self.is_open.write().await;
        if !*is_open_guard {
            return;
        }
        *is_open_guard = false;

        self.sender.close();
    }

    #[allow(dead_code)]
    /// Set interested users list
    pub async fn set_interested_users(self: Arc<Self>, interested_ids: Vec<i64>) {
        let mut interested_guard = self.interested_users.write().await;
        *interested_guard = interested_ids;
    }
    #[allow(dead_code)]
    pub async fn get_interested_users(self: Arc<Self>) -> Vec<i64> {
        let interested_guard = self.interested_users.read().await;
        interested_guard.clone()
    }

    #[allow(dead_code)]
    /// Check if interested in a user and send notification
    pub async fn are_you_interested(self: Arc<Self>, user_id: i64, user_status: &str) {
        let interested_guard = self.clone().get_interested_users().await;
        if interested_guard.contains(&user_id) {
            let status = if user_status == "user_invisible" {
                "user_offline"
            } else {
                user_status
            };
            let notification = CommunicationValue::new(CommunicationType::ClientChanged)
                .add_typed_default(DataType::UserId, DataValue::Str(user_id.to_string()))
                .add_typed_default(DataType::UserState, DataValue::Str(status.to_string()));

            self.send_message(&notification).await;
        }
    }

    pub async fn handle_close(&self) {
        *self.is_open.write().await = false;
        anonymous_manager::remove_anonymous_user(self.user_id).await;
    }
}

// Implement Clone to make it easier to work with Arc<AnonymousClientConnection>
impl Clone for AnonymousClientConnection {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            _mtp_connection: self._mtp_connection.clone(),
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: self.user_id,
            interested_users: Arc::clone(&self.interested_users),
            is_open: Arc::clone(&self.is_open),
            user_name: Arc::clone(&self.user_name),
            display_name: Arc::clone(&self.display_name),
            avatar: Arc::clone(&self.avatar),
            message_slots: Arc::clone(&self.message_slots),
            tasks: Arc::clone(&self.tasks),
        }
    }
}
