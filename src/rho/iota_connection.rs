mod forwarding;
mod requests;
mod state_sync;
use crate::app_state::AppState;
use crate::calls::call_group::CallGroup;
use crate::log_cv_in;
use crate::log_cv_out;
use crate::log_err;
use crate::log_in;
use crate::log_out;
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueExt, RequiredCommunicationFields,
};
use crate::rho::relay_router;
use crate::util::data_type_id;
use crate::util::logger::PrintType;
use mtp::codec::CommunicationType;
use mtp::codec::CommunicationValue;
use mtp::codec::DataType;
use mtp::codec::DataTypeId;
use mtp::codec::DataValue;
use mtp::codec::TypeMap;
use mtp::crypto::KemPublicKey;
use std::collections::BTreeMap;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

use super::rho_connection::RhoConnection;

const MAX_MESSAGE_HANDLERS: usize = 32;

fn is_iota_notification(frame: &CommunicationValue) -> bool {
    matches!(
        frame.get_comm_type_enum(),
        Some(
            CommunicationType::SyncedSettingChanged
                | CommunicationType::UserBlobChanged
                | CommunicationType::UserAssetChanged
                | CommunicationType::BlockedUsersChanged
                | CommunicationType::ReceiptPolicyChanged
                | CommunicationType::MessageStoragePolicyChanged
                | CommunicationType::PushNotification
        )
    )
}

pub(crate) fn contact_snapshot(value: &CommunicationValue) -> Option<(i64, i64, Vec<i64>)> {
    if !value.is_type(CommunicationType::AccountStateSnapshot)
        && !value.is_type(CommunicationType::AddConversation)
    {
        return None;
    }

    let user_id = value
        .receiver()
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)?;
    let Some(DataValue::Array(values)) = value.get_data(DataType::UserIds) else {
        return None;
    };

    let user_id_type = data_type_id(DataType::UserId, &TypeMap::latest());
    let mut contact_ids = Vec::with_capacity(values.len());
    for value in values {
        let contact_id = match value {
            DataValue::SignedNumber(id) => i64::try_from(*id).ok(),
            DataValue::Container(entries) => entries.iter().find_map(|(key, value)| {
                (*key == user_id_type)
                    .then(|| value.as_signed_number())
                    .flatten()
                    .and_then(|id| i64::try_from(id).ok())
            }),
            _ => None,
        }
        .filter(|id| *id > 0)?;
        contact_ids.push(contact_id);
    }
    contact_ids.sort_unstable();
    contact_ids.dedup();

    Some((user_id, 0, contact_ids))
}

fn registration_request(value: &CommunicationValue, iota_id: u64) -> CommunicationValue {
    value
        .clone()
        .add_typed_default(DataType::IotaId, DataValue::SignedNumber(iota_id.into()))
        .add_typed_default(
            DataType::RegisterId,
            DataValue::Str(uuid::Uuid::new_v4().to_string()),
        )
}

fn is_iota_omega_management_operation(value: &CommunicationValue) -> bool {
    matches!(
        value.get_comm_type_enum(),
        Some(
            CommunicationType::GetUserData
                | CommunicationType::GetIotaData
                | CommunicationType::DeleteIota
                | CommunicationType::AttachUserBegin
                | CommunicationType::AttachUserComplete
                | CommunicationType::ReleaseUserFromIota
                | CommunicationType::DeleteUserCredentialBegin
                | CommunicationType::DeleteUserCredentialComplete
                | CommunicationType::EraseHostedUserDataAck
                | CommunicationType::AcknowledgeIotaUserProvision
                | CommunicationType::CreateUserInvitation
                | CommunicationType::ListUserInvitations
                | CommunicationType::RevokeUserInvitation
        )
    )
}

#[allow(dead_code)]
pub struct IotaConnection {
    pub state: Arc<AppState>,
    _mtp_connection: Option<Arc<mtp::webserver::WebMTPConnection>>,
    pub iota_id: u64,
    /// Derived only from the MTP-authenticated transport key, never its numeric ID.
    pub(crate) node_id: Option<relay_router::IotaNodeId>,
    pub client_version: String,
    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub(super) user_ids: Arc<RwLock<std::collections::HashSet<i64>>>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub waiting_tasks: tau::ResponseCorrelator,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    message_slots: Arc<tokio::sync::Semaphore>,
    delivery_slots: Arc<tokio::sync::Semaphore>,
    tasks: super::tasks::MessageTasks,
    mutation_journal_path: std::path::PathBuf,
}

impl IotaConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, iota_id: u64) -> Arc<Self> {
        let node_id = if general.connection_kind() == super::connection::ConnectionKind::Iota
            && general.mtp_connection.auth_state == mtp::host::AuthState::Authenticated
        {
            general
                .mtp_connection
                .client_public_key
                .as_ref()
                .and_then(|key| relay_router::IotaNodeId::from_public_keys(key).ok())
        } else {
            None
        };
        let connection = Arc::new(Self {
            state: general.state.clone(),
            _mtp_connection: Some(general.mtp_connection.clone()),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            user_ids: Arc::new(RwLock::new(std::collections::HashSet::new())),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            iota_id,
            node_id,
            client_version: general.client_version.read().await.clone(),
            waiting_tasks: tau::ResponseCorrelator::with_next_id(rand::random::<u32>().max(1)),
            message_slots: Arc::new(tokio::sync::Semaphore::new(MAX_MESSAGE_HANDLERS)),
            delivery_slots: Arc::new(tokio::sync::Semaphore::new(MAX_MESSAGE_HANDLERS / 2)),
            tasks: super::tasks::MessageTasks::new(
                general.shutdown.subscribe(),
                general.state.config.message_drain,
            ),
            mutation_journal_path: crate::omega::mutation_journal_path(),
        });
        connection
            .state
            .rho
            .register_revocation_transport(&connection);
        connection
    }
    pub(crate) async fn publish_and_run(self: Arc<Self>, rho: Arc<RhoConnection>) {
        self.set_rho_connection(rho.clone()).await;
        // Replacement publication can wait for a revocation receipt on this
        // transport. Its reader must already be running during that wait.
        tokio::join!(self.state.rho.add(rho.clone()), self.clone().run());
        // The reader may close before publication completes. Remove any route
        // that was published after its first cleanup attempt.
        rho.close_iota_connection().await;
    }

    pub async fn run(self: Arc<Self>) {
        let recovery = self.clone();
        if let Err(error) = self.tasks.spawn(async move {
            let mut ticks = tokio::time::interval(Duration::from_secs(60));
            while recovery
                .tasks
                .while_connected(&recovery.receiver, ticks.tick())
                .await
                .is_some()
            {
                if let Err(error) = recovery.reconcile_password_mutations().await {
                    log_err!(
                        recovery.iota_id as i64,
                        PrintType::Iota,
                        "Password mutation reconciliation failed: {}",
                        error
                    );
                }
            }
        }) {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Password reconciliation submission failed: {}",
                error
            );
        }
        let self_clone = self.clone();
        loop {
            match self_clone
                .tasks
                .while_connected(&self_clone.receiver, self_clone.receiver.receive())
                .await
            {
                Some(Ok(cv)) => {
                    if self_clone.complete_response(&cv).await {
                        continue;
                    }
                    let Ok(permit) = self_clone.message_slots.clone().try_acquire_owned() else {
                        // Waiting here would hide replies behind the next request.
                        let latest = TypeMap::latest();
                        let response = tau::error_response(
                            &cv,
                            CommunicationType::ErrorInternal,
                            cv.type_map().unwrap_or(&latest),
                        );
                        self_clone.send_message(&response).await;
                        continue;
                    };
                    let connection = self_clone.clone();
                    if let Err(error) = self_clone.tasks.spawn(async move {
                        let _permit = permit;
                        connection.handle_message_inner(cv).await;
                    }) {
                        log_err!(
                            self_clone.iota_id as i64,
                            PrintType::Iota,
                            "Iota message submission failed: {}",
                            error
                        );
                        self_clone.sender.close();
                        break;
                    }
                }
                Some(Err(error)) => {
                    log_err!(
                        self_clone.iota_id as i64,
                        PrintType::Iota,
                        "Iota receive loop ended: {}; transport close reason: {:?}",
                        error,
                        self_clone.receiver.close_reason()
                    );
                    break;
                }
                None => break,
            }
        }
        self_clone.waiting_tasks.close();
        self_clone.tasks.drain().await;
        self_clone.handle_close().await;
    }

    /// Get the Iota ID
    pub async fn get_iota_id(&self) -> u64 {
        self.iota_id
    }

    #[allow(dead_code)]
    pub async fn get_public_key(&self) -> Option<KemPublicKey> {
        let guard = self.pub_key.read().await;
        guard.as_ref().map(|bytes| KemPublicKey::new(bytes.clone()))
    }

    /// Get the user IDs
    #[cfg(test)]
    pub async fn get_user_ids(&self) -> Vec<u64> {
        let mut users: Vec<_> = self
            .user_ids
            .read()
            .await
            .iter()
            .filter_map(|id| u64::try_from(*id).ok())
            .collect();
        users.sort_unstable();
        users
    }

    pub async fn add_user_id(&self, user_id: u64) {
        let Ok(user_id) = i64::try_from(user_id) else {
            return;
        };
        let _ = self
            .state
            .rho
            .bind_user_to_iota(user_id, self.iota_id as i64)
            .await;
    }

    /// Set the RhoConnection reference
    pub async fn set_rho_connection(&self, rho_connection: Arc<RhoConnection>) {
        let mut rho_ref = self.rho_connection.write().await;
        *rho_ref = Some(rho_connection);
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        let rho_ref = self.rho_connection.read().await;
        rho_ref.as_ref().map(|weak_ref| weak_ref.clone())
    }

    /// Send a CommunicationValue to the Iota
    pub async fn send_message(&self, cv: &CommunicationValue) {
        log_cv_out!(PrintType::Iota, cv);
        if let Err(e) = self.sender.send(cv).await {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Failed to send message: {:?}",
                e
            );
        }
    }

    #[allow(dead_code)]
    pub async fn send_relay(&self, cv: &CommunicationValue) -> Result<(), String> {
        self.sender
            .send(cv)
            .await
            .map_err(|error| error.to_string())
    }

    async fn complete_response(&self, cv: &CommunicationValue) -> bool {
        let Some(id) = cv.id() else {
            return false;
        };
        // Only the existing nonce-bound revocation receipt may bypass current-route admission.
        if self.node_id.is_some()
            && cv.is_type(CommunicationType::Success)
            && cv.get_data(DataType::Status).as_str() == Some("revoked")
            && cv.get_data(DataType::Uuid).as_str().is_some()
        {
            return self.waiting_tasks.complete(id, cv.clone());
        }
        if cv.is_type(CommunicationType::Relay)
            || cv.is_type(CommunicationType::ChatSecretForward)
            || is_iota_notification(cv)
            || matches!(
                relay_router::message_security_class(cv),
                relay_router::MessageSecurityClass::RelayOnly
            )
        {
            return false;
        }
        let current = self.get_rho_connection().await.is_some_and(|rho| {
            std::ptr::eq(rho.get_iota_connection().as_ref(), self)
                && self.state.rho.is_current_rho(&rho)
        });
        let completed = current && self.waiting_tasks.complete(id, cv.clone());
        if completed {
            log_cv_in!(PrintType::Iota, cv);
        }
        completed
    }

    async fn handle_message_inner(self: Arc<Self>, cv: CommunicationValue) {
        if self.complete_response(&cv).await {
            return;
        }
        let current = self.get_rho_connection().await.is_some_and(|rho| {
            std::ptr::eq(rho.get_iota_connection().as_ref(), self.as_ref())
                && self.state.rho.is_current_rho(&rho)
        });
        if !current {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Rejected message from replaced or unpublished Iota connection"
            );
            self.sender.close();
            return;
        }
        let message_id = match cv.require_id() {
            Ok(message_id) => message_id,
            Err(error) => {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Iota,
                    "Rejected malformed message: {}",
                    error
                );
                let latest = TypeMap::latest();
                let response = tau::error_response(
                    &cv,
                    CommunicationType::ErrorInvalidData,
                    cv.type_map().unwrap_or(&latest),
                );
                self.send_message(&response).await;
                return;
            }
        };
        if matches!(
            relay_router::message_security_class(&cv),
            relay_router::MessageSecurityClass::Unsupported
        ) {
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData, None)
                .await;
            return;
        }
        if cv.is_type(CommunicationType::Relay) {
            if super::hosted_delivery::is_delivery(&cv) {
                let Ok(_delivery) = self.delivery_slots.clone().try_acquire_owned() else {
                    self.send_error_response(message_id, CommunicationType::ErrorInternal, None)
                        .await;
                    return;
                };
                let response = match super::hosted_delivery::deliver(&self, &cv).await {
                    Ok(response) => response.with_id(message_id),
                    Err(_) => CommunicationValue::new(CommunicationType::ErrorInvalidData)
                        .with_id(message_id),
                };
                self.send_message(&response).await;
                return;
            }

            let response = match relay_router::route_relay(
                &self.state,
                &self,
                relay_router::ensure_relay_frame_id(cv),
            )
            .await
            {
                Ok(response) => response.with_id(message_id),
                Err(error) => relay_router::relay_route_error_response(message_id, None, &error),
            };
            self.send_message(&response).await;
            return;
        }

        if matches!(
            crate::rho::relay_router::message_security_class(&cv),
            crate::rho::relay_router::MessageSecurityClass::RelayOnly
        ) {
            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::MessageLive
                        | CommunicationType::MessageState
                        | CommunicationType::MessageEditLive
                        | CommunicationType::MessageReactionLive
                        | CommunicationType::MessageDeleteLive
                )
            ) {
                self.forward_to_client(cv).await;
                return;
            }
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData, None)
                .await;
            return;
        }

        if cv.is_type(CommunicationType::ChatSecretForward) {
            self.forward_to_client(cv).await;
            return;
        }

        log_cv_in!(PrintType::Iota, cv);

        if is_iota_notification(&cv) {
            self.forward_to_client(cv).await;
            return;
        }

        if relay_router::is_relay_receipt_page(&cv) {
            // Account receipt pages are only released by their authenticated
            // request owner after its current-generation checks.
            return;
        }

        if cv.is_type(CommunicationType::AccountStateSnapshot) {
            let user_id = cv.receiver();
            let session_id = cv.get_data(DataType::SessionId).as_number();
            log_in!(
                self.iota_id as i64,
                PrintType::Iota,
                "AccountStateSnapshot user={:?} session={:?} stage=ignored_unsolicited",
                user_id,
                session_id
            );
            // Request-correlated state responses are consumed above by
            // `await_response`.  An unsolicited account-state snapshot cannot form
            // an initial snapshot because it has not crossed the Omega
            // presence barrier, so ClientConnection owns that transaction.
            return;
        }

        // Iota's UserIds field is an authoritative replacement snapshot for
        // the requesting client session, including contact mutations.
        if let Some((user_id, session_id, contact_ids)) = contact_snapshot(&cv) {
            self.update_presence_subscription(user_id, session_id, contact_ids);
        }

        if cv.is_type(CommunicationType::StateSubscribe) {
            self.send_error_response(
                message_id,
                CommunicationType::ErrorInvalidData,
                Some("StateSubscribe must come from an authoritative contact snapshot"),
            )
            .await;
            return;
        }

        // Handle GET_CHATS
        if cv.is_type(CommunicationType::GetChats) {
            self.handle_get_chats(cv).await;
            return;
        }

        if cv.is_type(CommunicationType::CompleteRegisterUser) {
            // Registration carries the authenticated Iota ID separately so
            // Omega can bind the allocation lease to this connection rather
            // than trusting a client-supplied value.
            let request = cv.clone().add_typed_default(
                DataType::IotaId,
                DataValue::SignedNumber(self.iota_id.into()),
            );
            log_in!(
                self.iota_id as i64,
                PrintType::Omega,
                "Forwarding CompleteRegisterUser to Omega (request_id={})",
                message_id
            );
            let mut response_cv = self
                .state
                .omega
                .clone()
                .await_response(&request, Some(Duration::from_secs(8)))
                .await;
            if let Err(error) = &response_cv {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Omega,
                    "CompleteRegisterUser request_id={} failed: {}; retrying once",
                    message_id,
                    error
                );
                response_cv = self
                    .state
                    .omega
                    .clone()
                    .await_response(&request, Some(Duration::from_secs(8)))
                    .await;
            }
            match response_cv {
                Ok(response_cv) => {
                    log_in!(
                        self.iota_id as i64,
                        PrintType::Omega,
                        "Omega completed registration (request_id={}, response_id={:?}, type={})",
                        message_id,
                        response_cv.id(),
                        response_cv
                            .get_comm_type_enum()
                            .map(|kind| kind.to_string())
                            .unwrap_or_else(|| response_cv.get_type().to_string())
                    );
                    if response_cv.is_type(CommunicationType::Success)
                        && let Some(user_id) = cv.get_data(DataType::UserId).as_number()
                    {
                        self.add_user_id(user_id as u64).await;
                    }
                    self.send_message(&response_cv).await;
                }
                Err(error) => {
                    /*
                     * A lost Success can follow a committed insert. Verify
                     * the requested identity and this authenticated Iota
                     * before adding a local binding.
                     */
                    let user_id = cv.get_data(DataType::UserId).as_number();
                    let username = cv.get_data(DataType::Username).as_str().map(str::to_owned);
                    let public_key = cv.get_data(DataType::PublicKey).as_str().map(str::to_owned);
                    if let Some(user_id) = user_id {
                        let verification = CommunicationValue::new(CommunicationType::GetUserData)
                            .with_sender(self.state.omega.omikron_id())
                            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id));
                        match self
                            .state
                            .omega
                            .clone()
                            .await_response(&verification, Some(Duration::from_secs(3)))
                            .await
                        {
                            Ok(verified)
                                if verified.get_data(DataType::UserId).as_number()
                                    == Some(user_id)
                                    && verified.get_data(DataType::IotaId).as_number()
                                        == Some(self.iota_id.into())
                                    && verified.get_data(DataType::Username).as_str()
                                        == username.as_deref()
                                    && verified.get_data(DataType::PublicKey).as_str()
                                        == public_key.as_deref() =>
                            {
                                log_in!(
                                    self.iota_id as i64,
                                    PrintType::Omega,
                                    "Registration response was lost; verified user {} remotely",
                                    user_id
                                );
                                self.add_user_id(user_id as u64).await;
                                self.send_message(
                                    &CommunicationValue::new(CommunicationType::Success)
                                        .with_id(message_id),
                                )
                                .await;
                                return;
                            }
                            Ok(verified) => log_err!(
                                self.iota_id as i64,
                                PrintType::Omega,
                                "Registration verification returned an unexpected user (request_id={:?}, response_id={:?})",
                                verification.id(),
                                verified.id()
                            ),
                            Err(verify_error) => log_err!(
                                self.iota_id as i64,
                                PrintType::Omega,
                                "Registration verification failed after request_id={:?}: {}",
                                verification.id(),
                                verify_error
                            ),
                        }
                    }
                    log_err!(
                        self.iota_id as i64,
                        PrintType::Omega,
                        "CompleteRegisterUser forwarding failed: {}",
                        error
                    );
                    self.send_error_response(
                        message_id,
                        CommunicationType::ErrorInternal,
                        Some(&format!("Omega forwarding failed: {error}")),
                    )
                    .await;
                }
            }
            return;
        }

        if is_iota_omega_management_operation(&cv) {
            let sender = self.get_iota_id().await;

            self.handle_omega_forward(cv.with_sender(sender as u64))
                .await;
            return;
        }

        // Register allocation is scoped to this authenticated Iota.  Keep the
        // source ID in typed data so Omega can create a durable lease.
        if cv.is_type(CommunicationType::GetRegister) {
            self.handle_omega_forward_without_sender(cv).await;
            return;
        }
        log_err!(
            self.iota_id as i64,
            PrintType::Iota,
            "Rejected unsupported communication type {}",
            cv.get_type()
        );
        self.send_error_response(message_id, CommunicationType::ErrorInvalidData, None)
            .await;
    }

    #[allow(dead_code)]
    async fn send_error_response(
        &self,
        message_id: u32,
        error_type: CommunicationType,
        detail: Option<&str>,
    ) {
        let mut error = CommunicationValue::new(error_type).with_id(message_id);
        if let Some(detail) = detail {
            error = error.add_typed_default(DataType::ErrorType, DataValue::Str(detail.into()));
        }
        self.send_message(&error).await;
    }

    #[allow(dead_code)]
    pub(crate) async fn close(&self) {
        self.sender.close();
    }

    pub async fn handle_close(&self) {
        self.waiting_tasks.close();
        log_out!(
            self.iota_id as i64,
            PrintType::Iota,
            "Iota {} disconnected",
            self.iota_id
        );
        if let Some(rho_conn) = self.get_rho_connection().await {
            rho_conn.close_iota_connection().await;
        }
    }
}

impl std::fmt::Debug for IotaConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IotaConnection")
            .field("iota_id", &"[async]")
            .field("identified", &"[async]")
            .field("ping", &"[async]")
            .finish()
    }
}

#[cfg(test)]
mod tests;
