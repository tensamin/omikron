mod calls;
mod omega_forward;
use crate::anonymous_clients::anonymous_manager;
use crate::app_state::AppState;
use crate::calls::{call_group::call_invite_secret_from_cv, call_manager::CallServiceError};
use crate::data::user::UserStatus;
use crate::omega::omega_connection::{AuthIdentity, AuthIdentityKind};
use crate::rho::connection::{
    GeneralConnection, MtpReceiver, MtpSender, OptionalDataValueExt, RequiredCommunicationFields,
    positive_data_i64,
};
use crate::rho::relay_router;
use crate::rho::rho_connection::RhoConnection;
use crate::util::logger::PrintType;
use crate::{log_cv_in, log_cv_out, log_err, log_out};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue};
use mtp::crypto::PublicKeyBundle;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, oneshot};
use uuid::Uuid;

static NEXT_POLICY_REQUEST_ID: AtomicU32 = AtomicU32::new(1);

fn is_password_receipt_query(frame: &CommunicationValue) -> bool {
    frame.is_type(CommunicationType::PasswordEnrollmentStatus)
        && frame
            .get_data(DataType::SecurePayload)
            .and_then(DataValue::as_bytes)
            .is_some_and(|bytes| !bytes.is_empty() && bytes.len() <= 512 * 1024)
        && frame
            .get_data(DataType::Version)
            .and_then(DataValue::as_str)
            .is_some_and(|text| {
                mtp::type_map::Version::parse(text)
                    .is_some_and(|version| version.to_string() == text)
            })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceClass {
    Desktop,
    Mobile,
    Web,
}

#[derive(Clone, Debug)]
pub struct SessionActivity {
    pub reported: bool,
    pub device_class: DeviceClass,
    pub notification_capable: bool,
}

impl Default for SessionActivity {
    fn default() -> Self {
        Self {
            reported: false,
            device_class: DeviceClass::Web,
            notification_capable: false,
        }
    }
}

fn next_policy_request_id() -> u32 {
    NEXT_POLICY_REQUEST_ID
        .fetch_add(1, Ordering::Relaxed)
        .max(1)
}

fn authenticated_peer_control_request(cv: &CommunicationValue, user_id: u64) -> CommunicationValue {
    cv.clone().with_sender(user_id)
}

fn authenticated_native_relay_request(
    cv: &CommunicationValue,
    actor: u64,
    session: u64,
    generation: u64,
) -> Result<CommunicationValue, &'static str> {
    if actor == 0
        || session == 0
        || generation == 0
        || !cv.is_type(CommunicationType::Relay)
        || cv.payload().as_encrypted().is_none()
    {
        return Err("invalid native relay forwarding context");
    }
    let map = cv.type_map().ok_or("missing native relay dictionary")?;
    let bytes = cv.to_bytes().map_err(|_| "invalid native relay frame")?;
    Ok(
        CommunicationValue::new_with_type_map(CommunicationType::Relay, map)
            .with_id(cv.id().ok_or("missing native relay correlation")?)
            .with_sender(actor)
            .add_typed_default(
                DataType::Status,
                DataValue::Str("tensamin-hosted-native-v1".into()),
            )
            .add_typed_default(
                DataType::SessionId,
                DataValue::UnsignedNumber(session.into()),
            )
            .add_typed_default(
                DataType::VersionNumber,
                DataValue::UnsignedNumber(generation.into()),
            )
            .add_typed_default(DataType::Uuid, DataValue::Str(Uuid::new_v4().to_string()))
            .add_typed_default(DataType::Version, DataValue::Str(map.version.to_string()))
            .add_typed_default(DataType::SecurePayload, DataValue::Bytes(bytes)),
    )
}

fn is_client_omega_operation(value: &CommunicationValue) -> bool {
    matches!(
        value.get_comm_type_enum(),
        Some(
            CommunicationType::ChangeUserData
                | CommunicationType::GetNotifications
                | CommunicationType::GetUserData
                | CommunicationType::GetIotaData
                | CommunicationType::DeleteUser
        )
    )
}

pub struct ClientConnection {
    pub state: Arc<AppState>,
    _mtp_connection: Option<Arc<mtp::webserver::WebMTPConnection>>,
    pub user_id: u64,
    pub session_id: u64,
    pub client_version: String,

    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    pub(super) is_open: Arc<RwLock<bool>>,
    pub(super) native_forwarding: Arc<super::native_forwarding::NativeForwarding>,
    pub(super) delivery_responses: Arc<tau::ResponseCorrelator>,
    message_slots: Arc<tokio::sync::Semaphore>,
    tasks: Arc<super::tasks::MessageTasks>,
    session_activity: Arc<RwLock<SessionActivity>>,
    pub(super) foreground_requests: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    managed_calls: Arc<AtomicBool>,
}

impl ClientConnection {
    pub async fn from_general(general: Arc<GeneralConnection>, user_id: u64) -> Arc<Self> {
        Arc::new(Self {
            state: general.state.clone(),
            _mtp_connection: Some(general.mtp_connection.clone()),
            pub_key: Arc::new(RwLock::new(None)),
            rho_connection: general.rho_connection.clone(),
            is_open: Arc::new(RwLock::new(true)),
            native_forwarding: Arc::new(super::native_forwarding::NativeForwarding::default()),
            delivery_responses: Arc::new(tau::ResponseCorrelator::with_next_id(
                rand::random::<u32>().max(1),
            )),
            sender: general.sender.clone(),
            receiver: general.receiver.clone(),
            user_id,
            session_id: *general.session_id.read().await,
            client_version: general.client_version.read().await.clone(),
            message_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            tasks: Arc::new(super::tasks::MessageTasks::new(
                general.shutdown.subscribe(),
                general.state.config.message_drain,
            )),
            session_activity: Arc::new(RwLock::new(SessionActivity::default())),
            foreground_requests: Arc::new(Mutex::new(HashMap::new())),
            managed_calls: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn session_activity(&self) -> SessionActivity {
        self.session_activity.read().await.clone()
    }
    pub(crate) fn supports_managed_calls(&self) -> bool {
        self.managed_calls.load(Ordering::Relaxed)
    }

    pub(crate) fn notify_connected(self: &Arc<Self>, iota_id: u64) {
        let client = self.clone();
        if let Err(error) = self.tasks.spawn(async move {
            if let Err(error) = client
                .state
                .omega
                .user_connected(
                    client.user_id as i64,
                    client.session_id as i64,
                    iota_id as i64,
                )
                .await
            {
                log_err!(
                    client.user_id as i64,
                    PrintType::Client,
                    "Client activation notification failed: {}",
                    error
                );
            }
        }) {
            log_err!(
                self.user_id as i64,
                PrintType::Client,
                "Client activation notification rejected: {}",
                error
            );
            self.sender.close();
        }
    }

    pub async fn foreground(&self) -> bool {
        let id = NEXT_POLICY_REQUEST_ID.fetch_add(1, Ordering::Relaxed) | 0x8000_0000;
        let (sender, receiver) = oneshot::channel();
        self.foreground_requests.lock().await.insert(id, sender);
        let request = CommunicationValue::new(CommunicationType::SessionActivitySet).with_id(id);
        let foreground = tokio::time::timeout(Duration::from_secs(1), async {
            self.send_relay(&request).await.ok()?;
            receiver.await.ok()
        })
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
        self.foreground_requests.lock().await.remove(&id);
        foreground
    }
    pub async fn run(self: Arc<Self>) {
        let self_clone2 = self.clone();
        if let Err(error) = self.tasks.spawn_cancellable(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if self_clone2.get_rho_connection().await.is_none() {
                self_clone2
                    .send_error_response(0, CommunicationType::ErrorNoIota)
                    .await;
            }
        }) {
            log_err!(
                self.user_id as i64,
                PrintType::Client,
                "Client route check rejected: {}",
                error
            );
            self.close().await;
        }
        while let Some(Ok(cv)) = self
            .tasks
            .while_connected(&self.receiver, self.receiver.receive())
            .await
        {
            self.clone().handle_message(cv).await;
        }
        self.tasks.drain().await;
        self.close().await;
        self.clone().handle_close().await;
    }

    /// Get the user ID
    pub async fn get_user_id(&self) -> u64 {
        self.user_id
    }

    /// Get RhoConnection if available
    pub async fn get_rho_connection(&self) -> Option<Arc<RhoConnection>> {
        let rho = self.rho_connection.read().await.clone()?;
        let current = self.state.rho.get_for_user(self.user_id as i64).await?;
        Arc::ptr_eq(&rho, &current).then_some(rho)
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
        let _ = self.sender.send(cv).await;
    }

    pub async fn send_relay(&self, cv: &CommunicationValue) -> Result<(), String> {
        if !*self.is_open.read().await {
            return Err("client connection is closed".to_string());
        }
        self.sender
            .send(cv)
            .await
            .map_err(|error| error.to_string())
    }

    /// Handle incoming message from client
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        if !*self.is_open.read().await {
            return;
        }

        if cv.is_type(CommunicationType::Success)
            || cv.get_comm_type_enum().is_some_and(tau::is_protocol_error)
        {
            if let Some(id) = cv.id()
                && self.delivery_responses.complete(id, cv.clone())
            {
                return;
            }

            if cv.is_type(CommunicationType::Success) {
                return;
            }
        }

        let Some(Ok(permit)) = self
            .tasks
            .while_connected(&self.receiver, self.message_slots.clone().acquire_owned())
            .await
        else {
            return;
        };
        let tasks = self.tasks.clone();
        let connection = self.clone();
        if let Err(error) = tasks.spawn(async move {
            let _permit = permit;
            if !*self.is_open.read().await {
                return;
            }
            let message_id = match cv.require_id() {
                Ok(message_id) => message_id,
                Err(error) => {
                    log_err!(
                        self.user_id as i64,
                        PrintType::Client,
                        "Rejected malformed message: {}",
                        error
                    );
                    let response =
                        CommunicationValue::new(CommunicationType::ErrorInvalidData).without_id();
                    self.send_message(&response).await;
                    return;
                }
            };
            log_cv_in!(PrintType::Client, cv);

            if cv.is_type(CommunicationType::RegisteringClientAuthenticate) {
                self.send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                    .await;
                return;
            }

            let mut cv = cv;

            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::ProvisioningBindAccount
                        | CommunicationType::QrProvisioningConfirm
                        | CommunicationType::ProvisioningCredential
                        | CommunicationType::ProvisioningCancel
                )
            ) {
                if let Err(reason) =
                    super::provisioning_connection::handle_authenticated_login(&self, &cv).await
                {
                    log_err!(
                        self.user_id as i64,
                        PrintType::Client,
                        "QR login rejected: {}",
                        reason
                    );
                    self.sender
                        .send(
                            &CommunicationValue::new(CommunicationType::ErrorInvalidData)
                                .with_id(message_id)
                                .add_typed_default(
                                    DataType::ErrorType,
                                    DataValue::Str(reason.into()),
                                ),
                        )
                        .await
                        .ok();
                }
                return;
            }

            if cv.is_type(CommunicationType::Relay) {
                let mutation = self.state.rho.mutation_guard().await;
                // Hold this client's route read guard through Iota's commit reply.
                // The opaque native frame is never rewritten with a claimed actor.
                let route = self.rho_connection.read().await;
                let Some(rho) = route.as_ref() else {
                    drop(route);
                    drop(mutation);
                    self.clone()
                        .send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                let Some(generation) = self
                    .state
                    .rho
                    .user_route_generation(self.user_id as i64, rho)
                else {
                    return;
                };
                if !rho.owns_client(&self) || cv.payload().as_encrypted().is_none() {
                    drop(route);
                    drop(mutation);
                    self.clone()
                        .send_error_response(message_id, CommunicationType::ErrorNotAuthenticated)
                        .await;
                    return;
                }
                let Ok(request) = authenticated_native_relay_request(
                    &cv,
                    self.user_id,
                    self.session_id,
                    generation,
                ) else {
                    return;
                };
                let open = self.is_open.read().await;
                if !*open {
                    return;
                }
                let nonce = request
                    .get_data(DataType::Uuid)
                    .as_str()
                    .and_then(|nonce| Uuid::parse_str(nonce).ok())
                    .expect("server-generated forwarding nonce");
                let Some(mut forwarding) = self.native_forwarding.begin(nonce) else {
                    drop(open);
                    drop(route);
                    drop(mutation);
                    self.sender
                        .send(
                            &CommunicationValue::new(CommunicationType::ErrorInternal)
                                .with_id(message_id),
                        )
                        .await
                        .ok();
                    return;
                };
                drop(mutation);
                match rho
                    .await_hosted_native_relay(&request, &mut forwarding.cancellation)
                    .await
                {
                    Ok(response)
                        if self
                            .state
                            .rho
                            .user_route_generation(self.user_id as i64, rho)
                            == Some(generation)
                            && rho.owns_client(&self) =>
                    {
                        self.sender.send(&response).await.ok();
                    }
                    _ => {
                        self.sender
                            .send(
                                &CommunicationValue::new(CommunicationType::ErrorInternal)
                                    .with_id(message_id),
                            )
                            .await
                            .ok();
                    }
                }
                return;
            }

            if matches!(
                relay_router::message_security_class(&cv),
                relay_router::MessageSecurityClass::RelayOnly
                    | relay_router::MessageSecurityClass::Unsupported
            ) {
                self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }

            if cv.is_type(CommunicationType::SessionActivitySet) {
                if let Some(reply) = self.foreground_requests.lock().await.remove(&message_id) {
                    let _ =
                        reply.send(cv.get_data(DataType::Foreground).as_bool().unwrap_or(false));
                    return;
                }
                let device_class = match cv.get_data(DataType::DeviceClass).as_str() {
                    Some("desktop") => DeviceClass::Desktop,
                    Some("mobile") => DeviceClass::Mobile,
                    Some("web") => DeviceClass::Web,
                    _ => {
                        self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                };
                let Some(notification_capable) =
                    cv.get_data(DataType::NotificationCapable).as_bool()
                else {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                };
                *self.session_activity.write().await = SessionActivity {
                    reported: true,
                    device_class,
                    notification_capable,
                };
                self.send_message(
                    &CommunicationValue::new(CommunicationType::Success).with_id(message_id),
                )
                .await;
                return;
            }

            if matches!(
                relay_router::message_security_class(&cv),
                relay_router::MessageSecurityClass::AuthenticatedPeerControl
            ) {
                let Some(rho) = self.get_rho_connection().await else {
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                let generation = self
                    .state
                    .rho
                    .user_route_generation(self.user_id as i64, &rho);
                if generation.is_none() || !rho.owns_client(&self) {
                    return;
                }
                let mut request = authenticated_peer_control_request(&cv, self.user_id);
                if request.is_type(CommunicationType::GetChats) {
                    request.remove_data(DataType::SessionId);
                    request = request.add_typed_default(
                        DataType::SessionId,
                        DataValue::UnsignedNumber(self.session_id.into()),
                    );
                }
                if relay_router::is_relay_receipt_page(&request) {
                    request.remove_data(DataType::SessionId);
                    request = request.add_typed_default(
                        DataType::SessionId,
                        DataValue::UnsignedNumber(self.session_id.into()),
                    );
                }
                let response = async {
                    let response = rho.await_peer_control(&request).await?;
                    if request.is_type(CommunicationType::GetChats)
                        && response.is_type(CommunicationType::GetChats)
                    {
                        rho.get_iota_connection()
                            .enrich_chat_snapshot(response, self.user_id, self.session_id as i64)
                            .await
                    } else {
                        Ok(response)
                    }
                }
                .await;
                match response {
                    Ok(response) => {
                        // Assignment publication needs this write lock. Keep the
                        // authorization check valid through account-data delivery.
                        let _route = self.rho_connection.read().await;
                        // Reassignment away and back must not release an old page or
                        // snapshot, nor may a replaced session receive account data.
                        if self
                            .state
                            .rho
                            .user_route_generation(self.user_id as i64, &rho)
                            == generation
                            && rho.owns_client(&self)
                            && (!relay_router::is_relay_receipt_page(&response)
                                || response.receiver() == Some(self.user_id))
                        {
                            self.clone().send_message(&response).await;
                        }
                    }
                    Err(error) => {
                        crate::log_event!(
                            self.user_id as i64,
                            PrintType::Client,
                            crate::util::logger::LogLevel::Error,
                            "iota.peer_control_failed",
                            "operation={:?} message_id={} outcome=unknown error={}",
                            request.get_comm_type_enum(),
                            message_id,
                            error
                        );
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await;
                    }
                }
                return;
            }

            // Compatibility for clients predating SetUserState.  The target
            // user fields, if present, are deliberately ignored: an
            // authenticated connection may only change its own state.
            if cv.is_type(CommunicationType::ClientChanged)
                && cv.get_data(DataType::UserState).is_some()
            {
                self.handle_set_user_state(
                    CommunicationValue::new(CommunicationType::ClientChanged)
                        .with_id(message_id)
                        .add_typed_default(
                            DataType::UserState,
                            cv.get_data(DataType::UserState)
                                .cloned()
                                .unwrap_or(DataValue::Null),
                        ),
                )
                .await;
                return;
            }

            // Handle call invites
            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::CallCommand
                        | CommunicationType::CallSnapshotGet
                        | CommunicationType::CallJoinAuthorize
                )
            ) {
                self.managed_calls.store(true, Ordering::Relaxed);
                self.handle_managed_call(cv).await;
                return;
            }
            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::CallKeyEnvelopeStage
                        | CommunicationType::CallKeyEnvelopeGet
                        | CommunicationType::CallKeyEnvelopeActivate
                )
            ) {
                self.managed_calls.store(true, Ordering::Relaxed);
                self.handle_call_epoch(cv).await;
                return;
            }
            if cv.is_type(CommunicationType::CallReserve) {
                let result = self.state.call_manager.reserve(self.user_id).await;
                match result {
                    Ok(id) => {
                        self.clone()
                            .send_message(
                                &CommunicationValue::new(CommunicationType::CallReserve)
                                    .with_id(message_id)
                                    .add_typed_default(
                                        DataType::CallId,
                                        DataValue::Str(id.to_string()),
                                    )
                                    .add_typed_default(
                                        DataType::OmikronId,
                                        DataValue::SignedNumber(
                                            (self.state.call_manager.owner_omikron_id as i64)
                                                .into(),
                                        ),
                                    ),
                            )
                            .await
                    }
                    Err(error) => self.send_call_error(message_id, &error).await,
                }
                return;
            }
            if cv.is_type(CommunicationType::CallActivate) {
                self.handle_call_activate(cv).await;
                return;
            }
            if cv.is_type(CommunicationType::CallInvite) {
                self.handle_call_invite(cv).await;
                return;
            }

            // Handle get call requests
            if cv.is_type(CommunicationType::CallToken) {
                self.handle_get_call(cv).await;
                return;
            }

            if cv.is_type(CommunicationType::CallData) {
                self.handle_get_call_data(cv).await;
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

            if cv.is_type(CommunicationType::CallSetAnonymousJoining) {
                self.handle_call_set_anonymous_joining(cv).await;
                return;
            }
            if cv.is_type(CommunicationType::EndCall) {
                self.handle_end_call(cv).await;
                return;
            }
            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::PasswordEnrollmentStart
                        | CommunicationType::PasswordEnrollmentFinish
                        | CommunicationType::PasswordEnrollmentStatus
                        | CommunicationType::PasswordEnrollmentDisable
                )
            ) {
                let Some(rho) = self.get_rho_connection().await else {
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                if cv.receiver() != Some(rho.get_iota_id().await)
                    || (cv.payload().as_encrypted().is_none() && !is_password_receipt_query(&cv))
                {
                    self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                        .await;
                    return;
                }
                match rho
                    .get_iota_connection()
                    .clone()
                    .await_response(
                        &cv.with_sender(self.user_id),
                        Some(self.state.config.password_upstream_timeout),
                    )
                    .await
                {
                    Ok(response) => self.send_message(&response.with_id(message_id)).await,
                    Err(_) => {
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await
                    }
                }
                return;
            }
            if matches!(
                cv.get_comm_type_enum(),
                Some(
                    CommunicationType::TAuthAuthorize
                        | CommunicationType::TAuthGrantList
                        | CommunicationType::TAuthGrantRevoke
                        | CommunicationType::TAuthGrantMetadataSet
                )
            ) {
                let Some(rho) = self.get_rho_connection().await else {
                    self.send_error_response(message_id, CommunicationType::ErrorNoIota)
                        .await;
                    return;
                };
                match rho
                    .get_iota_connection()
                    .clone()
                    .await_response(&cv.with_sender(self.user_id), Some(Duration::from_secs(20)))
                    .await
                {
                    Ok(response) => self.send_message(&response.with_id(message_id)).await,
                    Err(_) => {
                        self.send_error_response(message_id, CommunicationType::ErrorInternal)
                            .await
                    }
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
                        DataValue::SignedNumber(anonymous.get_user_id().into()),
                    )
                    .add_typed_default(
                        DataType::Display,
                        DataValue::Str(anonymous.get_display_name().await),
                    )
                    .add_typed_default(
                        DataType::Avatar,
                        DataValue::Str(anonymous.get_avatar().await),
                    )
                    .add_typed_default(DataType::UserState, DataValue::Str("online".to_string()));

                self.send_message(&response).await;

                return;
            }

            if cv.is_type(CommunicationType::AccountStateRequest) {
                if cv.get_data(DataType::Json).is_some() {
                    // Scoped pages and acknowledgements are Iota-owned. Do not
                    // add legacy SessionId fields or compose presence into their JSON.
                    if tau::sync::decode_request(&cv).is_err() {
                        self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                            .await;
                        return;
                    }
                    let Some(rho) = self.get_rho_connection().await else {
                        if let Ok(response) = tau::sync::encode_response(
                            &cv,
                            &tau::sync::Response::Unavailable {
                                error: tau::sync::SyncError::Retryable,
                            },
                        ) {
                            self.send_message(&response).await;
                        }
                        return;
                    };
                    let generation = self
                        .state
                        .rho
                        .user_route_generation(self.user_id as i64, &rho);
                    if generation.is_none() || !rho.owns_client(&self) {
                        return;
                    }
                    let request = cv.clone().with_sender(self.user_id);
                    let upstream = rho
                        .get_iota_connection()
                        .clone()
                        .await_response(&request, Some(Duration::from_secs(20)))
                        .await;
                    match &upstream {
                        Err(error) => crate::log_event!(
                            self.user_id as i64,
                            PrintType::Client,
                            crate::util::logger::LogLevel::Error,
                            "state_sync.request_failed",
                            "message_id={} error={}",
                            message_id,
                            error
                        ),
                        Ok(response)
                            if response.receiver() != Some(self.user_id)
                                || tau::sync::decode_response(response, &request).is_err() =>
                        {
                            crate::log_event!(
                                self.user_id as i64,
                                PrintType::Client,
                                crate::util::logger::LogLevel::Error,
                                "state_sync.response_rejected",
                                "message_id={} error_class=invalid_upstream_response",
                                message_id
                            );
                        }
                        _ => {}
                    }
                    let response = match upstream {
                        Ok(response)
                            if response.receiver() == Some(self.user_id)
                                && tau::sync::decode_response(&response, &request).is_ok() =>
                        {
                            response
                        }
                        _ => match tau::sync::encode_response(
                            &cv,
                            &tau::sync::Response::Unavailable {
                                error: tau::sync::SyncError::Retryable,
                            },
                        ) {
                            Ok(response) => response,
                            Err(_) => return,
                        },
                    };
                    let _route = self.rho_connection.read().await;
                    if self
                        .state
                        .rho
                        .user_route_generation(self.user_id as i64, &rho)
                        != generation
                        || !rho.owns_client(&self)
                    {
                        return;
                    }
                    self.clone().send_message(&response).await;
                    return;
                }
                self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }

            if cv.is_type(CommunicationType::AccountStateApplied) {
                self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                    .await;
                return;
            }

            if is_client_omega_operation(&cv) {
                let sender = self.get_user_id().await;
                self.handle_omega_forward(cv.with_sender(sender as u64))
                    .await;
                return;
            }

            let is_per_device_settings = cv.is_type(CommunicationType::SettingsSave)
                || cv.is_type(CommunicationType::SettingsLoad)
                || cv.is_type(CommunicationType::SettingsList);
            let is_global_settings = cv.is_type(CommunicationType::GlobalSettingsSave)
                || cv.is_type(CommunicationType::GlobalSettingsLoad);

            if is_per_device_settings || is_global_settings {
                let expected_session_id: i128 = self.session_id.into();
                let session_id = cv.get_data(DataType::SessionId).as_signed_number();

                if is_per_device_settings {
                    let Some(session_id) = session_id else {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(message_id)
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("Missing session_id".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    };

                    if session_id != expected_session_id {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(message_id)
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("session_id mismatch".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    }
                } else if let Some(session_id) = session_id {
                    if session_id != expected_session_id {
                        let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                            .with_id(message_id)
                            .with_receiver(self.user_id)
                            .add_typed_default(
                                DataType::Message,
                                DataValue::Str("session_id mismatch".to_string()),
                            )
                            .add_typed_default(
                                DataType::SessionId,
                                DataValue::SignedNumber(expected_session_id),
                            );
                        self.send_message(&response).await;
                        return;
                    }
                } else {
                    cv = cv.add_typed_default(
                        DataType::SessionId,
                        DataValue::SignedNumber(expected_session_id),
                    );
                }
            }

            // Every Iota request is bound to the authenticated device.  A
            // caller may omit the field for compatibility, but can never
            // select a different device session.
            let expected_session_id = self.session_id as i128;
            if let Some(session_id) = cv.get_data(DataType::SessionId).as_signed_number() {
                if session_id != expected_session_id {
                    let response = CommunicationValue::new(CommunicationType::ErrorInvalidData)
                        .with_id(message_id)
                        .add_typed_default(
                            DataType::SessionId,
                            DataValue::SignedNumber(expected_session_id),
                        );
                    self.send_message(&response).await;
                    return;
                }
            } else {
                cv = cv.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(expected_session_id),
                );
            }

            log_err!(
                self.user_id as i64,
                PrintType::Client,
                "Rejected unsupported communication type {}",
                cv.get_type()
            );
            self.send_error_response(message_id, CommunicationType::ErrorInvalidData)
                .await;
        }) {
            log_err!(
                connection.user_id as i64,
                PrintType::Client,
                "Client message task rejected: {}",
                error
            );
            connection.close().await;
        }
    }

    /// Send error response
    async fn send_error_response(self: Arc<Self>, message_id: u32, error_type: CommunicationType) {
        let error = CommunicationValue::new(error_type).with_id(message_id);
        self.send_message(&error).await;
    }

    /// Close the connection
    pub async fn close(&self) {
        self.delivery_responses.close();
        let pause = self.native_forwarding.pause();
        pause.wait().await;
        let mut is_open_guard = self.is_open.write().await;
        let mut requests = self.foreground_requests.lock().await;
        if !*is_open_guard {
            return;
        }
        *is_open_guard = false;
        requests.clear();

        self.sender.close();
    }

    /// Handle connection close
    pub async fn handle_close(self: Arc<Self>) {
        let provisioning = self
            .state
            .provisioning
            .for_participant(self.session_id)
            .ok();
        let route = self.rho_connection.read().await.clone();
        if let Some(rho_conn) = route {
            if !rho_conn.close_client_connection(self.clone()).await {
                return;
            }
        } else {
            let _mutation = self.state.rho.mutation_guard().await;
            if self.state.rho.has_replacement_client(&self) {
                return;
            }
            self.cleanup_local();
        }
        if let Some(session) = provisioning
            && let Some(sender) = session.contact.and_then(|peer| peer.sender.upgrade())
        {
            super::tasks::finish_cleanup(self.state.config.cleanup_timeout, async {
                let _ = sender
                    .send(
                        &CommunicationValue::new(CommunicationType::ProvisioningCancel)
                            .add_typed_default(
                                DataType::Uuid,
                                DataValue::Str(session.id.to_string()),
                            ),
                    )
                    .await;
            })
            .await;
        }
    }

    pub(crate) fn cleanup_local(&self) {
        self.state
            .omega
            .invalidate_client_presence(self.user_id as i64, self.session_id as i64);
        self.state.provisioning.remove_participant(self.session_id);
    }
}

// Implement Clone to make it easier to work with Arc<ClientConnection>
impl Clone for ClientConnection {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            _mtp_connection: self._mtp_connection.clone(),
            sender: Arc::clone(&self.sender),
            receiver: Arc::clone(&self.receiver),
            user_id: self.user_id,
            session_id: self.session_id,
            client_version: self.client_version.clone(),
            pub_key: Arc::clone(&self.pub_key),
            rho_connection: Arc::clone(&self.rho_connection),
            is_open: Arc::clone(&self.is_open),
            native_forwarding: self.native_forwarding.clone(),
            delivery_responses: self.delivery_responses.clone(),
            message_slots: Arc::clone(&self.message_slots),
            tasks: Arc::clone(&self.tasks),
            session_activity: Arc::clone(&self.session_activity),
            foreground_requests: Arc::clone(&self.foreground_requests),
            managed_calls: Arc::clone(&self.managed_calls),
        }
    }
}

#[cfg(test)]
mod tests;
