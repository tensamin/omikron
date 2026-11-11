use std::{sync::Arc, time::Duration};
use strum_macros::Display;
use tokio::sync::RwLock;

use crate::{
    anonymous_clients::anonymous_client_connection::AnonymousClientConnection,
    app_state::AppState,
    log_err, log_in, log_out,
    rho::{
        client_connection::ClientConnection, iota_connection::IotaConnection,
        provisioning_connection::ProvisioningConnection,
        registration_connection::RegistrationConnection, rho_connection::RhoConnection,
    },
    util::logger::PrintType,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::webserver::{WebMTPConnection, WebMtpReceiver, WebMtpSender};
use tau::{
    AdmissionEngine, AdmissionError, AuthenticationRequirement, RoleRule, RoleRules, Session,
};
use uuid::Uuid;

pub type MtpSender = WebMtpSender;
pub type MtpReceiver = WebMtpReceiver;

pub use tau::{OptionalDataValueExt, RequiredCommunicationFields, positive_data_i64};

#[cfg(test)]
mod tests {
    use super::{ConnectionKind, RequiredCommunicationFields, admission_engine, positive_data_i64};
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
    use mtp::crypto::{Ed25519Signer, SignatureScheme, auth::register_proof_payload};
    use mtp::host::AuthState;
    use tau::{MtpFieldError, ProtocolValueError};

    // Exercise Omikron's configured policy through Tau, with a verified key for
    // authenticated metadata. Handshake verification remains covered by MTP.
    fn connection_kind(
        description: Option<&str>,
        auth_state: &AuthState,
    ) -> Option<ConnectionKind> {
        static KEY: std::sync::LazyLock<mtp::crypto::PublicKeyBundle> =
            std::sync::LazyLock::new(|| mtp::crypto::Keyring::generate().public_key_bundle());
        admission_engine()
            .admit(&tau::ConnectionFacts {
                mtp_client_id: 42,
                description,
                auth_state: auth_state.clone(),
                public_key: (*auth_state == AuthState::Authenticated).then_some(&*KEY),
                version: mtp::codec::Version(0, 3),
                path: "/",
                remote_addr: None,
            })
            .ok()
            .map(|admission| *admission.role())
    }

    #[test]
    fn receiver_id_rejects_missing_negative_zero_and_overflow() {
        let frame = CommunicationValue::new(CommunicationType::CallInvite);
        assert_eq!(
            positive_data_i64(&frame, DataType::ReceiverId, "receiver_id"),
            Err(ProtocolValueError::Missing("receiver_id"))
        );
        for value in [-1, 0] {
            let frame = frame
                .clone()
                .add_typed_default(DataType::ReceiverId, DataValue::SignedNumber(value));
            assert_eq!(
                positive_data_i64(&frame, DataType::ReceiverId, "receiver_id"),
                Err(ProtocolValueError::Invalid("receiver_id"))
            );
        }
        for value in [i128::from(i64::MAX) + 1, i128::from(u64::MAX)] {
            let frame = frame
                .clone()
                .add_typed_default(DataType::ReceiverId, DataValue::SignedNumber(value));
            assert_eq!(
                positive_data_i64(&frame, DataType::ReceiverId, "receiver_id"),
                Err(ProtocolValueError::OutOfRange("receiver_id"))
            );
        }
        let frame = frame.add_typed_default(
            DataType::ReceiverId,
            DataValue::SignedNumber(i128::from(i64::MAX)),
        );
        assert_eq!(
            positive_data_i64(&frame, DataType::ReceiverId, "receiver_id"),
            Ok(i64::MAX)
        );
    }

    #[test]
    fn required_fields_preserve_missing_field_errors() {
        let frame = CommunicationValue::new(CommunicationType::Success)
            .without_id()
            .without_sender()
            .without_receiver();

        assert_eq!(frame.require_id(), Err(MtpFieldError::MissingId));
        assert_eq!(frame.require_sender(), Err(MtpFieldError::MissingSender));
        assert_eq!(
            frame.require_receiver(),
            Err(MtpFieldError::MissingReceiver)
        );
    }

    #[test]
    fn zero_is_a_present_routing_value() {
        let frame = CommunicationValue::new(CommunicationType::Success)
            .with_id(0)
            .with_sender(0)
            .with_receiver(0);

        assert_eq!(frame.require_id(), Ok(0));
        assert_eq!(frame.require_sender(), Ok(0));
        assert_eq!(frame.require_receiver(), Ok(0));
    }

    #[test]
    fn anonymous_roles_require_unauthenticated_mtp_state() {
        assert_eq!(
            connection_kind(Some("anonymous"), &AuthState::Unauthenticated),
            Some(ConnectionKind::AnonymousClient)
        );
        assert_eq!(
            connection_kind(Some("registering-client"), &AuthState::Unauthenticated),
            Some(ConnectionKind::RegisteringClient)
        );
        assert_eq!(
            connection_kind(Some("anonymous"), &AuthState::Authenticated),
            None
        );
        assert_eq!(
            connection_kind(Some("registering-client"), &AuthState::Authenticated),
            None
        );
        assert_eq!(
            connection_kind(Some("provisioning-client"), &AuthState::Unauthenticated),
            Some(ConnectionKind::ProvisioningClient)
        );
        assert_eq!(
            connection_kind(Some("provisioning-client"), &AuthState::Authenticated),
            None
        );
    }

    #[test]
    fn actual_identity_adapter_preserves_namespaces_and_rejects_guest_roles() {
        use super::{OmikronIdentity, resolve_transport_identity};
        let key = mtp::crypto::Keyring::generate().public_key_bundle();
        assert_eq!(
            resolve_transport_identity(&ConnectionKind::Client, 42, &key).unwrap(),
            OmikronIdentity::Client(42)
        );
        assert_eq!(
            resolve_transport_identity(&ConnectionKind::Iota, 42, &key).unwrap(),
            OmikronIdentity::Iota(42)
        );
        assert_ne!(
            resolve_transport_identity(&ConnectionKind::Client, 42, &key).unwrap(),
            resolve_transport_identity(&ConnectionKind::Iota, 42, &key).unwrap()
        );
        assert!(resolve_transport_identity(&ConnectionKind::RegisteringClient, 42, &key).is_err());
    }

    #[tokio::test]
    async fn successful_mtp_authentication_can_fail_application_activation() {
        use super::{GeneralConnection, OmikronIdentity};
        use crate::rho::test_support;
        let state = test_support::state();
        let (host, client, connection) = test_support::authenticated("iota").await;
        let general =
            GeneralConnection::admit(connection, state.clone(), &admission_engine()).unwrap();
        assert_eq!(general.mtp_connection.auth_state, AuthState::Authenticated);
        general.clone().handle().await;
        let session = general.tau_session.read().await;
        assert_eq!(session.outcome(), Some(tau::SessionOutcome::Rejected));
        assert_eq!(session.lifecycle(), tau::LifecycleState::Closed);
        assert!(matches!(
            session.authentication(),
            tau::ApplicationAuthentication::TransportAuthenticated {
                identity: OmikronIdentity::Iota(42)
            }
        ));
        assert!(state.rho.get_by_iota(42).await.is_none());
        assert_eq!(general.active_handler(), None);
        client.sender.close().await;
        host.shutdown().await;
    }

    #[test]
    fn iota_registration_proof_cannot_authenticate_as_client() {
        let (signer, _, _) = Ed25519Signer::generate();
        let signature = signer
            .sign(&register_proof_payload(
                "0.3",
                Some("iota"),
                b"public-key",
                1,
                2,
            ))
            .unwrap();

        assert!(
            signer
                .verify(
                    &register_proof_payload("0.3", Some("client"), b"public-key", 1, 2,),
                    &signature,
                )
                .is_err()
        );
        assert_eq!(
            connection_kind(Some("iota"), &AuthState::Authenticated),
            Some(ConnectionKind::Iota)
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[allow(dead_code)]
pub enum ConnectionKind {
    Client,
    Iota,
    AnonymousClient,
    RegisteringClient,
    ProvisioningClient,
}

pub fn admission_engine() -> AdmissionEngine<ConnectionKind> {
    use AuthenticationRequirement::{Authenticated, Guest};
    let mut rules = RoleRules::new();
    for (description, authentication, role) in [
        ("client", Authenticated, ConnectionKind::Client),
        ("iota", Authenticated, ConnectionKind::Iota),
        ("anonymous", Guest, ConnectionKind::AnonymousClient),
        (
            "registering-client",
            Guest,
            ConnectionKind::RegisteringClient,
        ),
        (
            "provisioning-client",
            Guest,
            ConnectionKind::ProvisioningClient,
        ),
    ] {
        rules
            .register(RoleRule {
                description: description.into(),
                authentication,
                role,
            })
            .expect("Omikron role descriptions are unique");
    }
    AdmissionEngine::new(rules)
}

#[derive(Debug, PartialEq, Eq)]
pub enum OmikronIdentity {
    Client(u64),
    Iota(u64),
}

/// MTP checked this key through Omega's role-scoped lookup before admission.
/// Numeric IDs are meaningful only within the admitted identity namespace.
fn resolve_transport_identity(
    role: &ConnectionKind,
    id: u64,
    _verified_key: &mtp::crypto::PublicKeyBundle,
) -> Result<OmikronIdentity, AdmissionError> {
    match role {
        ConnectionKind::Client => Ok(OmikronIdentity::Client(id)),
        ConnectionKind::Iota => Ok(OmikronIdentity::Iota(id)),
        _ => Err(AdmissionError::RejectedActivation),
    }
}

pub struct GeneralConnection {
    pub state: Arc<AppState>,
    pub sender: Arc<MtpSender>,
    pub receiver: Arc<MtpReceiver>,
    pub(crate) mtp_connection: Arc<WebMTPConnection>,

    connection_kind: ConnectionKind,
    // Admission role stays immutable. This records only the handler actually running.
    active_handler: std::sync::RwLock<Option<ConnectionKind>>,
    id: u64,

    pub rho_connection: Arc<RwLock<Option<Arc<RhoConnection>>>>,
    pub session_id: Arc<RwLock<u64>>,
    pub client_version: Arc<RwLock<String>>,
    pub(crate) tau_session: RwLock<Session<ConnectionKind, OmikronIdentity>>,
    pub(crate) shutdown: tokio::sync::watch::Sender<bool>,
}

impl GeneralConnection {
    /// Admit this accepted MTP connection exactly once and resolve its principal.
    /// MTP verified transport possession through the Omega callbacks. Guest
    /// registration can authenticate later through the application verifier.
    pub fn admit(
        conn: WebMTPConnection,
        state: Arc<AppState>,
        engine: &AdmissionEngine<ConnectionKind>,
    ) -> Result<Arc<Self>, AdmissionError> {
        let admission = engine.admit(&tau::ConnectionFacts::from_mtp(&conn))?;
        let kind = *admission.role();
        let tau_session = admission.into_session(resolve_transport_identity)?;

        let id = if matches!(
            kind,
            ConnectionKind::RegisteringClient | ConnectionKind::ProvisioningClient
        ) {
            (rand::random::<u64>() & ((1_u64 << 48) - 1)).max(1)
        } else {
            tau_session.transport().mtp_client_id()
        };
        let client_version = conn.version.to_string();
        let conn = Arc::new(conn);
        Ok(Arc::new(Self {
            state,
            sender: Arc::new(conn.sender.clone()),
            receiver: Arc::new(conn.receiver.clone()),
            mtp_connection: conn,
            connection_kind: kind,
            active_handler: std::sync::RwLock::new(None),
            id,
            rho_connection: Arc::new(RwLock::new(None)),
            session_id: Arc::new(RwLock::new(match kind {
                ConnectionKind::Client
                | ConnectionKind::RegisteringClient
                | ConnectionKind::ProvisioningClient => {
                    ((Uuid::new_v4().as_u128() as u64) & ((1_u64 << 53) - 1)).max(1)
                }
                _ => id,
            })),
            client_version: Arc::new(RwLock::new(client_version)),
            tau_session: RwLock::new(tau_session),
            shutdown: tokio::sync::watch::channel(false).0,
        }))
    }

    pub fn connection_kind(&self) -> ConnectionKind {
        self.connection_kind
    }

    pub fn active_handler(&self) -> Option<ConnectionKind> {
        *self
            .active_handler
            .read()
            .expect("handler state lock poisoned")
    }

    pub(crate) fn set_active_handler(&self, handler: ConnectionKind) {
        *self
            .active_handler
            .write()
            .expect("handler state lock poisoned") = Some(handler);
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn handle(self: Arc<Self>) {
        log_in!(0, PrintType::General, "General connection handler started");
        if self.migrate().await {
            log_out!(
                0,
                PrintType::General,
                "General connection handler stopped, upgraded to {}",
                self.active_handler().unwrap_or(self.connection_kind)
            );
        } else {
            self.tau_session.write().await.reject();
            log_out!(
                0,
                PrintType::General,
                "General connection handler stopped without upgrade"
            );
        }
        self.tau_session.write().await.close();
        self.sender.close();
        *self
            .active_handler
            .write()
            .expect("handler state lock poisoned") = None;
    }

    pub(crate) async fn handle_until_shutdown(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let handler = self.clone().handle();
        tokio::pin!(handler);
        tokio::select! {
            _ = &mut handler => {},
            _ = async { let _ = shutdown.wait_for(|stop| *stop).await; } => {
                self.shutdown.send_replace(true);
                self.sender.close();
                handler.await;
            }
        }
    }

    async fn migrate(self: &Arc<Self>) -> bool {
        if !matches!(
            self.connection_kind,
            ConnectionKind::Client | ConnectionKind::Iota
        ) && self.tau_session.write().await.activate().is_err()
        {
            return false;
        }
        match self.connection_kind {
            ConnectionKind::Client => self.migrate_client().await,
            ConnectionKind::Iota => self.migrate_iota().await,
            ConnectionKind::AnonymousClient => {
                self.set_active_handler(ConnectionKind::AnonymousClient);
                self.migrate_anonymous_client().await;
                true
            }
            ConnectionKind::RegisteringClient => {
                self.set_active_handler(ConnectionKind::RegisteringClient);
                RegistrationConnection::from_general(self.clone())
                    .start()
                    .await;
                true
            }
            ConnectionKind::ProvisioningClient => {
                self.set_active_handler(ConnectionKind::ProvisioningClient);
                ProvisioningConnection::from_general(self.clone())
                    .start()
                    .await;
                true
            }
        }
    }

    async fn migrate_client(self: &Arc<Self>) -> bool {
        let id = match self.tau_session.read().await.authentication() {
            tau::ApplicationAuthentication::TransportAuthenticated {
                identity: OmikronIdentity::Client(id),
            } => *id,
            _ => return false,
        };
        let user_id = id as i64;

        let client = ClientConnection::from_general(self.clone(), id).await;
        let preparation = super::tasks::MessageTasks::new(
            self.shutdown.subscribe(),
            self.state.config.message_drain,
        );
        let Some(rho) = preparation
            .while_connected(&self.receiver, self.find_user_rho(user_id))
            .await
        else {
            return false;
        };
        let mutation = self.state.rho.mutation_guard().await;
        if let Some(rho) = rho.as_ref()
            && self
                .state
                .rho
                .get_for_user(user_id)
                .await
                .is_none_or(|current| !Arc::ptr_eq(&current, rho))
        {
            return false;
        }
        *self.rho_connection.write().await = rho.clone();
        let mut session = self.tau_session.write().await;
        if *self.shutdown.borrow()
            || self.receiver.close_reason().is_some()
            || session
                .establish_transport_session()
                .and_then(|()| session.activate())
                .is_err()
        {
            return false;
        }
        drop(session);
        if let Some(rho_conn) = rho {
            rho_conn.add_client_connection(client.clone()).await;
            client.notify_connected(rho_conn.iota_id());
        } else {
            log_err!(
                user_id,
                PrintType::Client,
                "No RhoConnection found for user {}, client not attached to iota",
                id
            );
            let error = CommunicationValue::new(CommunicationType::ErrorNoIota);
            let _ = self.sender.send(&error).await;
        }

        drop(mutation);
        self.set_active_handler(ConnectionKind::Client);
        client.run().await;
        true
    }

    async fn find_user_rho(&self, user_id: i64) -> Option<Arc<RhoConnection>> {
        if let Some(rho) = self.state.rho.get_for_user(user_id).await {
            return Some(rho);
        }

        let get_user_msg = CommunicationValue::new(CommunicationType::GetUserData)
            .with_sender(self.state.omega.omikron_id())
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user_id.into()));
        let Ok(user_data_cv) = self
            .state
            .omega
            .clone()
            .await_response(&get_user_msg, Some(Duration::from_secs(20)))
            .await
        else {
            return None;
        };

        if !user_data_cv.is_type(CommunicationType::GetUserData)
            || user_data_cv
                .get_data(DataType::UserId)
                .and_then(DataValue::as_signed_number)
                != Some(user_id.into())
        {
            return None;
        }
        let iota_id = user_data_cv
            .get_data(DataType::IotaId)
            .and_then(DataValue::as_signed_number)
            .and_then(|id| i64::try_from(id).ok())
            .filter(|id| *id > 0)?;
        let Some(rho) = self.state.rho.bind_user_to_iota(user_id, iota_id).await else {
            log_err!(
                user_id,
                PrintType::Client,
                "Omega maps user {} to Iota {}, but no local Rho exists",
                user_id,
                iota_id
            );
            return None;
        };
        Some(rho)
    }

    async fn migrate_iota(self: &Arc<Self>) -> bool {
        let id = match self.tau_session.read().await.authentication() {
            tau::ApplicationAuthentication::TransportAuthenticated {
                identity: OmikronIdentity::Iota(id),
            } => *id,
            _ => return false,
        };
        log_in!(id as i64, PrintType::Iota, "Iota {} connected", id);

        let preparation = super::tasks::MessageTasks::new(
            self.shutdown.subscribe(),
            self.state.config.message_drain,
        );
        let user_ids = match preparation
            .while_connected(&self.receiver, self.state.omega.iota_connected(id as i64))
            .await
        {
            Some(Ok(user_ids)) => user_ids,
            Some(Err(error)) => {
                log_err!(
                    id as i64,
                    PrintType::Iota,
                    "Omega rejected Iota activation: {}",
                    error
                );
                return false;
            }
            None => return false,
        };
        let iota = IotaConnection::from_general(self.clone(), id).await;
        let rho = Arc::new(RhoConnection::new(iota.clone(), user_ids).await);
        let mut session = self.tau_session.write().await;
        if *self.shutdown.borrow()
            || self.receiver.close_reason().is_some()
            || session
                .establish_transport_session()
                .and_then(|()| session.activate())
                .is_err()
        {
            return false;
        }
        drop(session);
        self.set_active_handler(ConnectionKind::Iota);
        iota.publish_and_run(rho).await;
        true
    }

    async fn migrate_anonymous_client(self: &Arc<Self>) {
        let client = AnonymousClientConnection::from_general(self.clone(), self.id).await;
        client.run().await;
    }

    /// Preparation performs I/O but publishes neither authentication nor attachment.
    pub async fn prepare_registered_client(
        self: &Arc<Self>,
        user_id: u64,
        expected_iota_id: u64,
    ) -> Option<(Arc<ClientConnection>, Arc<RhoConnection>, u64)> {
        self.find_user_rho(user_id as i64).await?;
        let (rho, generation) = self
            .state
            .rho
            .prepare_registration_route(user_id as i64, expected_iota_id)?;
        let client = ClientConnection::from_general(self.clone(), user_id).await;
        Some((client, rho, generation))
    }
}
