use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;

use crate::{
    app_state::AppState,
    log, log_err,
    omega::{AuthIdentity, AuthIdentityKind, omega_connection::OmegaConnection},
    rho::connection::{ConnectionKind, GeneralConnection, OptionalDataValueExt, admission_engine},
    util::logger::PrintType,
};
use http::{Method, StatusCode};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::PublicKeyBundle;
use mtp::host::{AuthenticationPolicy, HostConfig, Policy, SendMode};
use mtp::webserver::{HttpResponse, MTPWebServer, WebServerConfig};
use tokio::sync::watch;

fn with_cors(response: HttpResponse) -> HttpResponse {
    response
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "*")
        .header("access-control-allow-private-network", "true")
}

struct TransportMetrics;

impl mtp::webserver::WebServerMetrics for TransportMetrics {
    fn error_occurred(&self, error: &mtp::webserver::WebServerError) {
        crate::log_event!(
            0,
            PrintType::General,
            crate::util::logger::LogLevel::Error,
            "transport.error",
            "error={}",
            error
        );
    }

    fn request_completed(&self, _path: &str, status: u16, duration: Duration) {
        if status >= 400 {
            crate::log_event!(
                0,
                PrintType::General,
                crate::util::logger::LogLevel::Warn,
                "transport.request_failed",
                "status={} elapsed_ms={}",
                status,
                duration.as_millis()
            );
        }
    }
}

fn web_config(max_connections: usize) -> Result<WebServerConfig, mtp::webserver::RouterError> {
    WebServerConfig::new()
        .with_metrics(Arc::new(TransportMetrics))
        .max_connections(max_connections)
        .route("/", |request, response| async move {
            let response = if request.method == Method::OPTIONS {
                response.status(StatusCode::NO_CONTENT)
            } else {
                response.body("OK")
            };
            with_cors(response)
        })?
        .fallback(|request, response| async move {
            let status = if request.method == Method::OPTIONS {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::NOT_FOUND
            };
            with_cors(response.status(status))
        })
}

pub(super) fn rho_policy() -> Policy {
    Policy::default()
        // Version selection and final acceptance must arrive in order. Separate
        // receive-stream tasks can otherwise deliver acceptance before selection.
        .with_send_mode(SendMode::PersistentStream)
        .with_timeouts(
            Duration::from_millis(2_000),
            Duration::from_millis(2_000),
            Duration::from_millis(30_000),
        )
        .with_keep_alive(Some(Duration::from_secs(6)))
        .with_max_idle_timeout(Some(Duration::from_secs(30)))
        .with_receiver_queue_capacity(1000)
        .with_max_concurrent_stream_tasks(10)
        .with_persistent_stream_retries(5, Duration::from_secs(5))
}

/*
 * Resolves the PublicKeyBundle mtp needs to verify a login's signed
 * challenge response. "iota"/"client" ids are looked up through Omega, the
 * source of truth for both kinds of registered keys. Any other description
 * (including "anonymous") never resolves, which routes the connection
 * through mtp's unauthenticated fallback instead of rejecting it outright.
 */
pub async fn get_by_connector_id(
    omega: Arc<OmegaConnection>,
    client_id: u64,
    description: Option<String>,
) -> Option<PublicKeyBundle> {
    let identity = authentication_identity(client_id, description.as_deref())?;
    if omega.recently_missing_key(identity) {
        return None;
    }
    let request = public_key_lookup_request(omega.omikron_id(), identity);

    if !omega.is_ready().await {
        return omega.cached_authenticated_key(identity);
    }

    let response = match omega
        .await_response(&request, Some(Duration::from_secs(20)))
        .await
    {
        Ok(response) => response,
        Err(e) => {
            log_err!(
                client_id as i64,
                PrintType::General,
                "Failed to look up public key for connector (description={:?}): {}",
                description,
                e
            );
            return omega.cached_authenticated_key(identity);
        }
    };

    if response.is_type(CommunicationType::ErrorNotFound) {
        omega.invalidate_authenticated_key(identity);
        omega.cache_missing_key(identity);
        return None;
    }

    let encoded = match authenticated_key_response(&response, identity) {
        Some(encoded) => encoded,
        None => {
            crate::log_event!(
                client_id as i64,
                PrintType::General,
                crate::util::logger::LogLevel::Error,
                "auth.key_validation_failed",
                "identity_kind={:?} message_id={:?} error_class=invalid_lookup_response",
                identity.kind,
                request.id()
            );
            return None;
        }
    };
    let bytes = match BASE64_STD.decode(encoded) {
        Ok(bytes) => bytes,
        Err(_) => {
            crate::log_event!(
                client_id as i64,
                PrintType::General,
                crate::util::logger::LogLevel::Error,
                "auth.key_validation_failed",
                "identity_kind={:?} message_id={:?} error_class=invalid_base64",
                identity.kind,
                request.id()
            );
            return None;
        }
    };
    let public_key = match PublicKeyBundle::from_bytes(&bytes) {
        Ok(key) => key,
        Err(_) => {
            crate::log_event!(
                client_id as i64,
                PrintType::General,
                crate::util::logger::LogLevel::Error,
                "auth.key_validation_failed",
                "identity_kind={:?} message_id={:?} error_class=invalid_key_bundle",
                identity.kind,
                request.id()
            );
            return None;
        }
    };
    omega.cache_authenticated_key(identity, public_key.clone());
    Some(public_key)
}

fn authenticated_key_response(
    response: &CommunicationValue,
    identity: AuthIdentity,
) -> Option<&str> {
    let (expected_type, expected_field) = match identity.kind {
        AuthIdentityKind::Iota => (CommunicationType::GetIotaData, DataType::IotaId),
        AuthIdentityKind::Client => (CommunicationType::GetUserData, DataType::UserId),
    };
    if !response.is_type(expected_type)
        || response
            .get_data(expected_field)
            .as_number()
            .and_then(|id| u64::try_from(id).ok())
            != Some(identity.id)
    {
        return None;
    }
    response
        .get_data(DataType::PublicKey)
        .and_then(DataValue::as_str)
}

fn authentication_identity(client_id: u64, description: Option<&str>) -> Option<AuthIdentity> {
    let kind = match description {
        Some("client") => AuthIdentityKind::Client,
        Some("iota") => AuthIdentityKind::Iota,
        _ => return None,
    };

    Some(AuthIdentity {
        kind,
        id: client_id,
    })
}

fn public_key_lookup_request(omikron_id: u64, identity: AuthIdentity) -> CommunicationValue {
    match identity.kind {
        AuthIdentityKind::Iota => {
            println!("Iota connection request for client_id: {}", identity.id);
            CommunicationValue::new(CommunicationType::GetIotaData)
                .with_sender(omikron_id)
                .add_typed_default(
                    DataType::IotaId,
                    DataValue::SignedNumber(identity.id as i128),
                )
        }
        AuthIdentityKind::Client => CommunicationValue::new(CommunicationType::GetUserData)
            .with_sender(omikron_id)
            .add_typed_default(
                DataType::UserId,
                DataValue::SignedNumber(identity.id as i128),
            ),
    }
}

/* Only Iota registration goes through mtp's Register flow; users are registered out of band. */
pub async fn complete_register(
    omega: Arc<OmegaConnection>,
    pub_key: PublicKeyBundle,
    description: Option<String>,
) -> u64 {
    println!("Iota register start");
    if description.as_deref() != Some("iota") {
        return 0;
    }
    println!("Iota connection request");

    let pub_key_bytes = match pub_key.try_as_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            log_err!(
                0,
                PrintType::General,
                "Failed to serialize Iota public key: {}",
                error
            );
            return 0;
        }
    };

    let request = CommunicationValue::new(CommunicationType::CompleteRegisterIota)
        .add_typed_default(
            DataType::PublicKey,
            DataValue::Str(BASE64_STD.encode(pub_key_bytes)),
        );

    // MTP may cancel its registration callback during transport shutdown. Keep
    // observing the remote mutation independently of that callback's lifetime.
    let (result, receive) = tokio::sync::oneshot::channel();
    let mut operations = tokio::task::JoinSet::new();
    operations.spawn(async move {
        let response = omega
            .await_response(&request, Some(Duration::from_secs(20)))
            .await;
        let _ = result.send(response);
    });
    drop(super::tasks::supervise(operations));
    let response = match receive.await {
        Ok(Ok(response)) => response,
        error => {
            log_err!(
                0,
                PrintType::General,
                "Failed to complete Iota registration: {:?}",
                error
            );
            return 0;
        }
    };

    match response.get_data(DataType::IotaId) {
        Some(DataValue::SignedNumber(id)) => {
            u64::try_from(*id).ok().filter(|id| *id > 0).unwrap_or(0)
        }
        _ => 0,
    }
}

pub async fn start(
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cert_file = std::env::var("TLS_CERT_FILE").unwrap_or_else(|_| "certs/cert.pem".into());
    let cert_pem = std::fs::read(&cert_file)
        .map_err(|error| format!("load TLS certificate {cert_file}: {error}"))?;
    let key_file = std::env::var("TLS_KEY_FILE").unwrap_or_else(|_| "certs/key.pem".into());
    let key_pem = std::fs::read(&key_file)
        .map_err(|error| format!("load TLS private key {key_file}: {error}"))?;

    let host_config = HostConfig::new(
        state.config.bind_address,
        state.config.rho_port,
        cert_pem,
        key_pem,
    )
    .with_policy(rho_policy())
    .with_authentication(
        state
            .keyring_for_host()
            .map_err(|error| format!("Unable to copy keyring for host: {error}"))?,
        Box::new({
            let omega = state.omega.clone();
            move |user_id, description| {
                Box::pin(get_by_connector_id(omega.clone(), user_id, description))
            }
        }),
        Box::new({
            let omega = state.omega.clone();
            move |pub_key, description| {
                Box::pin(complete_register(omega.clone(), pub_key, description))
            }
        }),
    )
    .with_authentication_policy(AuthenticationPolicy::AllowAuthentication);

    let web_config = web_config(state.config.rho_max_connections)?;
    let mut host = MTPWebServer::new(host_config, web_config).await?;
    let mut provisioning_cleanup = tokio::time::interval(Duration::from_secs(30));
    let admission_engine = Arc::new(admission_engine());
    let (connection_shutdown, _) = watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    log!(
        0,
        PrintType::General,
        "Server listening on {}:{}.",
        state.config.bind_address,
        state.config.rho_port
    );

    loop {
        let accepted = tokio::select! {
            _ = shutdown.wait_for(|shutting_down| *shutting_down) => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    super::tasks::record_failure(error);
                }
                continue;
            },
            _ = provisioning_cleanup.tick() => {
                state.provisioning.prune_expired();
                continue;
            }
            accepted = host.accept() => accepted,
        };
        let conn = match accepted {
            Ok(Some(conn)) => {
                println!("Accepted connection");
                conn
            }
            Ok(None) => break,
            Err(e) => {
                /*
                 * A single client's failed/aborted handshake (bad auth, a
                 * probe, a mid-handshake disconnect) must not take down the
                 * whole listener, only that connection attempt is lost.
                 */
                log_err!(0, PrintType::General, "Rejected connection: {}", e);
                continue;
            }
        };

        let global_permit = match state.rho_connection_limits.all.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                log_err!(
                    0,
                    PrintType::General,
                    "Rejected connection: global Rho connection limit reached"
                );
                continue;
            }
        };
        let peer_ip = conn.remote_addr.map(|address| address.ip());
        let state = state.clone();
        let admission_engine = admission_engine.clone();
        let shutdown = connection_shutdown.subscribe();
        connections.spawn(async move {
            let conn = match GeneralConnection::admit(conn, state.clone(), &admission_engine) {
                Ok(conn) => conn,
                Err(error) => {
                    log_err!(0, PrintType::General, "Rejected connection: {}", error);
                    return;
                }
            };

            let anonymous_permit = if matches!(
                conn.connection_kind(),
                ConnectionKind::AnonymousClient
                    | ConnectionKind::RegisteringClient
                    | ConnectionKind::ProvisioningClient
            ) {
                match state
                    .rho_connection_limits
                    .anonymous
                    .clone()
                    .try_acquire_owned()
                {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        log_err!(
                            0,
                            PrintType::General,
                            "Rejected anonymous connection: anonymous limit reached"
                        );
                        return;
                    }
                }
            } else {
                None
            };

            let anonymous_ip_permit = if matches!(
                conn.connection_kind(),
                ConnectionKind::AnonymousClient
                    | ConnectionKind::RegisteringClient
                    | ConnectionKind::ProvisioningClient
            ) {
                let Some(peer_ip) = peer_ip else {
                    log_err!(
                        0,
                        PrintType::General,
                        "Rejected anonymous connection: peer address unavailable"
                    );
                    return;
                };
                match state
                    .rho_connection_limits
                    .try_acquire_anonymous_per_ip(peer_ip)
                {
                    Some(permit) => Some(permit),
                    None => {
                        log_err!(
                            0,
                            PrintType::General,
                            "Rejected anonymous connection: per-IP limit reached"
                        );
                        return;
                    }
                }
            } else {
                None
            };

            let _global_permit = global_permit;
            let _anonymous_permit = anonymous_permit;
            let _anonymous_ip_permit = anonymous_ip_permit;
            conn.handle_until_shutdown(shutdown).await;
        });
    }
    // Stop accepting first, then let application handlers cancel messages and clean up.
    connection_shutdown.send_replace(true);
    // Transfer ownership before awaiting transport shutdown. A cancelled listener
    // must not drop its JoinSet and abort mutation-bearing connection handlers.
    let completion = super::tasks::supervise(connections);
    host.shutdown().await;
    let _ = completion.await;
    log!(0, PrintType::General, "Server stopped");

    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn cancelling_registration_callback_retains_remote_observation() {
        let state = crate::rho::test_support::state();
        let mut requests = state.omega.test_requests();
        let callback = tokio::spawn(super::complete_register(
            state.omega.clone(),
            mtp::crypto::Keyring::generate().public_key_bundle(),
            Some("iota".into()),
        ));
        let (request, response) = tokio::time::timeout(Duration::from_secs(2), requests.recv())
            .await
            .unwrap()
            .unwrap();
        callback.abort();
        assert!(callback.await.unwrap_err().is_cancelled());
        assert!(!response.is_closed());
        response
            .send(Ok(request.add_typed_default(
                DataType::IotaId,
                DataValue::SignedNumber(2),
            )))
            .unwrap();
    }
    use super::{
        AuthIdentity, AuthIdentityKind, HttpResponse, authenticated_key_response,
        authentication_identity, public_key_lookup_request, rho_policy, web_config, with_cors,
    };
    use mtp::codec::{CommunicationType, DataType, DataValue};
    use std::time::Duration;

    #[tokio::test]
    async fn listener_shutdown_ends_active_handlers_and_releases_their_permits() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            test_support,
        };
        let state = test_support::state();
        let (host, peer, accepted) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(accepted, state.clone(), &admission_engine()).unwrap();
        let global = state
            .rho_connection_limits
            .all
            .clone()
            .try_acquire_owned()
            .unwrap();
        let (shutdown, receive) = tokio::sync::watch::channel(false);
        let task = tokio::spawn({
            let general = general.clone();
            async move {
                let _permit = global;
                general.handle_until_shutdown(receive).await;
            }
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while general.active_handler().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            general.tau_session.read().await.lifecycle(),
            tau::LifecycleState::Closed
        );
        assert_eq!(general.active_handler(), None);
        assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn guest_handlers_hold_application_permits_until_the_receive_loop_exits() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            test_support,
        };
        use tau::LifecycleState;
        for role in ["anonymous", "registering-client", "provisioning-client"] {
            let state = test_support::state();
            let (host, client, connection) = test_support::guest(role).await;
            let general =
                GeneralConnection::admit(connection, state.clone(), &admission_engine()).unwrap();
            let global = state
                .rho_connection_limits
                .all
                .clone()
                .try_acquire_owned()
                .unwrap();
            let anonymous = state
                .rho_connection_limits
                .anonymous
                .clone()
                .try_acquire_owned()
                .unwrap();
            let ip = "127.0.0.1".parse().unwrap();
            let per_ip = state
                .rho_connection_limits
                .try_acquire_anonymous_per_ip(ip)
                .unwrap();
            let task = tokio::spawn({
                let general = general.clone();
                async move {
                    let _permits = (global, anonymous, per_ip);
                    general.handle().await;
                }
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while general.tau_session.read().await.lifecycle() != LifecycleState::Active {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!task.is_finished(), "{role} detached its receive loop");
            assert_eq!(state.rho_connection_limits.all.available_permits(), 1);
            assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 0);
            assert!(
                state
                    .rho_connection_limits
                    .try_acquire_anonymous_per_ip(ip)
                    .is_none()
            );
            client.sender.close().await;
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                general.tau_session.read().await.lifecycle(),
                LifecycleState::Closed
            );
            assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
            assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 1);
            assert!(
                state
                    .rho_connection_limits
                    .try_acquire_anonymous_per_ip(ip)
                    .is_some()
            );
            host.shutdown().await;
        }
    }

    #[tokio::test]
    async fn failed_admission_releases_the_listener_permit() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            test_support,
        };
        let state = test_support::state();
        let (host, client, connection) = test_support::guest("client").await;
        let permit = state
            .rho_connection_limits
            .all
            .clone()
            .try_acquire_owned()
            .unwrap();
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            assert!(GeneralConnection::admit(connection, task_state, &admission_engine()).is_err());
        });
        task.await.unwrap();
        assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
        client.sender.close().await;
        host.shutdown().await;
    }

    #[test]
    fn rho_connection_budget_configures_mtp_admission() {
        let config = web_config(7).expect("health route is valid");
        assert_eq!(config.max_connections, 7);
    }

    #[test]
    fn web_responses_allow_all_origins() {
        let response = with_cors(HttpResponse::default());
        assert_eq!(response.headers["access-control-allow-origin"], "*");
        assert_eq!(
            response.headers["access-control-allow-methods"],
            "GET, POST, OPTIONS"
        );
        assert_eq!(response.headers["access-control-allow-headers"], "*");
        assert_eq!(
            response.headers["access-control-allow-private-network"],
            "true"
        );
    }

    #[test]
    fn public_key_lookup_identifies_the_omikron() {
        let request = public_key_lookup_request(
            17,
            AuthIdentity {
                kind: AuthIdentityKind::Client,
                id: 42,
            },
        );

        assert!(request.is_type(CommunicationType::GetUserData));
        assert_eq!(request.sender(), Some(17));
        assert_eq!(
            request.get_data(DataType::UserId),
            Some(&DataValue::SignedNumber(42))
        );
    }

    #[test]
    fn authentication_identity_separates_clients_and_iotas_with_the_same_id() {
        assert_ne!(
            authentication_identity(42, Some("client")),
            authentication_identity(42, Some("iota"))
        );
        assert_eq!(authentication_identity(42, Some("anonymous")), None);
    }

    #[test]
    fn authentication_caches_only_matching_omega_identity_responses() {
        for kind in [AuthIdentityKind::Iota, AuthIdentityKind::Client] {
            let identity = AuthIdentity { kind, id: 42 };
            let (expected_type, expected_field, wrong_type) = match kind {
                AuthIdentityKind::Iota => (
                    CommunicationType::GetIotaData,
                    DataType::IotaId,
                    CommunicationType::GetUserData,
                ),
                AuthIdentityKind::Client => (
                    CommunicationType::GetUserData,
                    DataType::UserId,
                    CommunicationType::GetIotaData,
                ),
            };
            let frame = |ty, id| {
                mtp::codec::CommunicationValue::new(ty)
                    .add_typed_default(expected_field, DataValue::SignedNumber(id))
                    .add_typed_default(DataType::PublicKey, DataValue::Str("key".into()))
            };
            assert_eq!(
                authenticated_key_response(&frame(expected_type, 42), identity),
                Some("key")
            );
            assert_eq!(
                authenticated_key_response(&frame(wrong_type, 42), identity),
                None
            );
            assert_eq!(
                authenticated_key_response(&frame(expected_type, 43), identity),
                None
            );
        }
    }

    #[test]
    fn rho_policy_keeps_idle_peers_alive_and_detects_dead_peers() {
        let policy = rho_policy();
        assert_eq!(policy.send_mode, mtp::host::SendMode::PersistentStream);
        assert_eq!(policy.keep_alive_interval, Some(Duration::from_secs(6)));
        assert_eq!(policy.max_idle_timeout, Some(Duration::from_secs(30)));
    }
}
