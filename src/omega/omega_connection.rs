mod key_cache;
#[cfg(test)]
use key_cache::{authenticated_key_path, cached_at_is_fresh};
mod lifecycle;
#[cfg(test)]
use lifecycle::{reconnect_base_after_outcome, reconnect_delay_with_jitter};
mod routes;
use routes::{client_changed_target, signed_positive_iota_id};
#[cfg(test)]
use routes::{iota_activation_snapshot, iota_user_snapshot};
mod presence;
mod presence_projection;
mod requests;
use super::capabilities::PeerCapabilities;
use crate::{
    config::{Config, OfflineAuthPolicy, TransportConfig},
    log_cv_in, log_cv_out, log_err, log_in, log_out,
    rho::connection::{OptionalDataValueExt, RequiredCommunicationFields},
    rho::relay_router,
    rho::rho_manager::RhoManager,
    util::{data_type_id, logger::PrintType},
};
use dashmap::DashMap;
use mtp::client::{Client, MTPConnection, Sender};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::{
    client::ClientConfig,
    files::{load_public_key_bundle, save_public_key_bundle},
    host::{Policy, SendMode},
};
use mtp_native::ConnectionHandle;
use rand::RngExt;
pub use requests::OmegaRequestError;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex, RwLock, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep},
};

use uuid::Uuid;

const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);
const RECONNECT_JITTER: Duration = Duration::from_secs(1);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const CAPABILITY_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(1);
const PING_INTERVAL: Duration = Duration::from_secs(5);
const TASK_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const TASK_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_REQUESTS: usize = 128;
const CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 3;
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthIdentityKind {
    Client,
    Iota,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthIdentity {
    pub kind: AuthIdentityKind,
    pub id: u64,
}

#[derive(Clone)]
struct CachedAuthenticatedKey {
    public_key: mtp::crypto::PublicKeyBundle,
    cached_at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionOutcome {
    HealthySessionEnded,
    FailedBeforeHealthy,
}

fn parse_omega_capability_response(value: &CommunicationValue) -> Result<PeerCapabilities, String> {
    if !value.is_type(CommunicationType::IdentificationResponse) {
        return Err("not an identification response".to_string());
    }
    PeerCapabilities::from_omega_identification_description(
        value.get_data(DataType::Description).as_str(),
    )
    .map_err(|_| "Omega advertised an invalid capability set".to_string())
}

// ============================================================================
// Waiting Task System
// ============================================================================

#[cfg(test)]
type TestRequest = (
    CommunicationValue,
    oneshot::Sender<Result<CommunicationValue, String>>,
);

struct CircuitBreaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    fn allow_request(&mut self) -> bool {
        if self.open_until.is_some_and(|until| until > Instant::now()) {
            return false;
        }
        self.open_until = None;
        true
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            self.open_until = Some(Instant::now() + CIRCUIT_BREAKER_COOLDOWN);
        }
    }
}

pub fn start_task_cleanup_loop(omega: Arc<OmegaConnection>) {
    tokio::spawn(async move {
        loop {
            sleep(TASK_CLEANUP_INTERVAL).await;
            omega.waiting_tasks.retain_fresh(TASK_MAX_AGE);
        }
    });
}

// ============================================================================
// Connection State
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Identifying,
    SynchronizingRoutes,
    SynchronizingSubscriptions,
    Ready,
}

#[allow(unused_variables)]
impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        !matches!(
            self,
            ConnectionState::Disconnected | ConnectionState::Connecting
        )
    }

    #[allow(dead_code)]
    pub fn is_identified(&self) -> bool {
        matches!(
            self,
            ConnectionState::SynchronizingRoutes
                | ConnectionState::SynchronizingSubscriptions
                | ConnectionState::Ready
        )
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, ConnectionState::Ready)
    }
}

// ============================================================================
// Omega Connection (Client-side with auto-reconnect)
// ============================================================================
#[allow(dead_code)]
pub struct OmegaConnection {
    state: Arc<RwLock<ConnectionState>>,
    sender: Arc<RwLock<Option<Arc<Sender>>>>,
    connection_loop_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    host: String,
    port: u16,
    omikron_id: u64,
    sync_timeout: Duration,
    sync_retries: u32,
    transport_config: TransportConfig,
    offline_auth: OfflineAuthPolicy,
    pub connection_id: Uuid,
    shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    draining: std::sync::atomic::AtomicBool,
    mutation_journal_path: std::path::PathBuf,
    // Track if we should reconnect on close
    reconnect_on_close: Arc<RwLock<bool>>,
    request_slots: tokio::sync::Semaphore,
    circuit_breaker: Mutex<CircuitBreaker>,
    sync_lock: Mutex<()>,
    keyring: mtp::crypto::Keyring,
    rho: Arc<RhoManager>,
    authenticated_key_cache: DashMap<AuthIdentity, CachedAuthenticatedKey>,
    missing_key_cache: DashMap<AuthIdentity, Instant>,
    waiting_tasks: tau::ResponseCorrelator,
    session_presence: DashMap<(i64, i64), SessionPresenceState>,
    presence_delivery_locks: DashMap<(i64, i64), Arc<Mutex<()>>>,
    peer_capabilities: Arc<RwLock<PeerCapabilities>>,
    #[cfg(test)]
    test_requests: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<TestRequest>>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionPresenceState {
    pub subscribed_user_ids: Vec<i64>,
    pub pending: bool,
    pub generation: u64,
    projection: Option<presence_projection::ContactPresence>,
}

#[derive(Debug, thiserror::Error)]
pub enum InitialPresenceError {
    #[error("Omega is unavailable: {0}")]
    OmegaUnavailable(String),
    #[error("presence subscription was rejected: {0}")]
    SubscriptionRejected(String),
    #[error("invalid GetStates snapshot: {0}")]
    InvalidSnapshot(String),
}

fn omega_transport_policy(config: &TransportConfig) -> Policy {
    Policy::default()
        .with_send_mode(SendMode::SingleStreamPerMessage)
        .with_max_message_size(config.max_message_size)
        .with_handshake_max_message_size(config.handshake_max_message_size)
        .with_timeouts(
            Duration::from_millis(5_000),
            Duration::from_millis(5_000),
            Duration::from_millis(30_000),
        )
        .with_keep_alive(Some(Duration::from_secs(6)))
        .with_max_idle_timeout(Some(Duration::from_secs(30)))
        .with_receiver_queue_capacity(1000)
        .with_max_concurrent_stream_tasks(64)
        .with_persistent_stream_retries(5, Duration::from_secs(5))
}

impl OmegaConnection {
    pub(crate) fn begin_shutdown(&self) {
        self.draining
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn omikron_id(&self) -> u64 {
        self.omikron_id
    }

    pub fn from_config(
        config: &Config,
        keyring: mtp::crypto::Keyring,
        rho: Arc<RhoManager>,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);

        OmegaConnection {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            sender: Arc::new(RwLock::new(None)),
            connection_loop_handle: Arc::new(Mutex::new(None)),
            host: config.omega_host.clone(),
            port: config.omega_port,
            omikron_id: config.omikron_id,
            sync_timeout: config.omega_sync_timeout,
            sync_retries: config.omega_sync_retries,
            transport_config: config.omega_transport.clone(),
            offline_auth: config.offline_auth.clone(),
            connection_id: Uuid::new_v4(),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            draining: std::sync::atomic::AtomicBool::new(false),
            mutation_journal_path: super::mutation_journal_path(),
            reconnect_on_close: Arc::new(RwLock::new(true)),
            request_slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_REQUESTS),
            circuit_breaker: Mutex::new(CircuitBreaker {
                consecutive_failures: 0,
                open_until: None,
            }),
            sync_lock: Mutex::new(()),
            keyring,
            rho,
            authenticated_key_cache: DashMap::new(),
            missing_key_cache: DashMap::new(),
            waiting_tasks: tau::ResponseCorrelator::new(),
            session_presence: DashMap::new(),
            presence_delivery_locks: DashMap::new(),
            peer_capabilities: Arc::new(RwLock::new(PeerCapabilities::default())),
            #[cfg(test)]
            test_requests: std::sync::Mutex::new(None),
        }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    async fn try_send_message(&self, cv: &CommunicationValue) -> Result<(), String> {
        log_cv_out!(PrintType::Omega, &cv);

        let sender_guard = self.sender.read().await;
        if let Some(sender) = sender_guard.as_ref() {
            // Check if closed before sending
            if sender.is_closed() {
                crate::log_event!(
                    0,
                    PrintType::Omega,
                    crate::util::logger::LogLevel::Warn,
                    "omega.send_failed",
                    "message_id={:?} message_type={} reason=connection_closed",
                    cv.id(),
                    cv.get_type_name().unwrap_or("unknown")
                );
                drop(sender_guard);
                // Trigger reconnection by closing the connection state
                if let Some(sender) = self.sender.write().await.take() {
                    sender.close().await;
                }
                return Err("connection is closed".to_string());
            }

            let sender_clone = Arc::clone(sender);
            drop(sender_guard);

            if let Err(e) = sender_clone.send(cv).await {
                crate::log_event!(
                    0,
                    PrintType::Omega,
                    crate::util::logger::LogLevel::Error,
                    "omega.send_failed",
                    "message_id={:?} message_type={} error={}",
                    cv.id(),
                    cv.get_type_name().unwrap_or("unknown"),
                    e
                );
                return Err(e.to_string());
            }
        } else {
            crate::log_event!(
                0,
                PrintType::Omega,
                crate::util::logger::LogLevel::Debug,
                "omega.send_skipped",
                "message_id={:?} message_type={} reason=not_connected",
                cv.id(),
                cv.get_type_name().unwrap_or("unknown")
            );
            return Err("not connected".to_string());
        }
        Ok(())
    }

    pub async fn send_message(&self, cv: &CommunicationValue) {
        let _ = self.try_send_message(cv).await;
    }

    pub async fn send_message_result(&self, cv: &CommunicationValue) -> Result<(), String> {
        self.try_send_message(cv).await
    }

    #[allow(dead_code)]
    pub async fn supports_set_user_state(&self) -> bool {
        self.peer_capabilities.read().await.set_user_state_v1
    }

    pub async fn await_connection(&self, timeout_duration: Option<Duration>) -> Result<(), String> {
        if self.state.read().await.is_connected() {
            return Ok(());
        }

        let timeout = timeout_duration.unwrap_or(CONNECTION_TIMEOUT);
        let start = Instant::now();

        loop {
            if self.state.read().await.is_connected() {
                return Ok(());
            }

            if start.elapsed() >= timeout {
                return Err(format!(
                    "Connection not established within {} seconds",
                    timeout.as_secs()
                ));
            }

            sleep(Duration::from_millis(100)).await;
        }
    }

    #[cfg(test)]
    pub(crate) fn test_requests(&self) -> tokio::sync::mpsc::UnboundedReceiver<TestRequest> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        *self.test_requests.lock().unwrap() = Some(sender);
        receiver
    }

    #[allow(dead_code)]
    pub async fn is_connected(&self) -> bool {
        self.state.read().await.is_connected()
    }
    #[allow(dead_code)]
    pub async fn is_identified(&self) -> bool {
        self.state.read().await.is_identified()
    }

    pub async fn is_ready(&self) -> bool {
        self.state.read().await.is_ready()
    }
}

#[cfg(test)]
mod tests;
