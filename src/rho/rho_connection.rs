use super::{
    client_connection::{ClientConnection, DeviceClass},
    iota_connection::IotaConnection,
};

use crate::{log_err, rho::connection::OptionalDataValueExt};
use dashmap::DashMap;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell, RwLock};

pub struct RhoConnection {
    iota_connection: Arc<IotaConnection>,
    pub(super) user_ids: Arc<RwLock<HashSet<i64>>>,
    client_connections: DashMap<(u64, u64), Arc<ClientConnection>>,
    client_changes: std::sync::Mutex<()>,
    foreground_queries: Mutex<HashMap<u64, Arc<OnceCell<bool>>>>,
}

fn message_targets_client(cv: &CommunicationValue, user_id: u64, session_id: u64) -> bool {
    if cv.receiver() != Some(user_id) {
        return false;
    }
    let Some(target_session_id) = cv.get_data(DataType::SessionId).as_number() else {
        return true;
    };
    target_session_id == i128::from(session_id)
}

fn local_delivery_result(attempted: usize, sent: usize) -> Result<usize, String> {
    if attempted == 0 {
        Err("client offline".to_string())
    } else if sent == 0 {
        Err("all local client sends failed".to_string())
    } else {
        Ok(sent)
    }
}

impl RhoConnection {
    /// Create a new RhoConnection
    pub async fn new(iota_connection: Arc<IotaConnection>, user_ids: Vec<i64>) -> Self {
        let membership = iota_connection.user_ids.clone();
        *membership.write().await = user_ids.into_iter().filter(|id| *id > 0).collect();
        Self {
            iota_connection,
            user_ids: membership,
            client_connections: DashMap::new(),
            client_changes: std::sync::Mutex::new(()),
            foreground_queries: Mutex::new(HashMap::new()),
        }
    }

    pub fn iota_id(&self) -> u64 {
        self.iota_connection.iota_id
    }

    pub async fn get_iota_id(&self) -> u64 {
        self.iota_id()
    }

    pub async fn get_user_ids(&self) -> Vec<i64> {
        let mut users: Vec<_> = self.user_ids.read().await.iter().copied().collect();
        users.sort_unstable();
        users
    }

    pub fn get_iota_connection(&self) -> &Arc<IotaConnection> {
        &self.iota_connection
    }

    fn owns_user(&self, user_id: u64) -> bool {
        i64::try_from(user_id)
            .ok()
            .is_some_and(|user_id| self.iota_connection.state.rho.owns_rho_user(user_id, self))
    }

    pub(crate) fn owns_client(&self, client: &Arc<ClientConnection>) -> bool {
        self.owns_user(client.user_id)
            && self
                .client_connections
                .get(&(client.user_id, client.session_id))
                .is_some_and(|current| Arc::ptr_eq(current.value(), client))
    }

    pub async fn get_client_connections(&self) -> Vec<Arc<ClientConnection>> {
        self.client_connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn drain_client_connections(&self) -> Vec<Arc<ClientConnection>> {
        let keys: Vec<_> = self
            .client_connections
            .iter()
            .map(|entry| *entry.key())
            .collect();
        keys.into_iter()
            .filter_map(|key| self.client_connections.remove(&key).map(|(_, value)| value))
            .collect()
    }

    /// Get client connections for a specific user
    pub async fn get_client_connections_for_user(
        &self,
        user_id: i64,
    ) -> Vec<Arc<ClientConnection>> {
        self.client_connections
            .iter()
            .filter(|entry| entry.key().0 == user_id as u64)
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub(super) fn remove_user_clients(&self, user_id: i64) {
        self.client_connections
            .retain(|(id, _), _| *id != user_id as u64);
    }

    pub(super) fn has_replacement_client(&self, client: &ClientConnection) -> bool {
        self.client_connections
            .get(&(client.user_id, client.session_id))
            .is_some_and(|current| !std::ptr::eq(current.as_ref(), client))
    }

    /// Add a client connection
    #[allow(dead_code)]
    pub async fn add_client_connection(&self, connection: Arc<ClientConnection>) {
        let user_id = connection.user_id as i64;
        let session_id = connection.session_id as i64;

        let previous = {
            let _changes = self
                .client_changes
                .lock()
                .expect("client registry lock poisoned");
            self.client_connections
                .insert((user_id as u64, session_id as u64), connection)
        };
        if let Some(old_connection) = previous {
            // Publish first so stale cleanup cannot remove the replacement.
            old_connection.close().await;
        }
    }

    pub async fn get_client_connection(
        &self,
        user_id: i64,
        session_id: i64,
    ) -> Option<Arc<ClientConnection>> {
        if user_id <= 0
            || session_id <= 0
            || !self.iota_connection.state.rho.owns_rho_user(user_id, self)
        {
            return None;
        }
        self.client_connections
            .get(&(user_id as u64, session_id as u64))
            .map(|entry| entry.value().clone())
    }

    /// Registration publishes a fresh session only if its authentication commit succeeds.
    /// No asynchronous I/O occurs while the registry entry is locked.
    pub(crate) fn attach_registered_client(
        &self,
        client: Arc<ClientConnection>,
        commit: impl FnOnce() -> Result<(), tau::AdmissionError>,
    ) -> Result<(), tau::AdmissionError> {
        let _changes = self
            .client_changes
            .lock()
            .expect("client registry lock poisoned");
        match self
            .client_connections
            .entry((client.user_id, client.session_id))
        {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(tau::AdmissionError::RejectedActivation)
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                commit()?;
                entry.insert(client);
                Ok(())
            }
        }
    }

    /// Remove a client connection
    pub async fn close_client_connection(&self, connection: Arc<ClientConnection>) -> bool {
        let mutation = self
            .iota_connection
            .state
            .rho
            .native_mutation_guard(&[connection.user_id as i64], &[])
            .await;
        let target_user_id = connection.user_id as i64;
        let target_session_id = connection.session_id as i64;
        // Do not let a stale transport tear down the replacement for the same
        // persistent session.
        let key = (target_user_id as u64, target_session_id as u64);
        if self
            .iota_connection
            .state
            .rho
            .has_replacement_client(&connection)
        {
            self.client_connections
                .remove_if(&key, |_, current| Arc::ptr_eq(current, &connection));
            return false;
        }
        {
            let _changes = self
                .client_changes
                .lock()
                .expect("client registry lock poisoned");
            if self
                .client_connections
                .remove_if(&key, |_, current| Arc::ptr_eq(current, &connection))
                .is_none()
            {
                // Assignment cleanup may already have detached this entry. A
                // replacement with the same session still owns its local state.
                if !self.client_connections.contains_key(&key) {
                    connection.cleanup_local();
                }
                return false;
            }
            // Account assignment outlives any individual client session. Only
            // ownership updates or Rho termination invalidate the user binding.
            connection.cleanup_local();
        }
        drop(mutation);
        // Only the external acknowledgement is bounded. Registry and presence
        // invalidation above must finish even when Omega is unavailable.
        super::tasks::finish_cleanup(self.iota_connection.state.config.cleanup_timeout, async {
            if let Err(error) = self
                .iota_connection
                .state
                .omega
                .client_disconnected(target_user_id, target_session_id)
                .await
            {
                log_err!(
                    target_user_id,
                    crate::util::logger::PrintType::Client,
                    "UserDisconnected acknowledgement failed for session {}: {}",
                    target_session_id,
                    error
                );
            }
        })
        .await;
        true
    }

    /// Close the Iota connection and all associated client connections
    pub async fn close_iota_connection(&self) {
        let iota_id = self.get_iota_id().await as i64;
        if self
            .iota_connection
            .state
            .rho
            .remove_if_current(iota_id, self)
            .await
            .is_none()
        {
            return;
        }

        // Invalidate every local client before the first external notification.
        for connection in self.drain_client_connections() {
            connection.close().await;
            connection.cleanup_local();
        }

        // Notify OmegaConnection
        super::tasks::finish_cleanup(self.iota_connection.state.config.cleanup_timeout, async {
            if let Err(error) = self.iota_connection.state.omega.close_iota(iota_id).await {
                log_err!(
                    iota_id,
                    crate::util::logger::PrintType::Iota,
                    "IotaDisconnected acknowledgement failed: {}",
                    error
                );
            }
        })
        .await;
    }

    pub async fn close_deleted_iota_connection(&self) {
        let iota_id = self.get_iota_id().await as i64;
        if self
            .iota_connection
            .state
            .rho
            .remove_if_current(iota_id, self)
            .await
            .is_none()
        {
            return;
        }
        for connection in self.drain_client_connections() {
            connection.close().await;
            connection.cleanup_local();
        }
        self.iota_connection.close().await;
    }

    /// Send message from Iota to specific client
    pub async fn message_to_client(&self, cv: CommunicationValue) {
        let Some(user_id) = cv.receiver() else {
            log_err!(
                0,
                crate::util::logger::PrintType::General,
                "Discarded message without an MTP receiver"
            );
            return;
        };
        if !self.owns_user(user_id) {
            return;
        }
        let connections = self.get_client_connections().await;

        let target_connections: Vec<_> = connections
            .iter()
            .filter(|connection| {
                message_targets_client(&cv, connection.user_id, connection.session_id)
            })
            .cloned()
            .collect();
        let mut mobile_sessions = Vec::new();
        let mut desktop_sessions = Vec::new();
        if cv.is_type(CommunicationType::MessageLive) {
            for connection in &connections {
                if connection.user_id != cv.receiver().unwrap_or_default() {
                    continue;
                }
                let activity = connection.session_activity().await;
                if !self.owns_client(connection) {
                    continue;
                }
                if !activity.reported {
                    continue;
                }
                if activity.device_class == DeviceClass::Mobile
                    && target_connections
                        .iter()
                        .any(|target| target.session_id == connection.session_id)
                {
                    mobile_sessions.push(connection.session_id);
                } else if activity.notification_capable
                    && matches!(
                        activity.device_class,
                        DeviceClass::Desktop | DeviceClass::Web
                    )
                {
                    desktop_sessions.push(connection.clone());
                }
            }
        }
        let suppress_mobile = if !mobile_sessions.is_empty() && !desktop_sessions.is_empty() {
            let user_id = cv.receiver().unwrap_or_default();
            let query = {
                let mut queries = self.foreground_queries.lock().await;
                queries
                    .entry(user_id)
                    .or_insert_with(|| Arc::new(OnceCell::new()))
                    .clone()
            };
            let focused = *query
                .get_or_init(|| async {
                    let mut pending = tokio::task::JoinSet::new();
                    for connection in desktop_sessions {
                        let current = self
                            .iota_connection
                            .state
                            .rho
                            .get_for_user_on_iota(connection.user_id as i64, self.iota_id())
                            .filter(|rho| std::ptr::eq(rho.as_ref(), self));
                        if let Some(current) = current {
                            pending.spawn(async move {
                                let _route = connection.rho_connection.read().await;
                                if !current.owns_client(&connection) {
                                    return false;
                                }
                                connection.foreground().await
                            });
                        }
                    }
                    while let Some(result) = pending.join_next().await {
                        if matches!(result, Ok(true)) {
                            pending.shutdown().await;
                            return true;
                        }
                    }
                    false
                })
                .await;
            let mut queries = self.foreground_queries.lock().await;
            if queries
                .get(&user_id)
                .is_some_and(|current| Arc::ptr_eq(current, &query))
            {
                queries.remove(&user_id);
            }
            focused
        } else {
            false
        };

        for connection in target_connections {
            // Assignment publication takes this client's write lock. Recheck
            // the published owner after acquiring it and retain it through delivery.
            let _route = connection.rho_connection.read().await;
            if !self.owns_client(&connection) {
                continue;
            }
            let client_cv = if mobile_sessions.contains(&connection.session_id) {
                cv.clone().add_typed_default(
                    DataType::SuppressNotification,
                    DataValue::Bool(suppress_mobile),
                )
            } else {
                cv.clone()
            };
            // Durable account delivery is gated by Iota's scoped page ack.
            // Presence and other hints do not establish account acceptance.
            connection.clone().send_message(&client_cv).await;
        }
    }

    #[allow(dead_code)]
    pub async fn message_to_iota(&self, cv: CommunicationValue) {
        if self.iota_connection.state.rho.is_current_rho(self) {
            self.iota_connection.send_message(&cv).await;
        }
    }

    pub async fn send_to_local_user(
        &self,
        user_id: u64,
        cv: &CommunicationValue,
    ) -> Result<usize, String> {
        if !self.owns_user(user_id) {
            return Err("user route changed before delivery".into());
        }
        let connections = self.get_client_connections_for_user(user_id as i64).await;
        let attempted = connections.len();
        let mut sent = 0;
        for connection in connections {
            let _route = connection.rho_connection.read().await;
            if !self.owns_user(user_id) {
                return Err("user route changed before delivery".into());
            }
            if !self.owns_client(&connection) {
                continue;
            }
            match connection.send_relay(cv).await {
                Ok(()) => sent += 1,
                Err(error) => log_err!(
                    user_id as i64,
                    crate::util::logger::PrintType::Client,
                    "Relay send failed for session {}: {}",
                    connection.session_id,
                    error
                ),
            }
        }
        local_delivery_result(attempted, sent)
    }

    #[allow(dead_code)]
    pub async fn send_relay_to_iota(&self, cv: &CommunicationValue) -> Result<(), String> {
        if !self.iota_connection.state.rho.is_current_rho(self) {
            return Err("Iota route is obsolete".into());
        }
        self.iota_connection.send_relay(cv).await
    }

    pub async fn await_relay_to_iota(
        &self,
        cv: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        if !self.iota_connection.state.rho.is_current_rho(self) {
            return Err("Iota route is obsolete".into());
        }
        let response = self
            .iota_connection
            .clone()
            .await_response(cv, Some(std::time::Duration::from_secs(20)))
            .await?;
        if !self.iota_connection.state.rho.is_current_rho(self) {
            return Err("Iota route changed during relay".into());
        }
        Ok(response)
    }

    pub async fn await_peer_control(
        &self,
        cv: &CommunicationValue,
    ) -> Result<CommunicationValue, String> {
        let user = cv
            .sender()
            .filter(|id| *id > 0 && i64::try_from(*id).is_ok())
            .ok_or("peer control has no valid user")?;
        let manager = &self.iota_connection.state.rho;
        let generation = manager
            .user_route_generation(user as i64, self)
            .ok_or("user route is obsolete")?;
        let response = self
            .iota_connection
            .clone()
            .await_response(cv, Some(std::time::Duration::from_secs(20)))
            .await?;
        if manager.user_route_generation(user as i64, self) != Some(generation) {
            return Err("user route changed during peer control".into());
        }
        Ok(response)
    }

    /// The caller retains its session and route read guards until this returns.
    /// A timeout alone cannot release them: Iota must first durably revoke the
    /// exact forwarding authorization, serializing revocation with its commit.
    pub async fn await_hosted_native_relay(
        &self,
        request: &CommunicationValue,
        cancellation: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<CommunicationValue, String> {
        let nonce = request
            .get_data(DataType::Uuid)
            .as_str()
            .ok_or("missing forwarding nonce")?;
        if !self.iota_connection.state.rho.is_current_rho(self) {
            return Err("Iota route is obsolete".into());
        }
        // Native operations already have immutable user-signed replay identity.
        // This protocol owns cancellation; do not add a second uncertain-mutation
        // journal entry that cannot distinguish revocation from acceptance.
        let operation = self.iota_connection.waiting_tasks.exchange(
            request,
            std::time::Duration::from_secs(20),
            |response| {
                response.is_type(CommunicationType::Success)
                    || response
                        .get_comm_type_enum()
                        .is_some_and(tau::is_protocol_error)
            },
            |outbound| async move { self.iota_connection.sender.send(&outbound).await },
        );
        tokio::pin!(operation);
        let result = tokio::select! {
            biased;
            _ = cancellation.wait_for(|cancelled| *cancelled) => Err("forwarding authorization revoked".into()),
            result = &mut operation => result.map_err(|error| error.to_string()),
        };
        if let Ok(response) = &result
            && response.get_data(DataType::Uuid).as_str() == Some(nonce)
        {
            return result;
        }
        let revoke = CommunicationValue::new_with_type_map(
            CommunicationType::Relay,
            request.type_map().ok_or("missing forwarding dictionary")?,
        )
        .with_sender(request.sender().ok_or("missing forwarding actor")?)
        .add_typed_default(
            DataType::Status,
            DataValue::Str("tensamin-hosted-native-revoke-v1".into()),
        )
        .add_typed_default(DataType::Uuid, DataValue::Str(nonce.into()));
        let mut transports = self
            .iota_connection
            .state
            .rho
            .revocation_transport_changes();
        loop {
            let transport = self
                .iota_connection
                .state
                .rho
                .revocation_transport(&self.iota_connection)
                .unwrap_or_else(|| self.iota_connection.clone());
            let expected_nonce = nonce.to_owned();
            let exchange = transport.waiting_tasks.exchange(
                &revoke,
                std::time::Duration::from_secs(10),
                move |response| {
                    response.is_type(CommunicationType::Success)
                        && response.get_data(DataType::Uuid).as_str()
                            == Some(expected_nonce.as_str())
                        && response.get_data(DataType::Status).as_str() == Some("revoked")
                },
                |outbound| {
                    let sender = transport.sender.clone();
                    async move { sender.send(&outbound).await }
                },
            );
            tokio::pin!(exchange);
            let exchange = loop {
                tokio::select! {
                    biased;
                    result = &mut exchange => break Some(result),
                    _ = transports.changed() => {
                        let current = self.iota_connection.state.rho.revocation_transport(&self.iota_connection);
                        if current.as_ref().is_some_and(|current| !Arc::ptr_eq(current, &transport)) { break None; }
                    },
                }
            };
            let Some(exchange) = exchange else {
                continue;
            };
            if exchange.is_ok() {
                return Err("forwarded relay timed out; authorization revoked".into());
            }
            // Deliberately retain authorization guards if the peer is unreachable.
            // Publishing a new route would allow an old in-flight operation to
            // commit under a session that Omikron had already declared revoked.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    /// Check if this RhoConnection contains a specific user ID
    #[allow(dead_code)]
    pub async fn contains_user(&self, user_id: &i64) -> bool {
        u64::try_from(*user_id)
            .ok()
            .is_some_and(|user_id| self.owns_user(user_id))
    }

    /// Get count of active client connections
    #[allow(dead_code)]
    pub async fn client_count(&self) -> usize {
        self.client_connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{local_delivery_result, message_targets_client};
    use mtp::codec::{CommunicationType, CommunicationValue, DataType};

    #[tokio::test]
    async fn replaced_rho_cannot_forward_even_when_the_iota_arc_is_reused() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            test_support,
        };
        use std::{sync::Arc, time::Duration};

        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let iota = IotaConnection::from_general(general, 2).await;
        let old = Arc::new(super::RhoConnection::new(iota.clone(), vec![7]).await);
        state.rho.add(old.clone()).await;
        let replacement = Arc::new(super::RhoConnection::new(iota, vec![7]).await);
        state.rho.add(replacement.clone()).await;

        // Deliberately leave the obsolete mirror populated. Neither it nor the
        // shared Iota identity may grant authority to this retained Rho.
        old.user_ids.write().await.insert(7);
        assert!(!old.contains_user(&7).await);
        let message = CommunicationValue::new(CommunicationType::Ping).with_id(100);
        old.message_to_iota(message.clone()).await;
        assert!(old.send_relay_to_iota(&message).await.is_err());
        assert!(old.await_relay_to_iota(&message).await.is_err());
        assert!(
            old.await_peer_control(&message.clone().with_sender(7))
                .await
                .is_err()
        );
        assert!(old.send_to_local_user(7, &message).await.is_err());

        // A marker from the live route proves the transport remained usable
        // and that none of the rejected forwarding attempts preceded it.
        replacement.message_to_iota(message.with_id(102)).await;
        let received = tokio::time::timeout(Duration::from_secs(2), peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.id(), Some(102));
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn cached_user_route_cannot_deliver_after_reassignment() {
        use crate::rho::{
            client_connection::ClientConnection,
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            test_support,
        };
        use std::{sync::Arc, time::Duration};

        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        *general.session_id.write().await = 42;
        let old = Arc::new(
            super::RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7],
            )
            .await,
        );
        let client = ClientConnection::from_general(general.clone(), 7).await;
        state.rho.add(old.clone()).await;
        old.add_client_connection(client.clone()).await;
        assert!(old.get_client_connection(7, 42).await.is_some());
        let replacement = Arc::new(
            super::RhoConnection::new(IotaConnection::from_general(general, 3).await, vec![7])
                .await,
        );
        state.rho.add(replacement.clone()).await;

        // Retain a stale registry entry too, so invalidation alone cannot make
        // this test pass without a published ownership check at delivery.
        old.add_client_connection(client.clone()).await;
        assert!(
            old.get_client_connection(7, client.session_id as i64)
                .await
                .is_none()
        );
        let event = CommunicationValue::new(CommunicationType::SyncedSettingChanged)
            .with_receiver(7)
            .with_id(110);
        old.message_to_client(event.clone()).await;
        assert!(old.send_to_local_user(7, &event).await.is_err());
        replacement.add_client_connection(client).await;
        replacement.message_to_client(event.with_id(111)).await;
        let received = tokio::time::timeout(Duration::from_secs(2), peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.id(), Some(111));
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[tokio::test]
    async fn obsolete_client_cleanup_keeps_the_replacement_installed() {
        use crate::rho::{
            client_connection::ClientConnection,
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            test_support,
        };
        use std::sync::Arc;
        let state = test_support::state();
        let (old_host, old_peer, old_transport) = test_support::guest("anonymous").await;
        let (new_host, new_peer, new_transport) = test_support::guest("anonymous").await;
        let old_general =
            GeneralConnection::admit(old_transport, state.clone(), &admission_engine()).unwrap();
        let new_general =
            GeneralConnection::admit(new_transport, state.clone(), &admission_engine()).unwrap();
        *old_general.session_id.write().await = 42;
        *new_general.session_id.write().await = *old_general.session_id.read().await;
        let old = ClientConnection::from_general(old_general.clone(), 7).await;
        let replacement = ClientConnection::from_general(new_general, 7).await;
        let rho = Arc::new(
            super::RhoConnection::new(IotaConnection::from_general(old_general, 2).await, vec![7])
                .await,
        );
        state.rho.add(rho.clone()).await;
        rho.add_client_connection(old.clone()).await;
        rho.add_client_connection(replacement.clone()).await;
        rho.close_client_connection(old.clone()).await;
        rho.close_client_connection(old).await;
        let current = rho
            .get_client_connection(7, replacement.session_id as i64)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&current, &replacement));
        assert!(state.rho.get_for_user(7).await.is_some());
        old_peer.sender.close().await;
        new_peer.sender.close().await;
        old_host.shutdown().await;
        new_host.shutdown().await;
    }

    #[tokio::test]
    async fn obsolete_iota_cleanup_keeps_replacement_and_user_bindings() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            test_support,
        };
        use std::sync::Arc;
        let state = test_support::state();
        let (host, peer, transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let old = Arc::new(
            super::RhoConnection::new(
                IotaConnection::from_general(general.clone(), 2).await,
                vec![7],
            )
            .await,
        );
        let replacement = Arc::new(
            super::RhoConnection::new(IotaConnection::from_general(general, 2).await, vec![7])
                .await,
        );
        state.rho.add(old.clone()).await;
        state.rho.add(replacement.clone()).await;
        old.close_iota_connection().await;
        old.close_iota_connection().await;
        state.rho.remove_user_binding(7, &old);
        assert!(Arc::ptr_eq(
            &state.rho.get_by_iota(2).await.unwrap(),
            &replacement
        ));
        assert!(Arc::ptr_eq(
            &state.rho.get_for_user(7).await.unwrap(),
            &replacement
        ));
        peer.sender.close().await;
        host.shutdown().await;
    }

    #[test]
    fn sessionless_setting_change_targets_all_devices_for_one_user() {
        let event =
            CommunicationValue::new(CommunicationType::SyncedSettingChanged).with_receiver(7);

        assert!(message_targets_client(&event, 7, 1));
        assert!(message_targets_client(&event, 7, 2));
        assert!(!message_targets_client(&event, 8, 1));
        assert!(event.get_data(DataType::SessionId).is_none());
    }

    #[test]
    fn one_successful_session_makes_local_delivery_successful() {
        assert_eq!(local_delivery_result(2, 1), Ok(1));
        assert!(local_delivery_result(2, 0).is_err());
        assert!(local_delivery_result(0, 0).is_err());
    }
}
