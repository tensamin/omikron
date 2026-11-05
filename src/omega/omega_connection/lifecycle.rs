use super::*;

pub(super) fn reconnect_base_after_outcome(
    current: Duration,
    outcome: ConnectionOutcome,
) -> Duration {
    match outcome {
        ConnectionOutcome::HealthySessionEnded => RECONNECT_DELAY,
        ConnectionOutcome::FailedBeforeHealthy => current,
    }
}

pub(super) fn reconnect_delay_with_jitter(delay: Duration) -> Duration {
    let max_jitter_ms = std::cmp::min(delay, RECONNECT_JITTER).as_millis() as u64;
    delay + Duration::from_millis(rand::rng().random_range(0..=max_jitter_ms))
}

impl OmegaConnection {
    // -------------------------------------------------------------------------
    // Connection Management
    // -------------------------------------------------------------------------

    pub async fn start(self: Arc<Self>) {
        // Cancel any existing connection loop
        if let Some(handle) = self.connection_loop_handle.lock().await.take() {
            handle.abort();
        }

        // Recreate shutdown_tx if it was taken by stop()
        if self.shutdown_tx.lock().await.is_none() {
            let (shutdown_tx, _) = watch::channel(false);
            *self.shutdown_tx.lock().await = Some(shutdown_tx);
        }

        // Set reconnect flag
        *self.reconnect_on_close.write().await = true;

        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.connection_loop().await;
        });

        *self.connection_loop_handle.lock().await = Some(handle);
    }

    #[allow(dead_code)]
    pub async fn stop(&self) {
        // Disable reconnection
        *self.reconnect_on_close.write().await = false;

        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(true);
        }

        if let Some(handle) = self.connection_loop_handle.lock().await.take() {
            handle.abort();
        }

        // Close sender if connected
        if let Some(sender) = self.sender.read().await.as_ref() {
            sender.close().await;
        }

        *self.state.write().await = ConnectionState::Disconnected;
        *self.sender.write().await = None;
    }

    pub(super) async fn connection_loop(self: Arc<Self>) {
        let mut reconnect_delay = RECONNECT_DELAY;
        let shutdown_rx = self.shutdown_tx.lock().await.as_ref().unwrap().subscribe();
        let mut shutdown_rx = shutdown_rx;

        loop {
            if *shutdown_rx.borrow() {
                log_in!(0, PrintType::Omega, "Connection loop shutting down");
                break;
            }

            // Check if reconnection is enabled
            if !*self.reconnect_on_close.read().await {
                log_in!(0, PrintType::Omega, "Reconnection disabled, exiting loop");
                break;
            }

            match self.clone().connect_once().await {
                Ok(outcome) => {
                    reconnect_delay = reconnect_base_after_outcome(reconnect_delay, outcome);
                    match outcome {
                        ConnectionOutcome::HealthySessionEnded => {
                            log_err!(
                                0,
                                PrintType::Omega,
                                "Healthy Omega connection ended; reconnecting"
                            );
                        }
                        ConnectionOutcome::FailedBeforeHealthy => {
                            log_err!(
                                0,
                                PrintType::Omega,
                                "Omega connection failed before synchronization"
                            );
                        }
                    }
                }
                Err(error) => {
                    log_err!(0, PrintType::Omega, "Connection failed: {}", error);
                }
            }

            if !*self.reconnect_on_close.read().await {
                log_in!(0, PrintType::Omega, "Connection closed, not reconnecting");
                break;
            }

            let retry_delay = reconnect_delay_with_jitter(reconnect_delay);
            log_err!(
                0,
                PrintType::Omega,
                "Retrying Omega connection in {:?}...",
                retry_delay
            );

            tokio::select! {
                _ = sleep(retry_delay) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }

            reconnect_delay = std::cmp::min(reconnect_delay * 2, MAX_RECONNECT_DELAY);
        }
    }

    pub(super) async fn connect_once(self: Arc<Self>) -> Result<ConnectionOutcome, String> {
        *self.state.write().await = ConnectionState::Connecting;

        let client_config = ClientConfig::new(format!("https://{}:{}", self.host, self.port))
            .with_client_id(self.omikron_id)
            .with_description(PeerCapabilities::current().identification_description())
            .with_policy(omega_transport_policy(&self.transport_config))
            .with_ping_interval(PING_INTERVAL);

        let host_public_key = load_public_key_bundle("./omega.mpkb")
            .map_err(|e| format!("Failed to load omega.mpkb: {}", e))?;

        let connection = Client::auth_connect(client_config, &self.keyring, &host_public_key)
            .await
            .map_err(|e| format!("Connection failed: {}", e))?;

        log_in!(
            0,
            PrintType::Omega,
            "QUIC connection established to {}",
            format!("https://{}:{}", self.host, self.port)
        );

        // Store sender
        let sender_arc = Arc::new(connection.sender.clone());
        *self.sender.write().await = Some(sender_arc.clone());
        // A new authenticated transport gets a fresh request circuit. A
        // previous transport can have failed while synchronizing and must not
        // prevent this connection from making its initial requests.
        self.circuit_breaker.lock().await.record_success();
        *self.state.write().await = ConnectionState::Identifying;

        // Get handle for close monitoring
        let sender_handle = sender_arc.handle().clone();
        let connection = Arc::new(connection);
        let (capability_tx, capability_rx) = oneshot::channel();

        // Start read loop
        let read_self = self.clone();
        let read_handle = tokio::spawn(async move {
            read_self
                .read_loop(connection, sender_handle, Some(capability_tx))
                .await;
        });

        let negotiated_capabilities =
            match tokio::time::timeout(CAPABILITY_NEGOTIATION_TIMEOUT, capability_rx).await {
                Ok(Ok(Ok(capabilities))) => capabilities,
                Ok(Ok(Err(error))) => {
                    self.fail_synchronization("capability negotiation", error)
                        .await;
                    let _ = read_handle.await;
                    return Ok(ConnectionOutcome::FailedBeforeHealthy);
                }
                Ok(Err(_)) | Err(_) => {
                    // An Omega from before capability negotiation sends no second
                    // identification response. Fall back to its documented
                    // legacy contracts rather than guessing modern support.
                    PeerCapabilities::default()
                }
            };
        *self.peer_capabilities.write().await = negotiated_capabilities;

        // Tell omega our current state now that we're actually connected -
        // doing this after teardown (as before) sent into a sender that had
        // already been cleared, silently dropping the sync every time.
        let reached_healthy_state = self.clone().sync_client_iota_status().await;

        // Wait for read loop to complete (connection closed)
        let result = read_handle.await;

        // Cleanup
        let close_reason = sender_arc.close_reason();
        if let Some(reason) = close_reason {
            log_err!(
                0,
                PrintType::Omega,
                "Omega transport ended with close reason: {:?}",
                reason
            );
        } else {
            log_in!(
                0,
                PrintType::Omega,
                "Omega transport ended without a close reason"
            );
        }
        *self.sender.write().await = None;
        *self.state.write().await = ConnectionState::Disconnected;
        self.waiting_tasks.clear();

        match result {
            Ok(()) if reached_healthy_state => Ok(ConnectionOutcome::HealthySessionEnded),
            Ok(()) => Ok(ConnectionOutcome::FailedBeforeHealthy),
            Err(e) => Err(format!("Read loop error: {}", e)),
        }
    }

    pub(super) async fn sync_client_iota_status(&self) -> bool {
        let _sync_guard = self.sync_lock.lock().await;
        *self.state.write().await = ConnectionState::SynchronizingRoutes;
        let mut connected_iota_ids: Vec<DataValue> = Vec::new();
        let mut connected_sessions: Vec<DataValue> = Vec::new();
        let mut connected_user_ids: Vec<DataValue> = Vec::new();

        let iota_ids = self.rho.iota_ids().await;
        let rho_connections = self.rho.connections().await;

        for iota_id in iota_ids {
            connected_iota_ids.push(DataValue::SignedNumber(iota_id.into()));
        }

        for rho in rho_connections {
            for client_conn in rho.get_client_connections().await {
                let type_map = mtp::codec::TypeMap::latest();
                let user_id = DataValue::SignedNumber(client_conn.get_user_id().await.into());
                let session_id = DataValue::SignedNumber(client_conn.session_id as i128);
                let iota_id = DataValue::SignedNumber(rho.get_iota_id().await as i128);
                let peer_capabilities = self.peer_capabilities.read().await.clone();
                if peer_capabilities.session_snapshot_v1 {
                    connected_sessions.push(DataValue::Container(vec![
                        (data_type_id(DataType::UserId, &type_map), user_id),
                        (data_type_id(DataType::SessionId, &type_map), session_id),
                        (data_type_id(DataType::IotaId, &type_map), iota_id),
                    ]));
                } else {
                    connected_user_ids.push(user_id);
                }
            }
        }

        let peer_capabilities = self.peer_capabilities.read().await.clone();
        let sync_msg = if peer_capabilities.session_snapshot_v1 {
            CommunicationValue::new(CommunicationType::SyncClientIotaStatus)
                .add_typed_default(DataType::IotaIds, DataValue::Array(connected_iota_ids))
                .add_typed_default(DataType::UserStates, DataValue::Array(connected_sessions))
                .add_typed_default(
                    DataType::RhoConnections,
                    DataValue::SignedNumber(self.rho.connection_count().await as i128),
                )
        } else {
            // Legacy Omega has no request/response contract for this message.
            // Its exact snapshot is IotaIds + UserIds + RhoConnections.
            CommunicationValue::new(CommunicationType::SyncClientIotaStatus)
                .add_typed_default(DataType::IotaIds, DataValue::Array(connected_iota_ids))
                .add_typed_default(DataType::UserIds, DataValue::Array(connected_user_ids))
                .add_typed_default(
                    DataType::RhoConnections,
                    DataValue::SignedNumber(self.rho.connection_count().await as i128),
                )
        };

        if !peer_capabilities.session_snapshot_v1 {
            if let Err(error) = self.send_message_result(&sync_msg).await {
                self.fail_synchronization("legacy route synchronization", error)
                    .await;
                return false;
            }
            *self.state.write().await = ConnectionState::SynchronizingSubscriptions;
            if let Err(error) = self.restore_presence_subscriptions().await {
                self.fail_synchronization("subscription restoration", error)
                    .await;
                return false;
            }
            *self.state.write().await = ConnectionState::Ready;
            return true;
        }

        let mut response = Err("route synchronization did not start".to_string());
        for attempt in 0..self.sync_retries {
            response = self
                .await_response(&sync_msg, Some(self.sync_timeout))
                .await;
            match &response {
                Ok(value) if value.is_type(CommunicationType::Success) => break,
                Ok(value) if value.is_type(CommunicationType::ErrorInvalidData) => break,
                _ if attempt + 1 < self.sync_retries => {
                    sleep(Duration::from_millis(250 * 2u64.pow(attempt))).await
                }
                _ => break,
            }
        }
        match response {
            Ok(response) if response.is_type(CommunicationType::Success) => {
                *self.state.write().await = ConnectionState::SynchronizingSubscriptions;
                if let Err(error) = self.restore_presence_subscriptions().await {
                    log_err!(
                        0,
                        PrintType::Omega,
                        "Presence subscription restoration failed: {}",
                        error
                    );
                    self.fail_synchronization("subscription restoration", error)
                        .await;
                    return false;
                }
                *self.state.write().await = ConnectionState::Ready;
            }
            Ok(response) => {
                let error = format!(
                    "Omega rejected presence snapshot with {}",
                    response.get_type()
                );
                self.fail_synchronization("route synchronization", error)
                    .await;
                return false;
            }
            Err(error) => {
                self.fail_synchronization("route synchronization", error)
                    .await;
                return false;
            }
        }
        true
    }

    pub(super) async fn fail_synchronization(&self, phase: &str, error: String) {
        log_err!(
            0,
            PrintType::Omega,
            "Omega {} failed after {} attempts: {}; closing transport for reconnect",
            phase,
            self.sync_retries,
            error
        );
        *self.state.write().await = ConnectionState::Disconnected;
        self.waiting_tasks.clear();
        if let Some(sender) = self.sender.read().await.as_ref() {
            sender.close().await;
        }
    }

    // -------------------------------------------------------------------------
    // Read Loop
    // -------------------------------------------------------------------------

    pub(super) async fn read_loop(
        self: Arc<Self>,
        connection: Arc<MTPConnection>,
        sender_handle: Arc<ConnectionHandle>,
        mut capability_tx: Option<oneshot::Sender<Result<PeerCapabilities, String>>>,
    ) {
        // Monitor both receiver and sender handle for close
        let mut close_rx = sender_handle.subscribe_close();

        loop {
            tokio::select! {
                result = connection.receive() => {
                    match result {
                        Ok(cv) => {
                            log_cv_in!(PrintType::Omega, &cv);

                            if cv.is_type(CommunicationType::IdentificationResponse) {
                                if let Some(tx) = capability_tx.take() {
                                    let result = parse_omega_capability_response(&cv);
                                    let _ = tx.send(result);
                                }
                                continue;
                            }

                            if self.apply_route_update(&cv).await {
                                continue;
                            }

                            if cv.is_type(CommunicationType::Relay) {
                                let request_id = match cv.require_id() {
                                    Ok(request_id) => request_id,
                                    Err(error) => {
                                        log_err!(
                                            self.omikron_id as i64,
                                            PrintType::Omega,
                                            "Rejected malformed relay: {}",
                                            error
                                        );
                                        let latest = mtp::codec::TypeMap::latest();
                                        let response = tau::error_response(
                                            &cv,
                                            CommunicationType::ErrorInvalidData,
                                            cv.type_map().unwrap_or(&latest),
                                        );
                                        let _ = self.send_message_result(&response).await;
                                        continue;
                                    }
                                };
                                let response = match relay_router::route_from_omega(&self.rho, cv).await {
                                    Ok(response) => response.with_id(request_id),
                                    Err(error) => {
                                        log_err!(
                                            self.omikron_id as i64,
                                            PrintType::Omega,
                                            "Relay routing failed: {}",
                                            error
                                        );
                                        CommunicationValue::new(
                                            relay_router::error_response_type(&error),
                                        )
                                        .with_id(request_id)
                                    }
                                };
                                if let Err(send_error) = self.send_message_result(&response).await {
                                    log_err!(
                                        self.omikron_id as i64,
                                        PrintType::Omega,
                                        "Relay routing response failed: {}",
                                        send_error
                                    );
                                }
                                continue;
                            }

                            let msg_id = match cv.require_id() {
                                Ok(msg_id) => msg_id,
                                Err(error) => {
                                    log_err!(
                                        self.omikron_id as i64,
                                        PrintType::Omega,
                                        "Discarded response without an MTP id: {}",
                                        error
                                    );
                                    continue;
                                }
                            };
                            if self.waiting_tasks.complete(msg_id, cv.clone()) {
                                continue;
                            }

                            if cv.is_type(CommunicationType::EraseHostedUserData) {
                                let Some(iota_id) = signed_positive_iota_id(&cv)
                                else {
                                    log_err!(0, PrintType::Omega, "Discarded hosted-data erasure without IotaId");
                                    continue;
                                };
                                if let Some(rho) = self.rho.get_by_iota(iota_id).await {
                                    rho.get_iota_connection().send_message(&cv).await;
                                } else {
                                    log_err!(iota_id, PrintType::Omega, "Hosted-data erasure is pending because the Iota is offline");
                                }
                                continue;
                            }
                            if cv.is_type(CommunicationType::ProvisionIotaUser) {
                                let Some(iota_id) = signed_positive_iota_id(&cv)
                                else {
                                    log_err!(
                                        0,
                                        PrintType::Omega,
                                        "Discarded user provisioning without a valid IotaId"
                                    );
                                    continue;
                                };
                                if let Some(rho) = self.rho.get_by_iota(iota_id).await {
                                    rho.get_iota_connection().send_message(&cv).await;
                                } else {
                                    log_err!(
                                        iota_id,
                                        PrintType::Omega,
                                        "User provisioning is pending because the Iota is offline"
                                    );
                                }
                                continue;
                            }
                            if cv.is_type(CommunicationType::ClientChanged) {
                                let Some((receiver, session_id)) = client_changed_target(&cv)
                                else {
                                    continue;
                                };
                                self.forward_client_changed(receiver, session_id, &cv).await;
                                continue;
                            }
                        }
                        Err(e) => {
                            log_err!(0, PrintType::Omega, "Receive error: {}", e);
                            break;
                        }
                    }
                }
                _ = close_rx.changed() => {
                    // Connection was closed by either side
                    if let Some(reason) = close_rx.borrow().clone() {
                        log_err!(0, PrintType::Omega, "Connection closed: {:?}", reason);
                    } else {
                        log_in!(0, PrintType::Omega, "Connection closed cleanly");
                    }
                    break;
                }
            }
        }
        *self.state.write().await = ConnectionState::Disconnected;
        self.publish_presence_unavailable().await;
    }
}
