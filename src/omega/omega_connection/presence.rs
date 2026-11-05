use super::presence_projection::ContactPresence;
use super::*;

pub(super) fn normalize_presence_user_ids(mut user_ids: Vec<i64>) -> Result<Vec<i64>, String> {
    if user_ids.iter().any(|id| *id <= 0) {
        return Err("presence subscription contains invalid user id".into());
    }
    user_ids.sort_unstable();
    user_ids.dedup();
    Ok(user_ids)
}

impl OmegaConnection {
    pub async fn replace_state_subscription(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
    ) -> Result<(), String> {
        if user_id <= 0 || session_id <= 0 {
            return Err("invalid user or session id".to_string());
        }

        let user_ids = normalize_presence_user_ids(user_ids)?;

        let key = (user_id, session_id);
        if self
            .session_presence
            .get(&key)
            .is_some_and(|entry| entry.projection.is_some())
        {
            return Ok(());
        }
        // Store the latest authoritative snapshot before checking readiness.
        // A client can synchronize while the transport is reconnecting.
        let generation = self.replace_desired_presence_state(key, user_ids.clone(), None);

        if !self.is_ready().await {
            return Err("Omega is not synchronized".to_string());
        }

        self.deliver_state_subscription(key, user_ids, generation)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) async fn replace_contact_subscription(
        &self,
        user_id: i64,
        session_id: i64,
        contacts: &CommunicationValue,
        authority: &str,
    ) -> Result<CommunicationValue, String> {
        if user_id <= 0 || session_id <= 0 {
            return Err("invalid presence session".into());
        }
        let projection = ContactPresence::from_contacts(contacts, authority)
            .map_err(|error| error.to_string())?;
        let user_ids = projection.user_ids();
        let key = (user_id, session_id);
        let generation =
            self.replace_desired_presence_state(key, user_ids.clone(), Some(projection));
        if !self.is_ready().await {
            return Err("Omega is not synchronized".into());
        }
        let snapshot = self
            .deliver_state_subscription(key, user_ids, generation)
            .await
            .map_err(|error| error.to_string())?;
        if !self.is_current_presence_generation(key, generation) {
            return Err("presence subscription was replaced".into());
        }
        snapshot.ok_or_else(|| "presence subscription was replaced".into())
    }

    pub(super) fn replace_desired_presence_state(
        &self,
        key: (i64, i64),
        user_ids: Vec<i64>,
        projection: Option<ContactPresence>,
    ) -> u64 {
        self.session_presence
            .entry(key)
            .and_modify(|entry| {
                entry.subscribed_user_ids = user_ids.clone();
                entry.pending = true;
                entry.generation = entry.generation.saturating_add(1);
                entry.projection = projection.clone();
            })
            .or_insert_with(|| SessionPresenceState {
                subscribed_user_ids: user_ids,
                pending: true,
                generation: 1,
                projection,
            })
            .generation
    }

    pub(super) async fn forward_client_changed(
        &self,
        user_id: i64,
        session_id: i64,
        event: &CommunicationValue,
    ) {
        let event = {
            let Some(mut entry) = self.session_presence.get_mut(&(user_id, session_id)) else {
                return;
            };
            let pending = entry.pending;
            let generation = entry.generation;
            match entry.projection.as_mut() {
                Some(projection) => match projection.event(event, pending) {
                    Ok(event) => event.map(|event| {
                        event
                            .add_typed_default(
                                DataType::Uuid,
                                DataValue::Str(self.connection_id.to_string()),
                            )
                            .add_typed_default(
                                DataType::Timestamp,
                                DataValue::UnsignedNumber(generation.into()),
                            )
                    }),
                    Err(error) => {
                        log_err!(
                            user_id,
                            PrintType::Omega,
                            "Rejected presence update: {}",
                            error
                        );
                        return;
                    }
                },
                None => Some(event.clone()),
            }
        };
        if let Some(event) = event
            && let Some(client) = self.rho.get_client_connection(user_id, session_id).await
        {
            client.send_message(&event).await;
        }
    }

    pub(super) async fn publish_presence_unavailable(&self) {
        let mut snapshots = Vec::new();
        for mut entry in self.session_presence.iter_mut() {
            let Some(generation) = entry.generation.checked_add(1) else {
                continue;
            };
            let Some(projection) = entry.projection.as_mut() else {
                continue;
            };
            let missing = projection.suspend();
            entry.generation = generation;
            entry.pending = true;
            let (user, session) = *entry.key();
            let snapshot = CommunicationValue::new(CommunicationType::GetStates)
                .with_receiver(user as u64)
                .add_typed_default(DataType::SessionId, DataValue::SignedNumber(session.into()))
                .add_typed_default(
                    DataType::Uuid,
                    DataValue::Str(self.connection_id.to_string()),
                )
                .add_typed_default(
                    DataType::Timestamp,
                    DataValue::UnsignedNumber(generation.into()),
                )
                .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(1))
                .add_typed_default(DataType::UserStates, DataValue::Array(vec![]))
                .add_typed_default(DataType::MissingUserIds, DataValue::Array(missing));
            snapshots.push(((user, session), generation, snapshot));
        }
        for ((user, session), generation, snapshot) in snapshots {
            if self.is_current_presence_generation((user, session), generation)
                && let Some(client) = self.rho.get_client_connection(user, session).await
            {
                client.send_message(&snapshot).await;
            }
        }
    }

    pub(super) async fn deliver_state_subscription(
        &self,
        key: (i64, i64),
        user_ids: Vec<i64>,
        generation: u64,
    ) -> Result<Option<CommunicationValue>, InitialPresenceError> {
        let (user_id, session_id) = key;
        let delivery_lock = self
            .presence_delivery_locks
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _delivery_guard = delivery_lock.lock().await;

        // Replacements can be requested concurrently.  Serializing transport
        // side effects ensures that the current generation is installed last.
        if !self.is_current_presence_generation(key, generation) {
            return Ok(None);
        }

        if !self.peer_capabilities.read().await.state_subscribe_v1 {
            let result = self
                .request_user_states(user_id, session_id, user_ids, generation)
                .await;
            if result.is_ok() {
                self.mark_presence_delivered(key, generation).await;
            }
            return result.map(Some);
        }

        let subscription = CommunicationValue::new(CommunicationType::StateSubscribe)
            .with_sender(user_id as u64)
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(
                    user_ids
                        .iter()
                        .map(|user_id| DataValue::SignedNumber((*user_id).into()))
                        .collect(),
                ),
            );
        log_out!(
            user_id,
            PrintType::Omega,
            "PresenceSync user={} session={} stage=subscribe",
            user_id,
            session_id
        );
        let response = self
            .await_response(&subscription, Some(Duration::from_secs(20)))
            .await
            .map_err(InitialPresenceError::OmegaUnavailable)?;
        if !response.is_type(CommunicationType::Success) {
            return Err(InitialPresenceError::SubscriptionRejected(format!(
                "StateSubscribe rejected with {}",
                response.get_type()
            )));
        }

        let snapshot = self
            .request_user_states(user_id, session_id, user_ids, generation)
            .await?;
        self.mark_presence_delivered(key, generation).await;
        Ok(Some(snapshot))
    }

    pub(super) async fn restore_presence_subscriptions(&self) -> Result<(), String> {
        let mut active = Vec::new();
        for rho in self.rho.connections().await {
            active.extend(rho.get_client_connections().await);
        }
        let active_keys: std::collections::HashSet<_> = active
            .iter()
            .map(|client| (client.user_id as i64, client.session_id as i64))
            .collect();

        // Do not replay subscriptions for sessions that disappeared while the
        // transport was down.
        self.session_presence
            .retain(|key, _| active_keys.contains(key));

        // A fresh Omega transport has no connection-local subscription state.
        // Every desired subscription must be installed again, even one that was
        // delivered successfully on the previous transport.
        for mut entry in self.session_presence.iter_mut() {
            entry.pending = true;
            entry.generation = entry
                .generation
                .checked_add(1)
                .ok_or("presence generation exhausted")?;
        }

        loop {
            let pending: Vec<_> = active_keys
                .iter()
                .filter_map(|key| {
                    self.session_presence.get(key).and_then(|entry| {
                        entry
                            .pending
                            .then(|| (*key, entry.subscribed_user_ids.clone(), entry.generation))
                    })
                })
                .collect();
            if pending.is_empty() {
                break;
            }
            for (key, user_ids, generation) in pending {
                self.deliver_state_subscription(key, user_ids, generation)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    pub(super) async fn mark_presence_delivered(&self, key: (i64, i64), generation: u64) {
        if let Some(mut entry) = self.session_presence.get_mut(&key)
            && entry.generation == generation
        {
            entry.pending = false;
        }
    }

    pub(super) async fn fetch_user_states_snapshot(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: &[i64],
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let request = CommunicationValue::new(CommunicationType::GetStates)
            .add_typed_default(
                DataType::SessionId,
                DataValue::SignedNumber(session_id.into()),
            )
            .add_typed_default(
                DataType::UserIds,
                DataValue::Array(
                    user_ids
                        .iter()
                        .map(|user_id| DataValue::SignedNumber((*user_id).into()))
                        .collect(),
                ),
            );
        log_out!(
            user_id,
            PrintType::Omega,
            "PresenceSync user={} session={} stage=get_states",
            user_id,
            session_id
        );
        let mut response = self
            .await_response(&request, Some(Duration::from_secs(20)))
            .await
            .map_err(InitialPresenceError::OmegaUnavailable)?;
        if !response.is_type(CommunicationType::GetStates) {
            return Err(InitialPresenceError::InvalidSnapshot(
                "expected GetStates response".into(),
            ));
        }
        let legacy_peer = !self.peer_capabilities.read().await.client_state_push_v1;
        match response.get_data(DataType::SessionId).as_number() {
            Some(id) if id == session_id as i128 => {}
            None if legacy_peer => {
                response = response.add_typed_default(
                    DataType::SessionId,
                    DataValue::SignedNumber(session_id.into()),
                );
            }
            _ => {
                return Err(InitialPresenceError::InvalidSnapshot(
                    "GetStates response had the wrong session".into(),
                ));
            }
        }
        if !matches!(
            response.get_data(DataType::UserStates),
            Some(DataValue::Array(_))
        ) {
            return Err(InitialPresenceError::InvalidSnapshot(
                "GetStates response is missing UserStates".into(),
            ));
        }
        if !matches!(
            response.get_data(DataType::MissingUserIds),
            Some(DataValue::Array(_))
        ) {
            if legacy_peer && response.get_data(DataType::MissingUserIds).is_none() {
                response = response
                    .add_typed_default(DataType::MissingUserIds, DataValue::Array(Vec::new()));
            } else {
                return Err(InitialPresenceError::InvalidSnapshot(
                    "GetStates response is missing or has invalid MissingUserIds".into(),
                ));
            }
        }
        Ok(response)
    }

    pub(super) async fn request_user_states(
        &self,
        user_id: i64,
        session_id: i64,
        user_ids: Vec<i64>,
        generation: u64,
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let mut response = self
            .fetch_user_states_snapshot(user_id, session_id, &user_ids)
            .await?;

        {
            let mut entry = self
                .session_presence
                .get_mut(&(user_id, session_id))
                .ok_or_else(|| {
                    InitialPresenceError::InvalidSnapshot("presence session ended".into())
                })?;
            if entry.generation == generation
                && let Some(projection) = entry.projection.as_mut()
            {
                response = projection.snapshot(&response)?;
                response = response
                    .add_typed_default(
                        DataType::Uuid,
                        DataValue::Str(self.connection_id.to_string()),
                    )
                    .add_typed_default(
                        DataType::Timestamp,
                        DataValue::UnsignedNumber(generation.into()),
                    );
            }
        }

        if self.is_current_presence_generation((user_id, session_id), generation)
            && let Some(client) = self.rho.get_client_connection(user_id, session_id).await
        {
            client.send_message(&response).await;
            log_out!(
                user_id,
                PrintType::Client,
                "PresenceSync user={} session={} stage=get_states_forwarded",
                user_id,
                session_id
            );
        }
        Ok(response)
    }

    pub(super) fn is_current_presence_generation(&self, key: (i64, i64), generation: u64) -> bool {
        self.session_presence
            .get(&key)
            .is_some_and(|entry| entry.generation == generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn canonical_subscription_queries_real_ids_and_merges_an_early_live_update() {
        let state = crate::rho::test_support::state();
        let omega = state.omega.clone();
        *omega.state.write().await = ConnectionState::Ready;
        omega.peer_capabilities.write().await.state_subscribe_v1 = true;
        let mut requests = omega.test_requests();
        let map = mtp::codec::TypeMap::latest();
        let contacts = CommunicationValue::new(CommunicationType::GetChats).add_typed_default(
            DataType::UserIds,
            DataValue::Array(vec![DataValue::Container(vec![
                (
                    data_type_id(DataType::UserId, &map),
                    DataValue::SignedNumber(7),
                ),
                (
                    data_type_id(DataType::Principal, &map),
                    DataValue::Str(format!(
                        "{{\"authority\":\"omega-key:{}\",\"user_id\":42}}",
                        "1".repeat(64)
                    )),
                ),
            ])]),
        );
        let request_task = tokio::spawn({
            let omega = omega.clone();
            async move {
                omega
                    .replace_contact_subscription(
                        5,
                        9,
                        &contacts,
                        &format!("omega-key:{}", "1".repeat(64)),
                    )
                    .await
            }
        });
        let (subscribe, reply) = requests.recv().await.unwrap();
        assert!(subscribe.is_type(CommunicationType::StateSubscribe));
        assert_eq!(subscribe.sender(), Some(5));
        assert_eq!(
            subscribe.get_data(DataType::UserIds),
            Some(&DataValue::Array(vec![DataValue::SignedNumber(42)]))
        );
        reply
            .send(Ok(CommunicationValue::new(CommunicationType::Success)))
            .unwrap();
        let (get, reply) = requests.recv().await.unwrap();
        assert!(get.is_type(CommunicationType::GetStates));
        assert_eq!(
            get.get_data(DataType::UserIds),
            subscribe.get_data(DataType::UserIds)
        );
        let epoch = Uuid::new_v4();
        let early = CommunicationValue::new(CommunicationType::ClientChanged)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(42))
            .add_typed_default(DataType::UserState, DataValue::Str("user_dnd".into()))
            .add_typed_default(DataType::Uuid, DataValue::Str(epoch.to_string()))
            .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(4));
        omega.forward_client_changed(5, 9, &early).await;
        reply
            .send(Ok(CommunicationValue::new(CommunicationType::GetStates)
                .add_typed_default(DataType::SessionId, DataValue::SignedNumber(9))
                .add_typed_default(DataType::Uuid, DataValue::Str(epoch.to_string()))
                .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(1))
                .add_typed_default(DataType::MissingUserIds, DataValue::Array(vec![]))
                .add_typed_default(
                    DataType::UserStates,
                    DataValue::Array(vec![DataValue::Container(vec![
                        (
                            data_type_id(DataType::UserId, &map),
                            DataValue::SignedNumber(42),
                        ),
                        (
                            data_type_id(DataType::UserState, &map),
                            DataValue::Str("user_online".into()),
                        ),
                        (
                            data_type_id(DataType::VersionNumber, &map),
                            DataValue::UnsignedNumber(3),
                        ),
                    ])]),
                )))
            .unwrap();
        let snapshot = request_task.await.unwrap().unwrap();
        assert_eq!(
            snapshot.get_data(DataType::Uuid),
            Some(&DataValue::Str(omega.connection_id.to_string()))
        );
        assert_eq!(
            snapshot.get_data(DataType::Timestamp),
            Some(&DataValue::UnsignedNumber(1))
        );
        let Some(DataValue::Array(states)) = snapshot.get_data(DataType::UserStates) else {
            panic!("states")
        };
        assert_eq!(
            states[0].get_field(data_type_id(DataType::UserId, &map)),
            Some(&DataValue::SignedNumber(7))
        );
        assert_eq!(
            states[0].get_field(data_type_id(DataType::UserState, &map)),
            Some(&DataValue::Str("user_dnd".into()))
        );
        assert_eq!(
            states[0].get_field(data_type_id(DataType::VersionNumber, &map)),
            Some(&DataValue::UnsignedNumber(4))
        );
        assert!(!omega.session_presence.get(&(5, 9)).unwrap().pending);
        omega.publish_presence_unavailable().await;
        let entry = omega.session_presence.get(&(5, 9)).unwrap();
        assert!(entry.pending);
        assert_eq!(entry.generation, 2);
        assert_eq!(entry.projection.as_ref().unwrap().user_ids(), vec![42]);
    }
}
