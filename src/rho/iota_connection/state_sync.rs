use super::*;

impl IotaConnection {
    pub(super) async fn replace_state_subscription(
        &self,
        user_id: i64,
        session_id: i64,
        contact_ids: Vec<i64>,
    ) -> Result<(), String> {
        let Some(rho_connection) = self.get_rho_connection().await else {
            return Err("Rho connection is unavailable".to_string());
        };
        if rho_connection
            .get_client_connection(user_id, session_id)
            .await
            .is_none()
        {
            return Err("target client session is no longer connected".to_string());
        }

        self.state
            .omega
            .replace_state_subscription(user_id, session_id, contact_ids)
            .await
    }

    pub(super) fn update_presence_subscription(
        self: &Arc<Self>,
        user_id: i64,
        session_id: i64,
        contact_ids: Vec<i64>,
    ) {
        let connection = self.clone();
        if let Err(error) = self.tasks.spawn_cancellable(async move {
            log_in!(
                connection.iota_id as i64,
                PrintType::Omega,
                "PresenceSync user={} session={} stage=subscribe",
                user_id,
                session_id
            );
            if let Err(error) = connection
                .replace_state_subscription(user_id, session_id, contact_ids)
                .await
            {
                log_err!(
                    connection.iota_id as i64,
                    PrintType::Omega,
                    "Failed to replace presence subscription for user {} session {}: {}",
                    user_id,
                    session_id,
                    error
                );
            }
        }) {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Presence task submission failed: {}",
                error
            );
            self.sender.close();
        }
    }
    /// Handle GET_CHATS message
    pub(super) async fn handle_get_chats(&self, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let Ok(user_id) = cv.require_sender() else {
            log_err!(
                self.iota_id as i64,
                PrintType::Iota,
                "Rejected get_chats without an MTP sender"
            );
            return;
        };
        if !i64::try_from(user_id)
            .ok()
            .is_some_and(|user| self.state.rho.owns_iota_user(user, self))
        {
            return;
        }

        let Some(session_id) = cv
            .get_data(DataType::SessionId)
            .as_signed_number()
            .and_then(|id| i64::try_from(id).ok())
            .filter(|id| *id > 0)
        else {
            self.forward_to_client(
                CommunicationValue::new(CommunicationType::ErrorInvalidData)
                    .with_id(message_id)
                    .with_receiver(user_id),
            )
            .await;
            return;
        };
        let mut interested_ids = Vec::new();
        let tm = TypeMap::latest();
        if let Some(DataValue::Array(users)) = cv.get_data(DataType::UserIds) {
            for user in users {
                match user {
                    DataValue::SignedNumber(id) => interested_ids.push(*id as i64),
                    DataValue::Container(entries) => {
                        if let Some(DataValue::SignedNumber(id)) =
                            entries.iter().find_map(|(key, value)| {
                                (*key == data_type_id(DataType::UserId, &tm)).then_some(value)
                            })
                        {
                            interested_ids.push(*id as i64);
                        }
                    }
                    _ => {}
                }
            }
            interested_ids.sort_unstable();
            interested_ids.dedup();
        }
        if let Err(error) = self
            .replace_state_subscription(user_id as i64, session_id, interested_ids)
            .await
        {
            log_err!(
                self.iota_id as i64,
                PrintType::Omega,
                "Failed to replace presence subscription for user {} session {}: {}",
                user_id,
                session_id,
                error
            );
        }
        let response = match self.enrich_chat_snapshot(cv, user_id, session_id).await {
            Ok(response) => response,
            Err(_) => CommunicationValue::new(CommunicationType::ErrorInternal)
                .with_id(message_id)
                .with_receiver(user_id),
        };
        self.forward_to_client(response).await;
    }

    pub(crate) async fn enrich_chat_snapshot(
        &self,
        cv: CommunicationValue,
        user_id: u64,
        session_id: i64,
    ) -> Result<CommunicationValue, String> {
        if !i64::try_from(user_id)
            .ok()
            .filter(|user| *user > 0)
            .is_some_and(|user| self.state.rho.owns_iota_user(user, self))
            || session_id <= 0
        {
            return Err("chat snapshot has no current account route".into());
        }
        let tm = TypeMap::latest();

        // ============================
        // Load Calls
        // ============================
        let calls: Vec<Arc<CallGroup>> = self
            .state
            .call_manager
            .get_call_groups(user_id)
            .await
            .map_err(|_| "call state is unavailable")?;

        let mut invites: HashMap<i64, Vec<DataValue>> = HashMap::new();
        let mut global_calls: Vec<DataValue> = Vec::new();
        let empty = calls.is_empty();

        for call in calls {
            let (call_self, pending, members, pending_invitees) = {
                let state = call.state.read().await;
                (
                    state.members.get(&user_id).cloned(),
                    state.pending_invites.get(&user_id).cloned(),
                    state.members.keys().copied().collect::<Vec<_>>(),
                    state.pending_invites.keys().copied().collect::<Vec<_>>(),
                )
            };

            if call_self.is_none() && pending.is_none() {
                continue;
            }

            // Iota is authoritative for entitlement and the recipient envelope.
            let request = CommunicationValue::new(CommunicationType::CallEnvelopeGet)
                .with_id(crate::services::call_state::next_call_lookup_id())
                .add_typed_default(
                    DataType::ReceiverId,
                    DataValue::SignedNumber(user_id.into()),
                )
                .add_typed_default(DataType::CallId, DataValue::Str(call.call_id.to_string()));
            let secret = self
                .state
                .rho
                .get_for_user(user_id as i64)
                .await
                .map(|rho| rho.get_iota_connection().clone());
            let secret = match secret {
                Some(connection) => {
                    connection
                        .await_response(&request, Some(std::time::Duration::from_secs(8)))
                        .await
                }
                None => Err("Iota unavailable".into()),
            }
            .map_err(|_| "call envelope is unavailable")?;
            if !secret.is_type(CommunicationType::CallEnvelopeGet) {
                return Err("call envelope request was rejected".into());
            }
            let secret = secret.get_data(DataType::CallSecret).cloned();
            if secret.is_none() {
                return Err("call envelope response is incomplete".into());
            }
            if let Some(secret) = secret {
                let timeout = call_self
                    .as_ref()
                    .and_then(|member| member.timeout_until_ms)
                    .unwrap_or(0);
                let admin = call_self
                    .as_ref()
                    .is_some_and(|member| member.role == crate::calls::call_group::CallRole::Admin);

                // List of all members in the call, plus pending invitees so
                // clients recognize joinable calls for a contact.
                let member_ids: Vec<DataValue> = members
                    .iter()
                    .chain(pending_invitees.iter())
                    .map(|id| DataValue::SignedNumber((*id).into()))
                    .collect();

                // Build base call container
                let mut base_call_map: BTreeMap<DataTypeId, DataValue> = BTreeMap::new();
                base_call_map.insert(
                    data_type_id(DataType::CallId, &tm),
                    DataValue::Str(call.call_id.to_string()),
                );
                base_call_map.insert(
                    data_type_id(DataType::OmikronId, &tm),
                    DataValue::SignedNumber((call.owner_omikron_id as i64).into()),
                );
                base_call_map.insert(
                    data_type_id(DataType::CallMembers, &tm),
                    DataValue::Array(member_ids),
                );
                base_call_map.insert(data_type_id(DataType::CallSecret, &tm), secret);
                base_call_map.insert(
                    data_type_id(DataType::CreatedAt, &tm),
                    DataValue::SignedNumber(call.created_at_ms.into()),
                );
                if let Some(pending) = pending {
                    base_call_map.insert(
                        data_type_id(DataType::CallInvited, &tm),
                        DataValue::Bool(true),
                    );
                    base_call_map.insert(
                        data_type_id(DataType::SenderId, &tm),
                        DataValue::SignedNumber(pending.inviter_id.into()),
                    );
                }

                if timeout > 0 {
                    base_call_map.insert(
                        data_type_id(DataType::Timeout, &tm),
                        DataValue::SignedNumber(timeout.into()),
                    );
                }

                if admin {
                    base_call_map
                        .insert(data_type_id(DataType::HasAdmin, &tm), DataValue::Bool(true));
                }

                // Add to global calls with only this user's recipient-specific secret.
                global_calls.push(DataValue::container_from_map(&base_call_map));

                // Attach this call to EVERY member of the call (other than ourselves)
                for member_id in members {
                    if member_id == user_id {
                        continue;
                    }

                    let contact_call_map = base_call_map.clone();

                    invites
                        .entry(member_id as i64)
                        .or_default()
                        .push(DataValue::container_from_map(&contact_call_map));
                }
            }
        }

        // ============================
        // Enrich Contacts
        // ============================
        let enriched_contacts = if empty {
            match cv.get_data(DataType::UserIds) {
                Some(DataValue::Array(arr)) => DataValue::Array(arr.clone()),
                _ => DataValue::Array(vec![]),
            }
        } else {
            let mut enriched: Vec<DataValue> = Vec::new();

            if let Some(DataValue::Array(users)) = cv.get_data(DataType::UserIds) {
                for user_val in users {
                    if let DataValue::Container(entries) = user_val {
                        let mut user_map: BTreeMap<DataTypeId, DataValue> =
                            entries.iter().cloned().collect();

                        if let Some(DataValue::SignedNumber(id)) =
                            user_map.get(&data_type_id(DataType::UserId, &tm))
                            && let Some(call_list) = invites.get(&(*id as i64))
                            && !call_list.is_empty()
                        {
                            user_map.insert(
                                data_type_id(DataType::Calls, &tm),
                                DataValue::Array(call_list.clone()),
                            );
                        }

                        enriched.push(DataValue::container_from_map(&user_map));
                    }
                }
            }

            DataValue::Array(enriched)
        };

        // ============================
        // Forward to client
        // ============================
        let mut response = cv
            .add_typed_default(DataType::UserIds, enriched_contacts)
            .add_typed_default(DataType::Calls, DataValue::Array(global_calls))
            .add_typed_default(DataType::PresenceSnapshotComplete, DataValue::Bool(false));
        if let Ok(principal) = self.state.call_manager.principal(user_id) {
            match self
                .state
                .omega
                .replace_contact_subscription(
                    user_id as i64,
                    session_id,
                    &response,
                    principal.authority.as_str(),
                )
                .await
            {
                Ok(snapshot) => {
                    for field in [
                        DataType::UserStates,
                        DataType::MissingUserIds,
                        DataType::Uuid,
                        DataType::Timestamp,
                        DataType::VersionNumber,
                    ] {
                        let value = snapshot
                            .get_data(field)
                            .cloned()
                            .ok_or("incomplete presence snapshot")?;
                        response = response.add_typed_default(field, value);
                    }
                    response = response.add_typed_default(
                        DataType::PresenceSnapshotComplete,
                        DataValue::Bool(true),
                    );
                }
                Err(error) => {
                    log_err!(
                        user_id as i64,
                        PrintType::Omega,
                        "Canonical presence is unavailable: {}",
                        error
                    );
                }
            }
        }
        Ok(response)
    }

    /// Forward message to client
    pub(super) async fn forward_to_client(&self, cv: CommunicationValue) {
        if let Some(rho_conn) = self.get_rho_connection().await {
            let updated_cv = cv.with_sender(self.get_iota_id().await);
            rho_conn.message_to_client(updated_cv).await;
        }
    }
}
