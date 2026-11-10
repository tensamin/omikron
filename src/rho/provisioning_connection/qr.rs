use super::*;
use crate::rho::connection::positive_data_i64;

impl ProvisioningConnection {
    pub(super) async fn create(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let method = match request
            .get_data(DataType::ProvisioningMethod)
            .and_then(DataValue::as_str)
        {
            Some("password") => ProvisioningMethod::Password,
            Some("qr-contact-created") => ProvisioningMethod::QrContactCreated,
            Some("qr-owner-created") => return Err("legacy QR login is no longer supported"),
            _ => return Err("invalid method"),
        };
        let role = Self::role(request)?;
        if self
            .general
            .state
            .provisioning
            .for_participant(self.general.id())
            .is_ok()
        {
            return Err("connection already has a login session");
        }
        if request.get_data(DataType::Username).is_some()
            && request.get_data(DataType::UserId).is_some()
        {
            return Err("ambiguous account hint");
        }
        if method != ProvisioningMethod::Password
            && (request.get_data(DataType::Username).is_some()
                || request.get_data(DataType::UserId).is_some())
        {
            return Err("QR creation does not accept an account hint");
        }
        if (method == ProvisioningMethod::QrContactCreated && role != ProvisioningRole::Contact)
            || (method == ProvisioningMethod::QrOwnerCreated && role != ProvisioningRole::Owner)
            || (method == ProvisioningMethod::Password && role != ProvisioningRole::Contact)
        {
            return Err("invalid creator role");
        }
        let participant = self.participant(request, role)?;
        let account = if method == ProvisioningMethod::Password {
            let source = tau::ConnectionFacts::from_mtp(&self.general.mtp_connection)
                .remote_addr
                .map(|address| address.ip());
            self.general
                .state
                .provisioning
                .password_admission
                .initiate(None, source)?;
            let account = self.resolve_account(request).await?;
            self.general
                .state
                .rho
                .get_by_iota(account.iota_id)
                .await
                .ok_or("Iota unavailable")?;
            Some(account)
        } else {
            None
        };
        let id = self
            .general
            .state
            .provisioning
            .create_with_id(
                if method == ProvisioningMethod::QrContactCreated {
                    Self::session_id(request)?
                } else {
                    Uuid::new_v4()
                },
                method,
                participant,
            )
            .map_err(|_| "cannot create session")?;
        if let Some(account) = account {
            self.general
                .state
                .provisioning
                .bind(id, self.general.id(), account)?;
        }
        let reply = CommunicationValue::new(CommunicationType::ProvisioningCreated)
            .add_typed_default(
                DataType::Timestamp,
                DataValue::UnsignedNumber(
                    self.general
                        .state
                        .provisioning
                        .remaining_seconds(id)?
                        .into(),
                ),
            )
            .with_id(request.id().ok_or("missing request ID")?)
            .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string()))
            .add_typed_default(
                DataType::ProvisioningParticipantId,
                DataValue::UnsignedNumber(self.general.id().into()),
            )
            .add_typed_default(
                DataType::ProvisioningMethod,
                DataValue::Str(method.as_str().into()),
            )
            .add_typed_default(
                DataType::ProvisioningRole,
                DataValue::Str(role.as_str().into()),
            );
        if bounded_send(&self.sender, &reply).await.is_err() {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("send failed");
        }
        Ok(())
    }

    // A request may have at most one response with its frame ID. Notify the peer
    // before replying, and never retry the requester response path after attempting it.
    pub(super) async fn join(
        &self,
        request: &CommunicationValue,
    ) -> Result<(), ProvisioningOperationError> {
        let id = Self::session_id(request)?;
        let role = Self::role(request)?;
        // Contact-created login claims are handled only on authenticated connections.
        if role == ProvisioningRole::Owner {
            return Err("owner joins are no longer supported".into());
        }
        let participant = self.participant(request, role)?;
        let frame_id = request.id().ok_or("missing request ID")?;
        let session = self
            .general
            .state
            .provisioning
            .join(id, participant.clone())?;
        if session.method == ProvisioningMethod::QrContactCreated {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("QR login must be claimed by an authenticated client".into());
        }
        let peer = match role {
            ProvisioningRole::Contact => session.owner,
            ProvisioningRole::Owner => session.contact,
        }
        .ok_or("peer missing")?;
        let peer_sender = match peer.sender.upgrade() {
            Some(sender) => sender,
            None => {
                self.terminate_forward(id, ProvisioningFailure::PeerDisconnected)
                    .await;
                return Err("peer disconnected".into());
            }
        };
        let event_to_peer = match peer_joined_message(id, &participant, None) {
            Ok(message) => message,
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                    .await;
                return Err(error.into());
            }
        };
        let reply_to_joiner = match peer_joined_message(id, &peer, Some(frame_id)) {
            Ok(message) => message.add_typed_default(
                DataType::ClientId,
                DataValue::UnsignedNumber(participant.id.into()),
            ),
            Err(error) => {
                self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                    .await;
                return Err(error.into());
            }
        };
        let delivery = deliver_peer_then_reply(
            event_to_peer,
            reply_to_joiner,
            |message| async move { bounded_send(&peer_sender, &message).await.is_ok() },
            |message| async move { bounded_send(&self.sender, &message).await.is_ok() },
        )
        .await;
        if let Err(failure) = delivery {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err(match failure {
                DeliveryFailure::Peer => "peer notification failed".into(),
                DeliveryFailure::Requester => {
                    ProvisioningOperationError::NoFurtherReply("join response delivery failed")
                }
            });
        }
        Ok(())
    }

    pub(super) async fn resolve_account(
        &self,
        request: &CommunicationValue,
    ) -> Result<ResolvedAccount, &'static str> {
        let mut lookup = CommunicationValue::new(CommunicationType::GetUserData)
            .with_sender(self.general.state.omega.omikron_id());
        if request.get_data(DataType::UserId).is_some() {
            let id = positive_data_i64(request, DataType::UserId, "user ID")
                .map_err(|_| "invalid user ID")?;
            lookup = lookup.add_typed_default(DataType::UserId, DataValue::SignedNumber(id.into()));
        } else {
            let username = request
                .get_data(DataType::Username)
                .and_then(DataValue::as_str)
                .ok_or("missing account hint")?;
            if username.is_empty() || username.len() > MAX_USERNAME_LENGTH {
                return Err("invalid username");
            }
            lookup = lookup.add_typed_default(DataType::Username, DataValue::Str(username.into()));
        }
        let response = self
            .general
            .state
            .omega
            .clone()
            .await_response(&lookup, Some(Duration::from_secs(20)))
            .await
            .map_err(|_| "account lookup failed")?;
        if !response.is_type(CommunicationType::GetUserData) {
            return Err("account not found");
        }
        let positive = |field| {
            positive_data_i64(&response, field, "account ID").map_err(|_| "invalid account")
        };
        let string = |field| {
            response
                .get_data(field)
                .and_then(DataValue::as_str)
                .map(str::to_owned)
                .ok_or("invalid account")
        };
        let encoded = string(DataType::PublicKey)?;
        Ok(ResolvedAccount {
            user_id: positive(DataType::UserId)?,
            username: string(DataType::Username)?,
            principal: string(DataType::Principal)?,
            iota_id: positive(DataType::IotaId)?,
            public_key: PublicKeyBundle::from_base64(&encoded)
                .map_err(|_| "invalid account key")?,
        })
    }

    // A request may have at most one response with its frame ID. Notify the peer
    // before replying, and never retry the requester response path after attempting it.
    pub(super) async fn bind(
        &self,
        request: &CommunicationValue,
    ) -> Result<(), ProvisioningOperationError> {
        if request.get_data(DataType::Username).is_some()
            && request.get_data(DataType::UserId).is_some()
        {
            return Err("ambiguous account hint".into());
        }
        let id = Self::session_id(request)?;
        let frame_id = request.id().ok_or("missing request ID")?;
        let session = self
            .general
            .state
            .provisioning
            .snapshot(id, self.general.id())?;
        session.require_actor(self.general.id(), ProvisioningRole::Owner)?;
        let account = self.resolve_account(request).await?;
        let encoded_public_key = account
            .public_key
            .try_to_base64()
            .map_err(|_| ProvisioningOperationError::Replyable("key encoding failed"))?;
        let session =
            self.general
                .state
                .provisioning
                .bind(id, self.general.id(), account.clone())?;
        let contact = match session.contact.and_then(|contact| contact.sender.upgrade()) {
            Some(contact) => contact,
            None => {
                self.terminate_forward(id, ProvisioningFailure::PeerDisconnected)
                    .await;
                return Err("contact disconnected".into());
            }
        };
        let event_to_contact = account_bound_message(id, &account, &encoded_public_key, None);
        let reply_to_owner =
            account_bound_message(id, &account, &encoded_public_key, Some(frame_id));
        let delivery = deliver_peer_then_reply(
            event_to_contact,
            reply_to_owner,
            |message| async move { bounded_send(&contact, &message).await.is_ok() },
            |message| async move { bounded_send(&self.sender, &message).await.is_ok() },
        )
        .await;
        if let Err(failure) = delivery {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err(match failure {
                DeliveryFailure::Peer => "contact notification failed".into(),
                DeliveryFailure::Requester => ProvisioningOperationError::NoFurtherReply(
                    "account binding response delivery failed",
                ),
            });
        }
        Ok(())
    }

    pub(super) async fn confirm(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        self.general
            .state
            .provisioning
            .confirm(id, self.general.id())?;
        let session = self
            .general
            .state
            .provisioning
            .snapshot(id, self.general.id())?;
        if session.method == ProvisioningMethod::QrContactCreated
            && let Some(sender) = session.owner.and_then(|peer| peer.sender.upgrade())
        {
            bounded_send(
                &sender,
                &CommunicationValue::new(CommunicationType::QrProvisioningConfirm)
                    .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string())),
            )
            .await
            .map_err(|_| "owner disconnected")?;
        }
        if let Err(error) = self.send_success(request).await {
            self.terminate_forward(id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err(error);
        }
        Ok(())
    }

    pub(super) async fn relay_credential(
        &self,
        request: &CommunicationValue,
    ) -> Result<(), &'static str> {
        let session =
            authorize_qr_credential(&self.general.state.provisioning, self.general.id(), request)?;
        let Some(contact) = session.contact.and_then(|contact| contact.sender.upgrade()) else {
            self.terminate_forward(session.id, ProvisioningFailure::PeerDisconnected)
                .await;
            return Err("contact disconnected");
        };
        self.general
            .state
            .provisioning
            .delivered(session.id, self.general.id())
            .map_err(|_| "session expired")?;
        if bounded_send(&contact, request).await.is_err() {
            self.terminate_forward(session.id, ProvisioningFailure::DeliveryFailed)
                .await;
            return Err("credential delivery failed");
        }
        Ok(())
    }

    pub(super) async fn complete(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        let id = Self::session_id(request)?;
        let owner = self
            .general
            .state
            .provisioning
            .complete(id, self.general.id())?;
        if let Some(owner) = owner.and_then(|owner| owner.sender.upgrade()) {
            let _ = bounded_send(
                &owner,
                &CommunicationValue::new(CommunicationType::ProvisioningComplete)
                    .add_typed_default(DataType::Uuid, DataValue::Str(id.to_string())),
            )
            .await;
        }
        self.send_success(request).await
    }

    pub(super) async fn cancel(&self, request: &CommunicationValue) -> Result<(), &'static str> {
        self.general
            .state
            .provisioning
            .snapshot(Self::session_id(request)?, self.general.id())?;
        self.terminate_forward(
            Self::session_id(request)?,
            ProvisioningFailure::PeerDisconnected,
        )
        .await;
        self.send_success(request).await
    }
}
