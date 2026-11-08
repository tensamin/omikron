use super::{
    authenticated_peer_control_request, is_client_omega_operation, is_password_receipt_query,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

mod chat_reads;
mod password_receipts;

#[test]
fn password_receipt_queries_are_bounded_and_cannot_be_used_as_plaintext_mutations() {
    let query = CommunicationValue::new(CommunicationType::PasswordEnrollmentStatus)
        .add_typed_default(DataType::SecurePayload, DataValue::Bytes(vec![1]))
        .add_typed_default(DataType::Version, DataValue::Str("1.1".into()));
    assert!(is_password_receipt_query(&query));
    for kind in [
        CommunicationType::PasswordEnrollmentStart,
        CommunicationType::PasswordEnrollmentFinish,
        CommunicationType::PasswordEnrollmentDisable,
    ] {
        let mutation = CommunicationValue::new(kind)
            .add_typed_default(DataType::SecurePayload, DataValue::Bytes(vec![1]))
            .add_typed_default(DataType::Version, DataValue::Str("1.1".into()));
        assert!(!is_password_receipt_query(&mutation));
    }
    for payload in [
        DataValue::Bytes(vec![]),
        DataValue::Bytes(vec![0; 512 * 1024 + 1]),
        DataValue::Str("not bytes".into()),
    ] {
        assert!(!is_password_receipt_query(
            &CommunicationValue::new(CommunicationType::PasswordEnrollmentStatus)
                .add_typed_default(DataType::SecurePayload, payload)
                .add_typed_default(DataType::Version, DataValue::Str("1.1".into()))
        ));
    }
    for version in ["", "01.1", "1.01", "1", "1.1 "] {
        assert!(!is_password_receipt_query(
            &CommunicationValue::new(CommunicationType::PasswordEnrollmentStatus)
                .add_typed_default(DataType::SecurePayload, DataValue::Bytes(vec![1]))
                .add_typed_default(DataType::Version, DataValue::Str(version.into()))
        ));
    }
}

#[test]
fn managed_call_allowlist_is_local_and_excludes_results_and_direct_revocation() {
    use crate::rho::relay_router::{MessageSecurityClass, message_security_class};
    for operation in [
        CommunicationType::CallCommand,
        CommunicationType::CallSnapshotGet,
        CommunicationType::CallJoinAuthorize,
        CommunicationType::CallKeyEnvelopeStage,
        CommunicationType::CallKeyEnvelopeGet,
        CommunicationType::CallKeyEnvelopeActivate,
    ] {
        assert_eq!(
            message_security_class(&CommunicationValue::new(operation)),
            MessageSecurityClass::AuthenticatedLocalRequest
        );
    }
    for operation in [
        CommunicationType::CallCommandResult,
        CommunicationType::CallSnapshot,
        CommunicationType::CallStateChanged,
        CommunicationType::CallJoinGrant,
        CommunicationType::CallKeyEpochChanged,
        CommunicationType::CallKeyEnvelopeRevoke,
    ] {
        assert_eq!(
            message_security_class(&CommunicationValue::new(operation)),
            MessageSecurityClass::Unsupported
        );
    }
}

#[tokio::test]
async fn managed_commands_cross_authenticated_mtp_dispatch_with_the_session_actor() {
    use crate::{
        calls::{
            call_manager::CallManager,
            call_util::LiveKitService,
            repository::{SqliteCallRepository, tests::ContractAdapters},
        },
        rho::{
            connection::{GeneralConnection, admission_engine},
            test_support,
        },
    };
    use std::{sync::Arc, time::Duration};
    use tau::calls::*;

    async fn exchange(
        peer: &mtp::client::MTPConnection,
        general: &Arc<GeneralConnection>,
        client: &Arc<super::ClientConnection>,
        request: CommunicationValue,
    ) -> serde_json::Value {
        let id = request.id();
        tokio::time::timeout(Duration::from_secs(3), async {
            peer.sender.send(&request).await.unwrap();
            let incoming = general.receiver.receive().await.unwrap();
            client.clone().handle_message(incoming).await;
            let response = peer.receive().await.unwrap();
            assert_eq!(response.id(), id);
            let payload = response
                .get_data(DataType::CallPayload)
                .and_then(|v| v.as_bytes())
                .expect("managed response must use the typed call protocol");
            serde_json::from_slice(&payload).unwrap()
        })
        .await
        .unwrap()
    }

    let mut state = test_support::state();
    let repository =
        Arc::new(SqliteCallRepository::open(std::path::Path::new(":memory:")).unwrap());
    let mut call = crate::calls::repository::tests::call();
    call.id.owner_authority =
        CallAuthority::new(format!("omikron-key:{}", "b".repeat(64))).unwrap();
    let principal = CallPrincipal {
        authority: call.owner.authority.clone(),
        user_id: 42,
    };
    call.members.push(CallMember {
        principal: principal.clone(),
        role: CallRole::Member,
        authorized: true,
        approved: true,
        guest: false,
        restrictions: Restrictions::default(),
        overrides: PermissionOverrides::default(),
        timeout_until_ms: None,
    });
    repository.insert(call.clone()).await.unwrap();
    let adapters = Arc::new(ContractAdapters);
    let engine = Arc::new(CallEngine::new(
        repository.clone(),
        adapters.clone(),
        adapters.clone(),
        adapters,
        Arc::new(SystemCallClock),
    ));
    let manager = Arc::new(
        CallManager::new_with_owner(Arc::new(LiveKitService::new(None)), 1).with_runtime(
            repository.clone(),
            engine,
            call.id.owner_authority.clone(),
            call.owner.authority.clone(),
        ),
    );
    let owned = Arc::get_mut(&mut state).unwrap();
    owned.call_manager = manager;
    let (host, peer, transport) = test_support::authenticated("client").await;
    let general = GeneralConnection::admit(transport, state, &admission_engine()).unwrap();
    let client = super::ClientConnection::from_general(general.clone(), 42).await;
    let target = call
        .members
        .iter()
        .find(|m| m.principal.user_id == 4)
        .unwrap()
        .principal
        .clone();
    let mut request = CallCommandRequest {
        call: call.id.clone(),
        operation_id: uuid::Uuid::new_v4(),
        expected_revision: None,
        command: CallCommand::SetMemberRestriction {
            target: target.clone(),
            restriction: MemberRestriction::Microphone,
            enabled: true,
        },
    };
    let wire = CommunicationValue::new(CommunicationType::CallCommand)
        .with_id(41)
        .with_sender(1)
        .add_typed_default(DataType::UserId, DataValue::UnsignedNumber(1))
        .add_typed_default(
            DataType::CallPayload,
            DataValue::Bytes(encode_call_command(&request).unwrap()),
        );
    let denied = exchange(&peer, &general, &client, wire).await;
    assert_eq!(denied["error"]["error"], "not_authorized");
    assert!(
        !repository
            .read(call.id.clone())
            .await
            .unwrap()
            .member(&target)
            .unwrap()
            .restrictions
            .microphone
    );

    repository
        .transact(
            AuthenticatedCallActor::from_verified_session(call.owner.clone()).unwrap(),
            CallCommandRequest {
                call: call.id.clone(),
                operation_id: uuid::Uuid::new_v4(),
                expected_revision: None,
                command: CallCommand::SetRole {
                    target: principal,
                    role: CallRole::Moderator,
                },
            },
            SystemCallClock.now_ms().unwrap(),
        )
        .await
        .unwrap();
    request.operation_id = uuid::Uuid::new_v4();
    let wire = CommunicationValue::new(CommunicationType::CallCommand)
        .with_id(42)
        .with_sender(9999)
        .add_typed_default(
            DataType::CallPayload,
            DataValue::Bytes(encode_call_command(&request).unwrap()),
        );
    let applied = exchange(&peer, &general, &client, wire.clone()).await;
    assert_eq!(applied["result"]["revision"], 2);
    assert_eq!(
        exchange(&peer, &general, &client, wire.with_id(43)).await,
        applied
    );
    assert_eq!(repository.read(call.id.clone()).await.unwrap().revision, 2);

    let lookup = serde_json::to_vec(&serde_json::json!({"version":1,"call":call.id})).unwrap();
    let snapshot = exchange(
        &peer,
        &general,
        &client,
        CommunicationValue::new(CommunicationType::CallSnapshotGet)
            .with_id(44)
            .with_sender(1)
            .add_typed_default(DataType::CallPayload, DataValue::Bytes(lookup.clone())),
    )
    .await;
    assert_eq!(snapshot["result"]["member"]["principal"]["user_id"], 42);
    assert_eq!(snapshot["result"]["member"]["role"], "moderator");
    let target_snapshot = snapshot["result"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["principal"]["user_id"] == 4)
        .unwrap();
    assert_eq!(target_snapshot["permissions"]["publish_microphone"], false);
    let grant = exchange(
        &peer,
        &general,
        &client,
        CommunicationValue::new(CommunicationType::CallJoinAuthorize)
            .with_id(45)
            .with_sender(1)
            .add_typed_default(DataType::CallPayload, DataValue::Bytes(lookup)),
    )
    .await;
    assert_eq!(grant["result"]["permissions"]["moderate"], true);
    tokio::time::timeout(Duration::from_secs(3), async {
        peer.sender
            .send(
                &CommunicationValue::new(CommunicationType::CallDisconnectUser)
                    .with_id(46)
                    .add_typed_default(DataType::CallId, DataValue::Str(call.id.id.to_string()))
                    .add_typed_default(DataType::UserId, DataValue::UnsignedNumber(4)),
            )
            .await
            .unwrap();
        client
            .clone()
            .handle_message(general.receiver.receive().await.unwrap())
            .await;
        let response = peer.receive().await.unwrap();
        assert!(response.is_type(CommunicationType::Success));
        assert_eq!(
            response
                .get_data(DataType::Description)
                .and_then(|v| v.as_str()),
            Some("pending_enforcement")
        );
        assert_eq!(
            response
                .get_data(DataType::VersionNumber)
                .and_then(|v| v.as_number()),
            Some(3)
        );
    })
    .await
    .unwrap();
    peer.sender.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn local_cleanup_outlives_notification_budget_without_omega() {
    use crate::{
        provisioning::session::{ProvisioningMethod, ProvisioningParticipant, ProvisioningRole},
        rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        },
    };
    use std::{sync::Arc, time::Duration};

    let mut state = test_support::state();
    Arc::get_mut(&mut state).unwrap().config.cleanup_timeout = Duration::from_millis(10);
    assert!(!state.omega.is_ready().await);
    let (host, peer, transport) = test_support::guest("anonymous").await;
    let general = GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    *general.session_id.write().await = 42;
    let rho = Arc::new(
        RhoConnection::new(
            IotaConnection::from_general(general.clone(), 2).await,
            vec![7],
        )
        .await,
    );
    state.rho.add(rho.clone()).await;
    *general.rho_connection.write().await = Some(rho.clone());
    let client = super::ClientConnection::from_general(general, 7).await;
    rho.add_client_connection(client.clone()).await;
    state
        .provisioning
        .create(
            ProvisioningMethod::QrOwnerCreated,
            ProvisioningParticipant {
                id: client.session_id,
                role: ProvisioningRole::Owner,
                temporary_public_key: mtp::crypto::Keyring::generate().public_key_bundle(),
                sender: Arc::downgrade(&client.sender),
            },
        )
        .unwrap();

    let mutation = state.rho.mutation_guard().await;
    let cleanup = tokio::spawn(client.clone().handle_close());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!cleanup.is_finished());
    assert!(state.provisioning.for_participant(42).is_ok());
    drop(mutation);
    tokio::time::timeout(Duration::from_secs(2), cleanup)
        .await
        .unwrap()
        .unwrap();
    assert!(rho.get_client_connection(7, 42).await.is_none());
    assert!(state.provisioning.for_participant(42).is_err());
    // Disconnecting a device must preserve its account's Iota assignment.
    assert!(state.rho.get_for_user(7).await.is_some());
    peer.sender.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn disconnected_client_bounds_drain_and_preserves_pending_mutations() {
    use crate::rho::{
        connection::{GeneralConnection, admission_engine},
        test_support,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    for finish_during_drain in [false, true] {
        let state = test_support::state();
        let (host, peer, accepted) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(accepted, state.clone(), &admission_engine()).unwrap();
        let connection = super::ClientConnection::from_general(general.clone(), 7).await;
        let writes = Arc::new(AtomicUsize::new(0));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (finish, blocked) = tokio::sync::oneshot::channel();
        let (alive, mut cancelled) = tokio::sync::oneshot::channel::<()>();
        let (completed, completion) = tokio::sync::oneshot::channel();
        connection
            .tasks
            .spawn({
                let writes = writes.clone();
                async move {
                    let _alive = alive;
                    started.send(()).unwrap();
                    let _ = blocked.await;
                    writes.fetch_add(1, Ordering::SeqCst);
                    completed.send(()).unwrap();
                }
            })
            .unwrap();
        let global = state
            .rho_connection_limits
            .all
            .clone()
            .try_acquire_owned()
            .unwrap();
        let guest = state
            .rho_connection_limits
            .anonymous
            .clone()
            .try_acquire_owned()
            .unwrap();
        let handlers = connection.tasks.clone();
        let task = tokio::spawn(async move {
            let _permits = (global, guest);
            connection.run().await;
        });
        ready.await.unwrap();
        peer.sender.close().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!task.is_finished());
        assert_eq!(state.rho_connection_limits.all.available_permits(), 1);
        assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 0);
        let pending_mutation = if finish_during_drain {
            finish.send(()).unwrap();
            None
        } else {
            handlers.drain_expired.notified().await;
            Some(finish)
        };
        tokio::time::timeout(Duration::from_secs(4), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.rho_connection_limits.all.available_permits(), 2);
        assert_eq!(state.rho_connection_limits.anonymous.available_permits(), 1);
        if let Some(finish) = pending_mutation {
            assert!(matches!(
                cancelled.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(writes.load(Ordering::SeqCst), 0);
            finish.send(()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(4), completion)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        host.shutdown().await;
    }
}

#[test]
fn peer_control_requests_replace_a_client_supplied_sender() {
    let request = CommunicationValue::new(CommunicationType::SyncedSettingSet)
        .with_sender(99)
        .add_typed_default(DataType::UserId, DataValue::SignedNumber(99));

    let authenticated = authenticated_peer_control_request(&request, 7);

    assert_eq!(authenticated.sender(), Some(7));
    assert_eq!(
        authenticated
            .get_data(DataType::UserId)
            .and_then(|value| value.as_number()),
        Some(99)
    );
}

#[test]
fn native_forwarding_keeps_sealed_frame_and_separates_authenticated_actor() {
    use mtp::{
        codec::relay::SealedRelayBuilder,
        crypto::{Ed25519Signer, Keyring},
    };
    let (signer, _, _) = Ed25519Signer::generate();
    let node = Keyring::generate();
    let original = SealedRelayBuilder::new(
        CommunicationType::AddConversation,
        DataValue::Container(vec![]),
        99,
        22,
        1,
        &signer,
    )
    .message_id(1_u128)
    .created_at(1)
    .metadata_recipients(vec![node.public_key_bundle()])
    .content_recipients(vec![node.public_key_bundle()])
    .build()
    .unwrap()
    .with_id(7);
    let request = super::authenticated_native_relay_request(&original, 11, 4, 5).unwrap();
    assert_eq!(request.sender(), Some(11));
    assert_eq!(
        request.get_data(DataType::SessionId),
        Some(&DataValue::UnsignedNumber(4))
    );
    assert_eq!(
        request.get_data(DataType::VersionNumber),
        Some(&DataValue::UnsignedNumber(5))
    );
    assert_eq!(
        request.get_data(DataType::SecurePayload),
        Some(&DataValue::Bytes(original.to_bytes().unwrap()))
    );
    assert!(super::authenticated_native_relay_request(&original, 11, 4, 0).is_err());
    let legacy = CommunicationValue::new(CommunicationType::Relay)
        .with_id(7)
        .add_typed_default(
            DataType::SecurePayload,
            DataValue::Bytes(br#"{"version":2}"#.to_vec()),
        );
    assert!(super::authenticated_native_relay_request(&legacy, 11, 4, 5).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_timeout_or_unbound_reply_cannot_release_session_before_revocation_receipt() {
    use crate::rho::{
        client_connection::ClientConnection,
        connection::{GeneralConnection, admission_engine},
        iota_connection::IotaConnection,
        rho_connection::RhoConnection,
        test_support,
    };
    use mtp::{
        codec::relay::SealedRelayBuilder,
        crypto::{Ed25519Signer, Keyring},
    };
    use std::{sync::Arc, time::Duration};
    for unbound_reply in [true, false] {
        let state = test_support::state();
        let (iota_host, iota_peer, iota_transport) = test_support::guest("anonymous").await;
        let iota_general =
            GeneralConnection::admit(iota_transport, state.clone(), &admission_engine()).unwrap();
        let iota = IotaConnection::from_general(iota_general.clone(), 2).await;
        let rho = Arc::new(RhoConnection::new(iota.clone(), vec![7]).await);
        state.rho.add(rho.clone()).await;
        let (client_host, client_peer, client_transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(client_transport, state.clone(), &admission_engine()).unwrap();
        *general.session_id.write().await = 42;
        let client = ClientConnection::from_general(general.clone(), 7).await;
        rho.add_client_connection(client.clone()).await;
        *client.rho_connection.write().await = Some(rho.clone());
        let (signer, _, _) = Ed25519Signer::generate();
        let node = Keyring::generate();
        let native = SealedRelayBuilder::new(
            CommunicationType::SetChatSecret,
            DataValue::Container(vec![]),
            7,
            22,
            1,
            &signer,
        )
        .message_id(5_u128)
        .created_at(1)
        .metadata_recipients(vec![node.public_key_bundle()])
        .content_recipients(vec![node.public_key_bundle()])
        .build()
        .unwrap()
        .with_id(73);
        client.clone().handle_message(native).await;
        let forwarded = tokio::time::timeout(Duration::from_secs(2), iota_peer.receive())
            .await
            .unwrap()
            .unwrap();
        let nonce = forwarded
            .get_data(DataType::Uuid)
            .and_then(DataValue::as_str)
            .unwrap()
            .to_owned();
        // An unbound response has the same uncertainty as a timeout. It must
        // trigger explicit revocation rather than release either authorization lock.
        if unbound_reply {
            assert!(
                iota.waiting_tasks.complete(
                    forwarded.id().unwrap(),
                    CommunicationValue::new(CommunicationType::ErrorInternal)
                        .with_id(forwarded.id().unwrap())
                )
            );
        }
        let revoke = tokio::time::timeout(Duration::from_secs(25), iota_peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            revoke
                .get_data(DataType::Status)
                .and_then(DataValue::as_str),
            Some("tensamin-hosted-native-revoke-v1")
        );
        assert_eq!(
            revoke.get_data(DataType::Uuid).and_then(DataValue::as_str),
            Some(nonce.as_str())
        );
        let closing = tokio::spawn({
            let client = client.clone();
            async move {
                client.close().await;
            }
        });
        let reassignment = tokio::spawn({
            let state = state.clone();
            async move {
                state.rho.invalidate_user(7).await;
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(1), state.rho.bind_user_to_iota(8, 2))
                .await
                .unwrap()
                .is_some()
        );
        assert!(!closing.is_finished());
        assert!(!reassignment.is_finished());
        let receipt = CommunicationValue::new(CommunicationType::Success)
            .with_id(revoke.id().unwrap())
            .add_typed_default(DataType::Status, DataValue::Str("revoked".into()))
            .add_typed_default(DataType::Uuid, DataValue::Str(nonce));
        assert!(iota.waiting_tasks.complete(revoke.id().unwrap(), receipt));
        if let Ok(response) = tokio::time::timeout(Duration::from_secs(2), client_peer.receive())
            .await
            .unwrap()
        {
            assert!(response.is_type(CommunicationType::ErrorInternal));
            assert_eq!(response.id(), Some(73));
        }
        tokio::time::timeout(Duration::from_secs(2), closing)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), reassignment)
            .await
            .unwrap()
            .unwrap();
        iota_peer.sender.close().await;
        client_peer.sender.close().await;
        iota_host.shutdown().await;
        client_host.shutdown().await;
    }
}

#[test]
fn normal_clients_cannot_manage_invitations() {
    for operation in [
        CommunicationType::CreateUserInvitation,
        CommunicationType::ListUserInvitations,
        CommunicationType::RevokeUserInvitation,
    ] {
        assert!(!is_client_omega_operation(&CommunicationValue::new(
            operation
        )));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_revocation_uses_authenticated_replacement_before_route_publication() {
    use crate::rho::{
        client_connection::ClientConnection,
        connection::{GeneralConnection, admission_engine},
        iota_connection::IotaConnection,
        rho_connection::RhoConnection,
        test_support,
    };
    use mtp::{
        codec::relay::SealedRelayBuilder,
        crypto::{Ed25519Signer, Keyring},
    };
    use std::{sync::Arc, time::Duration};
    let state = test_support::state();
    let node_key = Keyring::generate();
    let (old_host, old_peer, transport) =
        test_support::authenticated_with_key("iota", &node_key).await;
    let old_general =
        GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    let old = IotaConnection::from_general(old_general.clone(), 2).await;
    let rho = Arc::new(RhoConnection::new(old.clone(), vec![7]).await);
    state.rho.add(rho.clone()).await;
    let (client_host, client_peer, transport) = test_support::guest("anonymous").await;
    let general = GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    *general.session_id.write().await = 42;
    let client = ClientConnection::from_general(general.clone(), 7).await;
    rho.add_client_connection(client.clone()).await;
    *client.rho_connection.write().await = Some(rho.clone());
    let (signer, _, _) = Ed25519Signer::generate();
    let native = SealedRelayBuilder::new(
        CommunicationType::SetChatSecret,
        DataValue::Container(vec![]),
        7,
        22,
        1,
        &signer,
    )
    .message_id(6_u128)
    .created_at(1)
    .metadata_recipients(vec![node_key.public_key_bundle()])
    .content_recipients(vec![node_key.public_key_bundle()])
    .build()
    .unwrap()
    .with_id(74);
    client.clone().handle_message(native).await;
    let request = tokio::time::timeout(Duration::from_secs(2), old_peer.receive())
        .await
        .unwrap()
        .unwrap();
    let nonce = request
        .get_data(DataType::Uuid)
        .and_then(DataValue::as_str)
        .unwrap()
        .to_owned();
    // The old authenticated MTP transport is genuinely gone, not just removed
    // from a routing map. Cancellation must not retry only this closed sender.
    old_peer.sender.close().await;
    let closing = tokio::spawn({
        let client = client.clone();
        async move {
            client.close().await;
        }
    });
    let (new_host, new_peer, transport) =
        test_support::authenticated_with_key("iota", &node_key).await;
    let new_general =
        GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    let replacement = IotaConnection::from_general(new_general.clone(), 2).await;
    assert_eq!(replacement.node_id, old.node_id);
    let new_rho = Arc::new(RhoConnection::new(replacement.clone(), vec![7]).await);
    let publication = tokio::spawn({
        let replacement = replacement.clone();
        async move {
            replacement.publish_and_run(new_rho).await;
        }
    });
    // Waiting for user7's remote cancellation must not monopolize the global
    // routing lock. A different user's assignment still publishes now.
    assert!(
        tokio::time::timeout(Duration::from_secs(1), state.rho.bind_user_to_iota(8, 2))
            .await
            .unwrap()
            .is_some()
    );
    let revoke = tokio::time::timeout(Duration::from_secs(15), new_peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        revoke.get_data(DataType::Uuid).and_then(DataValue::as_str),
        Some(nonce.as_str())
    );
    assert_eq!(
        revoke
            .get_data(DataType::Status)
            .and_then(DataValue::as_str),
        Some("tensamin-hosted-native-revoke-v1")
    );
    assert!(!closing.is_finished());
    assert!(!publication.is_finished());
    assert!(Arc::ptr_eq(&state.rho.get_by_iota(2).await.unwrap(), &rho));
    let receipt = CommunicationValue::new(CommunicationType::Success)
        .with_id(revoke.id().unwrap())
        .add_typed_default(DataType::Status, DataValue::Str("revoked".into()))
        .add_typed_default(DataType::Uuid, DataValue::Str(nonce));
    new_peer.sender.send(&receipt).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), closing)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.rho.is_current_rho(&rho) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    new_peer.sender.close().await;
    tokio::time::timeout(Duration::from_secs(2), publication)
        .await
        .unwrap()
        .unwrap();
    client_peer.sender.close().await;
    old_host.shutdown().await;
    new_host.shutdown().await;
    client_host.shutdown().await;
}
