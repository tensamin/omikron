#[tokio::test]
async fn correlated_replies_bypass_saturated_message_slots() {
    use crate::rho::{
        client_connection::ClientConnection,
        connection::{GeneralConnection, admission_engine},
        rho_connection::RhoConnection,
        test_support,
    };
    use std::{sync::Arc, time::Duration};

    let state = test_support::state();
    let (host, peer, transport) = test_support::guest("anonymous").await;
    let general = GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    let _shutdown = general.shutdown.clone();
    let iota = super::IotaConnection::from_general(general, 2).await;
    let rho = Arc::new(RhoConnection::new(iota.clone(), vec![7]).await);
    state.rho.add(rho.clone()).await;
    let (client_host, client_peer, client_transport) = test_support::guest("anonymous").await;
    let general = GeneralConnection::admit(client_transport, state, &admission_engine()).unwrap();
    let client = ClientConnection::from_general(general, 7).await;
    rho.add_client_connection(client).await;
    iota.set_rho_connection(rho).await;
    let slots = iota
        .message_slots
        .clone()
        .acquire_many_owned(super::MAX_MESSAGE_HANDLERS as u32)
        .await
        .unwrap();
    let reader = tokio::spawn(iota.clone().run());
    let exchange = tokio::spawn({
        let iota = iota.clone();
        async move {
            let sender = iota.sender.clone();
            iota.waiting_tasks
                .exchange(
                    &CommunicationValue::new(CommunicationType::Ping).with_id(41),
                    Duration::from_secs(2),
                    |response| response.is_type(CommunicationType::Pong),
                    |outbound| async move { sender.send(&outbound).await },
                )
                .await
        }
    });
    let request = tokio::time::timeout(Duration::from_secs(2), peer.receive())
        .await
        .unwrap()
        .unwrap();
    peer.sender
        .send(&CommunicationValue::new(CommunicationType::Relay).with_id(73))
        .await
        .unwrap();
    peer.sender
        .send(
            &CommunicationValue::new(CommunicationType::SyncedSettingChanged)
                .with_id(74)
                .with_receiver(7),
        )
        .await
        .unwrap();
    // Fill the bounded pending queue, then verify overload still leaves replies readable.
    let overload_id = 73 + super::MAX_MESSAGE_HANDLERS as u32;
    for id in 75..=overload_id {
        peer.sender
            .send(&CommunicationValue::new(CommunicationType::Relay).with_id(id))
            .await
            .unwrap();
    }
    peer.sender
        .send(&CommunicationValue::new(CommunicationType::Pong).with_id(request.id().unwrap()))
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), exchange)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.id(), Some(41));
    assert!(response.is_type(CommunicationType::Pong));
    let rejected = tokio::time::timeout(Duration::from_secs(2), peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(rejected.is_type(CommunicationType::ErrorInternal));
    assert_eq!(rejected.id(), Some(overload_id));

    drop(slots);
    let notification = tokio::time::timeout(Duration::from_secs(2), client_peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(notification.is_type(CommunicationType::SyncedSettingChanged));
    assert_eq!(notification.id(), Some(74));
    assert_eq!(notification.receiver(), Some(7));
    client_peer.sender.close().await;
    peer.sender.close().await;
    tokio::time::timeout(Duration::from_secs(2), reader)
        .await
        .unwrap()
        .unwrap();
    host.shutdown().await;
    client_host.shutdown().await;
}

#[tokio::test]
async fn saturated_hosted_delivery_returns_a_retryable_error() {
    use crate::rho::{
        connection::{GeneralConnection, admission_engine},
        rho_connection::RhoConnection,
        test_support,
    };
    use std::{sync::Arc, time::Duration};

    let state = test_support::state();
    let (host, peer, transport) = test_support::guest("anonymous").await;
    let general = GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    let iota = super::IotaConnection::from_general(general, 2).await;
    let rho = Arc::new(RhoConnection::new(iota.clone(), vec![7]).await);
    state.rho.add(rho.clone()).await;
    iota.set_rho_connection(rho).await;
    let _capacity = iota
        .delivery_slots
        .clone()
        .acquire_many_owned(iota.delivery_slots.available_permits() as u32)
        .await
        .unwrap();
    let request = CommunicationValue::new(CommunicationType::Relay)
        .with_id(72)
        .add_typed_default(
            DataType::Status,
            DataValue::Str("tensamin-hosted-delivery-v1".into()),
        );
    iota.handle_message_inner(request).await;
    let response = tokio::time::timeout(Duration::from_secs(2), peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(response.is_type(CommunicationType::ErrorInternal));
    assert_eq!(response.id(), Some(72));
    peer.sender.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn timed_out_forward_retains_intent_and_rejects_transport_id_retry() {
    use crate::rho::{
        connection::{GeneralConnection, admission_engine},
        test_support,
    };
    let state = test_support::state();
    let (host, peer, transport) = test_support::guest("anonymous").await;
    let general = GeneralConnection::admit(transport, state, &admission_engine()).unwrap();
    let iota = super::IotaConnection::from_general(general, 2).await;
    let request = CommunicationValue::new(CommunicationType::SyncedSettingSet)
        .with_sender(7)
        .add_typed_default(
            DataType::OpaqueMessage,
            DataValue::Bytes(b"private-setting".to_vec()),
        );
    let task = tokio::spawn({
        let iota = iota.clone();
        let request = request.clone();
        async move {
            iota.await_response(&request, Some(std::time::Duration::from_millis(50)))
                .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(task.await.unwrap().is_err());
    let journal = crate::omega::MutationJournal::open(&iota.mutation_journal_path).unwrap();
    assert_eq!(journal.unresolved().unwrap(), 1);
    let retry = iota
        .clone()
        .await_response(
            &request.with_id(123),
            Some(std::time::Duration::from_millis(50)),
        )
        .await;
    assert!(retry.unwrap_err().contains("uncertain outcome"));
    assert_eq!(journal.unresolved().unwrap(), 1);
    drop(journal);
    std::fs::remove_file(&iota.mutation_journal_path).unwrap();
    peer.sender.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn receipt_page_response_is_correlated_and_rejects_assignment_aba() {
    use crate::rho::{
        connection::{GeneralConnection, admission_engine},
        rho_connection::RhoConnection,
        test_support,
    };
    use mtp::codec::{CommunicationType, CommunicationValue};
    use std::{sync::Arc, time::Duration};

    let state = test_support::state();
    let (host, peer, transport) = test_support::guest("anonymous").await;
    let general = GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    let iota = super::IotaConnection::from_general(general, 2).await;
    let rho = Arc::new(RhoConnection::new(iota.clone(), vec![7]).await);
    state.rho.add(rho.clone()).await;
    let mut bytes = CommunicationValue::new(CommunicationType::Success)
        .with_id(99)
        .with_sender(7)
        .to_bytes()
        .unwrap();
    bytes[4..6].copy_from_slice(&225u16.to_be_bytes());
    let page = CommunicationValue::from_bytes(&bytes).unwrap();
    for reassign in [false, true] {
        let task = tokio::spawn({
            let rho = rho.clone();
            let page = page.clone();
            async move { rho.await_peer_control(&page).await }
        });
        let outbound = tokio::time::timeout(Duration::from_secs(2), peer.receive())
            .await
            .unwrap()
            .unwrap();
        if reassign {
            state.rho.invalidate_user(7).await;
            state.rho.bind_user_to_iota(7, 2).await.unwrap();
        }
        assert!(
            iota.waiting_tasks
                .complete(outbound.id().unwrap(), outbound)
        );
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        if reassign {
            assert!(result.unwrap_err().contains("route changed"));
        } else {
            assert_eq!(result.unwrap().id(), Some(99));
        }
    }
    peer.sender.close().await;
    host.shutdown().await;
}
use super::{contact_snapshot, is_iota_omega_management_operation, registration_request};
use crate::util::data_type_id;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};

#[tokio::test]
async fn password_lost_ack_uses_protected_status_and_resumes_after_reconnect() {
    use crate::{
        app_protection::*,
        rho::{
            connection::{GeneralConnection, admission_engine},
            test_support,
        },
    };
    use mtp::{
        codec::ProtectedMessageBuilder,
        crypto::{DualSigner, Keyring},
    };
    use std::{
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    let account = Keyring::generate();
    let node = Keyring::generate();
    let build = |kind,
                 key: &Keyring,
                 recipient: &Keyring,
                 signer_id,
                 recipient_id,
                 signature,
                 encryption,
                 nonce| {
        let signer = DualSigner::new(
            &key.sig_cl_secret_key,
            &key.sig_pq_secret_key,
            &key.sig_pq_public_key,
        )
        .unwrap();
        ProtectedMessageBuilder::new(
            kind,
            DataValue::Container(Vec::new()),
            signer_id,
            recipient_id,
            &signer,
            purpose(signature),
            purpose(encryption),
        )
        .message_id(nonce)
        .created_at(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        )
        .recipients(vec![recipient.public_key_bundle()])
        .frame_id(99)
        .build()
        .unwrap()
    };
    let state = test_support::state();
    let (host, peer, transport) = test_support::authenticated_with_key("iota", &node).await;
    let general = GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    let iota = super::IotaConnection::from_general(general, 42).await;
    let rho = Arc::new(crate::rho::rho_connection::RhoConnection::new(iota.clone(), vec![7]).await);
    state.rho.add(rho.clone()).await;
    let original_generation = state.rho.user_route_generation(7, &rho).unwrap();
    for (index, kind) in [
        CommunicationType::PasswordEnrollmentFinish,
        CommunicationType::PasswordEnrollmentDisable,
    ]
    .into_iter()
    .enumerate()
    {
        let original = build(
            kind,
            &account,
            &node,
            7,
            42,
            PASSWORD_MANAGEMENT_SIGNATURE,
            PASSWORD_MANAGEMENT_ENCRYPTION,
            index as u128 + 1,
        )
        .with_sender(7);
        let task = tokio::spawn({
            let iota = iota.clone();
            let original = original.clone();
            async move {
                iota.await_response(&original, Some(Duration::from_millis(100)))
                    .await
            }
        });
        let outbound = tokio::time::timeout(Duration::from_secs(2), peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(outbound.is_type(kind));
        // The mutation's acknowledgment is lost. Only a read-only proof wrapper
        // may follow, never a second enrollment finish or disable command.
        let query = tokio::time::timeout(Duration::from_secs(2), peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(query.is_type(CommunicationType::PasswordEnrollmentStatus));
        assert_eq!(
            query
                .get_data(DataType::SecurePayload)
                .unwrap()
                .as_bytes()
                .unwrap(),
            original.clone().without_id().to_bytes().unwrap()
        );
        let response = if index == 0 {
            build(
                CommunicationType::PasswordEnrollmentStatus,
                &node,
                &account,
                42,
                7,
                PASSWORD_RESPONSE_SIGNATURE,
                PASSWORD_RESPONSE_ENCRYPTION,
                100,
            )
        } else {
            CommunicationValue::new(CommunicationType::ErrorInternal)
        }
        .with_id(query.id().unwrap());
        assert!(iota.waiting_tasks.complete(query.id().unwrap(), response));
        let result = task.await.unwrap();
        if index == 0 {
            assert_eq!(result.unwrap().id(), Some(99));
        } else {
            assert!(result.is_err());
        }
    }
    let journal = crate::omega::MutationJournal::open(&iota.mutation_journal_path).unwrap();
    assert_eq!(journal.unresolved().unwrap(), 1);
    assert_eq!(journal.password_pending("iota:42").unwrap().len(), 1);
    state.rho.bind_user_to_iota(99, 42).await.unwrap();
    assert_ne!(
        state.rho.user_route_generation(7, &rho).unwrap(),
        original_generation
    );
    let (new_host, new_peer, transport) = test_support::authenticated_with_key("iota", &node).await;
    let general = GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
    let replacement = super::IotaConnection::from_general(general, 42).await;
    // The transport registry retains a Weak, so get_mut cannot adjust this fixture.
    let mut replacement = Arc::try_unwrap(replacement)
        .unwrap_or_else(|_| panic!("replacement already has another strong owner"));
    replacement.mutation_journal_path = iota.mutation_journal_path.clone();
    let replacement = Arc::new(replacement);
    state.rho.register_revocation_transport(&replacement);
    let replacement_rho = Arc::new(
        crate::rho::rho_connection::RhoConnection::new(replacement.clone(), vec![7, 99]).await,
    );
    state.rho.add(replacement_rho.clone()).await;
    assert_ne!(
        state
            .rho
            .user_route_generation(7, &replacement_rho)
            .unwrap(),
        original_generation
    );
    assert_eq!(replacement.node_id, iota.node_id);
    let recovery = tokio::spawn({
        let replacement = replacement.clone();
        async move { replacement.reconcile_password_mutations().await }
    });
    let query = tokio::time::timeout(Duration::from_secs(2), new_peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert!(query.is_type(CommunicationType::PasswordEnrollmentStatus));
    let response = build(
        CommunicationType::PasswordEnrollmentStatus,
        &node,
        &account,
        42,
        7,
        PASSWORD_RESPONSE_SIGNATURE,
        PASSWORD_RESPONSE_ENCRYPTION,
        101,
    )
    .with_id(query.id().unwrap());
    assert!(
        replacement
            .waiting_tasks
            .complete(query.id().unwrap(), response)
    );
    recovery.await.unwrap().unwrap();
    assert_eq!(journal.unresolved().unwrap(), 0);
    assert!(journal.password_pending("iota:42").unwrap().is_empty());
    drop(journal);
    let _ = std::fs::remove_file(&iota.mutation_journal_path);
    peer.sender.close().await;
    new_peer.sender.close().await;
    host.shutdown().await;
    new_host.shutdown().await;
}

#[tokio::test]
async fn password_forwards_accept_only_their_exact_success_contract() {
    use crate::rho::{
        connection::{GeneralConnection, admission_engine},
        test_support,
    };
    use CommunicationType::*;
    use std::time::Duration;

    let (host, peer, transport) = test_support::guest("anonymous").await;
    let general =
        GeneralConnection::admit(transport, test_support::state(), &admission_engine()).unwrap();
    let iota = super::IotaConnection::from_general(general, 2).await;
    for (request, success) in [
        (PasswordEnrollmentStart, PasswordEnrollmentResponse),
        (PasswordEnrollmentStatus, PasswordEnrollmentStatus),
        (PasswordProvisioningStart, PasswordProvisioningResponse),
        (PasswordProvisioningFinish, ProvisioningCredential),
    ] {
        for response_type in [
            success,
            ErrorInvalidData,
            ErrorNotAuthenticated,
            ErrorInternal,
        ] {
            let frame = CommunicationValue::new(request)
                .with_id(99)
                .add_typed_default(
                    DataType::Uuid,
                    DataValue::Str(uuid::Uuid::new_v4().to_string()),
                );
            let task = tokio::spawn({
                let iota = iota.clone();
                async move {
                    iota.await_response(&frame, Some(Duration::from_secs(2)))
                        .await
                }
            });
            let outbound = tokio::time::timeout(Duration::from_secs(2), peer.receive())
                .await
                .unwrap()
                .unwrap();
            let id = outbound.id().unwrap();
            assert!(
                !iota
                    .waiting_tasks
                    .complete(id + 1, CommunicationValue::new(response_type))
            );
            assert!(
                !iota
                    .waiting_tasks
                    .complete(id, CommunicationValue::new(Success))
            );
            assert!(
                !iota
                    .waiting_tasks
                    .complete(id, CommunicationValue::new(Ping))
            );
            assert!(
                iota.waiting_tasks
                    .complete(id, CommunicationValue::new(response_type).with_id(id))
            );
            let response = task.await.unwrap().unwrap();
            assert!(response.is_type(response_type));
            assert_eq!(response.id(), Some(99));
        }
    }
    let _ = std::fs::remove_file(&iota.mutation_journal_path);
    peer.sender.close().await;
    host.shutdown().await;
}

fn snapshot(user_ids: DataValue) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::AccountStateSnapshot)
        .with_receiver(7)
        .add_typed_default(DataType::SessionId, DataValue::SignedNumber(11))
        .add_typed_default(DataType::UserIds, user_ids)
}

#[test]
fn response_id_allocator_skips_collisions_and_zero() {
    let waiting = tau::ResponseCorrelator::new();
    let occupied = waiting.reserve(|_| true).expect("registered");
    let id = waiting.reserve(|_| true).expect("allocated id");

    assert_ne!(id.id(), 0);
    assert_ne!(id.id(), occupied.id());
    assert!(waiting.complete(
        occupied.id(),
        CommunicationValue::new(CommunicationType::Success)
    ));
    assert!(waiting.complete(id.id(), CommunicationValue::new(CommunicationType::Success)));
    assert!(waiting.is_empty());
}

#[test]
fn clearing_waiters_on_disconnect_closes_response_channels() {
    let waiting = tau::ResponseCorrelator::new();
    let (sender, receiver) = std::sync::mpsc::channel::<CommunicationValue>();
    let _pending = waiting
        .reserve(move |response| {
            sender.send(response).unwrap();
            true
        })
        .expect("internal id");
    waiting.clear();
    assert!(receiver.recv().is_err());
}

#[test]
fn same_external_ids_have_distinct_internal_correlations() {
    let waiting = tau::ResponseCorrelator::new();
    let external_id = 42;
    let (first_tx, first_rx) = std::sync::mpsc::channel();
    let (second_tx, second_rx) = std::sync::mpsc::channel();
    let first = waiting
        .reserve(move |response| {
            first_tx.send(response.with_id(external_id)).unwrap();
            true
        })
        .expect("first internal id");
    let second = waiting
        .reserve(move |response| {
            second_tx.send(response.with_id(external_id)).unwrap();
            true
        })
        .expect("second internal id");
    assert_ne!(first.id(), second.id());
    assert!(waiting.complete(
        second.id(),
        CommunicationValue::new(CommunicationType::Success).with_id(second.id())
    ));
    assert!(waiting.complete(
        first.id(),
        CommunicationValue::new(CommunicationType::ErrorInvalidData).with_id(first.id())
    ));
    let first_response = first_rx.recv().unwrap();
    let second_response = second_rx.recv().unwrap();
    assert_eq!(first_response.id(), Some(42));
    assert!(first_response.is_type(CommunicationType::ErrorInvalidData));
    assert_eq!(second_response.id(), Some(42));
    assert!(second_response.is_type(CommunicationType::Success));
}

#[test]
fn contact_snapshot_deduplicates_flat_and_typed_ids() {
    let user_id_type = data_type_id(DataType::UserId, &TypeMap::latest());
    let parsed = contact_snapshot(&snapshot(DataValue::Array(vec![
        DataValue::SignedNumber(20),
        DataValue::Container(vec![(user_id_type, DataValue::SignedNumber(21))]),
        DataValue::SignedNumber(20),
    ])))
    .unwrap();

    assert_eq!(parsed, (7, 0, vec![20, 21]));
}

#[test]
fn contact_snapshot_accepts_empty_contact_sets() {
    assert_eq!(
        contact_snapshot(&snapshot(DataValue::Array(Vec::new()))),
        Some((7, 0, Vec::new()))
    );
}

#[test]
fn contact_snapshot_rejects_malformed_contact_sets() {
    assert_eq!(
        contact_snapshot(&snapshot(DataValue::Array(vec![DataValue::Str(
            "bad".into(),
        )]))),
        None
    );
}

#[test]
fn authenticated_iota_forwards_all_invitation_management_operations() {
    for operation in [
        CommunicationType::CreateUserInvitation,
        CommunicationType::ListUserInvitations,
        CommunicationType::RevokeUserInvitation,
    ] {
        assert!(is_iota_omega_management_operation(
            &CommunicationValue::new(operation)
        ));
    }
}

#[test]
fn registration_retry_keeps_operation_token_when_transport_id_changes() {
    let request = registration_request(
        &CommunicationValue::new(CommunicationType::GetRegister).with_id(42),
        7,
    );
    let first = request.clone().with_id(1001);
    let second = request.with_id(1002);

    assert_ne!(first.id(), second.id());
    assert_eq!(
        first.get_data(DataType::RegisterId),
        second.get_data(DataType::RegisterId)
    );
}
