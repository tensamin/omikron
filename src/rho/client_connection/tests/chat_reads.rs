use crate::rho::{
    client_connection::ClientConnection,
    connection::{GeneralConnection, admission_engine},
    iota_connection::IotaConnection,
    rho_connection::RhoConnection,
    test_support,
};
use mtp::codec::{
    CommunicationType as C, CommunicationValue as Frame, DataType as D, DataValue as V,
};
use std::{sync::Arc, time::Duration};

/// Both hops use authenticated MTP transports and production dispatch. The Iota
/// endpoint is controlled here to inject miscorrelation and ownership failures.
#[tokio::test]
async fn authenticated_chat_reads_bind_actor_route_and_response_owner() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let state = test_support::state();
        let (iota_host, iota_peer, transport) = test_support::authenticated("iota").await;
        let iota_general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let iota = IotaConnection::from_general(iota_general.clone(), 2).await;
        let rho = Arc::new(RhoConnection::new(iota.clone(), vec![42]).await);
        state.rho.add(rho.clone()).await;
        iota.set_rho_connection(rho.clone()).await;
        let reader = tokio::spawn(iota.clone().run());
        let (client_host, client_peer, transport) = test_support::authenticated("client").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let client = ClientConnection::from_general(general.clone(), 42).await;
        rho.add_client_connection(client.clone()).await;
        *client.rho_connection.write().await = Some(rho.clone());
        assert!(rho.owns_client(&client));
        assert!(client.get_rho_connection().await.is_some());

        for (index, kind) in [
            C::UserResolve,
            C::GetChats,
            C::GetCommunities,
            C::GetChatSecret,
        ]
        .into_iter()
        .enumerate()
        {
            let id = 100 + index as u32;
            let request = Frame::new(kind).with_id(id).with_sender(999);
            client_peer.sender.send(&request).await.unwrap();
            client
                .clone()
                .handle_message(general.receiver.receive().await.unwrap())
                .await;
            let forwarded = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                frame = iota_peer.receive() => frame.unwrap(),
                frame = client_peer.receive() => panic!("{kind:?} was not forwarded: {frame:?}"),
            }
        }).await.unwrap();
            assert_eq!(
                forwarded.sender(),
                Some(42),
                "caller cannot select another account"
            );
            assert_ne!(
                forwarded.id(),
                Some(id),
                "the upstream correlation namespace is independent"
            );
            let response = Frame::new(C::ErrorInvalidData).with_id(forwarded.id().unwrap());
            iota_peer.sender.send(&response).await.unwrap();
            let response = tokio::time::timeout(Duration::from_secs(3), client_peer.receive())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.id(), Some(id));
            assert!(response.is_type(C::ErrorInvalidData));
        }

        let owner =
            tau::relay_protocol::Principal::new(format!("omega-key:{}", "1".repeat(64)), 42)
                .unwrap();
        let partner =
            tau::relay_protocol::Principal::new(format!("omega-key:{}", "2".repeat(64)), 42)
                .unwrap();
        let canonical = serde_json::to_string(&owner).unwrap();
        let pair = tau::relay_protocol::ConversationPair::new(owner.clone(), partner).unwrap();
        let secret_request = tau::chat_secret::ReadRequest {
            owner,
            secret_id: tau::relay_protocol::chat_secret_id(&pair.chat_id().unwrap()),
            pair,
            epoch: Some(1.try_into().unwrap()),
        };
        let key = mtp::crypto::Keyring::generate().public_key_bundle();
        let public_key = key.try_to_base64().unwrap();
        let fingerprint = mtp::crypto::sha256(&key.try_as_bytes().unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for (index, kind) in [
            C::UserResolve,
            C::GetChats,
            C::GetCommunities,
            C::GetChatSecret,
        ]
        .into_iter()
        .enumerate()
        {
            let id = 300 + index as u32;
            let request = match kind {
                C::UserResolve => Frame::new(kind)
                    .with_id(id)
                    .add_typed_default(D::UserAddress, V::Str(canonical.clone())),
                C::GetChatSecret => secret_request
                    .to_frame(&mtp::codec::TypeMap::latest(), id)
                    .unwrap(),
                _ => Frame::new(kind)
                    .with_id(id)
                    .add_typed_default(D::SessionId, V::UnsignedNumber(999)),
            }
            .with_sender(999);
            client_peer.sender.send(&request).await.unwrap();
            client
                .clone()
                .handle_message(general.receiver.receive().await.unwrap())
                .await;
            let forwarded = iota_peer.receive().await.unwrap();
            assert_eq!(forwarded.sender(), Some(42));
            if kind == C::GetChats {
                assert_eq!(
                    forwarded.get_data(D::SessionId).and_then(V::as_number),
                    Some(client.session_id.into())
                );
            }
            // A frame with the wrong upstream ID must not consume this waiter.
            iota_peer
                .sender
                .send(&Frame::new(C::ErrorInvalidData).with_id(forwarded.id().unwrap() + 1000))
                .await
                .unwrap();
            let rejected = iota_peer.receive().await.unwrap();
            assert!(rejected.is_type(C::ErrorInvalidData));
            assert!(
                tokio::time::timeout(Duration::from_millis(50), client_peer.receive())
                    .await
                    .is_err()
            );
            let response = match kind {
                C::UserResolve => Frame::new(C::UserResolved)
                    .add_typed_default(D::Principal, V::Str(canonical.clone()))
                    .add_typed_default(D::UserAddress, V::Str(canonical.clone()))
                    .add_typed_default(D::UserId, V::UnsignedNumber(42))
                    .add_typed_default(
                        D::AuthorityId,
                        V::Str(secret_request.owner.authority.clone()),
                    )
                    .add_typed_default(D::NodeId, V::Str(format!("iota:v1:{fingerprint}")))
                    .add_typed_default(D::PublicKey, V::Str(public_key.clone()))
                    .add_typed_default(D::SigningKeys, V::Array(vec![V::Str(public_key.clone())])),
                C::GetChats => Frame::new(C::GetChats).with_receiver(42).add_typed_default(
                    D::UserIds,
                    V::Array(vec![V::Container(vec![
                        (
                            D::Principal
                                .try_to_id(&mtp::codec::TypeMap::latest())
                                .unwrap(),
                            V::Str(canonical.clone()),
                        ),
                        (
                            D::UserId.try_to_id(&mtp::codec::TypeMap::latest()).unwrap(),
                            V::UnsignedNumber(1),
                        ),
                    ])]),
                ),
                C::GetCommunities => Frame::new(C::GetCommunities)
                    .with_receiver(42)
                    .add_typed_default(D::Communities, V::Array(vec![])),
                _ => tau::chat_secret::ReadResponse {
                    scope: secret_request.clone(),
                    encrypted_secret: vec![1, 2, 3],
                    kem_ciphertext: vec![4, 5, 6],
                    wrapping_scheme: "test-encrypted-envelope".into(),
                    created_at: 1,
                    updated_at: 1,
                }
                .to_frame(&forwarded)
                .unwrap(),
            }
            .with_id(forwarded.id().unwrap());
            iota_peer.sender.send(&response).await.unwrap();
            let received = client_peer.receive().await.unwrap();
            assert_eq!(received.id(), Some(id));
            let expected = if kind == C::GetChats {
                response
                    .clone()
                    .add_typed_default(D::Calls, V::Array(vec![]))
                    .add_typed_default(D::PresenceSnapshotComplete, V::Bool(false))
            } else {
                response.clone()
            };
            assert_eq!(received.payload(), expected.payload());
            if kind == C::GetChatSecret {
                let decoded =
                    tau::chat_secret::ReadResponse::from_frame(&received, &request.with_sender(42))
                        .unwrap();
                assert_eq!(decoded.scope, secret_request);
            }
        }

        // A valid response type is insufficient to release another account's data.
        let request = Frame::new(C::GetChats).with_id(200);
        client_peer.sender.send(&request).await.unwrap();
        client
            .clone()
            .handle_message(general.receiver.receive().await.unwrap())
            .await;
        let forwarded = iota_peer.receive().await.unwrap();
        iota_peer
            .sender
            .send(
                &Frame::new(C::GetChats)
                    .with_id(forwarded.id().unwrap())
                    .with_receiver(999)
                    .add_typed_default(D::UserIds, V::Array(vec![])),
            )
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(3), client_peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(
            response.is_type(C::ErrorInternal),
            "mismatched owner was forwarded: {response:?}"
        );
        assert_eq!(response.id(), Some(200));

        // Matching owner but missing required data must fail closed as well.
        for (id, kind) in [
            (210, C::GetChats),
            (211, C::UserResolve),
            (212, C::GetChatSecret),
        ] {
            client_peer
                .sender
                .send(&Frame::new(kind).with_id(id))
                .await
                .unwrap();
            client
                .clone()
                .handle_message(general.receiver.receive().await.unwrap())
                .await;
            let forwarded = iota_peer.receive().await.unwrap();
            let result_kind = match kind {
                C::UserResolve => C::UserResolved,
                C::GetChatSecret => C::ChatSecretResponse,
                _ => kind,
            };
            iota_peer
                .sender
                .send(
                    &Frame::new(result_kind)
                        .with_id(forwarded.id().unwrap())
                        .with_receiver(42),
                )
                .await
                .unwrap();
            let received = client_peer.receive().await.unwrap();
            assert!(received.is_type(C::ErrorInternal));
            assert_eq!(received.id(), Some(id));
            assert!(received.get_data(D::EncryptedSecret).is_none());
        }

        client_peer
            .sender
            .send(&Frame::new(C::GetChats).with_id(220))
            .await
            .unwrap();
        client
            .clone()
            .handle_message(general.receiver.receive().await.unwrap())
            .await;
        let forwarded = iota_peer.receive().await.unwrap();
        iota_peer
            .sender
            .send(
                &Frame::new(C::ErrorInvalidData)
                    .with_id(forwarded.id().unwrap())
                    .add_typed_default(D::EncryptedSecret, V::Bytes(vec![99])),
            )
            .await
            .unwrap();
        let received = client_peer.receive().await.unwrap();
        assert!(received.is_type(C::ErrorInternal));
        assert_eq!(received.id(), Some(220));
        assert!(received.get_data(D::EncryptedSecret).is_none());

        for (id, field, value) in [
            (230, D::VersionNumber, V::UnsignedNumber(2)),
            (
                231,
                D::UserId,
                V::Str(serde_json::to_string(&secret_request.pair.second).unwrap()),
            ),
        ] {
            let request = secret_request
                .to_frame(&mtp::codec::TypeMap::latest(), id)
                .unwrap();
            client_peer.sender.send(&request).await.unwrap();
            client
                .clone()
                .handle_message(general.receiver.receive().await.unwrap())
                .await;
            let forwarded = iota_peer.receive().await.unwrap();
            let response = tau::chat_secret::ReadResponse {
                scope: secret_request.clone(),
                encrypted_secret: vec![99],
                kem_ciphertext: vec![88],
                wrapping_scheme: "test-encrypted-envelope".into(),
                created_at: 1,
                updated_at: 1,
            }
            .to_frame(&forwarded)
            .unwrap()
            .add_typed_default(field, value);
            iota_peer.sender.send(&response).await.unwrap();
            let received = client_peer.receive().await.unwrap();
            assert!(received.is_type(C::ErrorInternal));
            assert_eq!(received.id(), Some(id));
            assert!(received.get_data(D::EncryptedSecret).is_none());
        }

        client_peer
            .sender
            .send(&Frame::new(C::GetChats).with_id(500))
            .await
            .unwrap();
        client
            .clone()
            .handle_message(general.receiver.receive().await.unwrap())
            .await;
        let timed_out = iota_peer.receive().await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(25), client_peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(received.is_type(C::ErrorInternal));
        assert_eq!(received.id(), Some(500));
        iota_peer
            .sender
            .send(
                &Frame::new(C::GetChats)
                    .with_id(timed_out.id().unwrap())
                    .with_receiver(42)
                    .add_typed_default(D::UserIds, V::Array(vec![])),
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client_peer.receive())
                .await
                .is_err()
        );

        let (other_host, other_peer, transport) = test_support::authenticated("iota").await;
        let other_general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let other_iota = IotaConnection::from_general(other_general.clone(), 3).await;
        let other_rho = Arc::new(RhoConnection::new(other_iota, vec![]).await);
        state.rho.add(other_rho).await;
        client_peer
            .sender
            .send(&Frame::new(C::GetChats).with_id(600))
            .await
            .unwrap();
        client
            .clone()
            .handle_message(general.receiver.receive().await.unwrap())
            .await;
        let obsolete = iota_peer.receive().await.unwrap();
        state.rho.bind_user_to_iota(42, 3).await.unwrap();
        state.rho.bind_user_to_iota(42, 2).await.unwrap();
        iota_peer
            .sender
            .send(
                &Frame::new(C::GetChats)
                    .with_id(obsolete.id().unwrap())
                    .with_receiver(42)
                    .add_typed_default(D::UserIds, V::Array(vec![])),
            )
            .await
            .unwrap();
        let received = client_peer.receive().await.unwrap();
        assert!(
            received.is_type(C::ErrorInternal),
            "reassignment must not release an obsolete account response"
        );
        assert_eq!(received.id(), Some(600));
        assert!(received.get_data(D::UserIds).is_none());

        client.close().await;
        client_peer.sender.close().await;
        iota_peer.sender.close().await;
        tokio::time::timeout(Duration::from_secs(3), reader)
            .await
            .unwrap()
            .unwrap();
        client_host.shutdown().await;
        iota_host.shutdown().await;
        other_peer.sender.close().await;
        other_host.shutdown().await;
    })
    .await
    .expect("authenticated chat read scenario exceeded its budget");
}

#[tokio::test]
async fn unauthenticated_transport_cannot_become_a_client() {
    let (host, peer, transport) = test_support::guest("client").await;
    assert!(
        GeneralConnection::admit(transport, test_support::state(), &admission_engine()).is_err()
    );
    peer.sender.close().await;
    host.shutdown().await;
}
