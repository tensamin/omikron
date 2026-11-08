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

#[tokio::test]
async fn password_receipt_queries_cross_authenticated_dispatch_with_the_session_actor() {
    tokio::time::timeout(Duration::from_secs(30), async {
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
        let general = GeneralConnection::admit(transport, state, &admission_engine()).unwrap();
        let client = ClientConnection::from_general(general.clone(), 42).await;
        rho.add_client_connection(client.clone()).await;
        *client.rho_connection.write().await = Some(rho);
        let original = Frame::new(C::PasswordEnrollmentDisable)
            .with_sender(42)
            .with_receiver(2)
            .to_bytes()
            .unwrap();
        let query = Frame::new(C::PasswordEnrollmentStatus)
            .with_id(701)
            .with_sender(999)
            .with_receiver(2)
            .add_typed_default(D::SecurePayload, V::Bytes(original.clone()))
            .add_typed_default(D::Version, V::Str("1.1".into()));
        client_peer.sender.send(&query).await.unwrap();
        client
            .clone()
            .handle_message(general.receiver.receive().await.unwrap())
            .await;
        let forwarded = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                frame = iota_peer.receive() => frame.unwrap(),
                frame = client_peer.receive() => panic!("receipt query was rejected before forwarding: {:?}", frame.unwrap().get_comm_type_enum()),
            }
        }).await.expect("receipt query was not forwarded");
        assert!(forwarded.is_type(C::PasswordEnrollmentStatus));
        assert_eq!(forwarded.sender(), Some(42));
        assert_eq!(forwarded.receiver(), Some(2));
        assert_ne!(forwarded.id(), Some(701));
        assert_eq!(
            forwarded
                .get_data(D::SecurePayload)
                .and_then(V::as_bytes)
                .unwrap(),
            original
        );
        iota_peer
            .sender
            .send(&Frame::new(C::ErrorInvalidData).with_id(forwarded.id().unwrap()))
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(3), client_peer.receive()).await.expect("receipt response was not forwarded").unwrap();
        assert_eq!(reply.id(), Some(701));
        assert!(reply.is_type(C::ErrorInvalidData));
        tokio::time::timeout(Duration::from_secs(3), client.close()).await.expect("client did not close");
        client_peer.sender.close().await;
        iota_peer.sender.close().await;
        tokio::time::timeout(Duration::from_secs(3), reader)
            .await
            .unwrap()
            .unwrap();
        iota_host.shutdown().await;
        client_host.shutdown().await;
    })
    .await
    .unwrap();
}
