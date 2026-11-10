use super::*;
use crate::rho::{
    connection::{GeneralConnection, admission_engine},
    test_support,
};
use mtp::{
    codec::relay::SealedRelayBuilder,
    crypto::{Ed25519Signer, Keyring},
};

fn request() -> CommunicationValue {
    let keys = Keyring::generate();
    let signer = Ed25519Signer::new(&keys.sig_cl_secret_key).unwrap();
    let map = mtp::type_map::TypeMap::latest();
    let application = CommunicationValue::new_with_type_map(CommunicationType::MessageSend, &map)
        .add_typed_default(DataType::Content, DataValue::Str("AQ==".into()));
    let payload = SealedRelayBuilder::new(
        CommunicationType::MessageSend,
        application.payload().clone(),
        8,
        7,
        3,
        &signer,
    )
    .type_map(&map)
    .message_id(1u128)
    .created_at(1)
    .metadata_recipients(vec![keys.public_key_bundle()])
    .content_recipients(vec![keys.public_key_bundle()])
    .build()
    .unwrap()
    .with_id(55);
    let authority = format!("omega-key:{}", "1".repeat(64));
    let context = serde_json::json!({
        "recipient": Principal::new(authority.clone(), 7).unwrap(),
        "signer": Principal::new(authority, 8).unwrap(),
        "message_id": "mtp-sealed-v1:1",
        "dictionary_version": map.version.to_string(),
    });

    CommunicationValue::new_with_type_map(CommunicationType::Relay, &map)
        .with_id(91)
        .add_typed_default(DataType::Status, DataValue::Str(DELIVERY_STATUS.into()))
        .add_typed_default(
            DataType::Json,
            DataValue::Bytes(serde_json::to_vec(&context).unwrap()),
        )
        .add_typed_default(
            DataType::SecurePayload,
            DataValue::Bytes(payload.to_bytes().unwrap()),
        )
}

fn acknowledgement(id: u32, delivery: &Delivery) -> CommunicationValue {
    CommunicationValue::new(CommunicationType::Success)
        .with_id(id)
        .add_typed_default(DataType::Status, DataValue::Str("notification".into()))
        .add_typed_default(
            DataType::RelayMessageId,
            DataValue::Str(delivery.message_id.clone()),
        )
        .add_typed_default(
            DataType::Principal,
            DataValue::Str(serde_json::to_string(&delivery.signer).unwrap()),
        )
}

struct Fixture {
    source: Arc<IotaConnection>,
    rho: Arc<RhoConnection>,
    client: Arc<ClientConnection>,
    iota_peer: mtp::client::MTPConnection,
    client_peer: mtp::client::MTPConnection,
    hosts: [mtp::webserver::MTPWebServer; 2],
}

impl Fixture {
    async fn new() -> Self {
        let state = test_support::state();
        let (iota_host, iota_peer, iota_transport) = test_support::guest("anonymous").await;
        let (client_host, client_peer, client_transport) = test_support::guest("anonymous").await;
        let general =
            GeneralConnection::admit(iota_transport, state.clone(), &admission_engine()).unwrap();
        let source = IotaConnection::from_general(general, 2).await;
        let rho = Arc::new(RhoConnection::new(source.clone(), vec![7, 8]).await);
        state.rho.add(rho.clone()).await;
        let general =
            GeneralConnection::admit(client_transport, state, &admission_engine()).unwrap();
        *general.session_id.write().await = 42;
        let client = ClientConnection::from_general(general, 7).await;
        rho.add_client_connection(client.clone()).await;

        Self {
            source,
            rho,
            client,
            iota_peer,
            client_peer,
            hosts: [iota_host, client_host],
        }
    }

    async fn close(self) {
        self.client.close().await;
        self.iota_peer.sender.close().await;
        self.client_peer.sender.close().await;

        for host in self.hosts {
            host.shutdown().await;
        }
    }
}

#[test]
fn acknowledgements_bind_message_signer_and_notification_status() {
    let (delivery, _) = decode(&request()).unwrap();
    let response = acknowledgement(55, &delivery);
    assert!(acknowledgement_matches(&response, &delivery));

    for (field, value) in [
        (
            DataType::RelayMessageId,
            DataValue::Str("other-message".into()),
        ),
        (DataType::RelayMessageId, DataValue::Str("1".into())),
        (
            DataType::Principal,
            DataValue::Str(serde_json::to_string(&delivery.recipient).unwrap()),
        ),
        (DataType::Status, DataValue::Str("retained".into())),
    ] {
        let altered = response.clone().add_typed_default(field, value);
        assert!(!acknowledgement_matches(&altered, &delivery));
    }

    assert!(!acknowledgement_matches(
        &CommunicationValue::new(CommunicationType::Success).with_id(55),
        &delivery
    ));
}

#[test]
fn delivery_rejects_plaintext_payloads_and_unbound_context() {
    let request = request();
    let plaintext = CommunicationValue::new(CommunicationType::Relay)
        .to_bytes()
        .unwrap();
    assert!(
        decode(
            &request
                .clone()
                .add_typed_default(DataType::SecurePayload, DataValue::Bytes(plaintext))
        )
        .is_err()
    );

    let mut context: serde_json::Value = serde_json::from_slice(
        request
            .get_data(DataType::Json)
            .and_then(DataValue::as_bytes_slice)
            .unwrap(),
    )
    .unwrap();
    context["unexpected"] = true.into();
    assert!(
        decode(&request.add_typed_default(
            DataType::Json,
            DataValue::Bytes(serde_json::to_vec(&context).unwrap())
        ))
        .is_err()
    );
}

#[tokio::test]
async fn delivery_preserves_ciphertext_and_requires_the_recipient_connection_ack() {
    let fixture = Fixture::new().await;
    let request = request();
    let (delivery, payload) = decode(&request).unwrap();
    let source = fixture.source.clone();
    let operation = tokio::spawn(async move { deliver(&source, &request).await });
    let forwarded = tokio::time::timeout(Duration::from_secs(2), fixture.client_peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        forwarded.clone().without_id().to_bytes().unwrap(),
        payload.without_id().to_bytes().unwrap()
    );
    let response = acknowledgement(forwarded.id().unwrap(), &delivery);

    let (other_host, other_peer, other_transport) = test_support::guest("anonymous").await;
    let other_general = GeneralConnection::admit(
        other_transport,
        fixture.source.state.clone(),
        &admission_engine(),
    )
    .unwrap();
    let other_client = ClientConnection::from_general(other_general, 8).await;
    fixture
        .rho
        .add_client_connection(other_client.clone())
        .await;
    other_client.clone().handle_message(response.clone()).await;
    assert_eq!(fixture.client.delivery_responses.len(), 1);
    fixture
        .source
        .send_message(&CommunicationValue::new(CommunicationType::Ping).with_id(9999))
        .await;
    let marker = tokio::time::timeout(Duration::from_secs(2), fixture.iota_peer.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(marker.id(), Some(9999));

    fixture.client.clone().handle_message(response).await;
    let accepted = tokio::time::timeout(Duration::from_secs(2), operation)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(accepted.id(), Some(55));
    assert!(acknowledgement_matches(&accepted, &delivery));
    assert!(fixture.client.delivery_responses.is_empty());

    other_client.close().await;
    other_peer.sender.close().await;
    other_host.shutdown().await;
    fixture.close().await;
}

#[tokio::test]
async fn route_replacement_cancels_delivery_without_an_acknowledgement() {
    let fixture = Fixture::new().await;
    let source = fixture.source.clone();
    let operation = tokio::spawn(async move { deliver(&source, &request()).await });
    tokio::time::timeout(Duration::from_secs(2), fixture.client_peer.receive())
        .await
        .unwrap()
        .unwrap();
    let replacement = Arc::new(RhoConnection::new(fixture.source.clone(), vec![7]).await);
    fixture.source.state.rho.add(replacement).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), operation)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(fixture.client.delivery_responses.is_empty());
    assert!(!fixture.rho.owns_client(&fixture.client));
    fixture.close().await;
}

#[tokio::test]
async fn delivery_refuses_an_iota_that_does_not_own_the_recipient() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .state
        .rho
        .remove_user_binding(7, &fixture.rho);
    assert!(deliver(&fixture.source, &request()).await.is_err());
    assert!(fixture.client.delivery_responses.is_empty());
    fixture.close().await;
}
