use super::{
    client_connection::ClientConnection, iota_connection::IotaConnection,
    rho_connection::RhoConnection,
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use std::{sync::Arc, time::Duration};
use tau::relay_protocol::Principal;

const DELIVERY_STATUS: &str = "tensamin-hosted-delivery-v1";

#[cfg(test)]
mod tests;

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    recipient: Principal,
    signer: Principal,
    message_id: String,
    dictionary_version: String,
}

pub(super) fn is_delivery(frame: &CommunicationValue) -> bool {
    frame.is_type(CommunicationType::Relay)
        && frame.get_data(DataType::Status).and_then(DataValue::as_str) == Some(DELIVERY_STATUS)
}

fn decode(frame: &CommunicationValue) -> Result<(Delivery, CommunicationValue), String> {
    let map = frame.type_map().ok_or("missing delivery dictionary")?;
    let json = frame
        .get_data(DataType::Json)
        .and_then(DataValue::as_bytes_slice)
        .ok_or("missing delivery context")?;

    if json.len() > 2048 {
        return Err("delivery context is too large".into());
    }

    let delivery: Delivery =
        serde_json::from_slice(json).map_err(|_| "invalid delivery context")?;
    delivery
        .recipient
        .validate()
        .map_err(|_| "invalid delivery recipient")?;
    delivery
        .signer
        .validate()
        .map_err(|_| "invalid delivery signer")?;

    if delivery.message_id.is_empty()
        || delivery.message_id.len() > 256
        || delivery.dictionary_version != map.version.to_string()
    {
        return Err("invalid delivery identity or dictionary".into());
    }

    let bytes = frame
        .get_data(DataType::SecurePayload)
        .and_then(DataValue::as_bytes_slice)
        .ok_or("missing delivery payload")?;
    let payload =
        CommunicationValue::from_bytes_with(bytes, map).map_err(|_| "invalid delivery payload")?;

    if !payload.is_type(CommunicationType::Relay) || payload.payload().as_encrypted().is_none() {
        return Err("delivery requires an encrypted native relay".into());
    }

    Ok((delivery, payload))
}

fn acknowledgement_matches(response: &CommunicationValue, delivery: &Delivery) -> bool {
    response.is_type(CommunicationType::Success)
        && response
            .get_data(DataType::Status)
            .and_then(DataValue::as_str)
            == Some("notification")
        && response
            .get_data(DataType::RelayMessageId)
            .and_then(DataValue::as_str)
            == Some(delivery.message_id.as_str())
        && response
            .get_data(DataType::Principal)
            .and_then(DataValue::as_str)
            .and_then(|principal| serde_json::from_str::<Principal>(principal).ok())
            .as_ref()
            == Some(&delivery.signer)
}

async fn deliver_to_client(
    client: Arc<ClientConnection>,
    rho: Arc<RhoConnection>,
    payload: CommunicationValue,
    delivery: Delivery,
    generation: u64,
) -> Result<CommunicationValue, String> {
    let mut forwarding = client
        .native_forwarding
        .begin(uuid::Uuid::new_v4())
        .ok_or("client route is changing")?;

    if !rho.owns_client(&client) {
        return Err("client route changed".into());
    }

    let expected = delivery.clone();
    let exchange = client.delivery_responses.exchange(
        &payload,
        Duration::from_secs(20),
        move |response| {
            acknowledgement_matches(response, &expected)
                || response
                    .get_comm_type_enum()
                    .is_some_and(tau::is_protocol_error)
        },
        |outbound| {
            let client = client.clone();
            let rho = rho.clone();

            async move {
                if !rho.owns_client(&client)
                    || client
                        .state
                        .rho
                        .user_route_generation(client.user_id as i64, &rho)
                        != Some(generation)
                {
                    return Err("client route changed".to_owned());
                }

                client.send_relay(&outbound).await
            }
        },
    );
    let response = tokio::select! {
        biased;
        _ = forwarding.cancellation.changed() => return Err("client route changed".into()),
        response = exchange => response.map_err(|error| error.to_string())?,
    };

    if !rho.owns_client(&client)
        || client
            .state
            .rho
            .user_route_generation(client.user_id as i64, &rho)
            != Some(generation)
        || !acknowledgement_matches(&response, &delivery)
    {
        return Err("client did not accept the relay notification on its current route".into());
    }

    Ok(response)
}

pub(super) async fn deliver(
    source: &Arc<IotaConnection>,
    request: &CommunicationValue,
) -> Result<CommunicationValue, String> {
    let (delivery, payload) = decode(request)?;
    let user_id = i64::try_from(delivery.recipient.user_id)
        .map_err(|_| "delivery recipient is out of range")?;

    if !source.state.rho.owns_iota_user(user_id, source) {
        return Err("Iota does not own the delivery recipient".into());
    }

    let rho = source
        .state
        .rho
        .get_for_user_on_iota(user_id, source.iota_id)
        .ok_or("delivery route is unavailable")?;
    let generation = source
        .state
        .rho
        .user_route_generation(user_id, &rho)
        .ok_or("delivery route changed")?;
    let mut attempts = tokio::task::JoinSet::new();

    for client in rho.get_client_connections_for_user(user_id).await {
        attempts.spawn(deliver_to_client(
            client,
            rho.clone(),
            payload.clone(),
            delivery.clone(),
            generation,
        ));
    }

    while let Some(result) = attempts.join_next().await {
        if let Ok(Ok(response)) = result {
            if !source.state.rho.owns_iota_user(user_id, source)
                || source.state.rho.user_route_generation(user_id, &rho) != Some(generation)
            {
                return Err("delivery route changed".into());
            }

            return Ok(response);
        }
    }

    Err("no current client accepted the relay notification".into())
}
