use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use thiserror::Error;

use crate::{app_state::AppState, rho::rho_manager::RhoManager};

pub use tau::{MessageSecurityClass, RouteTarget};

static NEXT_RELAY_FRAME_ID: AtomicU32 = AtomicU32::new(1);

/// Full public-key fingerprint. Numeric MTP IDs and hints are not route keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IotaNodeId(String);

impl IotaNodeId {
    pub fn new(value: &str) -> Result<Self, RelayRouteError> {
        let fingerprint = value
            .strip_prefix("iota:v1:")
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(RelayRouteError::InvalidEnvelope)?;
        Ok(Self(format!(
            "iota:v1:{}",
            fingerprint.to_ascii_lowercase()
        )))
    }

    pub(crate) fn from_public_keys(
        keys: &mtp::crypto::PublicKeyBundle,
    ) -> Result<Self, RelayRouteError> {
        let bytes = keys
            .try_as_bytes()
            .map_err(|_| RelayRouteError::UnverifiedIota)?;
        let fingerprint = mtp::crypto::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::new(&format!("iota:v1:{fingerprint}"))
    }
}

/// Hosted client control policy is independent of the opaque V2 relay content.
pub fn message_security_class(frame: &CommunicationValue) -> MessageSecurityClass {
    if is_relay_receipt_page(frame) {
        return MessageSecurityClass::AuthenticatedPeerControl;
    }
    const PEER_CONTROL_TYPES: &[CommunicationType] = &[
        CommunicationType::UserResolve,
        CommunicationType::GetChats,
        CommunicationType::GetCommunities,
        CommunicationType::GetChatSecret,
        CommunicationType::MessageGet,
        CommunicationType::MessagesGet,
        CommunicationType::SyncedSettingSet,
        CommunicationType::SyncedSettingGet,
        CommunicationType::SyncedSettingDelete,
        CommunicationType::SyncedSettingsList,
        CommunicationType::UserBlobPut,
        CommunicationType::UserBlobGet,
        CommunicationType::UserBlobDelete,
        CommunicationType::UserBlobList,
        CommunicationType::UserAssetUploadStart,
        CommunicationType::UserAssetUploadChunk,
        CommunicationType::UserAssetUploadStatus,
        CommunicationType::UserAssetUploadCommit,
        CommunicationType::UserAssetUploadAbort,
        CommunicationType::UserAssetGetChunk,
        CommunicationType::UserAssetList,
        CommunicationType::UserAssetDelete,
        CommunicationType::FileFolderPut,
        CommunicationType::FileFolderDelete,
        CommunicationType::FilePlacementPut,
        CommunicationType::FilePlacementDelete,
        CommunicationType::FileVersionPublish,
        CommunicationType::FileKeyEnvelopePut,
        CommunicationType::FileMetadataPut,
        CommunicationType::FileUploadStart,
        CommunicationType::FileListPage,
        CommunicationType::FileGetManifest,
        CommunicationType::FileChangesGet,
        CommunicationType::FileDelete,
        CommunicationType::FileReplicaAccept,
        CommunicationType::FileReplicaCancel,
        CommunicationType::FileReplicaStatus,
        CommunicationType::UserBlock,
        CommunicationType::UserUnblock,
        CommunicationType::BlockedUsersGet,
        CommunicationType::ReceiptPolicyGet,
        CommunicationType::ReceiptPolicySet,
        CommunicationType::MessageStoragePolicyGet,
        CommunicationType::MessageStoragePolicySet,
        CommunicationType::ReadNotification,
    ];
    const LOCAL_REQUEST_TYPES: &[CommunicationType] = &[
        CommunicationType::Relay,
        CommunicationType::SessionActivitySet,
        CommunicationType::ClientChanged,
        CommunicationType::CallReserve,
        CommunicationType::CallActivate,
        CommunicationType::CallInvite,
        CommunicationType::CallToken,
        CommunicationType::CallData,
        CommunicationType::CallDisconnectUser,
        CommunicationType::CallTimeoutUser,
        CommunicationType::CallSetAnonymousJoining,
        CommunicationType::CallCommand,
        CommunicationType::CallSnapshotGet,
        CommunicationType::CallJoinAuthorize,
        CommunicationType::CallKeyEnvelopeStage,
        CommunicationType::CallKeyEnvelopeGet,
        CommunicationType::CallKeyEnvelopeActivate,
        CommunicationType::EndCall,
        CommunicationType::PasswordEnrollmentStart,
        CommunicationType::PasswordEnrollmentFinish,
        CommunicationType::PasswordEnrollmentStatus,
        CommunicationType::PasswordEnrollmentDisable,
        CommunicationType::TAuthAuthorize,
        CommunicationType::TAuthGrantList,
        CommunicationType::TAuthGrantRevoke,
        CommunicationType::TAuthGrantMetadataSet,
        CommunicationType::GetUserData,
        CommunicationType::GetIotaData,
        CommunicationType::ChangeUserData,
        CommunicationType::DeleteUser,
        CommunicationType::GetNotifications,
        CommunicationType::AccountStateRequest,
        CommunicationType::AccountStateApplied,
        CommunicationType::SettingsLoad,
        CommunicationType::SettingsList,
        CommunicationType::GlobalSettingsLoad,
        CommunicationType::ChatSecretForward,
        CommunicationType::SyncedSettingChanged,
        CommunicationType::UserBlobChanged,
        CommunicationType::UserAssetChanged,
        CommunicationType::BlockedUsersChanged,
        CommunicationType::ReceiptPolicyChanged,
        CommunicationType::MessageStoragePolicyChanged,
        CommunicationType::PushNotification,
        CommunicationType::AccountStateSnapshot,
        CommunicationType::StateSubscribe,
        CommunicationType::CompleteRegisterUser,
        CommunicationType::DeleteIota,
        CommunicationType::AttachUserBegin,
        CommunicationType::AttachUserComplete,
        CommunicationType::ReleaseUserFromIota,
        CommunicationType::DeleteUserCredentialBegin,
        CommunicationType::DeleteUserCredentialComplete,
        CommunicationType::EraseHostedUserDataAck,
        CommunicationType::AcknowledgeIotaUserProvision,
        CommunicationType::CreateUserInvitation,
        CommunicationType::ListUserInvitations,
        CommunicationType::RevokeUserInvitation,
        CommunicationType::GetRegister,
    ];
    tau::message_security_class_with(frame, PEER_CONTROL_TYPES, LOCAL_REQUEST_TYPES)
}

pub(crate) fn is_relay_receipt_page(frame: &CommunicationValue) -> bool {
    frame.is_type(CommunicationType::RelayReceiptPage)
}

#[derive(Debug, Error)]
pub enum RelayRouteError {
    #[error("expected a V2 relay with a canonical destination")]
    InvalidEnvelope,
    #[error("relay requires a current Iota with a verified MTP public key")]
    UnverifiedIota,
    #[error("relay destination Iota is not connected to this Omikron")]
    DestinationIotaNotLocal,
    #[error("relay route resolves back to its source Iota")]
    RouteLoop,
    #[error("relay send failed: {0}")]
    Send(String),
}

pub fn error_response_type(error: &RelayRouteError) -> CommunicationType {
    match error {
        RelayRouteError::UnverifiedIota => CommunicationType::ErrorNotAuthenticated,
        RelayRouteError::DestinationIotaNotLocal => CommunicationType::ErrorNoIota,
        RelayRouteError::Send(_) => CommunicationType::ErrorInternal,
        _ => CommunicationType::ErrorInvalidData,
    }
}

pub fn relay_route_error_response(
    message_id: u32,
    _target: Option<RouteTarget>,
    error: &RelayRouteError,
) -> CommunicationValue {
    CommunicationValue::new(error_response_type(error)).with_id(message_id)
}

/// Read only the signed envelope's routing hint. The destination Iota verifies
/// the signature, principals, authority, content and acceptance metadata.
fn destination(frame: &CommunicationValue) -> Result<IotaNodeId, RelayRouteError> {
    if !frame.is_type(CommunicationType::Relay)
        || frame.sender().is_some()
        || !matches!(
            frame.get_data(DataType::VersionNumber),
            Some(DataValue::UnsignedNumber(2) | DataValue::SignedNumber(2))
        )
    {
        return Err(RelayRouteError::InvalidEnvelope);
    }
    #[derive(serde::Deserialize)]
    struct DeclaredRoute {
        version: u32,
        destination: String,
    }
    let Some(DataValue::Bytes(payload)) = frame.get_data(DataType::SecurePayload) else {
        return Err(RelayRouteError::InvalidEnvelope);
    };
    let declared: DeclaredRoute =
        serde_json::from_slice(payload).map_err(|_| RelayRouteError::InvalidEnvelope)?;
    if declared.version != 2 {
        return Err(RelayRouteError::InvalidEnvelope);
    }
    IotaNodeId::new(&declared.destination)
}

/// Callers authorize the originating connection against the published snapshot.
/// Forward the original V2 envelope without decoding its application content.
pub async fn route_relay(
    state: &Arc<AppState>,
    source: &super::iota_connection::IotaConnection,
    frame: CommunicationValue,
) -> Result<CommunicationValue, RelayRouteError> {
    let destination = destination(&frame)?;
    let (source_node, target) = state
        .rho
        .relay_routes(source, &destination)
        .ok_or(RelayRouteError::UnverifiedIota)?;
    if destination == source_node {
        return Err(RelayRouteError::RouteLoop);
    }
    if let Some(target) = target {
        return route_response(
            target
                .await_relay_to_iota(&frame)
                .await
                .map_err(RelayRouteError::Send)?,
        );
    }
    route_response(
        state
            .omega
            .await_response(&frame, Some(Duration::from_secs(20)))
            .await
            .map_err(RelayRouteError::Send)?,
    )
}

pub async fn route_from_omega(
    rho: &RhoManager,
    frame: CommunicationValue,
) -> Result<CommunicationValue, RelayRouteError> {
    let destination = destination(&frame)?;
    let target = rho
        .get_by_node(&destination)
        .ok_or(RelayRouteError::DestinationIotaNotLocal)?;
    route_response(
        target
            .await_relay_to_iota(&frame)
            .await
            .map_err(RelayRouteError::Send)?,
    )
}

fn route_response(response: CommunicationValue) -> Result<CommunicationValue, RelayRouteError> {
    if response.is_type(CommunicationType::Success)
        || response
            .get_type_name()
            .is_some_and(|name| name.starts_with("Error"))
    {
        Ok(response)
    } else {
        Err(RelayRouteError::Send(format!(
            "next Relay hop rejected the frame with {}",
            response.get_type()
        )))
    }
}

pub fn ensure_relay_frame_id(frame: CommunicationValue) -> CommunicationValue {
    if frame.id().is_some() {
        return frame;
    }
    frame.with_id(NEXT_RELAY_FRAME_ID.fetch_add(1, Ordering::Relaxed).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_pages_require_authenticated_peer_control() {
        let page = CommunicationValue::new(CommunicationType::RelayReceiptPage);
        assert_eq!(page.get_type().0, 225);
        for (kind, id) in [
            (DataType::ReceiptCursor, 250),
            (DataType::ReceiptUpper, 251),
            (DataType::ReceiptMore, 252),
            (DataType::ReceiptComplete, 253),
            (DataType::ReceiptSequence, 254),
            (DataType::ReceiptAcceptedAt, 255),
        ] {
            let frame = page
                .clone()
                .add_typed_default(kind, DataValue::UnsignedNumber(42));
            assert_eq!(frame.data().unwrap()[0].0.0, id);
        }
        let bytes = page.to_bytes().unwrap();
        let page = CommunicationValue::from_bytes(&bytes).unwrap();
        assert!(is_relay_receipt_page(&page));
        assert_eq!(
            message_security_class(&page),
            MessageSecurityClass::AuthenticatedPeerControl
        );
    }

    #[test]
    fn synchronized_setting_requests_use_authenticated_peer_control() {
        for kind in [
            CommunicationType::SyncedSettingSet,
            CommunicationType::SyncedSettingGet,
            CommunicationType::SyncedSettingDelete,
            CommunicationType::SyncedSettingsList,
        ] {
            assert_eq!(
                message_security_class(&CommunicationValue::new(kind)),
                MessageSecurityClass::AuthenticatedPeerControl
            );
        }
    }

    #[test]
    fn synchronized_setting_notifications_are_not_relay_only() {
        assert_ne!(
            message_security_class(&CommunicationValue::new(
                CommunicationType::SyncedSettingChanged
            )),
            MessageSecurityClass::RelayOnly
        );
    }

    fn relay(node: &str) -> CommunicationValue {
        CommunicationValue::new(CommunicationType::Relay).with_id(7)
            .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
            .add_typed_default(DataType::SecurePayload, DataValue::Bytes(format!(
                "{{ \"version\":2, \"destination\":\"{node}\", \"signature\":\"opaque\", \"content\":\"not decoded\" }}"
            ).into_bytes()))
    }

    #[test]
    fn routing_reads_only_v2_destination_and_preserves_envelope() {
        let node = format!("iota:v1:{}", "AB".repeat(32));
        let frame = relay(&node).with_receiver(123);
        let bytes = frame.to_bytes().unwrap();
        assert_eq!(
            destination(&frame).unwrap(),
            IotaNodeId::new(&node).unwrap()
        );
        assert_eq!(frame.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn legacy_numeric_and_principal_destinations_are_rejected() {
        for node in ["42", "user:42", "omega:example:42", "iota:v1:abcd"] {
            assert!(destination(&relay(node)).is_err());
        }
        let legacy = CommunicationValue::new(CommunicationType::Relay)
            .with_receiver(42)
            .with_payload(DataValue::Bytes(vec![1, 2, 3]));
        assert!(destination(&legacy).is_err());
    }

    #[test]
    fn both_version_markers_and_no_outer_sender_are_required() {
        let frame = relay(&format!("iota:v1:{}", "ab".repeat(32)));
        assert!(
            destination(
                &frame
                    .clone()
                    .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(1))
            )
            .is_err()
        );
        assert!(destination(&frame.with_sender(9)).is_err());
        let frame = CommunicationValue::new(CommunicationType::Relay)
            .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
            .add_typed_default(
                DataType::SecurePayload,
                DataValue::Bytes(
                    format!(
                        "{{\"version\":1,\"destination\":\"iota:v1:{}\"}}",
                        "ab".repeat(32)
                    )
                    .into_bytes(),
                ),
            );
        assert!(destination(&frame).is_err());
    }

    #[test]
    fn duplicate_signed_destinations_are_rejected() {
        let node = format!("iota:v1:{}", "ab".repeat(32));
        let frame = relay(&node).add_typed_default(
            DataType::SecurePayload,
            DataValue::Bytes(
                format!("{{\"version\":2,\"destination\":\"{node}\",\"destination\":\"{node}\"}}")
                    .into_bytes(),
            ),
        );
        assert!(destination(&frame).is_err());
    }

    #[test]
    fn fingerprint_matches_iota_full_serialized_key_algorithm() {
        let keys = mtp::crypto::Keyring::generate().public_key_bundle();
        let hash = mtp::crypto::sha256(&keys.try_as_bytes().unwrap());
        let expected = format!(
            "iota:v1:{}",
            hash.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        assert_eq!(IotaNodeId::from_public_keys(&keys).unwrap().0, expected);
    }

    #[tokio::test]
    async fn omega_requires_a_canonical_local_route() {
        let rho = RhoManager::new();
        assert!(matches!(
            route_from_omega(&rho, relay(&format!("iota:v1:{}", "ab".repeat(32)))).await,
            Err(RelayRouteError::DestinationIotaNotLocal)
        ));
    }

    #[tokio::test]
    async fn local_forwarding_keeps_opaque_envelope_and_destination_acceptance() {
        use crate::rho::{
            connection::{GeneralConnection, admission_engine},
            iota_connection::IotaConnection,
            rho_connection::RhoConnection,
            test_support,
        };
        let state = test_support::state();
        let (host, peer, transport) = test_support::authenticated("iota").await;
        let general =
            GeneralConnection::admit(transport, state.clone(), &admission_engine()).unwrap();
        let iota = IotaConnection::from_general(general, 42).await;
        let node = iota.node_id.as_ref().unwrap().0.clone();
        let rho = Arc::new(RhoConnection::new(iota.clone(), vec![]).await);
        state.rho.add(rho).await;
        let frame = relay(&node);
        let original_payload = frame.get_data(DataType::SecurePayload).cloned();
        let delivery = route_from_omega(&state.rho, frame);
        let endpoint = async {
            let received = peer.receive().await.unwrap();
            assert!(received.is_type(CommunicationType::Relay));
            assert_eq!(
                received.get_data(DataType::SecurePayload).cloned(),
                original_payload
            );
            assert_eq!(received.receiver(), None);
            assert_eq!(received.sender(), None);
            let response = CommunicationValue::new(CommunicationType::Success)
                .add_typed_default(
                    DataType::RelayMessageId,
                    DataValue::Str("accepted-original".into()),
                )
                .add_typed_default(DataType::RelayAcceptedAt, DataValue::UnsignedNumber(1234));
            assert!(
                iota.waiting_tasks
                    .complete(received.id().unwrap(), response.clone())
            );
            response
        };
        let (delivered, accepted) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(delivery, endpoint)
        })
        .await
        .unwrap();
        let delivered = delivered.unwrap();
        assert_eq!(
            delivered.get_data(DataType::RelayMessageId),
            accepted.get_data(DataType::RelayMessageId)
        );
        assert_eq!(
            delivered.get_data(DataType::RelayAcceptedAt),
            accepted.get_data(DataType::RelayAcceptedAt)
        );
        peer.sender.close().await;
        host.shutdown().await;
    }
}
